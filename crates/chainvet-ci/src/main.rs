//! Chainvet CI frontend: run a scan, emit SARIF, and set the exit code from a
//! fail-on-severity threshold — for GitHub/GitLab code-scanning pipelines.

mod sarif;

use chainvet_core::util::error::{Error, Result};
use chainvet_orchestrator::{HybridBudget, ScanMode, scan_path};

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage: chainvet-ci <path> [--mode static|symbolic|fuzzing|hybrid] [--fail-on high|medium|low|none] [--fail-on-confidence candidate|confirmed] [--sarif <out.json>]\n\
         emits SARIF (stdout or --sarif file); exits 1 if any finding meets both --fail-on (default high)\n\
         and --fail-on-confidence (default candidate, i.e. any tier), 0 otherwise.\n\
         -V, --version   print the version and exit."
    );
}

/// Confidence-tier rank for thresholding: `confirmed` outranks `candidate`.
fn tier_rank(tier: &str) -> u8 {
    match tier {
        "confirmed" => 2,
        _ => 1, // candidate + unknown
    }
}

fn parse_confidence(value: &str) -> Result<u8> {
    Ok(match value {
        "candidate" => 1,
        "confirmed" => 2,
        other => {
            return Err(Error::msg(format!(
                "unknown confidence tier: {other} (expected candidate|confirmed)"
            )));
        }
    })
}

/// Severity rank for thresholding. Unknown severities rank as low (1).
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "none" => 0,
        _ => 1,
    }
}

fn parse_mode(value: &str) -> Result<ScanMode> {
    Ok(match value {
        "static" => ScanMode::Static,
        "symbolic" => ScanMode::Symbolic,
        "fuzzing" => ScanMode::Fuzzing,
        "hybrid" => ScanMode::Hybrid,
        other => return Err(Error::msg(format!("unknown mode: {other}"))),
    })
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| Error::msg(format!("missing value for {flag}")))
}

fn run() -> Result<i32> {
    let mut path = None;
    let mut mode = ScanMode::Hybrid;
    let mut fail_on = "high".to_string();
    let mut fail_on_confidence = "candidate".to_string();
    let mut sarif_out: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => mode = parse_mode(&next(&mut args, "--mode")?)?,
            "--fail-on" => fail_on = next(&mut args, "--fail-on")?,
            "--fail-on-confidence" => fail_on_confidence = next(&mut args, "--fail-on-confidence")?,
            "--sarif" => sarif_out = Some(next(&mut args, "--sarif")?),
            "--version" | "-V" => {
                println!("chainvet-ci {}", env!("CARGO_PKG_VERSION"));
                return Ok(0);
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(0);
            }
            _ => {
                if arg.starts_with('-') {
                    return Err(Error::msg(format!("unknown flag: {arg}")));
                }
                if path.is_none() {
                    path = Some(arg);
                } else {
                    return Err(Error::msg("multiple input paths provided"));
                }
            }
        }
    }

    let Some(path) = path else {
        print_usage();
        return Ok(2);
    };

    let result = scan_path(&path, mode, &HybridBudget::default())?;

    let doc = sarif::to_sarif(&result);
    let json =
        serde_json::to_string_pretty(&doc).map_err(|e| Error::msg(format!("serialize: {e}")))?;
    match &sarif_out {
        Some(file) => {
            std::fs::write(file, &json).map_err(|e| Error::msg(format!("write {file}: {e}")))?
        }
        None => println!("{json}"),
    }

    let threshold = severity_rank(&fail_on);
    let conf_threshold = parse_confidence(&fail_on_confidence)?;
    // A finding trips the gate only if it meets *both* the severity and the
    // confidence threshold, so `--fail-on-confidence confirmed` gates on
    // execution-corroborated findings and ignores static-only candidates.
    let failed = threshold > 0
        && result.findings.iter().any(|f| {
            severity_rank(f.severity.as_deref().unwrap_or("")) >= threshold
                && tier_rank(&f.tier) >= conf_threshold
        });
    let worst = result
        .findings
        .iter()
        .filter_map(|f| f.severity.as_deref())
        .map(severity_rank)
        .max()
        .unwrap_or(0);
    eprintln!(
        "chainvet-ci: {} findings; worst severity rank {}; fail-on={} fail-on-confidence={} -> {}",
        result.findings.len(),
        worst,
        fail_on,
        fail_on_confidence,
        if failed { "FAIL" } else { "pass" }
    );
    Ok(i32::from(failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_parses_and_ranks_confirmed_above_candidate() {
        assert_eq!(parse_confidence("candidate").unwrap(), 1);
        assert_eq!(parse_confidence("confirmed").unwrap(), 2);
        assert!(parse_confidence("bogus").is_err());
        assert!(tier_rank("confirmed") > tier_rank("candidate"));
        assert_eq!(tier_rank("unknown"), tier_rank("candidate"));
    }

    /// The gate trips only when a finding clears *both* thresholds, so a
    /// high-severity candidate passes once `--fail-on-confidence confirmed` is set.
    #[test]
    fn gate_requires_both_severity_and_confidence() {
        let gate = |sev: &str, tier: &str, sev_thr: u8, conf_thr: u8| {
            sev_thr > 0 && severity_rank(sev) >= sev_thr && tier_rank(tier) >= conf_thr
        };
        // fail-on high, any tier (candidate=1): a high candidate fails.
        assert!(gate("high", "candidate", severity_rank("high"), 1));
        // fail-on high, confirmed only: the same high candidate now passes.
        assert!(!gate("high", "candidate", severity_rank("high"), 2));
        // a high confirmed still fails under the stricter confidence gate.
        assert!(gate("high", "confirmed", severity_rank("high"), 2));
    }
}
