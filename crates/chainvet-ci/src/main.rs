//! Chainvet CI frontend: run a scan, emit SARIF, and set the exit code from
//! fail-on-severity / fail-on-confidence thresholds — for GitHub/GitLab
//! code-scanning pipelines.

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
        "usage: chainvet-ci <path> [--mode static|symbolic|fuzzing|hybrid] [-s, --fail-on-severity high|medium|low] [-c, --fail-on-confidence high|medium|low] [--no-fail] [--sarif <out.json>]\n\
         emits SARIF (stdout or --sarif file); exits 1 if any finding meets both --fail-on-severity (default high)\n\
         and --fail-on-confidence (default low, i.e. any confidence), 0 otherwise.\n\
         --no-fail       run and emit SARIF but always exit 0 (report-only); cannot be combined with --fail-on-*.\n\
         -V, --version   print the version and exit."
    );
}

/// Confidence rank for thresholding: high (3) > medium (2) > low (1);
/// unknown/absent ranks as low (1) so it is never silently exempted from a gate.
fn confidence_rank(confidence: Option<&str>) -> u8 {
    match confidence {
        Some("high") => 3,
        Some("medium") => 2,
        _ => 1, // low + unknown/absent
    }
}

fn parse_confidence(value: &str) -> Result<u8> {
    Ok(match value {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        other => {
            return Err(Error::msg(format!(
                "unknown confidence: {other} (expected high|medium|low)"
            )));
        }
    })
}

/// Severity rank for a finding. Unknown/absent severities rank as low (1).
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "high" => 3,
        "medium" => 2,
        _ => 1, // low + unknown/absent
    }
}

fn parse_severity(value: &str) -> Result<u8> {
    Ok(match value {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        other => {
            return Err(Error::msg(format!(
                "unknown severity: {other} (expected high|medium|low; use --no-fail to disable gating)"
            )));
        }
    })
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
    // `None` = left at default; tracked so `--no-fail` can reject an explicit gate.
    let mut fail_on: Option<String> = None;
    let mut fail_on_confidence: Option<String> = None;
    let mut no_fail = false;
    let mut sarif_out: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => mode = parse_mode(&next(&mut args, "--mode")?)?,
            "--fail-on-severity" | "-s" => fail_on = Some(next(&mut args, "--fail-on-severity")?),
            "--fail-on-confidence" | "-c" => {
                fail_on_confidence = Some(next(&mut args, "--fail-on-confidence")?)
            }
            "--no-fail" => no_fail = true,
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

    if no_fail && (fail_on.is_some() || fail_on_confidence.is_some()) {
        return Err(Error::msg(
            "--no-fail cannot be combined with --fail-on-severity/--fail-on-confidence",
        ));
    }

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

    let fail_on = fail_on.unwrap_or_else(|| "high".to_string());
    let fail_on_confidence = fail_on_confidence.unwrap_or_else(|| "low".to_string());
    // A finding trips the gate only if it meets *both* the severity and the
    // confidence threshold, so `--fail-on-confidence high` gates on high-confidence
    // findings and ignores lower-confidence noise. `--no-fail` skips the gate
    // entirely (report-only) and always exits 0.
    let failed = if no_fail {
        false
    } else {
        let sev_threshold = parse_severity(&fail_on)?;
        let conf_threshold = parse_confidence(&fail_on_confidence)?;
        result.findings.iter().any(|f| {
            severity_rank(f.severity.as_deref().unwrap_or("")) >= sev_threshold
                && confidence_rank(f.confidence.as_deref()) >= conf_threshold
        })
    };
    let worst = result
        .findings
        .iter()
        .filter_map(|f| f.severity.as_deref())
        .map(severity_rank)
        .max()
        .unwrap_or(0);
    let gate = if no_fail {
        "no-fail (report-only)".to_string()
    } else {
        format!("fail-on-severity={fail_on} fail-on-confidence={fail_on_confidence}")
    };
    eprintln!(
        "chainvet-ci: {} findings; worst severity rank {}; {} -> {}",
        result.findings.len(),
        worst,
        gate,
        if failed { "FAIL" } else { "pass" }
    );
    Ok(i32::from(failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_parses_and_ranks_high_above_low() {
        assert_eq!(parse_confidence("low").unwrap(), 1);
        assert_eq!(parse_confidence("medium").unwrap(), 2);
        assert_eq!(parse_confidence("high").unwrap(), 3);
        assert!(parse_confidence("bogus").is_err());
        assert!(confidence_rank(Some("high")) > confidence_rank(Some("low")));
        // Unknown/absent confidence ranks as low so it is never exempted.
        assert_eq!(
            confidence_rank(Some("unknown")),
            confidence_rank(Some("low"))
        );
        assert_eq!(confidence_rank(None), confidence_rank(Some("low")));
    }

    #[test]
    fn severity_parses_high_medium_low_and_rejects_none() {
        assert_eq!(parse_severity("low").unwrap(), 1);
        assert_eq!(parse_severity("medium").unwrap(), 2);
        assert_eq!(parse_severity("high").unwrap(), 3);
        // `none` is no longer a severity — disabling the gate is `--no-fail`.
        assert!(parse_severity("none").is_err());
        assert!(parse_severity("bogus").is_err());
    }

    /// The gate trips only when a finding clears *both* thresholds, so a
    /// high-severity low-confidence finding passes once `--fail-on-confidence high`
    /// is set.
    #[test]
    fn gate_requires_both_severity_and_confidence() {
        let gate = |sev: &str, conf: Option<&str>, sev_thr: u8, conf_thr: u8| {
            severity_rank(sev) >= sev_thr && confidence_rank(conf) >= conf_thr
        };
        // fail-on-severity high, any confidence (low=1): a high/low-conf finding fails.
        assert!(gate("high", Some("low"), severity_rank("high"), 1));
        // fail-on-confidence high: the same high/low-conf finding now passes.
        assert!(!gate("high", Some("low"), severity_rank("high"), 3));
        // a high/high-conf finding still fails under the stricter confidence gate.
        assert!(gate("high", Some("high"), severity_rank("high"), 3));
    }
}
