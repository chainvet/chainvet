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
        "usage: chainvet-ci <path> [--mode static|symbolic|fuzzing|hybrid] [--fail-on high|medium|low|none] [--sarif <out.json>]\n\
         emits SARIF (stdout or --sarif file); exits 1 if any finding meets --fail-on (default high), 0 otherwise."
    );
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
    let mut sarif_out: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => mode = parse_mode(&next(&mut args, "--mode")?)?,
            "--fail-on" => fail_on = next(&mut args, "--fail-on")?,
            "--sarif" => sarif_out = Some(next(&mut args, "--sarif")?),
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
    let worst = result
        .findings
        .iter()
        .filter_map(|f| f.severity.as_deref())
        .map(severity_rank)
        .max()
        .unwrap_or(0);
    let failed = threshold > 0 && worst >= threshold;
    eprintln!(
        "chainvet-ci: {} findings; worst severity rank {}; fail-on={} -> {}",
        result.findings.len(),
        worst,
        fail_on,
        if failed { "FAIL" } else { "pass" }
    );
    Ok(i32::from(failed))
}
