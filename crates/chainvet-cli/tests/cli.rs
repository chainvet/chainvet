//! CLI smoke tests — invoke the binary as a subprocess.
//!
//! These test the user-facing interface rather than internal Rust types.
//! `env!("CARGO_BIN_EXE_chainvet")` resolves to the built binary path at
//! compile time; cargo guarantees the binary is built before tests run.

use std::process::Command;

const SE_TEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/se_test.sol");
const REENTRANCY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/vuln_reentrancy.sol"
);

/// Run the binary with the given arguments and return the output.
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_chainvet"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", env!("CARGO_BIN_EXE_chainvet")))
}

fn assert_ok(out: &std::process::Output, ctx: &str) {
    assert!(
        out.status.success(),
        "binary exited non-zero ({ctx})\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("thread '") && !stderr.contains("panicked"),
        "unexpected panic ({ctx}):\n{stderr}",
    );
}

#[test]
fn scan_symbolic_se_fixture_exits_ok() {
    assert_ok(
        &run(&["scan", "-m", "symbolic", SE_TEST]),
        "symbolic se_test",
    );
}

#[test]
fn scan_symbolic_reentrancy_exits_ok() {
    assert_ok(
        &run(&["scan", "-m", "symbolic", REENTRANCY]),
        "symbolic reentrancy",
    );
}

#[test]
fn scan_hybrid_reentrancy_exits_ok() {
    assert_ok(
        &run(&["scan", "-m", "hybrid", REENTRANCY]),
        "hybrid reentrancy",
    );
}

#[test]
fn scan_json_is_valid_and_has_findings() {
    let out = run(&["scan", "-m", "hybrid", "-f", "json", REENTRANCY]);
    assert_ok(&out, "hybrid json");
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("scan -f json must emit valid JSON");
    let findings = value.get("findings").and_then(|f| f.as_array());
    assert!(
        findings.is_some_and(|f| !f.is_empty()),
        "hybrid json should carry a non-empty findings array",
    );
}

#[test]
fn ir_dump_exits_ok() {
    assert_ok(&run(&["ir", REENTRANCY, "-f", "text"]), "ir dump");
}
