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

/// Run the analysis binary with the given arguments and return the output.
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_chainvet"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", env!("CARGO_BIN_EXE_chainvet")))
}

#[test]
fn symbolic_on_se_test_fixture_exits_ok() {
    let out = run(&["--symbolic", SE_TEST]);
    assert!(
        out.status.success(),
        "binary exited non-zero on se_test.sol\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    // Confirm no panic backtrace was emitted.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("thread '") && !stderr.contains("panicked"),
        "unexpected panic in se_test.sol run:\n{stderr}",
    );
}

#[test]
fn symbolic_on_reentrancy_fixture_exits_ok() {
    let out = run(&["--symbolic", REENTRANCY]);
    assert!(
        out.status.success(),
        "binary exited non-zero on vuln_reentrancy.sol\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("thread '") && !stderr.contains("panicked"),
        "unexpected panic in vuln_reentrancy.sol run:\n{stderr}",
    );
}

#[test]
fn hybrid_on_reentrancy_fixture_exits_ok() {
    let out = run(&["--hybrid", REENTRANCY]);
    assert!(
        out.status.success(),
        "binary exited non-zero on hybrid vuln_reentrancy.sol\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("thread '") && !stderr.contains("panicked"),
        "unexpected panic in hybrid vuln_reentrancy.sol run:\n{stderr}",
    );
}
