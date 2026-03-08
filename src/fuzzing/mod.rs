// Fuzzing engine: consumes IR/CFG/SSA to guide target selection and fuzz harness generation.

pub mod executor;
pub mod generator;
pub mod mutator;
pub mod oracle;
pub mod runner;
pub mod scheduler;
pub mod types;

use crate::fuzzing::types::FuzzConfig;
use crate::norm::NormalizedAst;

/// Main entry point: run the fuzzer against a parsed project.
pub fn run_fuzzer(ast: &NormalizedAst, config: &FuzzConfig) {
    let report = runner::run(ast, config);
    runner::print_report(&report);
}
