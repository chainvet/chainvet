// Fuzzing engine: consumes IR/CFG/SSA to guide target selection and fuzz harness generation.

pub mod executor;
pub mod generator;
pub mod mutator;
pub mod oracle;
pub mod runner;
pub mod scheduler;
pub mod types;

use chainvet_frontend::frontend::FrontendOutput;
use crate::fuzzing::types::FuzzConfig;
use crate::report::OutputFormat;
use chainvet_core::util::error::Result;

/// Main entry point: run the fuzzer against a parsed project.
pub fn run_fuzzer(
    output: &FrontendOutput,
    config: &FuzzConfig,
    format: OutputFormat,
) -> Result<()> {
    let report = runner::run(output, config);
    match format {
        OutputFormat::Text => runner::print_report(&report),
        OutputFormat::Json => runner::print_report_json(&report)?,
    }
    Ok(())
}
