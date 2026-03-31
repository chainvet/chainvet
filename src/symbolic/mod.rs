pub mod solver;
pub mod state;
pub mod types;

pub mod detectors;
pub mod results;

// TODO: Phase 4
// pub mod engine;

use crate::frontend::FrontendOutput;
use crate::report::OutputFormat;
use crate::util::error::Result;

/// Entry point for symbolic execution analysis.
/// Called from main.rs: `symbolic::run(&output, format)?;`
pub fn run(_output: &FrontendOutput, _format: OutputFormat) -> Result<()> {
    eprintln!("[symbolic] engine not yet fully wired — types module available");
    Ok(())
}
