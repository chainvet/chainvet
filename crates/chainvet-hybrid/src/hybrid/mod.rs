mod budget;
mod orchestrator;
mod report;
mod seeding;
mod targeting;

pub use budget::HybridBudget;
pub use orchestrator::analyze;
pub use report::{
    HybridFindingRow, HybridJsonReport, HybridRunSummary, deduplicate_rows, print_hybrid_report,
};

use chainvet_frontend::frontend::FrontendOutput;
use chainvet_core::OutputFormat;
use chainvet_core::util::error::Result;

/// Run the hybrid engine with the default budget.
pub fn run(output: &FrontendOutput, format: OutputFormat) -> Result<()> {
    run_with_budget(output, &HybridBudget::default(), format)
}

/// Run the hybrid engine with a caller-supplied (e.g. CLI-overridden) budget.
pub fn run_with_budget(
    output: &FrontendOutput,
    budget: &HybridBudget,
    format: OutputFormat,
) -> Result<()> {
    orchestrator::run(output, budget, format)
}
