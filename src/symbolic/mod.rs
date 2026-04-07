pub mod solver;
pub mod state;
pub mod types;

pub mod detectors;
pub mod results;

pub mod engine;

use std::collections::HashSet;
use std::sync::Arc;

use crate::frontend::FrontendOutput;
use crate::report::OutputFormat;
use crate::symbolic::detectors::DetectorRegistry;
use crate::symbolic::engine::run_engine;
use crate::symbolic::engine::scheduler::SeConfig;
use crate::symbolic::results::coverage::CoverageReport;
use crate::symbolic::results::finding::SeFinding;
use crate::symbolic::results::report::print_se_report;
use crate::symbolic::solver::z3_backend::Z3Backend;
use crate::symbolic::state::storage::StorageLayout;
use crate::util::error::Result;

/// Entry point for symbolic execution analysis.
/// Called from main.rs: `symbolic::run(&output, format)?;`
pub fn run(output: &FrontendOutput, format: OutputFormat) -> Result<()> {
    if output.ast.contracts.is_empty() {
        eprintln!("[symbolic] no contracts found in AST");
        return Ok(());
    }

    let ir_module = crate::ir::lower_module(&output.ast);
    let cfgs = crate::cfg::build_from_ir(&ir_module);
    let layout = Arc::new(StorageLayout::from_ast(&output.ast));

    let mut all_findings: Vec<SeFinding> = Vec::new();
    let mut total_states: usize = 0;
    // TODO: merge coverage across contracts (Phase 6); for now use last contract's report.
    let mut combined_coverage = CoverageReport {
        blocks_visited: 0,
        blocks_total: 0,
        block_coverage_pct: 0.0,
        edges_visited: 0,
        functions_visited: 0,
        functions_total: 0,
        function_coverage_pct: 0.0,
    };

    for contract in &output.ast.contracts {
        // Filter CFGs to this contract's functions only.
        let func_ids: HashSet<u32> = contract.functions.iter().copied().collect();
        let contract_cfgs: Vec<_> = cfgs
            .iter()
            .filter(|c| func_ids.contains(&c.id))
            .cloned()
            .collect();

        if contract_cfgs.is_empty() {
            continue;
        }

        let config = SeConfig {
            contract_name: contract.name.clone(),
            storage_layout: Arc::clone(&layout),
            detectors: DetectorRegistry::with_defaults(),
            ..SeConfig::default()
        };

        let timeout_ms = u32::try_from(config.solver_timeout_ms).unwrap_or(u32::MAX);
        let solver = Z3Backend::new(timeout_ms);
        let result = run_engine(&contract_cfgs, &output.ast, config, &solver);

        all_findings.extend(result.findings);
        total_states += result.states_explored;
        combined_coverage = result.coverage;
    }

    print_se_report(&all_findings, &combined_coverage, total_states, format, &output.ast.files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::{CompilerInfo, FrontendMode, FrontendOutput};
    use crate::norm::NormalizedAst;

    fn test_compiler_info() -> CompilerInfo {
        CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: None,
            legacy_omitted_visibility_is_public: false,
        }
    }

    // ── run() early-exit branch ───────────────────────────────────────────────

    #[test]
    fn test_run_empty_ast_no_contracts_returns_ok() {
        // When the AST contains no contracts run() must return Ok(()) immediately
        // without attempting to lower IR, build CFGs, or invoke the SE engine.
        // This exercises the guard:  if output.ast.contracts.is_empty() { return Ok(()) }
        let output = FrontendOutput {
            mode: FrontendMode::Full,
            ast: NormalizedAst::empty(),
            compiler: test_compiler_info(),
        };
        let result = run(&output, OutputFormat::Text);
        assert!(result.is_ok(), "run() must succeed on an empty AST");
    }

    #[test]
    fn test_run_empty_ast_json_format_returns_ok() {
        // The same early-exit must also work when the caller requests JSON output.
        let output = FrontendOutput {
            mode: FrontendMode::Full,
            ast: NormalizedAst::empty(),
            compiler: test_compiler_info(),
        };
        let result = run(&output, OutputFormat::Json);
        assert!(result.is_ok(), "run() with JSON format must succeed on an empty AST");
    }

    #[test]
    fn test_run_partial_frontend_mode_empty_ast_returns_ok() {
        // FrontendMode::Partial with an empty AST must also take the early-exit path.
        let output = FrontendOutput {
            mode: FrontendMode::Partial,
            ast: NormalizedAst::empty(),
            compiler: test_compiler_info(),
        };
        let result = run(&output, OutputFormat::Text);
        assert!(result.is_ok(), "run() with Partial mode must succeed on an empty AST");
    }
}
