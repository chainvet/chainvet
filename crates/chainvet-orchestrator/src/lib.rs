//! ChainVet orchestration facade.
//!
//! One entry point — [`scan`] — that runs the requested analysis mode over a
//! loaded project and returns a typed [`ScanResult`]: the unified, deduplicated
//! findings every frontend (CLI / CI / server / LSP) renders, plus the full
//! hybrid telemetry when the hybrid engine ran. No printing, no file paths
//! assumed beyond an optional convenience loader — frontends own all I/O.

pub mod ai_report;

use chainvet_core::cfg;
use chainvet_core::ir;
use chainvet_core::util::error::Result;
use chainvet_frontend::frontend::{self, FrontendOutput};
use chainvet_fuzzing::fuzzing::{self, types::FuzzConfig};
use chainvet_hybrid::hybrid::{self, HybridFindingRow, HybridJsonReport};
use chainvet_sa::analysis;
use chainvet_se::symbolic::{self, SymbolicOptions};

pub use chainvet_hybrid::hybrid::{HybridBudget, HybridFindingRow as ScanFinding};

/// Which engine(s) a scan runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ScanMode {
    Static,
    Symbolic,
    Fuzzing,
    Hybrid,
}

/// The typed result of a scan: the finished (collected + deduplicated) findings
/// shared by every renderer, plus the hybrid engine's run telemetry when it ran.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    pub mode: ScanMode,
    /// Unified findings, already merged/deduplicated and tier-tagged — exactly
    /// what the CLI hybrid report renders, but available for any frontend.
    pub findings: Vec<HybridFindingRow>,
    /// Full hybrid telemetry (targets, seeds, coverage, SE assists). `Some` only
    /// when `mode == Hybrid`.
    pub hybrid: Option<HybridJsonReport>,
}

/// Run `mode` over an already-loaded project and return typed findings.
///
/// `budget` is only consulted in [`ScanMode::Hybrid`]; the other modes use each
/// engine's default configuration (matching the standalone CLI entry points).
pub fn scan(output: &FrontendOutput, mode: ScanMode, budget: &HybridBudget) -> Result<ScanResult> {
    let ast = &output.ast;
    let (findings, hybrid) = match mode {
        ScanMode::Static => {
            let ir_module = ir::lower_module(ast);
            let cfgs = cfg::build_from_ir(&ir_module);
            let call_graph = analysis::build_call_graph(ast);
            let taint = analysis::taint::analyze(ast, &cfgs);
            let static_findings = analysis::detectors::run_detectors(ast, &call_graph, &taint);
            // `collect` already merges/deduplicates across sources and tiers each row.
            (
                HybridFindingRow::collect(ast, &static_findings, &[], &[]),
                None,
            )
        }
        ScanMode::Symbolic => {
            let a = symbolic::analyze_with_options(output, &SymbolicOptions::default())?;
            (HybridFindingRow::collect(ast, &[], &a.findings, &[]), None)
        }
        ScanMode::Fuzzing => {
            let report = fuzzing::runner::run(output, &FuzzConfig::default());
            (
                HybridFindingRow::collect(ast, &[], &[], &report.findings),
                None,
            )
        }
        ScanMode::Hybrid => {
            let payload = hybrid::analyze(output, budget)?;
            // analyze's findings are already collected + deduplicated.
            (payload.findings.clone(), Some(payload))
        }
    };
    let mut result = ScanResult {
        mode,
        findings,
        hybrid,
    };
    // Optional AI review of findings (opt-in via CHAINVET_AI_REPORT; no-op otherwise).
    ai_report::enhance(&mut result);
    Ok(result)
}

/// Convenience: load a project from `path` (solc → tree-sitter → optional AI
/// fallback) and scan it. Frontends that already hold a [`FrontendOutput`]
/// should call [`scan`] directly.
pub fn scan_path(path: &str, mode: ScanMode, budget: &HybridBudget) -> Result<ScanResult> {
    let output = frontend::load_project(path)?;
    scan(&output, mode, budget)
}
