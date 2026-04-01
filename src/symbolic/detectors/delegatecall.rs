use crate::analysis::detectors::Severity;
use crate::cfg::BlockId;
use crate::ir::{IrCallOption, IrInstr, IrValue, IrVar};
use crate::norm::Span;
use crate::symbolic::detectors::Detector;
use crate::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};
use crate::symbolic::solver::SmtSolver;
use crate::symbolic::state::SymbolicState;

/// Detects delegatecall-related vulnerabilities.
///
/// Covers:
/// - `UnsafeDelegatecall` — delegatecall to user-controlled address
/// - `PayableDelegatecallInLoop` — payable delegatecall inside a loop
pub struct DelegatecallDetector;

impl Detector for DelegatecallDetector {
    fn id(&self) -> &'static str {
        "delegatecall"
    }

    fn name(&self) -> &'static str {
        "Delegatecall Detector"
    }

    fn on_instruction(
        &mut self,
        state: &SymbolicState,
        instr: &IrInstr,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        let IrInstr::Call {
            callee,
            options,
            args,
            span,
            ..
        } = instr
        else {
            return vec![];
        };

        if !is_delegatecall(callee) {
            return vec![];
        }

        let mut findings = Vec::new();

        // UnsafeDelegatecall: delegatecall to a potentially user-controlled target.
        // The first argument is the target address for low-level `address.delegatecall(...)`.
        // For Solidity `delegatecall`, the callee itself IS the address.
        let target = if args.is_empty() { callee } else { &args[0] };
        if is_user_controlled(target) {
            findings.push(make_finding(
                SeVulnKind::UnsafeDelegatecall,
                Severity::High,
                Confidence::Medium,
                "delegatecall to user-controlled address can execute arbitrary code",
                span.clone(),
                state,
            ));
        }

        // PayableDelegatecallInLoop: delegatecall with ETH value inside a loop body.
        // path_depth > 0 serves as a proxy for being inside a loop or deep branch.
        let has_value = options
            .iter()
            .any(|o| matches!(o, IrCallOption::Value(_)));
        if has_value && state.path_depth > 0 {
            findings.push(make_finding(
                SeVulnKind::PayableDelegatecallInLoop,
                Severity::High,
                Confidence::Medium,
                "delegatecall with ETH value inside a loop can drain contract balance",
                span.clone(),
                state,
            ));
        }

        findings
    }

    fn on_block_exit(
        &mut self,
        _state: &SymbolicState,
        _block_id: BlockId,
        _solver: &dyn SmtSolver,
    ) -> Vec<SeFinding> {
        vec![]
    }

    fn reset(&mut self) {}
}

fn is_delegatecall(callee: &IrValue) -> bool {
    matches!(
        callee,
        IrValue::Var(IrVar::Named(n)) if n == "delegatecall"
    )
}

/// Returns true if a value is not a known constant.
fn is_user_controlled(val: &IrValue) -> bool {
    match val {
        IrValue::Var(IrVar::Named(n)) => n != "this" && n != "address(this)",
        IrValue::Var(IrVar::Temp(_)) | IrValue::Unknown => true,
        IrValue::Literal(_) => false,
    }
}

fn make_finding(
    kind: SeVulnKind,
    severity: Severity,
    confidence: Confidence,
    message: &str,
    span: Span,
    state: &SymbolicState,
) -> SeFinding {
    SeFinding {
        kind,
        severity,
        confidence,
        message: message.to_string(),
        span,
        function_id: None,
        path_constraints: state
            .path_constraints
            .descriptions()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        witness: None,
        state_id: state.id,
        path_depth: state.path_depth,
    }
}
