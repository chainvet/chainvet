use chainvet_core::norm::{NormalizedAst, Span};
use chainvet_sa::analysis::detectors::{Finding, FindingKind, Severity};

#[derive(Debug, Clone, serde::Serialize)]
pub struct HybridTarget {
    pub kind: String,
    pub severity: String,
    pub function_id: Option<u32>,
    pub function_name: Option<String>,
    pub file: Option<String>,
    pub span: HybridSpan,
    pub target_reason: String,
    pub selected_for_symbolic: bool,
    pub constraint_hints: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HybridSpan {
    pub start: u32,
    pub end: u32,
}

pub fn classify_threshold(targets: &[HybridTarget]) -> Severity {
    if targets
        .iter()
        .any(|target| target.severity == Severity::High.as_str())
    {
        Severity::High
    } else {
        Severity::Medium
    }
}

pub fn selected_targets(targets: &[HybridTarget]) -> Vec<HybridTarget> {
    let threshold = classify_threshold(targets);
    targets
        .iter()
        .filter(|target| target.selected_for_symbolic && target.severity == threshold.as_str())
        .cloned()
        .collect()
}

pub fn build_targets(ast: &NormalizedAst, findings: &[Finding]) -> Vec<HybridTarget> {
    findings
        .iter()
        .filter_map(|finding| to_target(ast, finding))
        .collect()
}

fn to_target(ast: &NormalizedAst, finding: &Finding) -> Option<HybridTarget> {
    if !is_high_signal_kind(finding.kind) {
        return None;
    }
    let function_name = finding
        .function
        .and_then(|id| ast.functions.get(id as usize))
        .and_then(|function| function.name.clone());
    Some(HybridTarget {
        kind: finding.kind.as_str().to_string(),
        severity: finding.severity.as_str().to_string(),
        function_id: finding.function,
        function_name,
        file: file_for_span(ast, finding.span),
        span: HybridSpan {
            start: finding.span.start,
            end: finding.span.end,
        },
        target_reason: reason_for_kind(finding.kind).to_string(),
        selected_for_symbolic: matches!(finding.severity, Severity::High | Severity::Medium),
        constraint_hints: constraint_hints(finding),
    })
}

fn file_for_span(ast: &NormalizedAst, span: Span) -> Option<String> {
    ast.files
        .get(span.file as usize)
        .map(|file| file.path.clone())
}

fn constraint_hints(finding: &Finding) -> Vec<String> {
    let mut hints = vec![finding.message.clone()];
    if finding.message.contains("require") {
        hints.push("message references require/assert guard".to_string());
    }
    hints
}

fn reason_for_kind(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::UnsafeDelegatecall | FindingKind::DelegatecallInLoop => {
            "delegatecall sink is high impact and benefits from concrete witness generation"
        }
        FindingKind::ArbitraryStorageWrite => {
            "privileged storage write should be symbolically confirmed before fuzz broadening"
        }
        FindingKind::UnusedReturnValue | FindingKind::DosWithFailedCall => {
            "unchecked external call result is a strong exploit sink"
        }
        FindingKind::ReentrancyNegativeEvents
        | FindingKind::ReentrancyTransfer
        | FindingKind::ReentrancySameEffect
        | FindingKind::ReentrancyEthTransfer
        | FindingKind::ReentrancyNoEthTransfer => {
            "reentrancy-shaped call-before-write path is a strong symbolic target"
        }
        FindingKind::UnprotectedEtherWithdrawal | FindingKind::UnprotectedSelfdestruct => {
            "sensitive externally reachable sink should be checked with concrete caller/value"
        }
        _ => "static prefilter selected this sink for bounded symbolic exploration",
    }
}

fn is_high_signal_kind(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::UnsafeDelegatecall
            | FindingKind::DelegatecallInLoop
            | FindingKind::ArbitraryStorageWrite
            | FindingKind::UnusedReturnValue
            | FindingKind::DosWithFailedCall
            | FindingKind::ReentrancyNegativeEvents
            | FindingKind::ReentrancyTransfer
            | FindingKind::ReentrancySameEffect
            | FindingKind::ReentrancyEthTransfer
            | FindingKind::ReentrancyNoEthTransfer
            | FindingKind::UnprotectedEtherWithdrawal
            | FindingKind::UnprotectedSelfdestruct
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_core::norm::{NormalizedAst, SourceFile, Span};
    use chainvet_sa::analysis::detectors::{Finding, FindingKind, Severity};

    fn ast() -> NormalizedAst {
        NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "fixture.sol".to_string(),
            source: String::new(),
        }])
    }

    #[test]
    fn high_signal_findings_become_targets() {
        let finding = Finding {
            kind: FindingKind::UnsafeDelegatecall,
            severity: Severity::High,
            message: "delegatecall sink".to_string(),
            span: Span {
                file: 0,
                start: 4,
                end: 9,
            },
            function: None,
        };
        let targets = build_targets(&ast(), &[finding]);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, "unsafe-delegatecall");
    }

    #[test]
    fn low_signal_findings_are_filtered_out() {
        let finding = Finding {
            kind: FindingKind::Shadowing,
            severity: Severity::High,
            message: "shadowing".to_string(),
            span: Span {
                file: 0,
                start: 1,
                end: 2,
            },
            function: None,
        };
        assert!(build_targets(&ast(), &[finding]).is_empty());
    }

    #[test]
    fn threshold_falls_back_to_medium_when_no_high_targets_exist() {
        let target = HybridTarget {
            kind: "unsafe-delegatecall".to_string(),
            severity: "medium".to_string(),
            function_id: None,
            function_name: None,
            file: None,
            span: HybridSpan { start: 0, end: 0 },
            target_reason: String::new(),
            selected_for_symbolic: true,
            constraint_hints: Vec::new(),
        };
        assert_eq!(classify_threshold(&[target]), Severity::Medium);
    }
}
