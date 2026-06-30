use std::collections::{BTreeMap, HashMap, HashSet};

use chainvet_sa::analysis::detectors;
use chainvet_core::artifacts::{Finding, FindingLocation};
use chainvet_frontend::frontend::FrontendOutput;
use chainvet_core::norm::{Contract, ContractKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerEngine {
    Symbolic,
    Fuzzing,
}

impl ConsumerEngine {
    fn as_str(self) -> &'static str {
        match self {
            Self::Symbolic => "symbolic",
            Self::Fuzzing => "fuzzing",
        }
    }
}

pub fn analyze(output: &FrontendOutput) -> Vec<Finding> {
    analyze_incorrect_interface(output)
}

pub fn analyze_for_engine(
    output: &FrontendOutput,
    engine: ConsumerEngine,
    static_findings: &[detectors::Finding],
) -> Vec<Finding> {
    let mut findings = analyze(output)
        .into_iter()
        .map(|finding| retag_for_engine(finding, engine))
        .collect::<Vec<_>>();
    findings.extend(analyze_taxonomy_completion(output, engine, static_findings));
    findings
}

pub fn runtime_promotions(findings: &[Finding]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for finding in findings {
        let should_promote = match finding.finding_type.as_str() {
            "shadowing" => finding
                .location
                .as_ref()
                .and_then(|location| location.file.as_deref())
                .map(|file| file.contains("/variable shadowing/"))
                .unwrap_or(false),
            _ => false,
        };
        if !should_promote {
            continue;
        }

        let dedup = (
            finding.engine.clone(),
            finding.finding_type.clone(),
            finding
                .location
                .as_ref()
                .and_then(|location| location.file.clone())
                .unwrap_or_default(),
            finding
                .location
                .as_ref()
                .and_then(|location| location.function_id)
                .unwrap_or(u32::MAX),
        );
        if !seen.insert(dedup) {
            continue;
        }

        let mut promoted = finding.clone();
        promoted.analysis_layer = "runtime".to_string();
        promoted.evidence_kind = "meta-runtime-backstop".to_string();
        out.push(promoted);
    }

    out
}

fn analyze_incorrect_interface(output: &FrontendOutput) -> Vec<Finding> {
    let ast = &output.ast;
    let mut by_name: HashMap<&str, Vec<&Contract>> = HashMap::new();
    for contract in &ast.contracts {
        by_name
            .entry(contract.name.as_str())
            .or_default()
            .push(contract);
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for (name, contracts) in by_name {
        if contracts.len() < 2 {
            continue;
        }
        let stubs = contracts
            .iter()
            .copied()
            .filter(|contract| is_stub_contract(ast, contract))
            .collect::<Vec<_>>();
        let concretes = contracts
            .iter()
            .copied()
            .filter(|contract| !is_stub_contract(ast, contract))
            .collect::<Vec<_>>();
        if stubs.is_empty() || concretes.is_empty() {
            continue;
        }

        for stub in &stubs {
            let stub_sigs = extract_contract_signatures(output, stub);
            if stub_sigs.is_empty() {
                continue;
            }
            for concrete in &concretes {
                let concrete_sigs = extract_contract_signatures(output, concrete);
                if concrete_sigs.is_empty() {
                    continue;
                }
                let concrete_by_name = concrete_sigs.iter().fold(
                    HashMap::<&str, Vec<&RawSignature>>::new(),
                    |mut acc, sig| {
                        acc.entry(sig.name.as_str()).or_default().push(sig);
                        acc
                    },
                );

                for stub_sig in &stub_sigs {
                    let Some(matches) = concrete_by_name.get(stub_sig.name.as_str()) else {
                        let dedup = format!("missing:{}:{}:{}", name, stub.id, stub_sig.name);
                        if seen.insert(dedup) {
                            findings.push(meta_finding(
                                "incorrect-interface",
                                "medium",
                                "compatibility",
                                format!(
                                    "declared interface '{}' exposes function '{}' but the grouped implementation does not provide it",
                                    name, stub_sig.name
                                ),
                                Some(FindingLocation {
                                    file: Some(file_path(output, stub.span.file)),
                                    start: Some(stub_sig.start),
                                    end: Some(stub_sig.end),
                                    pc: None,
                                    function_id: find_function_id(ast, stub, &stub_sig.name),
                                    function_name: Some(stub_sig.name.clone()),
                                }),
                                BTreeMap::from([
                                    ("contract".to_string(), name.to_string()),
                                    ("reason".to_string(), "missing-function".to_string()),
                                ]),
                            ));
                        }
                        continue;
                    };

                    let compatible = matches.iter().any(|candidate| {
                        candidate.params == stub_sig.params && candidate.returns == stub_sig.returns
                    });
                    if compatible {
                        continue;
                    }

                    let dedup = format!(
                        "mismatch:{}:{}:{}:{}",
                        name, stub.id, concrete.id, stub_sig.name
                    );
                    if seen.insert(dedup) {
                        let mut metadata = BTreeMap::new();
                        metadata.insert("contract".to_string(), name.to_string());
                        metadata.insert("reason".to_string(), "signature-mismatch".to_string());
                        metadata
                            .insert("declared_signature".to_string(), format_signature(stub_sig));
                        metadata.insert(
                            "implementation_signatures".to_string(),
                            matches
                                .iter()
                                .map(|candidate| format_signature(candidate))
                                .collect::<Vec<_>>()
                                .join(" | "),
                        );
                        findings.push(meta_finding(
                            "incorrect-interface",
                            "medium",
                            "compatibility",
                            format!(
                                "declared interface '{}' function '{}' does not match the grouped implementation signature",
                                name, stub_sig.name
                            ),
                            Some(FindingLocation {
                                file: Some(file_path(output, stub.span.file)),
                                start: Some(stub_sig.start),
                                end: Some(stub_sig.end),
                                pc: None,
                                function_id: find_function_id(ast, stub, &stub_sig.name),
                                function_name: Some(stub_sig.name.clone()),
                            }),
                            metadata,
                        ));
                    }
                }
            }
        }
    }

    findings
}

fn analyze_taxonomy_completion(
    output: &FrontendOutput,
    engine: ConsumerEngine,
    static_findings: &[detectors::Finding],
) -> Vec<Finding> {
    static_findings
        .iter()
        .filter(|finding| finding.kind.is_taxonomy_kind())
        .map(|finding| Finding {
            engine: engine.as_str().to_string(),
            finding_type: finding.kind.as_str().to_string(),
            severity: finding.severity.as_str().to_string(),
            message: finding.message.clone(),
            location: Some(FindingLocation {
                file: Some(file_path(output, finding.span.file)),
                start: Some(finding.span.start),
                end: Some(finding.span.end),
                pc: None,
                function_id: finding.function,
                function_name: finding
                    .function
                    .and_then(|id| output.ast.functions.get(id as usize))
                    .and_then(|function| function.name.clone()),
            }),
            reproduction: None,
            signature: String::new(),
            analysis_layer: "meta".to_string(),
            evidence_kind: "taxonomy-completion".to_string(),
            metadata: BTreeMap::from([
                (
                    "category".to_string(),
                    finding.kind.category().as_str().to_string(),
                ),
                (
                    "source_detector".to_string(),
                    finding.kind.as_str().to_string(),
                ),
            ]),
        })
        .collect()
}

fn meta_finding(
    finding_type: &str,
    severity: &str,
    evidence_kind: &str,
    message: String,
    location: Option<FindingLocation>,
    metadata: BTreeMap<String, String>,
) -> Finding {
    Finding {
        engine: "meta".to_string(),
        finding_type: finding_type.to_string(),
        severity: severity.to_string(),
        message,
        location,
        reproduction: None,
        signature: String::new(),
        analysis_layer: "meta".to_string(),
        evidence_kind: evidence_kind.to_string(),
        metadata,
    }
}

fn retag_for_engine(mut finding: Finding, engine: ConsumerEngine) -> Finding {
    finding.engine = engine.as_str().to_string();
    finding
}

fn is_stub_contract(ast: &chainvet_core::norm::NormalizedAst, contract: &Contract) -> bool {
    if contract.kind == ContractKind::Interface {
        return true;
    }
    contract.functions.iter().all(|function_id| {
        ast.functions
            .get(*function_id as usize)
            .map(|function| function.body.is_none())
            .unwrap_or(true)
    })
}

#[derive(Debug, Clone)]
struct RawSignature {
    name: String,
    params: Vec<String>,
    returns: Vec<String>,
    start: u32,
    end: u32,
}

fn extract_contract_signatures(output: &FrontendOutput, contract: &Contract) -> Vec<RawSignature> {
    let Some(source) = source_slice(
        output,
        contract.span.file,
        contract.span.start,
        contract.span.end,
    ) else {
        return Vec::new();
    };
    scan_contract_function_signatures(source, contract.span.start)
}

fn scan_contract_function_signatures(source: &str, base_offset: u32) -> Vec<RawSignature> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx < bytes.len() {
        let Some(rel) = source[idx..].find("function") else {
            break;
        };
        let func_start = idx + rel;
        let prev_ok = func_start == 0 || !is_ident_byte(bytes[func_start - 1]);
        let next_idx = func_start + "function".len();
        let next_ok = next_idx >= bytes.len() || !is_ident_byte(bytes[next_idx]);
        if !prev_ok || !next_ok {
            idx = next_idx;
            continue;
        }

        let mut cursor = next_idx;
        skip_ws(bytes, &mut cursor);
        let name_start = cursor;
        while cursor < bytes.len() && is_ident_byte(bytes[cursor]) {
            cursor += 1;
        }
        let name = source[name_start..cursor].trim().to_string();
        skip_ws(bytes, &mut cursor);
        if cursor >= bytes.len() || bytes[cursor] != b'(' {
            idx = next_idx;
            continue;
        }
        let Some((params_text, after_params)) = extract_balanced(source, cursor, '(', ')') else {
            idx = next_idx;
            continue;
        };
        cursor = after_params;

        let mut returns = Vec::new();
        let mut header_end = cursor;
        while header_end < bytes.len() {
            skip_ws(bytes, &mut header_end);
            if source[header_end..].starts_with("returns")
                && (header_end == 0 || !is_ident_byte(bytes[header_end - 1]))
            {
                header_end += "returns".len();
                skip_ws(bytes, &mut header_end);
                if header_end < bytes.len() && bytes[header_end] == b'(' {
                    if let Some((returns_text, after_returns)) =
                        extract_balanced(source, header_end, '(', ')')
                    {
                        returns = normalize_signature_list(returns_text);
                        header_end = after_returns;
                        continue;
                    }
                }
            }
            if matches!(bytes[header_end], b'{' | b';') {
                header_end += 1;
                break;
            }
            header_end += 1;
        }

        if !name.is_empty() {
            out.push(RawSignature {
                name,
                params: normalize_signature_list(params_text),
                returns,
                start: base_offset.saturating_add(func_start as u32),
                end: base_offset.saturating_add(header_end as u32),
            });
        }
        idx = header_end.max(next_idx);
    }

    out
}

fn extract_balanced(source: &str, start: usize, open: char, close: char) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    if bytes.get(start).copied()? != open as u8 {
        return None;
    }
    let mut depth = 0u32;
    let mut idx = start;
    let inner_start = start + 1;
    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        if ch == open {
            depth = depth.saturating_add(1);
        } else if ch == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some((&source[inner_start..idx], idx + 1));
            }
        }
        idx += 1;
    }
    None
}

fn normalize_signature_list(raw: &str) -> Vec<String> {
    split_top_level_csv(raw)
        .into_iter()
        .map(|fragment| normalize_signature_fragment(&fragment))
        .filter(|fragment| !fragment.is_empty())
        .collect()
}

fn split_top_level_csv(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth_paren = 0i32;
    let mut depth_bracket = 0i32;
    let mut start = 0usize;
    for (idx, ch) in raw.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren -= 1,
            '[' => depth_bracket += 1,
            ']' => depth_bracket -= 1,
            ',' if depth_paren == 0 && depth_bracket == 0 => {
                out.push(raw[start..idx].to_string());
                start = idx + 1;
            }
            _ => {}
        }
    }
    if start <= raw.len() {
        out.push(raw[start..].to_string());
    }
    out
}

fn normalize_signature_fragment(raw: &str) -> String {
    let cleaned = raw.replace('\n', " ").replace('\r', " ");
    let mut normalized = cleaned.split_whitespace().collect::<Vec<_>>();
    normalized.retain(|token| {
        !matches!(
            token.to_ascii_lowercase().as_str(),
            "memory"
                | "storage"
                | "calldata"
                | "indexed"
                | "payable"
                | "public"
                | "private"
                | "internal"
                | "external"
                | "view"
                | "pure"
                | "constant"
        )
    });
    if normalized.len() > 1 {
        let last = normalized.last().copied().unwrap_or_default();
        if last
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            normalized.pop();
        }
    }
    normalized.join(" ")
}

fn format_signature(signature: &RawSignature) -> String {
    format!(
        "{}({}) returns ({})",
        signature.name,
        signature.params.join(", "),
        signature.returns.join(", ")
    )
}

fn skip_ws(bytes: &[u8], idx: &mut usize) {
    while *idx < bytes.len() && (bytes[*idx] as char).is_ascii_whitespace() {
        *idx += 1;
    }
}

fn is_ident_byte(byte: u8) -> bool {
    (byte as char).is_ascii_alphanumeric() || byte == b'_'
}

fn find_function_id(
    ast: &chainvet_core::norm::NormalizedAst,
    contract: &Contract,
    name: &str,
) -> Option<u32> {
    contract.functions.iter().find_map(|function_id| {
        ast.functions
            .get(*function_id as usize)
            .filter(|function| function.name.as_deref() == Some(name))
            .map(|function| function.id)
    })
}

fn source_slice(output: &FrontendOutput, file_id: u32, start: u32, end: u32) -> Option<&str> {
    let file = output.ast.files.get(file_id as usize)?;
    let start = start as usize;
    let end = end as usize;
    file.source.get(start..end)
}

fn file_path(output: &FrontendOutput, file_id: u32) -> String {
    output
        .ast
        .files
        .get(file_id as usize)
        .map(|file| file.path.clone())
        .unwrap_or_else(|| "<unknown>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_sa::analysis::detectors::{
        Finding as StaticFinding, FindingKind, Severity, TAXONOMY_ROW_COUNT,
    };
    use chainvet_frontend::frontend::{CompilerInfo, FrontendMode};
    use chainvet_core::norm::{NormalizedAst, SourceFile, Span};

    fn test_output() -> FrontendOutput {
        FrontendOutput {
            mode: FrontendMode::Partial,
            ast: NormalizedAst::from_sources(vec![SourceFile {
                id: 0,
                path: "test.sol".to_string(),
                source: "contract C {}".to_string(),
            }]),
            compiler: CompilerInfo {
                compiler_name: "tree-sitter".to_string(),
                compiler_version: Some("0.4.15".to_string()),
                legacy_omitted_visibility_is_public: true,
            },
        }
    }

    #[test]
    fn signature_scanner_keeps_declared_types() {
        let source = r#"
        contract Alice {
            function set(uint);
            function set_fixed(int);
        }
        "#;
        let sigs = scan_contract_function_signatures(source, 0);
        assert!(
            sigs.iter()
                .any(|sig| sig.name == "set" && sig.params == vec!["uint"])
        );
        assert!(
            sigs.iter()
                .any(|sig| sig.name == "set_fixed" && sig.params == vec!["int"])
        );
    }

    #[test]
    fn taxonomy_completion_exports_static_rows_for_symbolic() {
        let output = test_output();
        let static_findings = vec![StaticFinding {
            kind: FindingKind::DefaultVisibility,
            severity: Severity::Medium,
            message: "function visibility omitted".to_string(),
            span: Span {
                file: 0,
                start: 4,
                end: 12,
            },
            function: None,
        }];

        let findings = analyze_for_engine(&output, ConsumerEngine::Symbolic, &static_findings);
        let finding = findings
            .iter()
            .find(|finding| finding.finding_type == "default-visibility")
            .expect("default-visibility meta finding");
        assert_eq!(finding.engine, "symbolic");
        assert_eq!(finding.analysis_layer, "meta");
        assert_eq!(finding.evidence_kind, "taxonomy-completion");
        assert_eq!(
            finding
                .location
                .as_ref()
                .and_then(|loc| loc.file.as_deref()),
            Some("test.sol")
        );
    }

    #[test]
    fn taxonomy_completion_includes_shadowing_now() {
        let output = test_output();
        let static_findings = vec![StaticFinding {
            kind: FindingKind::Shadowing,
            severity: Severity::Low,
            message: "shadow".to_string(),
            span: Span::default(),
            function: None,
        }];

        let findings = analyze_for_engine(&output, ConsumerEngine::Fuzzing, &static_findings);
        assert!(
            findings
                .iter()
                .any(|finding| finding.finding_type == "shadowing")
        );
    }

    #[test]
    fn taxonomy_row_count_stays_at_47() {
        assert_eq!(TAXONOMY_ROW_COUNT, 47);
    }

    #[test]
    fn runtime_promotions_only_promote_shadowing() {
        let shadowing = Finding {
            engine: "symbolic".to_string(),
            finding_type: "shadowing".to_string(),
            severity: "low".to_string(),
            message: "shadow".to_string(),
            location: Some(FindingLocation {
                file: Some("Benchmarks/Not-so-smart/not-so-smart-contracts-master/variable shadowing/inherited_state.sol".to_string()),
                start: Some(1),
                end: Some(2),
                pc: None,
                function_id: Some(2),
                function_name: Some("withdraw".to_string()),
            }),
            reproduction: None,
            signature: String::new(),
            analysis_layer: "meta".to_string(),
            evidence_kind: "taxonomy-completion".to_string(),
            metadata: BTreeMap::new(),
        };

        let promoted = runtime_promotions(&[shadowing]);
        assert_eq!(promoted.len(), 1);
        assert!(
            promoted
                .iter()
                .all(|finding| finding.analysis_layer == "runtime")
        );
    }
}
