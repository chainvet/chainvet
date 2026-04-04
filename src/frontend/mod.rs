pub mod parser;
pub mod solc;
pub mod solc_manager;

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::norm::{Function, FunctionKind, Mutability, NormalizedAst, SourceFile, Visibility};
use crate::util::error::Result;

#[derive(Debug, Clone, Copy)]
pub enum FrontendMode {
    Full,
    Partial,
}

#[derive(Debug, Clone)]
pub struct CompilerInfo {
    pub compiler_name: String,
    pub compiler_version: Option<String>,
    pub legacy_omitted_visibility_is_public: bool,
}

#[derive(Debug, Clone)]
pub struct FrontendOutput {
    pub mode: FrontendMode,
    pub ast: NormalizedAst,
    pub compiler: CompilerInfo,
}

pub fn load_project(path: &str) -> Result<FrontendOutput> {
    let sources = collect_target_sources(path)?;
    let compiler = infer_compiler_info(&sources);

    match solc::load_via_solc_sources(path, sources.clone()) {
        Ok(ast) => Ok(FrontendOutput {
            mode: FrontendMode::Full,
            ast,
            compiler: CompilerInfo {
                compiler_name: "solc".to_string(),
                compiler_version: compiler.compiler_version.clone(),
                legacy_omitted_visibility_is_public: compiler.legacy_omitted_visibility_is_public,
            },
        }),
        Err(err) => {
            eprintln!("solc frontend failed: {err}");
            let ast = if compiler.legacy_omitted_visibility_is_public {
                parser::load_via_legacy_sources(sources)?
            } else {
                parser::load_via_parser_sources(sources)?
            };
            Ok(FrontendOutput {
                mode: FrontendMode::Partial,
                ast,
                compiler: CompilerInfo {
                    compiler_name: "tree-sitter".to_string(),
                    compiler_version: compiler.compiler_version,
                    legacy_omitted_visibility_is_public: compiler
                        .legacy_omitted_visibility_is_public,
                },
            })
        }
    }
}

pub fn effective_visibility(function: &Function, compiler: &CompilerInfo) -> Visibility {
    if function.visibility != Visibility::Unknown {
        return function.visibility;
    }
    if compiler.legacy_omitted_visibility_is_public && function.kind == FunctionKind::Function {
        return Visibility::Public;
    }
    Visibility::Unknown
}

pub fn is_public_entrypoint(function: &Function, compiler: &CompilerInfo) -> bool {
    match function.kind {
        FunctionKind::Function => matches!(
            effective_visibility(function, compiler),
            Visibility::Public | Visibility::External
        ),
        FunctionKind::Fallback | FunctionKind::Receive => true,
        FunctionKind::Constructor | FunctionKind::Unknown => false,
    }
}

pub fn is_mutating_entrypoint(function: &Function, compiler: &CompilerInfo) -> bool {
    if !is_public_entrypoint(function, compiler) {
        return false;
    }
    !matches!(function.mutability, Mutability::Pure | Mutability::View)
}

pub fn is_legacy_named_constructor(function: &Function, ast: &NormalizedAst) -> bool {
    if function.kind == FunctionKind::Constructor {
        return true;
    }
    let Some(name) = function.name.as_deref() else {
        return false;
    };
    surrounding_contract_name(function, ast)
        .or_else(|| {
            function
                .contract
                .and_then(|contract_id| ast.contracts.get(contract_id as usize))
                .map(|contract| contract.name.clone())
        })
        .map(|contract_name| name == contract_name)
        .unwrap_or(false)
}

pub fn has_authority_modifier_hint(function: &Function, ast: &NormalizedAst) -> bool {
    if function
        .modifiers
        .iter()
        .any(|modifier| authority_modifier_token(modifier))
    {
        return true;
    }

    function_head_snippet(function, ast)
        .map(signature_contains_authority_modifier)
        .unwrap_or(false)
}

pub fn has_sender_authority_check_hint(function: &Function, ast: &NormalizedAst) -> bool {
    if has_authority_modifier_hint(function, ast) {
        return true;
    }
    let Some(source_lower) = function_source_lower(function, ast) else {
        return false;
    };
    source_lower.lines().any(|line| {
        let compact = line
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>();
        compact.contains("msg.sender")
            && (compact.contains("==") || compact.contains("!="))
            && AUTHORITY_CHECK_TOKENS
                .iter()
                .any(|token| compact.contains(token))
    })
}

pub fn has_public_sender_payout_hint(function: &Function, ast: &NormalizedAst) -> bool {
    let Some(source_lower) = function_source_lower(function, ast) else {
        return false;
    };
    let sender_payout = source_lower.contains("msg.sender.transfer(")
        || source_lower.contains("msg.sender.transfer (")
        || source_lower.contains("msg.sender.send(")
        || source_lower.contains("msg.sender.send (")
        || source_lower.contains("msg.sender.call.value(")
        || source_lower.contains("msg.sender.call.value (");
    if !sender_payout {
        return false;
    }

    let function_name = function.name.as_deref().unwrap_or("").to_ascii_lowercase();
    let has_gate = source_lower.contains("require(")
        || source_lower.contains("require (")
        || source_lower.contains("assert(")
        || source_lower.contains("assert (")
        || source_lower.contains("if(")
        || source_lower.contains("if (");
    let has_reward_context = CLAIM_PAYOUT_TOKENS
        .iter()
        .any(|token| function_name.contains(token) || source_lower.contains(token))
        || source_lower.contains("msg.value");
    let has_sender_accounting_context = CALLER_ACCOUNT_INDEX_TOKENS
        .iter()
        .any(|token| source_lower.contains(token))
        && ACCOUNTING_CONTEXT_TOKENS
            .iter()
            .any(|token| source_lower.contains(token));

    has_gate && (has_reward_context || has_sender_accounting_context)
}

fn authority_modifier_token(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower.starts_with("only")
        || matches!(
            lower.as_str(),
            "authorized"
                | "auth"
                | "restricted"
                | "owneronly"
                | "adminonly"
                | "governanceonly"
                | "operatoronly"
        )
}

const AUTHORITY_CHECK_TOKENS: &[&str] = &[
    "owner",
    "admin",
    "operator",
    "governance",
    "auth",
    "authority",
    "controller",
    "creator",
    "organizer",
];

const CLAIM_PAYOUT_TOKENS: &[&str] = &[
    "reward",
    "prize",
    "jackpot",
    "winner",
    "won",
    "claim",
    "solve",
    "solution",
    "submission",
    "proof",
    "guess",
    "answer",
    "lottery",
    "bet",
    "play",
    "participate",
];

const CALLER_ACCOUNT_INDEX_TOKENS: &[&str] = &["[msg.sender]", "[tx.origin]"];

const ACCOUNTING_CONTEXT_TOKENS: &[&str] = &[
    "balance",
    "balances",
    "credit",
    "credits",
    "deposit",
    "deposits",
    "refund",
    "refunds",
    "share",
    "shares",
    "stake",
    "stakes",
    "owed",
    "allowance",
    "allowances",
];

fn function_head_snippet<'a>(function: &Function, ast: &'a NormalizedAst) -> Option<&'a str> {
    let file = ast.files.get(function.span.file as usize)?;
    let start = function.span.start as usize;
    let end = function.span.end as usize;
    let snippet = file.source.get(start..end)?;
    let head_end = snippet
        .find('{')
        .or_else(|| snippet.find(';'))
        .unwrap_or(snippet.len());
    snippet.get(..head_end)
}

fn signature_contains_authority_modifier(signature: &str) -> bool {
    signature
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty())
        .any(authority_modifier_token)
}

fn function_source_lower(function: &Function, ast: &NormalizedAst) -> Option<String> {
    let file = ast.files.get(function.span.file as usize)?;
    let start = function.span.start as usize;
    let end = function.span.end as usize;
    Some(
        file.source
            .get(start..end)
            .filter(|source| !source.is_empty())
            .unwrap_or(file.source.as_str())
            .to_ascii_lowercase(),
    )
}

fn surrounding_contract_name(function: &Function, ast: &NormalizedAst) -> Option<String> {
    let file = ast.files.get(function.span.file as usize)?;
    let prefix = file.source.get(..function.span.start as usize)?;
    let mut tokens = prefix
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty());
    let mut last_name = None::<String>;
    while let Some(token) = tokens.next() {
        if matches!(token, "contract" | "library" | "interface") {
            if let Some(name) = tokens.next() {
                last_name = Some(name.to_string());
            }
        }
    }
    last_name
}

pub fn load_sources(root: &str) -> Result<Vec<SourceFile>> {
    let root = Path::new(root);
    let mut files = Vec::new();
    collect_sources(root, &mut files)?;
    Ok(files)
}

pub fn collect_target_sources(path: &str) -> Result<Vec<SourceFile>> {
    let input = Path::new(path);
    let metadata = fs::metadata(input)?;
    if metadata.is_dir() {
        return load_sources(path);
    }

    let source_paths = target_group_paths(input)?;
    let mut files = Vec::new();
    for source_path in source_paths {
        let source = fs::read_to_string(&source_path)?;
        let id = files.len() as u32;
        files.push(SourceFile {
            id,
            path: source_path.display().to_string(),
            source,
        });
    }
    Ok(files)
}

pub fn resolve_root(path: &str) -> Result<PathBuf> {
    let input = Path::new(path);
    let metadata = fs::metadata(input)?;
    let root = if metadata.is_dir() {
        input
    } else {
        input.parent().unwrap_or(input)
    };

    match root.canonicalize() {
        Ok(value) => Ok(value),
        Err(_) => Ok(root.to_path_buf()),
    }
}

fn collect_sources(path: &Path, out: &mut Vec<SourceFile>) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            collect_sources(&entry.path(), out)?;
        }
        return Ok(());
    }

    if !metadata.is_file() {
        return Ok(());
    }

    if !is_solidity_file(path) {
        return Ok(());
    }

    let source = fs::read_to_string(path)?;
    let id = out.len() as u32;
    out.push(SourceFile {
        id,
        path: path.display().to_string(),
        source,
    });
    Ok(())
}

fn is_solidity_file(path: &Path) -> bool {
    matches!(path.extension().and_then(|ext| ext.to_str()), Some("sol"))
}

fn infer_compiler_info(files: &[SourceFile]) -> CompilerInfo {
    let mut best_version = None::<(u64, u64, u64)>;
    for file in files {
        if let Some(version) = first_pragma_version(&file.source) {
            best_version = Some(match best_version {
                Some(existing) if existing <= version => existing,
                _ => version,
            });
        }
    }

    let compiler_version =
        best_version.map(|(major, minor, patch)| format!("{major}.{minor}.{patch}"));
    // If pragma is missing entirely, prefer legacy entrypoint semantics so
    // omitted visibilities are treated as externally callable (0.4-style).
    let legacy_omitted_visibility_is_public = best_version
        .map(|(major, minor, _)| major == 0 && minor < 5)
        .unwrap_or(true);

    CompilerInfo {
        compiler_name: "solidity".to_string(),
        compiler_version,
        legacy_omitted_visibility_is_public,
    }
}

fn first_pragma_version(source: &str) -> Option<(u64, u64, u64)> {
    let lower = source.to_ascii_lowercase();
    let pragma_idx = lower.find("pragma solidity")?;
    let after = &source[pragma_idx + "pragma solidity".len()..];
    let end = after.find(';').unwrap_or(after.len());
    let clause = &after[..end];
    let bytes = clause.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        if ch.is_ascii_digit() {
            let start = idx;
            while idx < bytes.len() && ((bytes[idx] as char).is_ascii_digit() || bytes[idx] == b'.')
            {
                idx += 1;
            }
            let raw = &clause[start..idx];
            let mut parts = raw.split('.');
            let major = parts.next()?.parse().ok()?;
            let minor = parts.next().unwrap_or("0").parse().ok()?;
            let patch = parts.next().unwrap_or("0").parse().ok()?;
            return Some((major, minor, patch));
        }
        idx += 1;
    }
    None
}

fn target_group_paths(input: &Path) -> Result<Vec<PathBuf>> {
    if let Some(paths) = lookup_target_manifest(input)? {
        return Ok(paths);
    }
    collect_file_and_imports(input)
}

fn collect_file_and_imports(input: &Path) -> Result<Vec<PathBuf>> {
    let mut ordered = Vec::new();
    let mut stack = vec![canonical_or_original(input)];
    let mut seen = std::collections::HashSet::new();

    while let Some(path) = stack.pop() {
        let key = canonical_or_original(&path);
        if !seen.insert(key.clone()) {
            continue;
        }
        if !key.is_file() || !is_solidity_file(&key) {
            continue;
        }
        let source = fs::read_to_string(&key)?;
        ordered.push(key.clone());
        let parent = key.parent().unwrap_or_else(|| Path::new("."));
        let mut imports = scan_imports(&source)
            .into_iter()
            .filter_map(|import| resolve_import_path(parent, &import))
            .collect::<Vec<_>>();
        imports.sort();
        imports.reverse();
        stack.extend(imports);
    }

    ordered.sort();
    Ok(ordered)
}

fn canonical_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn resolve_import_path(parent: &Path, import: &str) -> Option<PathBuf> {
    let trimmed = import.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if trimmed.starts_with("./") || trimmed.starts_with("../") {
        parent.join(trimmed)
    } else {
        PathBuf::from(trimmed)
    };
    if candidate.exists() {
        Some(canonical_or_original(&candidate))
    } else {
        None
    }
}

fn scan_imports(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("import ") {
            continue;
        }
        if let Some(path) = first_quoted_path(trimmed) {
            out.push(path);
        }
    }
    out
}

fn first_quoted_path(line: &str) -> Option<String> {
    let mut quote = None::<char>;
    let mut start = 0usize;
    for (idx, ch) in line.char_indices() {
        if ch == '"' || ch == '\'' {
            if let Some(current) = quote {
                if current == ch {
                    return Some(line[start..idx].to_string());
                }
            } else {
                quote = Some(ch);
                start = idx + ch.len_utf8();
            }
        }
    }
    None
}

#[derive(Debug, Deserialize)]
struct TargetManifest {
    targets: Vec<TargetManifestEntry>,
}

#[derive(Debug, Deserialize)]
struct TargetManifestEntry {
    inputs: Vec<String>,
    sources: Vec<String>,
}

fn lookup_target_manifest(input: &Path) -> Result<Option<Vec<PathBuf>>> {
    let manifest_path = Path::new("Benchmarks").join("target_manifest.json");
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&manifest_path)?;
    let manifest: TargetManifest = serde_json::from_str(&raw)
        .map_err(|err| crate::util::error::Error::msg(format!("invalid target manifest: {err}")))?;
    let input_norm = normalize_manifest_path(input);

    for entry in manifest.targets {
        if entry
            .inputs
            .iter()
            .map(|value| normalize_manifest_path(Path::new(value)))
            .any(|candidate| candidate == input_norm)
        {
            let mut out = entry
                .sources
                .into_iter()
                .map(|value| normalize_manifest_path(Path::new(&value)))
                .collect::<Vec<_>>();
            out.sort();
            out.dedup();
            return Ok(Some(out));
        }
    }

    Ok(None)
}

fn normalize_manifest_path(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(".").join(path)
    };
    canonical_or_original(&joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::parser::load_via_parser_sources;
    use crate::norm::{Function, NormalizedAst, SourceFile, Span};

    fn function(kind: FunctionKind, visibility: Visibility, mutability: Mutability) -> Function {
        Function {
            id: 0,
            contract: None,
            name: Some("f".to_string()),
            kind,
            visibility,
            mutability,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span::default(),
        }
    }

    fn parse(source: &str) -> NormalizedAst {
        load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: source.to_string(),
        }])
        .expect("parser should succeed")
    }

    #[test]
    fn legacy_pragma_defaults_unknown_visibility_to_public() {
        let info = infer_compiler_info(&[SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: "pragma solidity ^0.4.15; contract C { function f() {} }".to_string(),
        }]);
        let func = function(
            FunctionKind::Function,
            Visibility::Unknown,
            Mutability::NonPayable,
        );
        assert_eq!(effective_visibility(&func, &info), Visibility::Public);
        assert!(is_public_entrypoint(&func, &info));
        assert!(is_mutating_entrypoint(&func, &info));
    }

    #[test]
    fn modern_pragma_keeps_unknown_visibility_unknown() {
        let info = infer_compiler_info(&[SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: "pragma solidity ^0.8.20; contract C { function f() {} }".to_string(),
        }]);
        let func = function(
            FunctionKind::Function,
            Visibility::Unknown,
            Mutability::NonPayable,
        );
        assert_eq!(effective_visibility(&func, &info), Visibility::Unknown);
        assert!(!is_public_entrypoint(&func, &info));
    }

    #[test]
    fn missing_pragma_defaults_unknown_visibility_to_public_for_legacy_compat() {
        let info = infer_compiler_info(&[SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: "contract C { function f() {} }".to_string(),
        }]);
        let func = function(
            FunctionKind::Function,
            Visibility::Unknown,
            Mutability::NonPayable,
        );
        assert_eq!(effective_visibility(&func, &info), Visibility::Public);
        assert!(is_public_entrypoint(&func, &info));
    }

    #[test]
    fn self_service_withdraw_counts_as_public_sender_payout() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract SimpleDAO {
                mapping(address => uint256) public credit;
                function withdraw(uint256 amount) public {
                    if (credit[msg.sender] >= amount) {
                        msg.sender.call.value(amount)();
                        credit[msg.sender] -= amount;
                    }
                }
            }
            "#,
        );

        let function = ast
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("withdraw"))
            .expect("withdraw function should exist");
        assert!(has_public_sender_payout_hint(function, &ast));
    }

    #[test]
    fn arbitrary_public_drain_is_not_treated_as_sender_owned_payout() {
        let ast = parse(
            r#"
            pragma solidity ^0.4.24;
            contract Lotto {
                bool public payedOut;
                function withdrawLeftOver() public {
                    require(payedOut);
                    msg.sender.send(this.balance);
                }
            }
            "#,
        );

        let function = ast
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("withdrawLeftOver"))
            .expect("withdrawLeftOver function should exist");
        assert!(!has_public_sender_payout_hint(function, &ast));
    }
}
