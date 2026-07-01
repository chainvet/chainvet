use std::collections::{BTreeMap, HashMap};
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use chainvet_core::norm::{
    CallMeta, CallOption, CallTarget, ChainSegment, Contract, ContractBase, ContractKind,
    ErrorDefinition, Event, Expr, ExprKind, ExprMeta, Function, FunctionKind, Literal, Modifier,
    Mutability, NormalizedAst, Span, StateVariable, Stmt, StmtKind, TryClause, Visibility,
};
use chainvet_core::util::error::{Error, Result};

use super::solc_manager::SolcManager;

pub fn load_via_solc(path: &str) -> Result<NormalizedAst> {
    let sources = crate::frontend::collect_target_sources(path)?;
    load_via_solc_sources(path, sources)
}

pub fn load_via_solc_sources(
    path: &str,
    sources: Vec<chainvet_core::norm::SourceFile>,
) -> Result<NormalizedAst> {
    if sources.is_empty() {
        return Err(Error::msg("no Solidity files found"));
    }

    let manager = SolcManager::new()?;
    let solc_path = manager.prepare(&sources)?;
    manager.check_solc(&solc_path)?;

    let root = crate::frontend::resolve_root(path)?;
    let remappings = load_remappings(&root)?;
    let include_paths = detect_include_paths(&root);
    let allow_paths = build_allow_paths(&root, &include_paths);

    let input = build_standard_json(&sources, remappings)?;
    let output = match run_solc(&solc_path, &root, &include_paths, &allow_paths, &input) {
        Ok(output) => output,
        Err(primary_err) => {
            let Some(legacy_solc) = manager.prepare_legacy_retry(&sources, &solc_path)? else {
                return Err(primary_err);
            };
            manager.check_solc(&legacy_solc)?;
            match run_solc(&legacy_solc, &root, &include_paths, &allow_paths, &input) {
                Ok(output) => output,
                Err(_) => return Err(primary_err),
            }
        }
    };
    let ast = normalize_output(sources, output)?;
    Ok(ast)
}

#[derive(Serialize)]
struct SolcInput {
    language: String,
    sources: BTreeMap<String, SolcSourceInput>,
    settings: SolcSettings,
}

#[derive(Serialize)]
struct SolcSourceInput {
    content: String,
}

#[derive(Serialize)]
struct SolcSettings {
    #[serde(rename = "outputSelection")]
    output_selection: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    remappings: Vec<String>,
}

#[derive(Deserialize)]
struct SolcOutput {
    sources: Option<BTreeMap<String, SolcOutputSource>>,
    errors: Option<Vec<SolcError>>,
}

#[derive(Deserialize)]
struct SolcOutputSource {
    id: u32,
    ast: Option<Value>,
}

#[derive(Deserialize)]
struct SolcError {
    severity: Option<String>,
    #[serde(rename = "formattedMessage")]
    formatted_message: Option<String>,
    message: Option<String>,
}

fn build_standard_json(
    sources: &[chainvet_core::norm::SourceFile],
    remappings: Vec<String>,
) -> Result<SolcInput> {
    let mut map = BTreeMap::new();
    for source in sources {
        map.insert(
            source.path.clone(),
            SolcSourceInput {
                content: source.source.clone(),
            },
        );
    }

    let mut output_selection = BTreeMap::new();
    let mut files = BTreeMap::new();
    files.insert(String::new(), vec!["ast".to_string()]);
    output_selection.insert("*".to_string(), files);

    Ok(SolcInput {
        language: "Solidity".to_string(),
        sources: map,
        settings: SolcSettings {
            output_selection,
            remappings,
        },
    })
}

fn run_solc(
    solc_path: &Path,
    base_path: &Path,
    include_paths: &[PathBuf],
    allow_paths: &[PathBuf],
    input: &SolcInput,
) -> Result<SolcOutput> {
    let output = run_solc_once(
        solc_path,
        base_path,
        include_paths,
        allow_paths,
        input,
        true,
    )?;
    match parse_solc_output(&output) {
        Ok(parsed) => Ok(parsed),
        Err(_err) if should_retry_without_path_flags(&output) => {
            let fallback = run_solc_once(
                solc_path,
                base_path,
                include_paths,
                allow_paths,
                input,
                false,
            )?;
            parse_solc_output(&fallback)
        }
        Err(err) => Err(err),
    }
}

fn run_solc_once(
    solc_path: &Path,
    base_path: &Path,
    include_paths: &[PathBuf],
    allow_paths: &[PathBuf],
    input: &SolcInput,
    with_path_flags: bool,
) -> Result<Output> {
    let mut cmd = Command::new(solc_path);
    cmd.current_dir(base_path);
    cmd.arg("--standard-json");
    if with_path_flags {
        cmd.arg("--base-path");
        cmd.arg(path_to_arg(base_path)?);

        for include in include_paths {
            cmd.arg("--include-path");
            cmd.arg(path_to_arg(include)?);
        }

        if !allow_paths.is_empty() {
            cmd.arg("--allow-paths");
            cmd.arg(join_paths(allow_paths)?);
        }
    }

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| Error::msg("failed to open solc stdin"))?;
    let payload = serde_json::to_vec(input)
        .map_err(|err| Error::msg(format!("solc input serialization failed: {err}")))?;
    stdin.write_all(&payload)?;

    child.wait_with_output().map_err(Into::into)
}

fn parse_solc_output(output: &Output) -> Result<SolcOutput> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            return Err(Error::msg(format!("solc failed: {stderr}")));
        }
    }

    let parsed: SolcOutput = serde_json::from_slice(&output.stdout)
        .map_err(|err| Error::msg(format!("solc output parse error: {err}")))?;
    check_solc_errors(&parsed)?;
    Ok(parsed)
}

fn should_retry_without_path_flags(output: &Output) -> bool {
    let mut combined = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if !combined.is_empty() {
        combined.push('\n');
    }
    combined.push_str(&String::from_utf8_lossy(&output.stdout).to_ascii_lowercase());

    [
        "unrecognised option '--base-path'",
        "unrecognized option '--base-path'",
        "unrecognised option '--include-path'",
        "unrecognized option '--include-path'",
        "unrecognised option '--allow-paths'",
        "unrecognized option '--allow-paths'",
    ]
    .iter()
    .any(|needle| combined.contains(needle))
}

fn load_remappings(root: &Path) -> Result<Vec<String>> {
    let mut remappings = Vec::new();

    if let Ok(value) = env::var("STATIC_SOLC_REMAPPINGS") {
        remappings.extend(split_remapping_list(&value));
    }

    let remap_path = root.join("remappings.txt");
    if remap_path.exists() {
        let raw = std::fs::read_to_string(remap_path)?;
        for line in raw.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            remappings.push(trimmed.to_string());
        }
    }

    Ok(remappings)
}

fn split_remapping_list(value: &str) -> Vec<String> {
    value
        .split([';', ','])
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_string())
        .collect()
}

fn detect_include_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let candidates = ["node_modules", "lib", "contracts", "src"];
    for name in candidates {
        let path = root.join(name);
        if path.is_dir() {
            paths.push(path);
        }
    }
    paths
}

fn build_allow_paths(root: &Path, include_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    paths.push(root.to_path_buf());
    for include in include_paths {
        if !paths.iter().any(|existing| existing == include) {
            paths.push(include.clone());
        }
    }
    paths
}

fn path_to_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(|value| value.to_string())
        .ok_or_else(|| Error::msg("path is not valid UTF-8"))
}

fn join_paths(paths: &[PathBuf]) -> Result<String> {
    let mut joined = String::new();
    for (idx, path) in paths.iter().enumerate() {
        if idx > 0 {
            joined.push(',');
        }
        joined.push_str(&path_to_arg(path)?);
    }
    Ok(joined)
}

fn check_solc_errors(output: &SolcOutput) -> Result<()> {
    let Some(errors) = output.errors.as_ref() else {
        return Ok(());
    };

    let mut messages = Vec::new();
    for err in errors {
        if err.severity.as_deref() == Some("error")
            && let Some(msg) = err.formatted_message.as_ref().or(err.message.as_ref())
        {
            messages.push(msg.trim().to_string());
        }
    }

    if messages.is_empty() {
        return Ok(());
    }

    Err(Error::msg(messages.join("\n")))
}

fn normalize_output(
    sources: Vec<chainvet_core::norm::SourceFile>,
    output: SolcOutput,
) -> Result<NormalizedAst> {
    let mut ast = NormalizedAst::from_sources(sources);
    let sources_out = output
        .sources
        .ok_or_else(|| Error::msg("solc output missing sources"))?;
    let source_map = build_source_id_map(&ast.files, &sources_out);

    for (path, source) in sources_out {
        let Some(ast_value) = source.ast else {
            return Err(Error::msg(format!("solc output missing ast for {path}")));
        };
        normalize_source_unit(&ast_value, &source_map, &mut ast)?;
    }

    Ok(ast)
}

fn build_source_id_map(
    files: &[chainvet_core::norm::SourceFile],
    sources_out: &BTreeMap<String, SolcOutputSource>,
) -> HashMap<u32, u32> {
    let mut path_map = HashMap::new();
    for file in files {
        path_map.insert(file.path.as_str(), file.id);
    }

    let mut source_map = HashMap::new();
    for (path, source) in sources_out {
        if let Some(file_id) = path_map.get(path.as_str()) {
            source_map.insert(source.id, *file_id);
        }
    }
    source_map
}

fn normalize_source_unit(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    ast: &mut NormalizedAst,
) -> Result<()> {
    let Some(children) = child_nodes(node) else {
        return Ok(());
    };

    for child in children {
        match node_type(child).as_deref() {
            Some("ContractDefinition") => normalize_contract(child, source_map, ast),
            Some("FunctionDefinition") => {
                let _ = normalize_function(child, source_map, None, ast);
            }
            Some("ErrorDefinition") => {
                let _ = normalize_error(child, source_map, None, ast);
            }
            _ => {}
        }
    }
    Ok(())
}

fn normalize_contract(node: &Value, source_map: &HashMap<u32, u32>, ast: &mut NormalizedAst) {
    let id = ast.contracts.len() as u32;
    let name = read_string(node, "name")
        .or_else(|| read_attr_string(node, "name"))
        .unwrap_or_else(|| "<unknown>".to_string());
    let kind = parse_contract_kind(node);
    let bases = parse_contract_bases(node);
    let span = parse_span(node, source_map);

    ast.contracts.push(Contract {
        id,
        name,
        kind,
        bases,
        functions: Vec::new(),
        state_vars: Vec::new(),
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
        span,
    });
    ast.items.push(chainvet_core::norm::Item::Contract(id));

    let Some(children) = child_nodes(node) else {
        return;
    };

    for child in children {
        match node_type(child).as_deref() {
            Some("FunctionDefinition") => {
                let func_id = normalize_function(child, source_map, Some(id), ast);
                if let Some(func_id) = func_id
                    && let Some(contract) = ast.contracts.get_mut(id as usize)
                {
                    contract.functions.push(func_id);
                }
            }
            Some("VariableDeclaration") => {
                if let Some(var_id) = normalize_state_var(child, source_map, id, ast)
                    && let Some(contract) = ast.contracts.get_mut(id as usize)
                {
                    contract.state_vars.push(var_id);
                }
            }
            Some("ModifierDefinition") => {
                if let Some(mod_id) = normalize_modifier(child, source_map, id, ast)
                    && let Some(contract) = ast.contracts.get_mut(id as usize)
                {
                    contract.modifiers.push(mod_id);
                }
            }
            Some("EventDefinition") => {
                if let Some(event_id) = normalize_event(child, source_map, id, ast)
                    && let Some(contract) = ast.contracts.get_mut(id as usize)
                {
                    contract.events.push(event_id);
                }
            }
            Some("ErrorDefinition") => {
                if let Some(error_id) = normalize_error(child, source_map, Some(id), ast)
                    && let Some(contract) = ast.contracts.get_mut(id as usize)
                {
                    contract.errors.push(error_id);
                }
            }
            _ => {}
        }
    }
}

fn normalize_function(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    contract: Option<u32>,
    ast: &mut NormalizedAst,
) -> Option<u32> {
    let id = ast.functions.len() as u32;
    let name = read_string(node, "name")
        .or_else(|| read_attr_string(node, "name"))
        .and_then(|value| if value.is_empty() { None } else { Some(value) });
    let kind = parse_function_kind(node);
    let visibility = parse_visibility(node);
    let mutability = parse_mutability(node);
    let params = parse_function_params(node);
    let returns = parse_function_returns(node);
    let modifiers = parse_function_modifiers(node);
    let body = parse_function_body(node, source_map, ast);
    let span = parse_span(node, source_map);

    ast.functions.push(Function {
        id,
        contract,
        name,
        kind,
        visibility,
        mutability,
        params,
        returns,
        modifiers,
        body,
        span,
    });
    ast.items.push(chainvet_core::norm::Item::Function(id));
    Some(id)
}

fn normalize_state_var(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    contract: u32,
    ast: &mut NormalizedAst,
) -> Option<u32> {
    if read_attr_bool(node, "stateVariable") == Some(false) {
        return None;
    }
    if read_attr_bool(node, "stateVariable").is_none() && read_bool(node, "stateVariable").is_none()
    {
        return None;
    }

    let id = ast.state_vars.len() as u32;
    let name = read_string(node, "name")
        .or_else(|| read_attr_string(node, "name"))
        .unwrap_or_else(|| "<unknown>".to_string());
    let visibility = parse_visibility(node);
    let mutability = parse_var_mutability(node);
    let constant = read_attr_bool(node, "constant").unwrap_or(false);
    let immutable = read_attr_bool(node, "immutable").unwrap_or(false);
    let type_string = read_type_string(node);
    let span = parse_span(node, source_map);

    ast.state_vars.push(StateVariable {
        id,
        contract,
        name,
        visibility,
        mutability,
        constant,
        immutable,
        type_string,
        span,
    });
    ast.items.push(chainvet_core::norm::Item::StateVar(id));
    Some(id)
}

fn normalize_modifier(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    contract: u32,
    ast: &mut NormalizedAst,
) -> Option<u32> {
    let id = ast.modifiers.len() as u32;
    let name = read_string(node, "name")
        .or_else(|| read_attr_string(node, "name"))
        .unwrap_or_else(|| "<unknown>".to_string());
    let span = parse_span(node, source_map);

    ast.modifiers.push(Modifier {
        id,
        contract,
        name,
        span,
    });
    ast.items.push(chainvet_core::norm::Item::Modifier(id));
    Some(id)
}

fn normalize_event(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    contract: u32,
    ast: &mut NormalizedAst,
) -> Option<u32> {
    let id = ast.events.len() as u32;
    let name = read_string(node, "name")
        .or_else(|| read_attr_string(node, "name"))
        .unwrap_or_else(|| "<unknown>".to_string());
    let span = parse_span(node, source_map);

    ast.events.push(Event {
        id,
        contract,
        name,
        span,
    });
    ast.items.push(chainvet_core::norm::Item::Event(id));
    Some(id)
}

fn normalize_error(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    contract: Option<u32>,
    ast: &mut NormalizedAst,
) -> Option<u32> {
    let id = ast.errors.len() as u32;
    let name = read_string(node, "name")
        .or_else(|| read_attr_string(node, "name"))
        .unwrap_or_else(|| "<unknown>".to_string());
    let span = parse_span(node, source_map);

    ast.errors.push(ErrorDefinition {
        id,
        contract,
        name,
        span,
    });
    ast.items.push(chainvet_core::norm::Item::Error(id));
    Some(id)
}

fn parse_function_body(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    ast: &mut NormalizedAst,
) -> Option<u32> {
    let body = node.get("body")?;
    parse_stmt(body, source_map, ast)
}

fn child_nodes(node: &Value) -> Option<&Vec<Value>> {
    if let Some(nodes) = node.get("nodes").and_then(Value::as_array) {
        return Some(nodes);
    }
    node.get("children").and_then(Value::as_array)
}

fn node_type(node: &Value) -> Option<String> {
    read_string(node, "nodeType")
        .or_else(|| read_string(node, "name"))
        .or_else(|| read_attr_string(node, "nodeType"))
        .or_else(|| read_attr_string(node, "name"))
}

fn read_string(node: &Value, key: &str) -> Option<String> {
    node.get(key).and_then(Value::as_str).map(|v| v.to_string())
}

fn read_attr_string(node: &Value, key: &str) -> Option<String> {
    node.get("attributes")
        .and_then(|attrs| attrs.get(key))
        .and_then(Value::as_str)
        .map(|v| v.to_string())
}

fn parse_contract_kind(node: &Value) -> ContractKind {
    let kind = read_string(node, "contractKind")
        .or_else(|| read_attr_string(node, "contractKind"))
        .unwrap_or_default();
    match kind.as_str() {
        "contract" => ContractKind::Contract,
        "interface" => ContractKind::Interface,
        "library" => ContractKind::Library,
        _ => ContractKind::Unknown,
    }
}

fn parse_contract_bases(node: &Value) -> Vec<ContractBase> {
    let mut bases = Vec::new();
    let Some(entries) = node.get("baseContracts").and_then(Value::as_array) else {
        return bases;
    };
    for entry in entries {
        let Some(base_name) = read_base_name(entry) else {
            continue;
        };
        bases.push(ContractBase { name: base_name });
    }
    bases
}

fn read_base_name(node: &Value) -> Option<String> {
    let base = node.get("baseName")?;
    read_string(base, "name")
        .or_else(|| read_string(base, "namePath"))
        .or_else(|| read_attr_string(base, "name"))
        .or_else(|| read_attr_string(base, "namePath"))
        .or_else(|| read_type_string(base))
}

fn parse_function_kind(node: &Value) -> FunctionKind {
    let kind = read_string(node, "kind")
        .or_else(|| read_attr_string(node, "kind"))
        .unwrap_or_default();
    match kind.as_str() {
        "function" => FunctionKind::Function,
        "constructor" => FunctionKind::Constructor,
        "fallback" => FunctionKind::Fallback,
        "receive" => FunctionKind::Receive,
        _ => {
            let is_constructor = read_attr_bool(node, "isConstructor").unwrap_or(false)
                || read_bool(node, "isConstructor").unwrap_or(false);
            if is_constructor {
                FunctionKind::Constructor
            } else if read_string(node, "name")
                .or_else(|| read_attr_string(node, "name"))
                .is_none_or(|name| name.is_empty())
            {
                // Legacy fallback form: `function() external/payable { ... }`
                // appears without a `kind` field in old AST shapes.
                FunctionKind::Fallback
            } else {
                // Old solc ASTs may omit `kind`; default to normal function.
                FunctionKind::Function
            }
        }
    }
}

fn parse_visibility(node: &Value) -> Visibility {
    let visibility = read_string(node, "visibility")
        .or_else(|| read_attr_string(node, "visibility"))
        .unwrap_or_default();
    match visibility.as_str() {
        "public" => Visibility::Public,
        "external" => Visibility::External,
        "internal" => Visibility::Internal,
        "private" => Visibility::Private,
        _ => Visibility::Unknown,
    }
}

fn parse_mutability(node: &Value) -> Mutability {
    let mutability = read_string(node, "stateMutability")
        .or_else(|| read_attr_string(node, "stateMutability"))
        .unwrap_or_default();
    match mutability.as_str() {
        "pure" => Mutability::Pure,
        "view" => Mutability::View,
        "payable" => Mutability::Payable,
        "nonpayable" => Mutability::NonPayable,
        _ => {
            if read_attr_bool(node, "payable") == Some(true) {
                Mutability::Payable
            } else if read_attr_bool(node, "constant") == Some(true) {
                Mutability::View
            } else {
                Mutability::Unknown
            }
        }
    }
}

fn parse_var_mutability(node: &Value) -> Mutability {
    if read_attr_bool(node, "constant") == Some(true) {
        return Mutability::View;
    }
    Mutability::Unknown
}

fn parse_function_modifiers(node: &Value) -> Vec<String> {
    let mut modifiers = Vec::new();
    let Some(entries) = node.get("modifiers").and_then(Value::as_array) else {
        return modifiers;
    };

    for entry in entries {
        if let Some(name) = read_child_name(entry, "modifierName") {
            modifiers.push(name);
        }
    }
    modifiers
}

fn read_attr_bool(node: &Value, key: &str) -> Option<bool> {
    node.get("attributes")
        .and_then(|attrs| attrs.get(key))
        .and_then(Value::as_bool)
}

fn read_bool(node: &Value, key: &str) -> Option<bool> {
    node.get(key).and_then(Value::as_bool)
}

fn parse_span(node: &Value, source_map: &HashMap<u32, u32>) -> Span {
    let Some(src) = node.get("src").and_then(Value::as_str) else {
        return Span::default();
    };
    parse_src(src, source_map).unwrap_or_default()
}

fn read_type_string(node: &Value) -> Option<String> {
    node.get("typeDescriptions")
        .and_then(|desc| desc.get("typeString"))
        .and_then(Value::as_str)
        .map(|value| value.to_string())
        .or_else(|| read_attr_string(node, "typeString"))
}

fn read_child_name(node: &Value, key: &str) -> Option<String> {
    let child = node.get(key)?;
    read_string(child, "name")
        .or_else(|| read_attr_string(child, "name"))
        .or_else(|| read_string(child, "identifier"))
        .or_else(|| read_attr_string(child, "identifier"))
}

fn push_stmt(ast: &mut NormalizedAst, kind: StmtKind, span: Span) -> u32 {
    let id = ast.statements.len() as u32;
    ast.statements.push(Stmt { kind, span });
    id
}

fn push_expr(ast: &mut NormalizedAst, kind: ExprKind, span: Span, meta: ExprMeta) -> u32 {
    let id = ast.expressions.len() as u32;
    ast.expressions.push(Expr { kind, span, meta });
    id
}

fn parse_stmt(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    ast: &mut NormalizedAst,
) -> Option<u32> {
    let kind = node_type(node)?;
    let span = parse_span(node, source_map);

    match kind.as_str() {
        "Block" => {
            let mut children = Vec::new();
            if let Some(statements) = node.get("statements").and_then(Value::as_array) {
                for stmt in statements {
                    if let Some(id) = parse_stmt(stmt, source_map, ast) {
                        children.push(id);
                    }
                }
            } else if let Some(statements) = node.get("nodes").and_then(Value::as_array) {
                for stmt in statements {
                    if let Some(id) = parse_stmt(stmt, source_map, ast) {
                        children.push(id);
                    }
                }
            }
            Some(push_stmt(ast, StmtKind::Block(children), span))
        }
        "ExpressionStatement" => {
            let expr = node
                .get("expression")
                .and_then(|expr| parse_expr(expr, source_map, ast))
                .unwrap_or_else(|| parse_unknown_expr(node, source_map, ast));
            Some(push_stmt(ast, StmtKind::Expr(expr), span))
        }
        "Return" => {
            let value = node
                .get("expression")
                .and_then(|expr| parse_expr(expr, source_map, ast));
            Some(push_stmt(ast, StmtKind::Return(value), span))
        }
        "IfStatement" => {
            let cond = node
                .get("condition")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let then_id = node
                .get("trueBody")
                .and_then(|stmt| parse_stmt(stmt, source_map, ast))?;
            let else_id = node
                .get("falseBody")
                .and_then(|stmt| parse_stmt(stmt, source_map, ast));
            Some(push_stmt(
                ast,
                StmtKind::If {
                    cond,
                    then_id,
                    else_id,
                },
                span,
            ))
        }
        "WhileStatement" => {
            let cond = node
                .get("condition")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let body = node
                .get("body")
                .and_then(|stmt| parse_stmt(stmt, source_map, ast))?;
            Some(push_stmt(ast, StmtKind::While { cond, body }, span))
        }
        "DoWhileStatement" => {
            let body = node
                .get("body")
                .and_then(|stmt| parse_stmt(stmt, source_map, ast))?;
            let cond = node
                .get("condition")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            Some(push_stmt(ast, StmtKind::DoWhile { body, cond }, span))
        }
        "ForStatement" => {
            let init = node
                .get("initializationExpression")
                .and_then(|stmt| parse_stmt(stmt, source_map, ast));
            let cond = node
                .get("condition")
                .and_then(|expr| parse_expr(expr, source_map, ast));
            let step = node
                .get("loopExpression")
                .and_then(|expr| parse_expr(expr, source_map, ast));
            let body = node
                .get("body")
                .and_then(|stmt| parse_stmt(stmt, source_map, ast))?;
            Some(push_stmt(
                ast,
                StmtKind::For {
                    init,
                    cond,
                    step,
                    body,
                },
                span,
            ))
        }
        "EmitStatement" => {
            let expr = node
                .get("eventCall")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            Some(push_stmt(ast, StmtKind::Emit(expr), span))
        }
        "RevertStatement" => {
            let expr = node
                .get("errorCall")
                .and_then(|expr| parse_expr(expr, source_map, ast));
            Some(push_stmt(ast, StmtKind::Revert(expr), span))
        }
        "VariableDeclarationStatement" => {
            let mut names = Vec::new();
            if let Some(decls) = node.get("declarations").and_then(Value::as_array) {
                for decl in decls {
                    if decl.is_null() {
                        continue;
                    }
                    if let Some(name) = read_string(decl, "name")
                        .or_else(|| read_attr_string(decl, "name"))
                        .or_else(|| read_type_string(decl))
                    {
                        names.push(name);
                    }
                }
            }
            let init = node
                .get("initialValue")
                .or_else(|| node.get("initialExpression"))
                .and_then(|expr| parse_expr(expr, source_map, ast));
            Some(push_stmt(ast, StmtKind::VarDecl { names, init }, span))
        }
        "TryStatement" => {
            let call = node
                .get("externalCall")
                .or_else(|| node.get("expression"))
                .and_then(|expr| parse_expr(expr, source_map, ast))
                .unwrap_or_else(|| parse_unknown_expr(node, source_map, ast));
            let mut clauses = Vec::new();
            if let Some(entries) = node.get("clauses").and_then(Value::as_array) {
                for clause in entries {
                    if let Some(parsed) = parse_try_clause(clause, source_map, ast) {
                        clauses.push(parsed);
                    }
                }
            }
            Some(push_stmt(ast, StmtKind::Try { call, clauses }, span))
        }
        "InlineAssembly" => {
            let language =
                read_string(node, "language").or_else(|| read_attr_string(node, "language"));
            Some(push_stmt(ast, StmtKind::InlineAsm { language }, span))
        }
        "Break" => Some(push_stmt(ast, StmtKind::Break, span)),
        "Continue" => Some(push_stmt(ast, StmtKind::Continue, span)),
        _ => {
            if is_expr_kind(kind.as_str())
                && let Some(expr_id) = parse_expr(node, source_map, ast)
            {
                return Some(push_stmt(ast, StmtKind::Expr(expr_id), span));
            }
            let expr_id = parse_unknown_expr(node, source_map, ast);
            Some(push_stmt(ast, StmtKind::Expr(expr_id), span))
        }
    }
}

fn parse_expr(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    ast: &mut NormalizedAst,
) -> Option<u32> {
    let kind = node_type(node)?;
    let span = parse_span(node, source_map);

    match kind.as_str() {
        "Identifier" => {
            let name = read_string(node, "name")
                .or_else(|| read_attr_string(node, "name"))
                .unwrap_or_else(|| "<unknown>".to_string());
            let meta = ExprMeta {
                chain: Some(vec![ChainSegment::Ident(name.clone())]),
                call: None,
            };
            Some(push_expr(ast, ExprKind::Ident(name), span, meta))
        }
        "ElementaryTypeNameExpression" | "TypeNameExpression" => {
            let type_name = node
                .get("typeName")
                .and_then(read_type_name)
                .or_else(|| read_type_name(node))
                .unwrap_or_else(|| "<unknown>".to_string());
            let meta = ExprMeta {
                chain: Some(vec![ChainSegment::Ident(type_name.clone())]),
                call: None,
            };
            Some(push_expr(ast, ExprKind::Ident(type_name), span, meta))
        }
        "Literal" => {
            let lit_kind = read_string(node, "kind")
                .or_else(|| read_attr_string(node, "kind"))
                .unwrap_or_else(|| "literal".to_string());
            let value = read_string(node, "value")
                .or_else(|| read_attr_string(node, "value"))
                .or_else(|| read_string(node, "hexValue"))
                .or_else(|| read_attr_string(node, "hexValue"))
                .unwrap_or_default();
            Some(push_expr(
                ast,
                ExprKind::Literal(Literal {
                    kind: lit_kind,
                    value,
                }),
                span,
                ExprMeta::default(),
            ))
        }
        "FunctionCall" => {
            let callee = node
                .get("expression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let mut args = Vec::new();
            if let Some(entries) = node.get("arguments").and_then(Value::as_array) {
                for entry in entries {
                    if let Some(arg) = parse_expr(entry, source_map, ast) {
                        args.push(arg);
                    }
                }
            }

            let (callee, options) = unwrap_call_options(ast, callee);
            let chain = chain_from_expr(ast, callee);
            let target = call_target_from_chain(chain.as_deref());
            let base_chain = chain.clone().unwrap_or_default();
            let mut chain_with_call = base_chain.clone();
            chain_with_call.push(ChainSegment::Call);
            let meta = ExprMeta {
                chain: Some(chain_with_call),
                call: Some(CallMeta {
                    target,
                    chain: base_chain,
                    options,
                }),
            };

            Some(push_expr(ast, ExprKind::Call { callee, args }, span, meta))
        }
        "FunctionCallOptions" => {
            let callee = node
                .get("expression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let options = parse_call_options(node, source_map, ast);
            let meta = ExprMeta {
                chain: chain_from_expr(ast, callee),
                call: None,
            };
            Some(push_expr(
                ast,
                ExprKind::CallOptions { callee, options },
                span,
                meta,
            ))
        }
        "BinaryOperation" => {
            let op = read_string(node, "operator")
                .or_else(|| read_attr_string(node, "operator"))
                .unwrap_or_else(|| "?".to_string());
            let lhs = node
                .get("leftExpression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let rhs = node
                .get("rightExpression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            Some(push_expr(
                ast,
                ExprKind::Binary { op, lhs, rhs },
                span,
                ExprMeta::default(),
            ))
        }
        "UnaryOperation" => {
            let op = read_string(node, "operator")
                .or_else(|| read_attr_string(node, "operator"))
                .unwrap_or_else(|| "?".to_string());
            let expr = node
                .get("subExpression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let prefix = read_bool(node, "prefix").unwrap_or(true);
            Some(push_expr(
                ast,
                ExprKind::Unary { op, expr, prefix },
                span,
                ExprMeta::default(),
            ))
        }
        "Assignment" => {
            let op = read_string(node, "operator")
                .or_else(|| read_attr_string(node, "operator"))
                .unwrap_or_else(|| "=".to_string());
            let lhs = node
                .get("leftHandSide")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let rhs = node
                .get("rightHandSide")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            Some(push_expr(
                ast,
                ExprKind::Assign { op, lhs, rhs },
                span,
                ExprMeta::default(),
            ))
        }
        "MemberAccess" => {
            let base = node
                .get("expression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let field = read_string(node, "memberName")
                .or_else(|| read_attr_string(node, "memberName"))
                .unwrap_or_else(|| "<unknown>".to_string());
            let chain = extend_chain(ast, base, ChainSegment::Member(field.clone()));
            let meta = ExprMeta { chain, call: None };
            Some(push_expr(ast, ExprKind::Member { base, field }, span, meta))
        }
        "IndexAccess" => {
            let base = node
                .get("baseExpression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let index = node
                .get("indexExpression")
                .and_then(|expr| parse_expr(expr, source_map, ast));
            let chain = extend_chain(ast, base, ChainSegment::Index);
            let meta = ExprMeta { chain, call: None };
            Some(push_expr(ast, ExprKind::Index { base, index }, span, meta))
        }
        "TupleExpression" => {
            let mut entries = Vec::new();
            if let Some(components) = node.get("components").and_then(Value::as_array) {
                for component in components {
                    if component.is_null() {
                        continue;
                    }
                    if let Some(expr_id) = parse_expr(component, source_map, ast) {
                        entries.push(expr_id);
                    }
                }
            }
            Some(push_expr(
                ast,
                ExprKind::Tuple(entries),
                span,
                ExprMeta::default(),
            ))
        }
        "Conditional" => {
            let cond = node
                .get("condition")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let then_expr = node
                .get("trueExpression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            let else_expr = node
                .get("falseExpression")
                .and_then(|expr| parse_expr(expr, source_map, ast))?;
            Some(push_expr(
                ast,
                ExprKind::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                },
                span,
                ExprMeta::default(),
            ))
        }
        "NewExpression" => {
            let type_name = read_type_name(node)
                .or_else(|| node.get("typeName").and_then(read_type_name))
                .unwrap_or_else(|| "<unknown>".to_string());
            let chain = if type_name == "<unknown>" {
                None
            } else {
                Some(vec![ChainSegment::Ident(type_name.clone())])
            };
            let meta = ExprMeta { chain, call: None };
            Some(push_expr(ast, ExprKind::New { type_name }, span, meta))
        }
        _ => Some(parse_unknown_expr(node, source_map, ast)),
    }
}

fn parse_unknown_expr(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    ast: &mut NormalizedAst,
) -> u32 {
    let span = parse_span(node, source_map);
    push_expr(ast, ExprKind::Unknown, span, ExprMeta::default())
}

fn is_expr_kind(kind: &str) -> bool {
    matches!(
        kind,
        "Identifier"
            | "ElementaryTypeNameExpression"
            | "TypeNameExpression"
            | "Literal"
            | "FunctionCall"
            | "FunctionCallOptions"
            | "BinaryOperation"
            | "UnaryOperation"
            | "Assignment"
            | "MemberAccess"
            | "IndexAccess"
            | "TupleExpression"
            | "Conditional"
            | "NewExpression"
    )
}

fn chain_from_expr(ast: &NormalizedAst, expr_id: u32) -> Option<Vec<ChainSegment>> {
    ast.expressions
        .get(expr_id as usize)
        .and_then(|expr| expr.meta.chain.clone())
}

fn extend_chain(
    ast: &NormalizedAst,
    base: u32,
    segment: ChainSegment,
) -> Option<Vec<ChainSegment>> {
    let mut chain = chain_from_expr(ast, base)?;
    chain.push(segment);
    Some(chain)
}

fn unwrap_call_options(ast: &NormalizedAst, callee: u32) -> (u32, Vec<CallOption>) {
    let Some(expr) = ast.expressions.get(callee as usize) else {
        return (callee, Vec::new());
    };
    match &expr.kind {
        ExprKind::CallOptions { callee, options } => (*callee, options.clone()),
        _ => (callee, Vec::new()),
    }
}

fn call_target_from_chain(chain: Option<&[ChainSegment]>) -> CallTarget {
    let Some(chain) = chain else {
        return CallTarget::Unknown;
    };
    let mut names = Vec::new();
    for segment in chain {
        match segment {
            ChainSegment::Ident(name) | ChainSegment::Member(name) => names.push(name.clone()),
            ChainSegment::Index | ChainSegment::Call => return CallTarget::Unknown,
        }
    }

    if names.is_empty() {
        return CallTarget::Unknown;
    }
    if names.len() == 1 {
        return CallTarget::Direct {
            name: names[0].clone(),
        };
    }

    let receiver = names[..names.len() - 1].to_vec();
    let name = names[names.len() - 1].clone();
    CallTarget::Member { receiver, name }
}

fn parse_call_options(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    ast: &mut NormalizedAst,
) -> Vec<CallOption> {
    let mut options = Vec::new();
    if let Some(entries) = node.get("options").and_then(Value::as_array) {
        let names = node.get("names").and_then(Value::as_array);
        for (idx, value) in entries.iter().enumerate() {
            let name = names
                .and_then(|values| values.get(idx))
                .and_then(Value::as_str)
                .unwrap_or("");
            let expr_id = match parse_expr(value, source_map, ast) {
                Some(id) => id,
                None => continue,
            };
            match name {
                "value" => options.push(CallOption::Value(expr_id)),
                "gas" => options.push(CallOption::Gas(expr_id)),
                "salt" => options.push(CallOption::Salt(expr_id)),
                _ => {}
            }
        }
        return options;
    }

    if let Some(map) = node.get("options").and_then(Value::as_object) {
        for (key, value) in map {
            let expr_id = match parse_expr(value, source_map, ast) {
                Some(id) => id,
                None => continue,
            };
            match key.as_str() {
                "value" => options.push(CallOption::Value(expr_id)),
                "gas" => options.push(CallOption::Gas(expr_id)),
                "salt" => options.push(CallOption::Salt(expr_id)),
                _ => {}
            }
        }
    }

    options
}

fn read_type_name(node: &Value) -> Option<String> {
    read_string(node, "name")
        .or_else(|| read_string(node, "namePath"))
        .or_else(|| read_attr_string(node, "name"))
        .or_else(|| read_attr_string(node, "namePath"))
        .or_else(|| read_type_string(node))
}

fn parse_try_clause(
    node: &Value,
    source_map: &HashMap<u32, u32>,
    ast: &mut NormalizedAst,
) -> Option<TryClause> {
    let kind = read_string(node, "kind")
        .or_else(|| read_attr_string(node, "kind"))
        .unwrap_or_else(|| "catch".to_string());
    let name = read_string(node, "errorName").or_else(|| read_attr_string(node, "errorName"));
    let params = parse_clause_params(node);
    let body_node = node.get("block").or_else(|| node.get("body"));
    let body = match body_node.and_then(|value| parse_stmt(value, source_map, ast)) {
        Some(id) => id,
        None => push_stmt(
            ast,
            StmtKind::Block(Vec::new()),
            parse_span(node, source_map),
        ),
    };

    Some(TryClause {
        kind,
        name,
        params,
        body,
    })
}

fn parse_clause_params(node: &Value) -> Vec<String> {
    let mut params = Vec::new();
    let mut list = None;
    if let Some(value) = node.get("parameters") {
        if let Some(array) = value.as_array() {
            list = Some(array);
        } else if let Some(array) = value.get("parameters").and_then(Value::as_array) {
            list = Some(array);
        }
    }

    if let Some(list) = list {
        for param in list {
            if param.is_null() {
                continue;
            }
            if let Some(name) = read_string(param, "name")
                .or_else(|| read_attr_string(param, "name"))
                .or_else(|| read_type_string(param))
                && !name.is_empty()
            {
                params.push(name);
            }
        }
    }

    params
}

fn parse_function_params(node: &Value) -> Vec<String> {
    let mut params = Vec::new();
    let mut list = None;
    if let Some(value) = node.get("parameters") {
        if let Some(array) = value.as_array() {
            list = Some(array);
        } else if let Some(array) = value.get("parameters").and_then(Value::as_array) {
            list = Some(array);
        }
    }

    if let Some(list) = list {
        for param in list {
            if param.is_null() {
                continue;
            }
            if let Some(name) =
                read_string(param, "name").or_else(|| read_attr_string(param, "name"))
                && !name.is_empty()
            {
                params.push(name);
            }
        }
    }

    params
}

fn parse_function_returns(node: &Value) -> Vec<String> {
    let mut returns = Vec::new();
    let mut list = None;
    if let Some(value) = node.get("returnParameters") {
        if let Some(array) = value.as_array() {
            list = Some(array);
        } else if let Some(array) = value.get("parameters").and_then(Value::as_array) {
            list = Some(array);
        }
    }

    if let Some(list) = list {
        for (idx, param) in list.iter().enumerate() {
            if param.is_null() {
                returns.push(format!("_ret{idx}"));
                continue;
            }
            let name = read_string(param, "name").or_else(|| read_attr_string(param, "name"));
            if let Some(name) = name
                && !name.is_empty()
            {
                returns.push(name);
                continue;
            }
            returns.push(format!("_ret{idx}"));
        }
    }

    returns
}

fn parse_src(src: &str, source_map: &HashMap<u32, u32>) -> Option<Span> {
    let mut parts = src.split(':');
    let start: u32 = parts.next()?.parse().ok()?;
    let length: u32 = parts.next()?.parse().ok()?;
    let source_id: u32 = parts.next()?.parse().ok()?;
    let file = source_map.get(&source_id).copied().unwrap_or(0);
    Some(Span {
        file,
        start,
        end: start.saturating_add(length),
    })
}
