use chainvet_core::norm::{
    Contract, ContractBase, ContractKind, Function, FunctionKind, Item, Mutability, NormalizedAst,
    SourceFile, Span, StateVariable, Visibility,
};
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";
const DEFAULT_MODEL: &str = "qwen2.5-coder:7b";
const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_NUM_PREDICT: u32 = 1536;
const DEFAULT_MAX_SOURCE_BYTES: usize = 24_000;
const DEFAULT_CHUNK_BYTES: usize = 18_000;
const DEFAULT_MAX_CHUNKS_PER_FILE: usize = 24;
const CHUNK_OVERLAP_BYTES: usize = 900;

pub fn enrich_ast_if_enabled(ast: &mut NormalizedAst) -> bool {
    if !ai_fallback_enabled() || ast.files.is_empty() {
        return false;
    }

    let config = AiFallbackConfig::from_env();
    let files = ast.files.clone();
    let mut changed = false;
    for file in &files {
        let chunks = build_source_chunks(file, &config);
        if chunks.is_empty() {
            continue;
        }
        for chunk in chunks {
            match extract_hints(&config, file, &chunk) {
                Ok(hints) => {
                    let file_changed = merge_hints(ast, file, hints);
                    changed |= file_changed;
                }
                Err(err) => debug_log(format!(
                    "AI fallback parser skipped {} chunk {}..{}: {err}",
                    file.path, chunk.start, chunk.end
                )),
            }
        }
    }

    changed
}

fn ai_fallback_enabled() -> bool {
    matches!(
        env::var("CHAINVET_AI_FALLBACK_PARSER")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn extract_hints(
    config: &AiFallbackConfig,
    file: &SourceFile,
    chunk: &SourceChunk,
) -> std::result::Result<AiParseHints, String> {
    let prompt = parse_prompt(file, chunk);
    let response = ollama_generate(config, &prompt)?;
    let value = parse_json_object(&response)?;
    serde_json::from_value(value).map_err(|err| format!("failed to decode AI parse hints: {err}"))
}

fn parse_prompt(file: &SourceFile, chunk: &SourceChunk) -> String {
    format!(
        r#"You are Chainvet's Solidity fallback parser helper.

Task:
Extract only syntax facts from the Solidity source. Do not identify vulnerabilities. Do not invent declarations.

Return JSON only with this exact shape:
{{
  "contracts": [
    {{
      "name": "ContractName",
      "kind": "contract | interface | library",
      "start": 0,
      "end": 100,
      "bases": ["Base"],
      "state_variables": [
        {{
          "name": "owner",
          "visibility": "public | external | internal | private | unknown",
          "mutability": "pure | view | payable | nonpayable | unknown",
          "constant": false,
          "immutable": false,
          "type_string": "address",
          "start": 10,
          "end": 30
        }}
      ],
      "functions": [
        {{
          "name": "withdraw",
          "kind": "function | constructor | fallback | receive",
          "visibility": "public | external | internal | private | unknown",
          "mutability": "pure | view | payable | nonpayable | unknown",
          "params": ["amount"],
          "returns": ["ok"],
          "modifiers": ["onlyOwner"],
          "start": 40,
          "end": 90
        }}
      ]
    }}
  ]
}}

Rules:
- start/end are zero-based UTF-8 byte offsets in this exact source file.
- The source below may be a slice of the file. Return absolute offsets in the full file, not offsets relative to the slice.
- Every start/end span must cover the declaration header/body it describes.
- For constructors, fallback, and receive functions, use null for name unless the source has an explicit legacy name.
- Include modifiers in source order, without arguments.
- Include only source-backed facts visible in the file.
- If unsure, use "unknown" or an empty list.
- For partial chunks, include only declarations whose name/header is visible in the chunk.

File: {path}
Visible full-file context:
{context}

Source slice byte range: {start}..{end}

```solidity
{source}
```
"#,
        path = file.path,
        context = chunk.context,
        start = chunk.start,
        end = chunk.end,
        source = chunk.source
    )
}

fn build_source_chunks(file: &SourceFile, config: &AiFallbackConfig) -> Vec<SourceChunk> {
    if file.source.trim().is_empty() {
        return Vec::new();
    }

    let context = file_context_summary(file);
    if file.source.len() <= config.max_source_bytes {
        return vec![SourceChunk {
            start: 0,
            end: file.source.len(),
            source: file.source.clone(),
            context,
        }];
    }

    let ranges = contract_ranges(file);
    let mut chunks = Vec::new();
    if ranges.is_empty() {
        chunks.extend(window_chunks(
            file,
            &context,
            0,
            file.source.len(),
            config.chunk_bytes,
        ));
    } else {
        let header_end = ranges
            .first()
            .map(|(start, _)| *start)
            .unwrap_or(file.source.len());
        if header_end > 0 {
            chunks.extend(window_chunks(
                file,
                &context,
                0,
                header_end,
                config.chunk_bytes,
            ));
        }
        for (start, end) in ranges {
            chunks.extend(window_chunks(
                file,
                &context,
                start,
                end,
                config.chunk_bytes,
            ));
        }
    }

    chunks.truncate(config.max_chunks_per_file);
    chunks
}

fn window_chunks(
    file: &SourceFile,
    context: &str,
    start: usize,
    end: usize,
    chunk_bytes: usize,
) -> Vec<SourceChunk> {
    if start >= end {
        return Vec::new();
    }
    let chunk_bytes = chunk_bytes.max(4_000);
    if end - start <= chunk_bytes {
        return source_chunk(file, context, start, end)
            .into_iter()
            .collect();
    }

    let mut chunks = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let raw_end = (cursor + chunk_bytes).min(end);
        let chunk_start = if cursor == start {
            cursor
        } else {
            cursor.saturating_sub(CHUNK_OVERLAP_BYTES)
        };
        let chunk_end = if raw_end >= end {
            end
        } else {
            expand_to_next_boundary(file.source.as_str(), raw_end, end)
        };
        if let Some(chunk) = source_chunk(file, context, chunk_start, chunk_end) {
            chunks.push(chunk);
        }
        if raw_end >= end {
            break;
        }
        cursor = raw_end;
    }
    chunks
}

fn source_chunk(file: &SourceFile, context: &str, start: usize, end: usize) -> Option<SourceChunk> {
    let start = floor_char_boundary(file.source.as_str(), start.min(file.source.len()));
    let end = ceil_char_boundary(file.source.as_str(), end.min(file.source.len()));
    if start >= end {
        return None;
    }
    let source = file.source.get(start..end)?.to_string();
    Some(SourceChunk {
        start,
        end,
        source,
        context: context.to_string(),
    })
}

fn contract_ranges(file: &SourceFile) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let bytes = file.source.as_bytes();
    let mut search_from = 0usize;
    while search_from < file.source.len() {
        let Some((keyword_start, keyword_len)) =
            find_next_contract_keyword(file.source.as_str(), search_from)
        else {
            break;
        };
        let Some(open_brace) = file.source[keyword_start + keyword_len..].find('{') else {
            search_from = keyword_start + keyword_len;
            continue;
        };
        let open_brace = keyword_start + keyword_len + open_brace;
        let end = find_matching_brace_byte(bytes, open_brace).unwrap_or_else(|| {
            find_next_contract_keyword(file.source.as_str(), open_brace + 1)
                .map(|(next, _)| next)
                .unwrap_or(file.source.len())
        });
        ranges.push((keyword_start, end.min(file.source.len())));
        search_from = end.max(open_brace + 1);
    }
    ranges
}

fn find_next_contract_keyword(source: &str, from: usize) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    for keyword in ["contract ", "interface ", "library "] {
        if let Some(relative) = source.get(from..)?.find(keyword) {
            let offset = from + relative;
            if best
                .map(|(best_offset, _)| offset < best_offset)
                .unwrap_or(true)
            {
                best = Some((offset, keyword.len()));
            }
        }
    }
    best
}

fn find_matching_brace_byte(bytes: &[u8], open_idx: usize) -> Option<usize> {
    if bytes.get(open_idx) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut idx = open_idx;
    while idx < bytes.len() {
        match bytes[idx] {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

fn expand_to_next_boundary(source: &str, offset: usize, limit: usize) -> usize {
    let mut end = offset.min(limit).min(source.len());
    let search_limit = (end + 2_000).min(limit).min(source.len());
    while end < search_limit {
        if source.as_bytes().get(end) == Some(&b'\n') {
            return end + 1;
        }
        end += 1;
    }
    ceil_char_boundary(source, offset.min(source.len()))
}

fn floor_char_boundary(source: &str, mut offset: usize) -> usize {
    offset = offset.min(source.len());
    while offset > 0 && !source.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

fn ceil_char_boundary(source: &str, mut offset: usize) -> usize {
    offset = offset.min(source.len());
    while offset < source.len() && !source.is_char_boundary(offset) {
        offset += 1;
    }
    offset
}

fn file_context_summary(file: &SourceFile) -> String {
    let mut lines = Vec::new();
    for raw_line in file.source.lines() {
        let line = raw_line.trim();
        if line.starts_with("pragma ")
            || line.starts_with("import ")
            || line.starts_with("using ")
            || line.starts_with("struct ")
            || line.starts_with("enum ")
            || line.starts_with("event ")
            || line.starts_with("error ")
            || line.starts_with("contract ")
            || line.starts_with("interface ")
            || line.starts_with("library ")
            || line.starts_with("modifier ")
        {
            lines.push(line.to_string());
        }
        if lines.len() >= 80 {
            break;
        }
    }
    if lines.is_empty() {
        "No compact context available.".to_string()
    } else {
        lines.join("\n")
    }
}

fn merge_hints(ast: &mut NormalizedAst, file: &SourceFile, hints: AiParseHints) -> bool {
    let mut changed = false;
    for contract_hint in hints.contracts {
        let Some(contract_span) = valid_span(file, contract_hint.start, contract_hint.end) else {
            continue;
        };
        if !source_span_mentions(file, contract_span, contract_hint.name.as_str()) {
            continue;
        }

        let contract_id = match find_contract(ast, file.id, contract_hint.name.as_str()) {
            Some(contract_id) => {
                if let Some(contract) = ast.contracts.get_mut(contract_id as usize) {
                    let kind = parse_contract_kind(contract_hint.kind.as_deref());
                    if kind != ContractKind::Unknown && contract.kind != kind {
                        contract.kind = kind;
                        changed = true;
                    }
                    let bases = normalized_bases(&contract_hint.bases);
                    if !bases.is_empty() && contract.bases.is_empty() {
                        contract.bases = bases;
                        changed = true;
                    }
                }
                contract_id
            }
            None => {
                if !source_span_has_contract_keyword(file, contract_span) {
                    continue;
                }
                let id = ast.contracts.len() as u32;
                ast.contracts.push(Contract {
                    id,
                    name: contract_hint.name.clone(),
                    kind: parse_contract_kind(contract_hint.kind.as_deref()),
                    bases: normalized_bases(&contract_hint.bases),
                    functions: Vec::new(),
                    state_vars: Vec::new(),
                    modifiers: Vec::new(),
                    events: Vec::new(),
                    errors: Vec::new(),
                    span: contract_span,
                });
                ast.items.push(Item::Contract(id));
                changed = true;
                id
            }
        };

        for state_hint in contract_hint.state_variables {
            if merge_state_var_hint(ast, file, contract_id, state_hint) {
                changed = true;
            }
        }

        for function_hint in contract_hint.functions {
            if merge_function_hint(ast, file, contract_id, function_hint) {
                changed = true;
            }
        }
    }
    changed
}

fn merge_state_var_hint(
    ast: &mut NormalizedAst,
    file: &SourceFile,
    contract_id: u32,
    hint: AiStateVariableHint,
) -> bool {
    let Some(span) = valid_span(file, hint.start, hint.end) else {
        return false;
    };
    if !source_span_mentions(file, span, hint.name.as_str())
        || source_span_has_function_keyword(file, span)
    {
        return false;
    }

    let visibility = parse_visibility(hint.visibility.as_deref());
    let mutability = parse_mutability(hint.mutability.as_deref());
    let type_string = hint.type_string.filter(|value| !value.trim().is_empty());

    if let Some(var_id) = find_state_var(ast, contract_id, hint.name.as_str()) {
        let Some(var) = ast.state_vars.get_mut(var_id as usize) else {
            return false;
        };
        let mut changed = false;
        if visibility != Visibility::Unknown && var.visibility != visibility {
            var.visibility = visibility;
            changed = true;
        }
        if mutability != Mutability::Unknown && var.mutability != mutability {
            var.mutability = mutability;
            changed = true;
        }
        if hint.constant.unwrap_or(false) && !var.constant {
            var.constant = true;
            changed = true;
        }
        if hint.immutable.unwrap_or(false) && !var.immutable {
            var.immutable = true;
            changed = true;
        }
        if type_string.is_some() && var.type_string.is_none() {
            var.type_string = type_string;
            changed = true;
        }
        return changed;
    }

    let id = ast.state_vars.len() as u32;
    ast.state_vars.push(StateVariable {
        id,
        contract: contract_id,
        name: hint.name,
        visibility,
        mutability,
        constant: hint.constant.unwrap_or(false),
        immutable: hint.immutable.unwrap_or(false),
        type_string,
        span,
    });
    ast.items.push(Item::StateVar(id));
    if let Some(contract) = ast.contracts.get_mut(contract_id as usize) {
        contract.state_vars.push(id);
    }
    true
}

fn merge_function_hint(
    ast: &mut NormalizedAst,
    file: &SourceFile,
    contract_id: u32,
    hint: AiFunctionHint,
) -> bool {
    let Some(span) = valid_span(file, hint.start, hint.end) else {
        return false;
    };
    let kind = parse_function_kind(hint.kind.as_deref(), hint.name.as_deref());
    if !source_span_has_function_like_keyword(file, span, kind) {
        return false;
    }
    if let Some(name) = hint.name.as_deref()
        && !name.is_empty()
        && !source_span_mentions(file, span, name)
    {
        return false;
    }

    let visibility = parse_visibility(hint.visibility.as_deref());
    let mutability = parse_mutability(hint.mutability.as_deref());
    let params = clean_names(hint.params);
    let returns = clean_names(hint.returns);
    let modifiers = clean_names(hint.modifiers);

    if let Some(function_id) = find_function(ast, contract_id, hint.name.as_deref(), kind, span) {
        let Some(function) = ast.functions.get_mut(function_id as usize) else {
            return false;
        };
        let mut changed = false;
        if kind != FunctionKind::Unknown && function.kind != kind {
            function.kind = kind;
            changed = true;
        }
        if visibility != Visibility::Unknown && function.visibility != visibility {
            function.visibility = visibility;
            changed = true;
        }
        if mutability != Mutability::Unknown && function.mutability != mutability {
            function.mutability = mutability;
            changed = true;
        }
        if !params.is_empty() && function.params != params {
            function.params = params;
            changed = true;
        }
        if !returns.is_empty() && function.returns != returns {
            function.returns = returns;
            changed = true;
        }
        if !modifiers.is_empty() && function.modifiers != modifiers {
            function.modifiers = modifiers;
            changed = true;
        }
        return changed;
    }

    let id = ast.functions.len() as u32;
    ast.functions.push(Function {
        id,
        contract: Some(contract_id),
        name: hint.name.filter(|value| !value.trim().is_empty()),
        kind,
        visibility,
        mutability,
        params,
        returns,
        modifiers,
        body: None,
        span,
    });
    ast.items.push(Item::Function(id));
    if let Some(contract) = ast.contracts.get_mut(contract_id as usize) {
        contract.functions.push(id);
    }
    true
}

fn valid_span(file: &SourceFile, start: Option<u32>, end: Option<u32>) -> Option<Span> {
    let start = start?;
    let end = end?;
    if start >= end || end as usize > file.source.len() {
        return None;
    }
    Some(Span {
        file: file.id,
        start,
        end,
    })
}

fn source_span(file: &SourceFile, span: Span) -> Option<&str> {
    if span.file != file.id {
        return None;
    }
    file.source.get(span.start as usize..span.end as usize)
}

fn source_span_mentions(file: &SourceFile, span: Span, token: &str) -> bool {
    if token.trim().is_empty() {
        return true;
    }
    source_span(file, span)
        .map(|source| source.contains(token))
        .unwrap_or(false)
}

fn source_span_has_contract_keyword(file: &SourceFile, span: Span) -> bool {
    source_span(file, span)
        .map(|source| {
            source.contains("contract ")
                || source.contains("interface ")
                || source.contains("library ")
        })
        .unwrap_or(false)
}

fn source_span_has_function_keyword(file: &SourceFile, span: Span) -> bool {
    source_span(file, span)
        .map(|source| {
            source.contains("function ")
                || source.contains("constructor")
                || source.contains("fallback")
                || source.contains("receive")
        })
        .unwrap_or(false)
}

fn source_span_has_function_like_keyword(
    file: &SourceFile,
    span: Span,
    kind: FunctionKind,
) -> bool {
    source_span(file, span)
        .map(|source| match kind {
            FunctionKind::Constructor => {
                source.contains("constructor") || source.contains("function ")
            }
            FunctionKind::Fallback => {
                source.contains("fallback")
                    || source.contains("function(")
                    || source.contains("function (")
            }
            FunctionKind::Receive => source.contains("receive"),
            FunctionKind::Function | FunctionKind::Unknown => source.contains("function "),
        })
        .unwrap_or(false)
}

fn find_contract(ast: &NormalizedAst, file_id: u32, name: &str) -> Option<u32> {
    ast.contracts
        .iter()
        .find(|contract| contract.span.file == file_id && contract.name == name)
        .map(|contract| contract.id)
}

fn find_state_var(ast: &NormalizedAst, contract_id: u32, name: &str) -> Option<u32> {
    ast.state_vars
        .iter()
        .find(|var| var.contract == contract_id && var.name == name)
        .map(|var| var.id)
}

fn find_function(
    ast: &NormalizedAst,
    contract_id: u32,
    name: Option<&str>,
    kind: FunctionKind,
    span: Span,
) -> Option<u32> {
    ast.functions
        .iter()
        .find(|function| {
            function.contract == Some(contract_id)
                && function.span.file == span.file
                && function_name_matches(function.name.as_deref(), name)
                && (kind == FunctionKind::Unknown
                    || function.kind == kind
                    || spans_overlap(function.span, span))
        })
        .or_else(|| {
            ast.functions.iter().find(|function| {
                function.contract == Some(contract_id)
                    && function.span.file == span.file
                    && spans_overlap(function.span, span)
            })
        })
        .map(|function| function.id)
}

fn function_name_matches(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        (None, None) => true,
        (_, Some("")) => true,
        _ => false,
    }
}

fn spans_overlap(left: Span, right: Span) -> bool {
    left.file == right.file && left.start < right.end && right.start < left.end
}

fn parse_contract_kind(value: Option<&str>) -> ContractKind {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "contract" => ContractKind::Contract,
        "interface" => ContractKind::Interface,
        "library" => ContractKind::Library,
        _ => ContractKind::Unknown,
    }
}

fn parse_function_kind(value: Option<&str>, name: Option<&str>) -> FunctionKind {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "constructor" => FunctionKind::Constructor,
        "fallback" => FunctionKind::Fallback,
        "receive" => FunctionKind::Receive,
        "function" => FunctionKind::Function,
        _ => match name {
            Some("constructor") => FunctionKind::Constructor,
            Some("fallback") => FunctionKind::Fallback,
            Some("receive") => FunctionKind::Receive,
            Some(_) => FunctionKind::Function,
            None => FunctionKind::Unknown,
        },
    }
}

fn parse_visibility(value: Option<&str>) -> Visibility {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "public" => Visibility::Public,
        "external" => Visibility::External,
        "internal" => Visibility::Internal,
        "private" => Visibility::Private,
        _ => Visibility::Unknown,
    }
}

fn parse_mutability(value: Option<&str>) -> Mutability {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "pure" => Mutability::Pure,
        "view" | "constant" => Mutability::View,
        "payable" => Mutability::Payable,
        "nonpayable" | "non-payable" => Mutability::NonPayable,
        _ => Mutability::Unknown,
    }
}

fn normalized_bases(values: &[String]) -> Vec<ContractBase> {
    clean_names(values.to_vec())
        .into_iter()
        .map(|name| ContractBase { name })
        .collect()
}

fn clean_names(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && value != "null" && is_safe_identifier(value))
        .collect()
}

fn is_safe_identifier(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
}

fn ollama_generate(config: &AiFallbackConfig, prompt: &str) -> std::result::Result<String, String> {
    let oc = chainvet_ai::ollama::OllamaConfig {
        endpoint: config.endpoint.clone(),
        model: config.model.clone(),
        timeout: config.timeout,
        num_predict: config.num_predict,
    };
    chainvet_ai::ollama::generate(&oc, prompt)
}

fn parse_json_object(raw: &str) -> std::result::Result<Value, String> {
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        return Ok(value);
    }
    let start = raw
        .find('{')
        .ok_or_else(|| "AI response had no JSON object".to_string())?;
    let end = raw
        .rfind('}')
        .ok_or_else(|| "AI response had no JSON object end".to_string())?;
    serde_json::from_str(&raw[start..=end])
        .map_err(|err| format!("failed to parse AI JSON response: {err}"))
}

fn debug_log(message: String) {
    if env::var("CHAINVET_AI_FALLBACK_DEBUG").ok().as_deref() == Some("1")
        || env::var("CHAINVET_AI_DEBUG").ok().as_deref() == Some("1")
    {
        eprintln!("{message}");
    }
}

struct AiFallbackConfig {
    endpoint: String,
    model: String,
    timeout: Duration,
    num_predict: u32,
    max_source_bytes: usize,
    chunk_bytes: usize,
    max_chunks_per_file: usize,
}

impl AiFallbackConfig {
    fn from_env() -> Self {
        let endpoint =
            env::var("CHAINVET_AI_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        let model = env::var("CHAINVET_AI_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
        let timeout_ms = env::var("CHAINVET_AI_FALLBACK_TIMEOUT_MS")
            .or_else(|_| env::var("CHAINVET_AI_TIMEOUT_MS"))
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        let num_predict = env::var("CHAINVET_AI_FALLBACK_NUM_PREDICT")
            .or_else(|_| env::var("CHAINVET_AI_NUM_PREDICT"))
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(DEFAULT_NUM_PREDICT);
        let max_source_bytes = env::var("CHAINVET_AI_FALLBACK_MAX_SOURCE_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_SOURCE_BYTES);
        let chunk_bytes = env::var("CHAINVET_AI_FALLBACK_CHUNK_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_CHUNK_BYTES);
        let max_chunks_per_file = env::var("CHAINVET_AI_FALLBACK_MAX_CHUNKS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_CHUNKS_PER_FILE);
        Self {
            endpoint,
            model,
            timeout: Duration::from_millis(timeout_ms),
            num_predict,
            max_source_bytes,
            chunk_bytes,
            max_chunks_per_file,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AiParseHints {
    #[serde(default)]
    contracts: Vec<AiContractHint>,
}

#[derive(Debug, Deserialize)]
struct AiContractHint {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    start: Option<u32>,
    #[serde(default)]
    end: Option<u32>,
    #[serde(default)]
    bases: Vec<String>,
    #[serde(default)]
    state_variables: Vec<AiStateVariableHint>,
    #[serde(default)]
    functions: Vec<AiFunctionHint>,
}

#[derive(Debug, Deserialize)]
struct AiStateVariableHint {
    name: String,
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    mutability: Option<String>,
    #[serde(default)]
    constant: Option<bool>,
    #[serde(default)]
    immutable: Option<bool>,
    #[serde(default)]
    type_string: Option<String>,
    #[serde(default)]
    start: Option<u32>,
    #[serde(default)]
    end: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AiFunctionHint {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    mutability: Option<String>,
    #[serde(default)]
    params: Vec<String>,
    #[serde(default)]
    returns: Vec<String>,
    #[serde(default)]
    modifiers: Vec<String>,
    #[serde(default)]
    start: Option<u32>,
    #[serde(default)]
    end: Option<u32>,
}

struct SourceChunk {
    start: usize,
    end: usize,
    source: String,
    context: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_core::norm::{ContractKind, FunctionKind, Mutability, SourceFile, Visibility};

    fn source_file(source: &str) -> SourceFile {
        SourceFile {
            id: 0,
            path: "Test.sol".to_string(),
            source: source.to_string(),
        }
    }

    fn test_config(max_source_bytes: usize, chunk_bytes: usize) -> AiFallbackConfig {
        AiFallbackConfig {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            model: DEFAULT_MODEL.to_string(),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            num_predict: DEFAULT_NUM_PREDICT,
            max_source_bytes,
            chunk_bytes,
            max_chunks_per_file: DEFAULT_MAX_CHUNKS_PER_FILE,
        }
    }

    #[test]
    fn large_files_are_chunked_by_contract_ranges() {
        let mut source = String::new();
        source.push_str("pragma solidity ^0.8.0;\n");
        for idx in 0..6 {
            source.push_str(&format!(
                "contract C{idx} {{\n    uint256 public value{idx};\n    function f{idx}(uint256 amount) public {{ value{idx} = amount; }}\n}}\n"
            ));
        }
        let file = source_file(&source);
        let chunks = build_source_chunks(&file, &test_config(120, 120));

        assert!(
            chunks.len() > 1,
            "expected multiple chunks for large source"
        );
        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.source.contains("contract C0")),
            "first contract should be visible in a chunk"
        );
        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.source.contains("contract C5")),
            "last contract should be visible in a chunk"
        );
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.start < chunk.end && chunk.end <= source.len()),
            "chunks must use valid absolute byte ranges"
        );
    }

    #[test]
    fn merge_hints_enriches_existing_function_metadata() {
        let source = r#"
contract Vault {
    address public owner;
    modifier onlyOwner() { _; }
    function withdraw(uint256 amount) public payable onlyOwner returns (bool ok) {
        return true;
    }
}
"#;
        let file = source_file(source);
        let mut ast = crate::frontend::parser::load_via_parser_sources(vec![file.clone()])
            .expect("fallback parser should parse fixture");
        let contract_start = source.find("contract Vault").unwrap() as u32;
        let contract_end = source.rfind('}').unwrap() as u32 + 1;
        let owner_start = source.find("address public owner").unwrap() as u32;
        let owner_end = source[owner_start as usize..].find(';').unwrap() as u32 + owner_start + 1;
        let withdraw_start = source.find("function withdraw").unwrap() as u32;
        let withdraw_end =
            source[withdraw_start as usize..].find('}').unwrap() as u32 + withdraw_start + 1;

        let hints = AiParseHints {
            contracts: vec![AiContractHint {
                name: "Vault".to_string(),
                kind: Some("contract".to_string()),
                start: Some(contract_start),
                end: Some(contract_end),
                bases: Vec::new(),
                state_variables: vec![AiStateVariableHint {
                    name: "owner".to_string(),
                    visibility: Some("public".to_string()),
                    mutability: Some("unknown".to_string()),
                    constant: Some(false),
                    immutable: Some(false),
                    type_string: Some("address".to_string()),
                    start: Some(owner_start),
                    end: Some(owner_end),
                }],
                functions: vec![AiFunctionHint {
                    name: Some("withdraw".to_string()),
                    kind: Some("function".to_string()),
                    visibility: Some("public".to_string()),
                    mutability: Some("payable".to_string()),
                    params: vec!["amount".to_string()],
                    returns: vec!["ok".to_string()],
                    modifiers: vec!["onlyOwner".to_string()],
                    start: Some(withdraw_start),
                    end: Some(withdraw_end),
                }],
            }],
        };

        assert!(merge_hints(&mut ast, &file, hints));
        let function = ast
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("withdraw"))
            .expect("withdraw should exist");
        assert_eq!(function.kind, FunctionKind::Function);
        assert_eq!(function.visibility, Visibility::Public);
        assert_eq!(function.mutability, Mutability::Payable);
        assert_eq!(function.params, vec!["amount"]);
        assert_eq!(function.returns, vec!["ok"]);
        assert_eq!(function.modifiers, vec!["onlyOwner"]);

        let owner = ast
            .state_vars
            .iter()
            .find(|var| var.name == "owner")
            .expect("owner state var should exist");
        assert_eq!(owner.visibility, Visibility::Public);
        assert_eq!(owner.type_string.as_deref(), Some("address"));
    }

    #[test]
    fn merge_hints_rejects_source_unbacked_declarations() {
        let source = "contract Vault { function withdraw() public {} }";
        let file = source_file(source);
        let mut ast = crate::frontend::parser::load_via_parser_sources(vec![file.clone()])
            .expect("fallback parser should parse fixture");
        let before_functions = ast.functions.len();
        let before_contracts = ast.contracts.len();

        let hints = AiParseHints {
            contracts: vec![AiContractHint {
                name: "Invented".to_string(),
                kind: Some("contract".to_string()),
                start: Some(0),
                end: Some(source.len() as u32),
                bases: Vec::new(),
                state_variables: Vec::new(),
                functions: vec![AiFunctionHint {
                    name: Some("drain".to_string()),
                    kind: Some("function".to_string()),
                    visibility: Some("public".to_string()),
                    mutability: Some("payable".to_string()),
                    params: Vec::new(),
                    returns: Vec::new(),
                    modifiers: Vec::new(),
                    start: Some(0),
                    end: Some(source.len() as u32),
                }],
            }],
        };

        assert!(!merge_hints(&mut ast, &file, hints));
        assert_eq!(ast.contracts.len(), before_contracts);
        assert_eq!(ast.functions.len(), before_functions);
        assert_eq!(ast.contracts[0].kind, ContractKind::Contract);
    }
}
