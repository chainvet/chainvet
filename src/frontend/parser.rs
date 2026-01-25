use crate::norm::{
    CallMeta, CallOption, CallTarget, ChainSegment, Contract, ContractKind, Expr, ExprKind,
    ExprMeta, Function, FunctionKind, Item, Mutability, NormalizedAst, SourceFile, Span, Stmt,
    StmtKind, Visibility,
};
use crate::util::error::{Error, Result};
use tree_sitter::{Node, Parser};
use tree_sitter_solidity as ts_solidity;

#[derive(Debug, Clone)]
enum TokenKind {
    Ident,
    Number,
    Keyword,
    Symbol,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    text: String,
    start: u32,
    end: u32,
}

impl Token {
    fn is_ident(&self) -> bool {
        matches!(self.kind, TokenKind::Ident)
    }

    fn is_number(&self) -> bool {
        matches!(self.kind, TokenKind::Number)
    }

    fn is_keyword(&self, value: &str) -> bool {
        matches!(self.kind, TokenKind::Keyword) && self.text == value
    }

    fn is_symbol(&self, value: char) -> bool {
        matches!(self.kind, TokenKind::Symbol) && self.text == value.to_string()
    }
}

struct ContractRange {
    body_start: usize,
    body_end: usize,
}

pub fn load_via_parser(path: &str) -> Result<NormalizedAst> {
    let sources = crate::frontend::load_sources(path)?;
    if sources.is_empty() {
        return Err(Error::msg("no Solidity files found"));
    }

    let mut ast = NormalizedAst::from_sources(sources);
    let files = ast.files.clone();
    for file in &files {
        if !parse_file_tree_sitter(file, &mut ast) {
            parse_file_legacy(file, &mut ast);
        }
    }

    Ok(ast)
}

fn parse_file_tree_sitter(file: &SourceFile, ast: &mut NormalizedAst) -> bool {
    let mut parser = Parser::new();
    let language = solidity_language();
    if parser.set_language(&language).is_err() {
        return false;
    }
    let tree = match parser.parse(&file.source, None) {
        Some(tree) => tree,
        None => return false,
    };
    let root = tree.root_node();
    let mut ctx = TsContext {
        file_id: file.id,
        source: file.source.as_bytes(),
        ast,
        parsed_any: false,
    };
    walk_ts_node(root, None, &mut ctx);
    ctx.parsed_any
}

fn parse_file_legacy(file: &SourceFile, ast: &mut NormalizedAst) {
    let tokens = tokenize(&file.source);
    if tokens.is_empty() {
        return;
    }

    let mut ranges = Vec::new();
    let mut idx = 0;
    while idx < tokens.len() {
        if let Some(kind) = contract_kind(&tokens[idx]) {
            let Some(name_idx) = next_ident(&tokens, idx + 1) else {
                idx += 1;
                continue;
            };
            let name = tokens[name_idx].text.clone();
            let Some(open_idx) = find_symbol(&tokens, name_idx + 1, '{') else {
                idx = name_idx + 1;
                continue;
            };
            let close_idx = find_matching_brace(&tokens, open_idx).unwrap_or(open_idx);
            let span = span_for(
                file.id,
                tokens[idx].start,
                tokens[close_idx].end,
            );
            let contract_id = push_contract(ast, name, kind, span);
            parse_functions_in_range(
                &tokens,
                file.id,
                open_idx + 1,
                close_idx,
                ast,
                Some(contract_id),
            );
            ranges.push(ContractRange {
                body_start: open_idx,
                body_end: close_idx,
            });
            idx = close_idx + 1;
            continue;
        }
        idx += 1;
    }

    parse_top_level_functions(&tokens, file.id, ast, &ranges);
}

struct TsContext<'a> {
    file_id: u32,
    source: &'a [u8],
    ast: &'a mut NormalizedAst,
    parsed_any: bool,
}

fn solidity_language() -> tree_sitter::Language {
    let func = ts_solidity::LANGUAGE.into_raw();
    let ptr = unsafe { func() };
    // tree-sitter 0.22 lacks LanguageFn conversions; cast raw pointer into Language.
    unsafe { std::mem::transmute::<*const (), tree_sitter::Language>(ptr) }
}

fn walk_ts_node(node: Node, contract_id: Option<u32>, ctx: &mut TsContext) {
    let kind = node.kind();
    if is_ts_contract_definition(kind) {
        let new_contract = parse_ts_contract(node, ctx);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_ts_node(child, Some(new_contract), ctx);
        }
        return;
    }
    if is_ts_function_definition(kind) {
        parse_ts_function(node, contract_id, ctx);
        return;
    }
    if is_ts_state_var_definition(kind) {
        parse_ts_state_var(node, contract_id, ctx);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_ts_node(child, contract_id, ctx);
    }
}

fn is_ts_contract_definition(kind: &str) -> bool {
    matches!(kind, "contract_definition" | "interface_definition" | "library_definition")
}

fn is_ts_function_definition(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition"
            | "constructor_definition"
            | "fallback_function"
            | "receive_function"
            | "fallback_definition"
            | "receive_definition"
    )
}

fn is_ts_state_var_definition(kind: &str) -> bool {
    matches!(kind, "state_variable_declaration")
}

fn parse_ts_contract(node: Node, ctx: &mut TsContext) -> u32 {
    let id = ctx.ast.contracts.len() as u32;
    let name = find_ts_name(node, ctx.source).unwrap_or_else(|| "<unknown>".to_string());
    let kind = contract_kind_from_text(node, ctx.source);
    let span = span_from_node(node, ctx.file_id);
    ctx.ast.contracts.push(Contract {
        id,
        name,
        kind,
        bases: Vec::new(),
        functions: Vec::new(),
        state_vars: Vec::new(),
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
        span,
    });
    ctx.ast.items.push(Item::Contract(id));
    ctx.parsed_any = true;
    id
}

fn contract_kind_from_text(node: Node, source: &[u8]) -> ContractKind {
    let Ok(text) = node.utf8_text(source) else {
        return ContractKind::Unknown;
    };
    if text.contains("interface ") {
        ContractKind::Interface
    } else if text.contains("library ") {
        ContractKind::Library
    } else {
        ContractKind::Contract
    }
}

fn parse_ts_state_var(node: Node, contract_id: Option<u32>, ctx: &mut TsContext) {
    let Some(contract_id) = contract_id else {
        return;
    };
    let name = find_ts_name(node, ctx.source).unwrap_or_else(|| "<unknown>".to_string());
    let span = span_from_node(node, ctx.file_id);
    let id = ctx.ast.state_vars.len() as u32;
    ctx.ast.state_vars.push(crate::norm::StateVariable {
        id,
        contract: contract_id,
        name,
        visibility: Visibility::Unknown,
        mutability: Mutability::Unknown,
        constant: false,
        immutable: false,
        type_string: None,
        span,
    });
    ctx.ast.items.push(Item::StateVar(id));
    if let Some(contract) = ctx.ast.contracts.get_mut(contract_id as usize) {
        contract.state_vars.push(id);
    }
    ctx.parsed_any = true;
}

fn parse_ts_function(node: Node, contract_id: Option<u32>, ctx: &mut TsContext) {
    let name = find_ts_name(node, ctx.source);
    let kind = function_kind_from_node(node, name.as_deref());
    let (visibility, mutability) = parse_visibility_mutability_text(node, ctx.source);
    let params = parse_ts_param_list(node, ctx);
    let returns = parse_ts_return_list(node, ctx);
    let body = find_ts_body(node).map(|body| parse_ts_block(body, ctx));
    let span = span_from_node(node, ctx.file_id);
    let id = ctx.ast.functions.len() as u32;
    ctx.ast.functions.push(Function {
        id,
        contract: contract_id,
        name,
        kind,
        visibility,
        mutability,
        params,
        returns,
        modifiers: Vec::new(),
        body,
        span,
    });
    ctx.ast.items.push(Item::Function(id));
    if let Some(contract_id) = contract_id {
        if let Some(contract) = ctx.ast.contracts.get_mut(contract_id as usize) {
            contract.functions.push(id);
        }
    }
    ctx.parsed_any = true;
}

fn function_kind_from_node(node: Node, name: Option<&str>) -> FunctionKind {
    match node.kind() {
        "constructor_definition" => FunctionKind::Constructor,
        "fallback_function" | "fallback_definition" => FunctionKind::Fallback,
        "receive_function" | "receive_definition" => FunctionKind::Receive,
        _ => match name {
            Some("constructor") => FunctionKind::Constructor,
            Some("fallback") => FunctionKind::Fallback,
            Some("receive") => FunctionKind::Receive,
            _ => FunctionKind::Function,
        },
    }
}

fn parse_visibility_mutability_text(node: Node, source: &[u8]) -> (Visibility, Mutability) {
    let Ok(text) = node.utf8_text(source) else {
        return (Visibility::Unknown, Mutability::Unknown);
    };
    let visibility = if text.contains(" public ") {
        Visibility::Public
    } else if text.contains(" external ") {
        Visibility::External
    } else if text.contains(" internal ") {
        Visibility::Internal
    } else if text.contains(" private ") {
        Visibility::Private
    } else {
        Visibility::Unknown
    };
    let mutability = if text.contains(" pure ") {
        Mutability::Pure
    } else if text.contains(" view ") {
        Mutability::View
    } else if text.contains(" payable ") {
        Mutability::Payable
    } else {
        Mutability::Unknown
    };
    (visibility, mutability)
}

fn parse_ts_param_list(node: Node, ctx: &mut TsContext) -> Vec<String> {
    let mut params = Vec::new();
    let Some(param_list) = find_ts_param_list(node) else {
        return params;
    };
    let mut cursor = param_list.walk();
    for child in param_list.named_children(&mut cursor) {
        if child.kind().contains("parameter") {
            if let Some(name) = find_ts_param_name(child, ctx.source) {
                if !name.is_empty() {
                    params.push(name);
                }
            }
        }
    }
    params
}

fn parse_ts_return_list(node: Node, ctx: &mut TsContext) -> Vec<String> {
    let mut returns = Vec::new();
    let Some(param_list) = find_ts_return_param_list(node) else {
        return returns;
    };
    let mut cursor = param_list.walk();
    let mut idx = 0usize;
    for child in param_list.named_children(&mut cursor) {
        if child.kind().contains("parameter") {
            let name = find_ts_param_name(child, ctx.source);
            if let Some(name) = name {
                if !name.is_empty() {
                    returns.push(name);
                    idx += 1;
                    continue;
                }
            }
            returns.push(format!("_ret{idx}"));
            idx += 1;
        }
    }
    returns
}

fn find_ts_param_list(node: Node) -> Option<Node> {
    node.child_by_field_name("parameters")
        .or_else(|| find_named_child(node, "parameter_list"))
}

fn find_ts_return_param_list(node: Node) -> Option<Node> {
    if let Some(ret) = node.child_by_field_name("return_type") {
        if let Some(list) = find_ts_param_list(ret) {
            return Some(list);
        }
        if let Some(inner) = find_named_child(ret, "return_type_definition") {
            if let Some(list) = find_ts_param_list(inner) {
                return Some(list);
            }
        }
    }
    if let Some(inner) = find_named_child(node, "return_type_definition") {
        if let Some(list) = find_ts_param_list(inner) {
            return Some(list);
        }
    }
    None
}

fn find_ts_body(node: Node) -> Option<Node> {
    node.child_by_field_name("body")
        .or_else(|| find_named_child(node, "block"))
}

fn parse_ts_block(node: Node, ctx: &mut TsContext) -> u32 {
    let mut statements = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(stmt_id) = parse_ts_statement(child, ctx) {
            statements.push(stmt_id);
        }
    }
    let span = span_from_node(node, ctx.file_id);
    push_stmt(ctx.ast, StmtKind::Block(statements), span)
}

fn parse_ts_statement(node: Node, ctx: &mut TsContext) -> Option<u32> {
    let span = span_from_node(node, ctx.file_id);
    match node.kind() {
        "block" => Some(parse_ts_block(node, ctx)),
        "expression_statement" => {
            let expr = first_ts_expr_child(node).map(|expr| parse_ts_expr(expr, ctx));
            let expr_id = expr.unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span)));
            Some(push_stmt(ctx.ast, StmtKind::Expr(expr_id), span))
        }
        "return_statement" => {
            let expr = first_ts_expr_child(node).map(|expr| parse_ts_expr(expr, ctx));
            Some(push_stmt(ctx.ast, StmtKind::Return(expr), span))
        }
        "emit_statement" => {
            let expr = first_ts_expr_child(node).map(|expr| parse_ts_expr(expr, ctx));
            let expr_id = expr.unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span)));
            Some(push_stmt(ctx.ast, StmtKind::Emit(expr_id), span))
        }
        "revert_statement" => {
            let expr = first_ts_expr_child(node).map(|expr| parse_ts_expr(expr, ctx));
            Some(push_stmt(ctx.ast, StmtKind::Revert(expr), span))
        }
        "if_statement" => parse_ts_if(node, ctx),
        "while_statement" => parse_ts_while(node, ctx),
        "do_while_statement" => parse_ts_do_while(node, ctx),
        "for_statement" => parse_ts_for(node, ctx),
        "break_statement" => Some(push_stmt(ctx.ast, StmtKind::Break, span)),
        "continue_statement" => Some(push_stmt(ctx.ast, StmtKind::Continue, span)),
        "variable_declaration_statement" => parse_ts_var_decl(node, ctx),
        "try_statement" => parse_ts_try(node, ctx),
        "inline_assembly_statement" => Some(push_stmt(
            ctx.ast,
            StmtKind::InlineAsm { language: None },
            span,
        )),
        _ => None,
    }
}

fn parse_ts_if(node: Node, ctx: &mut TsContext) -> Option<u32> {
    let span = span_from_node(node, ctx.file_id);
    let cond_node = node.child_by_field_name("condition").or_else(|| first_ts_expr_child(node));
    let Some(cond_node) = cond_node else {
        return None;
    };
    let cond = parse_ts_expr(cond_node, ctx);
    let then_node = node
        .child_by_field_name("consequence")
        .or_else(|| node.child_by_field_name("then"))
        .or_else(|| find_named_child(node, "block"));
    let else_node = node
        .child_by_field_name("alternative")
        .or_else(|| node.child_by_field_name("else"));
    let then_id = then_node
        .and_then(|child| parse_ts_statement(child, ctx))
        .unwrap_or_else(|| push_stmt(ctx.ast, StmtKind::Block(Vec::new()), span));
    let else_id = else_node.and_then(|child| parse_ts_statement(child, ctx));
    Some(push_stmt(
        ctx.ast,
        StmtKind::If {
            cond,
            then_id,
            else_id,
        },
        span,
    ))
}

fn parse_ts_while(node: Node, ctx: &mut TsContext) -> Option<u32> {
    let span = span_from_node(node, ctx.file_id);
    let cond = node
        .child_by_field_name("condition")
        .or_else(|| first_ts_expr_child(node))
        .map(|expr| parse_ts_expr(expr, ctx));
    let body = node
        .child_by_field_name("body")
        .or_else(|| find_named_child(node, "block"))
        .and_then(|child| parse_ts_statement(child, ctx));
    let Some(cond) = cond else { return None; };
    let Some(body) = body else { return None; };
    Some(push_stmt(ctx.ast, StmtKind::While { cond, body }, span))
}

fn parse_ts_do_while(node: Node, ctx: &mut TsContext) -> Option<u32> {
    let span = span_from_node(node, ctx.file_id);
    let cond = node
        .child_by_field_name("condition")
        .or_else(|| first_ts_expr_child(node))
        .map(|expr| parse_ts_expr(expr, ctx));
    let body = node
        .child_by_field_name("body")
        .or_else(|| find_named_child(node, "block"))
        .and_then(|child| parse_ts_statement(child, ctx));
    let Some(cond) = cond else { return None; };
    let Some(body) = body else { return None; };
    Some(push_stmt(
        ctx.ast,
        StmtKind::DoWhile { body, cond },
        span,
    ))
}

fn parse_ts_for(node: Node, ctx: &mut TsContext) -> Option<u32> {
    let span = span_from_node(node, ctx.file_id);
    let init = node
        .child_by_field_name("initialization")
        .and_then(|child| parse_ts_statement(child, ctx));
    let cond = node
        .child_by_field_name("condition")
        .and_then(|child| Some(parse_ts_expr(child, ctx)));
    let step = node
        .child_by_field_name("update")
        .and_then(|child| Some(parse_ts_expr(child, ctx)));
    let body = node
        .child_by_field_name("body")
        .or_else(|| find_named_child(node, "block"))
        .and_then(|child| parse_ts_statement(child, ctx));
    let Some(body) = body else { return None; };
    Some(push_stmt(
        ctx.ast,
        StmtKind::For {
            init,
            cond,
            step,
            body,
        },
        span,
    ))
}

fn parse_ts_try(node: Node, ctx: &mut TsContext) -> Option<u32> {
    let span = span_from_node(node, ctx.file_id);
    let call = first_ts_expr_child(node).map(|expr| parse_ts_expr(expr, ctx))?;
    let mut clauses = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind().contains("catch") {
            let body = find_named_child(child, "block")
                .and_then(|block| parse_ts_statement(block, ctx))
                .unwrap_or_else(|| push_stmt(ctx.ast, StmtKind::Block(Vec::new()), span));
            let name = find_ts_identifier(child, ctx.source);
            let params = parse_ts_param_list(child, ctx);
            clauses.push(crate::norm::TryClause {
                kind: "catch".to_string(),
                name,
                params,
                body,
            });
        }
    }
    Some(push_stmt(
        ctx.ast,
        StmtKind::Try { call, clauses },
        span,
    ))
}

fn parse_ts_var_decl(node: Node, ctx: &mut TsContext) -> Option<u32> {
    let span = span_from_node(node, ctx.file_id);
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind().contains("variable_declaration") {
            if let Some(name) = find_ts_name(child, ctx.source) {
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
    }
    if names.is_empty() {
        names = collect_ts_identifiers(node, ctx.source);
    }
    if names.is_empty() {
        return None;
    }
    let init = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| first_ts_expr_child(node))
        .map(|expr| parse_ts_expr(expr, ctx));
    Some(push_stmt(
        ctx.ast,
        StmtKind::VarDecl { names, init },
        span,
    ))
}

fn parse_ts_expr(node: Node, ctx: &mut TsContext) -> u32 {
    if let Some(literal) = literal_from_ts_node(node, ctx.source) {
        return push_expr(
            ctx.ast,
            Expr {
                kind: ExprKind::Literal(literal),
                span: span_from_node(node, ctx.file_id),
                meta: ExprMeta::default(),
            },
        );
    }

    match node.kind() {
        "identifier" => {
            let name = node_text(node, ctx.source).unwrap_or_else(|| "<unknown>".to_string());
            let chain = vec![ChainSegment::Ident(name.clone())];
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Ident(name),
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta {
                        chain: Some(chain),
                        call: None,
                    },
                },
            )
        }
        "member_expression" => {
            let base_node = node
                .child_by_field_name("expression")
                .or_else(|| node.child_by_field_name("object"))
                .or_else(|| first_ts_expr_child(node));
            let base = base_node
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let field = node
                .child_by_field_name("property")
                .or_else(|| node.child_by_field_name("name"))
                .and_then(|child| node_text(child, ctx.source))
                .or_else(|| find_ts_identifier(node, ctx.source))
                .unwrap_or_else(|| "<unknown>".to_string());
            let mut chain = chain_from_expr(ctx.ast, base);
            if let Some(chain) = chain.as_mut() {
                chain.push(ChainSegment::Member(field.clone()));
            }
            let meta = ExprMeta {
                chain: chain.clone(),
                call: None,
            };
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Member { base, field },
                    span: span_from_node(node, ctx.file_id),
                    meta,
                },
            )
        }
        "index_expression" | "index_access" => {
            let base_node = node
                .child_by_field_name("expression")
                .or_else(|| node.child_by_field_name("object"))
                .or_else(|| first_ts_expr_child(node));
            let base = base_node
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let index = node
                .child_by_field_name("index")
                .or_else(|| second_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx));
            let mut chain = chain_from_expr(ctx.ast, base);
            if let Some(chain) = chain.as_mut() {
                chain.push(ChainSegment::Index);
            }
            let meta = ExprMeta {
                chain: chain.clone(),
                call: None,
            };
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Index { base, index },
                    span: span_from_node(node, ctx.file_id),
                    meta,
                },
            )
        }
        "call_expression" => {
            let callee_node = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("callee"))
                .or_else(|| first_ts_expr_child(node));
            let callee = callee_node
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let args_node = node
                .child_by_field_name("arguments")
                .or_else(|| find_named_child(node, "argument_list"));
            let (args, options) = if let Some(args_node) = args_node {
                parse_ts_argument_list(args_node, ctx)
            } else {
                (Vec::new(), Vec::new())
            };
            let chain = chain_from_expr(ctx.ast, callee).unwrap_or_default();
            let target = call_target_from_chain(&chain);
            let mut chain_with_call = chain.clone();
            chain_with_call.push(ChainSegment::Call);
            let callee = if options.is_empty() {
                callee
            } else {
                let meta = ExprMeta {
                    chain: Some(chain.clone()),
                    call: None,
                };
                push_expr(
                    ctx.ast,
                    Expr {
                        kind: ExprKind::CallOptions {
                            callee,
                            options: options.clone(),
                        },
                        span: span_from_node(node, ctx.file_id),
                        meta,
                    },
                )
            };
            let meta = ExprMeta {
                chain: Some(chain_with_call),
                call: Some(CallMeta {
                    target,
                    chain,
                    options,
                }),
            };
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Call { callee, args },
                    span: span_from_node(node, ctx.file_id),
                    meta,
                },
            )
        }
        "assignment_expression" => {
            let lhs = node
                .child_by_field_name("left")
                .or_else(|| first_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let rhs = node
                .child_by_field_name("right")
                .or_else(|| second_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let op = node
                .child_by_field_name("operator")
                .and_then(|child| node_text(child, ctx.source))
                .unwrap_or_else(|| "=".to_string());
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Assign { op, lhs, rhs },
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta::default(),
                },
            )
        }
        "binary_expression" => {
            let lhs = node
                .child_by_field_name("left")
                .or_else(|| first_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let rhs = node
                .child_by_field_name("right")
                .or_else(|| second_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let op = node
                .child_by_field_name("operator")
                .and_then(|child| node_text(child, ctx.source))
                .unwrap_or_else(|| "?".to_string());
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Binary { op, lhs, rhs },
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta::default(),
                },
            )
        }
        "unary_expression" => {
            let expr = node
                .child_by_field_name("argument")
                .or_else(|| node.child_by_field_name("expression"))
                .or_else(|| first_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let op = node
                .child_by_field_name("operator")
                .and_then(|child| node_text(child, ctx.source))
                .unwrap_or_else(|| "?".to_string());
            let prefix = true;
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Unary { op, expr, prefix },
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta::default(),
                },
            )
        }
        "update_expression" => {
            let arg_node = node
                .child_by_field_name("argument")
                .or_else(|| first_ts_expr_child(node));
            let expr = arg_node
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let op = node
                .child_by_field_name("operator")
                .and_then(|child| node_text(child, ctx.source))
                .unwrap_or_else(|| "++".to_string());
            let prefix = node
                .child_by_field_name("operator")
                .and_then(|child| {
                    arg_node.map(|arg| child.start_byte() < arg.start_byte())
                })
                .unwrap_or(true);
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Unary { op, expr, prefix },
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta::default(),
                },
            )
        }
        "conditional_expression" | "ternary_expression" => {
            let cond = node
                .child_by_field_name("condition")
                .or_else(|| first_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let then_expr = node
                .child_by_field_name("consequence")
                .or_else(|| node.child_by_field_name("true_expression"))
                .or_else(|| second_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            let else_expr = node
                .child_by_field_name("alternative")
                .or_else(|| node.child_by_field_name("false_expression"))
                .or_else(|| third_ts_expr_child(node))
                .map(|expr| parse_ts_expr(expr, ctx))
                .unwrap_or_else(|| push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))));
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Conditional {
                        cond,
                        then_expr,
                        else_expr,
                    },
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta::default(),
                },
            )
        }
        "type_cast_expression" => {
            let type_node = find_named_child(node, "primitive_type")
                .or_else(|| find_named_child(node, "user_defined_type"))
                .or_else(|| find_named_child(node, "type_name"));
            let type_name = type_node
                .and_then(|child| node_text(child, ctx.source))
                .unwrap_or_else(|| "unknown".to_string());
            let callee_id = push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Ident(type_name.clone()),
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta {
                        chain: Some(vec![ChainSegment::Ident(type_name.clone())]),
                        call: None,
                    },
                },
            );
            let mut args = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if is_ts_expr_node(child.kind()) {
                    args.push(parse_ts_expr(child, ctx));
                }
            }
            let chain = chain_from_expr(ctx.ast, callee_id).unwrap_or_default();
            let target = call_target_from_chain(&chain);
            let mut chain_with_call = chain.clone();
            chain_with_call.push(ChainSegment::Call);
            let meta = ExprMeta {
                chain: Some(chain_with_call),
                call: Some(CallMeta {
                    target,
                    chain,
                    options: Vec::new(),
                }),
            };
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Call { callee: callee_id, args },
                    span: span_from_node(node, ctx.file_id),
                    meta,
                },
            )
        }
        "tuple_expression" => {
            let mut entries = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if is_ts_expr_node(child.kind()) {
                    entries.push(parse_ts_expr(child, ctx));
                }
            }
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::Tuple(entries),
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta::default(),
                },
            )
        }
        "new_expression" => {
            let type_name = node
                .child_by_field_name("type")
                .and_then(|child| node_text(child, ctx.source))
                .or_else(|| node_text(node, ctx.source))
                .unwrap_or_else(|| "unknown".to_string());
            push_expr(
                ctx.ast,
                Expr {
                    kind: ExprKind::New { type_name },
                    span: span_from_node(node, ctx.file_id),
                    meta: ExprMeta::default(),
                },
            )
        }
        "parenthesized_expression" => {
            let inner = first_ts_expr_child(node);
            inner.map(|expr| parse_ts_expr(expr, ctx)).unwrap_or_else(|| {
                push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id)))
            })
        }
        _ => push_expr(ctx.ast, Expr::unknown(span_from_node(node, ctx.file_id))),
    }
}

fn parse_ts_argument_list(node: Node, ctx: &mut TsContext) -> (Vec<u32>, Vec<CallOption>) {
    let mut args = Vec::new();
    let mut options = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "call_argument" {
            let (more_args, more_options) = parse_ts_call_argument(child, ctx);
            args.extend(more_args);
            options.extend(more_options);
        } else if is_ts_expr_node(child.kind()) {
            args.push(parse_ts_expr(child, ctx));
        }
    }
    (args, options)
}

fn parse_ts_call_argument(node: Node, ctx: &mut TsContext) -> (Vec<u32>, Vec<CallOption>) {
    let mut args = Vec::new();
    let mut options = Vec::new();
    let mut struct_values = Vec::new();
    let mut saw_struct = false;

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "call_struct_argument" {
            saw_struct = true;
            if let Some((name, value)) = parse_ts_call_struct_argument(child, ctx) {
                match name.as_str() {
                    "value" => options.push(CallOption::Value(value)),
                    "gas" => options.push(CallOption::Gas(value)),
                    "salt" => options.push(CallOption::Salt(value)),
                    _ => struct_values.push(value),
                }
            }
        } else if !saw_struct && is_ts_expr_node(child.kind()) {
            args.push(parse_ts_expr(child, ctx));
        }
    }

    if saw_struct && !struct_values.is_empty() {
        let span = span_from_node(node, ctx.file_id);
        let tuple_id = push_expr(
            ctx.ast,
            Expr {
                kind: ExprKind::Tuple(struct_values),
                span,
                meta: ExprMeta::default(),
            },
        );
        args.push(tuple_id);
    }

    (args, options)
}

fn parse_ts_call_struct_argument(node: Node, ctx: &mut TsContext) -> Option<(String, u32)> {
    let name = node
        .child_by_field_name("name")
        .and_then(|child| node_text(child, ctx.source))?;
    let value_node = node.child_by_field_name("value")?;
    let value = parse_ts_expr(value_node, ctx);
    Some((name, value))
}

fn first_ts_expr_child(node: Node) -> Option<Node> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_ts_expr_node(child.kind()) {
            return Some(child);
        }
    }
    None
}

fn second_ts_expr_child(node: Node) -> Option<Node> {
    let mut cursor = node.walk();
    let mut count = 0;
    for child in node.named_children(&mut cursor) {
        if is_ts_expr_node(child.kind()) {
            count += 1;
            if count == 2 {
                return Some(child);
            }
        }
    }
    None
}

fn third_ts_expr_child(node: Node) -> Option<Node> {
    let mut cursor = node.walk();
    let mut count = 0;
    for child in node.named_children(&mut cursor) {
        if is_ts_expr_node(child.kind()) {
            count += 1;
            if count == 3 {
                return Some(child);
            }
        }
    }
    None
}

fn is_ts_expr_node(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "number_literal"
            | "integer_literal"
            | "string_literal"
            | "hex_literal"
            | "boolean_literal"
            | "address_literal"
            | "member_expression"
            | "index_expression"
            | "index_access"
            | "call_expression"
            | "assignment_expression"
            | "binary_expression"
            | "unary_expression"
            | "update_expression"
            | "tuple_expression"
            | "conditional_expression"
            | "ternary_expression"
            | "type_cast_expression"
            | "new_expression"
            | "parenthesized_expression"
            | "true"
            | "false"
    )
}

fn literal_from_ts_node(node: Node, source: &[u8]) -> Option<crate::norm::Literal> {
    let kind = node.kind();
    let text = node_text(node, source)?;
    let (lit_kind, value) = match kind {
        "number_literal" | "integer_literal" => ("number", text),
        "hex_literal" => ("hex", text),
        "string_literal" => ("string", text),
        "boolean_literal" | "true" | "false" => ("bool", text),
        "address_literal" => ("address", text),
        _ => return None,
    };
    Some(crate::norm::Literal {
        kind: lit_kind.to_string(),
        value,
    })
}

fn find_ts_identifier(node: Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let mut last = None;
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            last = node_text(child, source);
        } else {
            let inner = find_ts_identifier(child, source);
            if inner.is_some() {
                last = inner;
            }
        }
    }
    last
}

fn find_ts_name(node: Node, source: &[u8]) -> Option<String> {
    node.child_by_field_name("name")
        .and_then(|child| node_text(child, source))
        .or_else(|| find_ts_identifier(node, source))
}

fn find_ts_param_name(node: Node, source: &[u8]) -> Option<String> {
    node.child_by_field_name("name")
        .and_then(|child| node_text(child, source))
}

fn collect_ts_identifiers(node: Node, source: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            if let Some(name) = node_text(child, source) {
                out.push(name);
            }
        } else {
            out.extend(collect_ts_identifiers(child, source));
        }
    }
    out
}

fn find_named_child<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == kind {
            return Some(child);
        }
    }
    None
}

fn node_text(node: Node, source: &[u8]) -> Option<String> {
    node.utf8_text(source).ok().map(|text| text.to_string())
}

fn span_from_node(node: Node, file_id: u32) -> Span {
    Span {
        file: file_id,
        start: node.start_byte() as u32,
        end: node.end_byte() as u32,
    }
}

fn chain_from_expr(ast: &NormalizedAst, expr_id: u32) -> Option<Vec<ChainSegment>> {
    ast.expressions
        .get(expr_id as usize)
        .and_then(|expr| expr.meta.chain.clone())
}

fn parse_top_level_functions(
    tokens: &[Token],
    file_id: u32,
    ast: &mut NormalizedAst,
    ranges: &[ContractRange],
) {
    let mut idx = 0;
    while idx < tokens.len() {
        if let Some(range) = range_covering(idx, ranges) {
            idx = range.body_end + 1;
            continue;
        }
        if is_function_keyword(&tokens[idx]) {
            if let Some((func_id, end_idx)) = parse_function(
                tokens,
                idx,
                file_id,
                ast,
                None,
                tokens.len(),
            ) {
                ast.items.push(Item::Function(func_id));
                idx = end_idx + 1;
                continue;
            }
        }
        idx += 1;
    }
}

fn parse_functions_in_range(
    tokens: &[Token],
    file_id: u32,
    start_idx: usize,
    end_idx: usize,
    ast: &mut NormalizedAst,
    contract_id: Option<u32>,
) {
    let mut idx = start_idx;
    while idx < end_idx {
        if is_function_keyword(&tokens[idx]) {
            if let Some((func_id, end_idx)) =
                parse_function(tokens, idx, file_id, ast, contract_id, end_idx)
            {
                if let Some(contract_id) = contract_id {
                    if let Some(contract) = ast.contracts.get_mut(contract_id as usize) {
                        contract.functions.push(func_id);
                    }
                }
                ast.items.push(Item::Function(func_id));
                idx = end_idx + 1;
                continue;
            }
        }
        idx += 1;
    }
}

fn parse_function(
    tokens: &[Token],
    start_idx: usize,
    file_id: u32,
    ast: &mut NormalizedAst,
    contract_id: Option<u32>,
    limit: usize,
) -> Option<(u32, usize)> {
    let (kind, name, idx) = parse_function_header(tokens, start_idx, limit)?;

    let mut paren_depth = 0u32;
    let mut param_start = None;
    let mut param_end = None;
    let mut header_end = None;
    let mut body_start = None;
    let end_idx;

    let mut j = idx;
    while j < limit {
        if tokens[j].is_symbol('(') {
            if paren_depth == 0 && param_start.is_none() {
                param_start = Some(j + 1);
            }
            paren_depth += 1;
        } else if tokens[j].is_symbol(')') {
            if paren_depth > 0 {
                paren_depth -= 1;
                if paren_depth == 0 && param_end.is_none() {
                    param_end = Some(j);
                }
            }
        } else if paren_depth == 0 && tokens[j].is_symbol('{') {
            header_end = Some(j);
            body_start = Some(j);
            break;
        } else if paren_depth == 0 && tokens[j].is_symbol(';') {
            header_end = Some(j);
            break;
        }
        j += 1;
    }

    let header_end = header_end?;
    let params = match (param_start, param_end) {
        (Some(start), Some(end)) if start <= end => parse_param_names(tokens, start, end),
        _ => Vec::new(),
    };
    let returns = parse_return_names(tokens, start_idx, header_end);
    let (visibility, mutability) = parse_visibility_mutability(tokens, start_idx, header_end);

    let mut body = None;
    if let Some(open_idx) = body_start {
        if let Some(close_idx) = find_matching_brace(tokens, open_idx) {
            let block = parse_body(tokens, file_id, open_idx + 1, close_idx, ast);
            body = Some(block);
            end_idx = Some(close_idx);
        } else {
            end_idx = Some(open_idx);
        }
    } else {
        end_idx = Some(header_end);
    }

    let end_idx = end_idx?;
    let span = span_for(file_id, tokens[start_idx].start, tokens[end_idx].end);
    let func_id = push_function(
        ast,
        Function {
            id: ast.functions.len() as u32,
            contract: contract_id,
            name,
            kind,
            visibility,
            mutability,
            params,
            returns,
            modifiers: Vec::new(),
            body,
            span,
        },
    );

    Some((func_id, end_idx))
}

fn parse_param_names(tokens: &[Token], start: usize, end: usize) -> Vec<String> {
    let mut params = Vec::new();
    let mut current = Vec::new();
    let mut depth = 0u32;

    let flush = |current: &mut Vec<String>, params: &mut Vec<String>| {
        if current.len() >= 2 {
            if let Some(name) = current.pop() {
                params.push(name);
            }
        }
        current.clear();
    };

    let end = end.min(tokens.len());
    for token in &tokens[start..end] {
        if token.is_symbol('(') {
            depth += 1;
            continue;
        }
        if token.is_symbol(')') {
            if depth > 0 {
                depth -= 1;
            }
            continue;
        }
        if depth > 0 {
            continue;
        }
        if token.is_symbol(',') {
            flush(&mut current, &mut params);
            continue;
        }
        if token.is_ident() && !is_param_stopword(&token.text) {
            current.push(token.text.clone());
        }
    }
    flush(&mut current, &mut params);
    params
}

fn parse_return_names(tokens: &[Token], start_idx: usize, end_idx: usize) -> Vec<String> {
    let mut idx = start_idx;
    while idx < end_idx {
        if tokens[idx].is_keyword("returns") {
            let Some(open_idx) = find_symbol_in_range(tokens, idx + 1, end_idx, '(') else {
                return Vec::new();
            };
            let Some(close_idx) = find_matching_paren(tokens, open_idx) else {
                return Vec::new();
            };
            if close_idx > end_idx {
                return Vec::new();
            }
            if open_idx + 1 >= close_idx {
                return Vec::new();
            }
            return parse_param_names(tokens, open_idx + 1, close_idx);
        }
        idx += 1;
    }
    Vec::new()
}

fn is_param_stopword(value: &str) -> bool {
    matches!(
        value,
        "memory"
            | "storage"
            | "calldata"
            | "payable"
            | "indexed"
            | "returns"
            | "mapping"
    )
}

fn parse_function_header(
    tokens: &[Token],
    start_idx: usize,
    limit: usize,
) -> Option<(FunctionKind, Option<String>, usize)> {
    let token = tokens.get(start_idx)?;
    if !is_function_keyword(token) {
        return None;
    }
    let keyword = token.text.as_str();
    let mut idx = start_idx + 1;
    let mut name = None;
    let kind = match keyword {
        "function" => {
            if idx < limit && tokens[idx].is_symbol('(') {
                FunctionKind::Fallback
            } else if idx < limit && tokens[idx].is_ident() {
                name = Some(tokens[idx].text.clone());
                idx += 1;
                FunctionKind::Function
            } else {
                FunctionKind::Unknown
            }
        }
        "constructor" => FunctionKind::Constructor,
        "fallback" => FunctionKind::Fallback,
        "receive" => FunctionKind::Receive,
        _ => FunctionKind::Unknown,
    };
    Some((kind, name, idx))
}

fn parse_visibility_mutability(
    tokens: &[Token],
    start_idx: usize,
    end_idx: usize,
) -> (Visibility, Mutability) {
    let mut visibility = Visibility::Unknown;
    let mut mutability = Mutability::Unknown;
    for token in &tokens[start_idx..end_idx] {
        if token.is_keyword("public") {
            visibility = Visibility::Public;
        } else if token.is_keyword("external") {
            visibility = Visibility::External;
        } else if token.is_keyword("internal") {
            visibility = Visibility::Internal;
        } else if token.is_keyword("private") {
            visibility = Visibility::Private;
        } else if token.is_keyword("pure") {
            mutability = Mutability::Pure;
        } else if token.is_keyword("view") {
            mutability = Mutability::View;
        } else if token.is_keyword("payable") {
            mutability = Mutability::Payable;
        }
    }
    (visibility, mutability)
}

fn parse_body(
    tokens: &[Token],
    file_id: u32,
    start_idx: usize,
    end_idx: usize,
    ast: &mut NormalizedAst,
) -> u32 {
    let mut statements = Vec::new();
    let mut idx = start_idx;
    while idx < end_idx {
        if let Some((stmt_id, end_idx)) = parse_return_stmt(tokens, idx, file_id, ast, end_idx) {
            statements.push(stmt_id);
            idx = end_idx + 1;
            continue;
        }
        if let Some((expr_id, end_idx)) = parse_assignment_expr(tokens, idx, file_id, ast, end_idx)
        {
            statements.push(push_stmt(
                ast,
                StmtKind::Expr(expr_id),
                span_for(file_id, tokens[idx].start, tokens[end_idx].end),
            ));
            idx = end_idx + 1;
            continue;
        }
        if let Some((expr_id, end_idx)) = parse_call_expr(tokens, idx, file_id, ast) {
            statements.push(push_stmt(
                ast,
                StmtKind::Expr(expr_id),
                span_for(file_id, tokens[idx].start, tokens[end_idx].end),
            ));
            idx = end_idx + 1;
            continue;
        }
        if let Some((expr_id, end_idx)) = parse_source_expr(tokens, idx, file_id, ast) {
            statements.push(push_stmt(
                ast,
                StmtKind::Expr(expr_id),
                span_for(file_id, tokens[idx].start, tokens[end_idx].end),
            ));
            idx = end_idx + 1;
            continue;
        }
        idx += 1;
    }

    let span = if start_idx > 0 && end_idx > 0 {
        span_for(file_id, tokens[start_idx - 1].start, tokens[end_idx].end)
    } else {
        span_for(file_id, 0, 0)
    };
    push_stmt(ast, StmtKind::Block(statements), span)
}

fn parse_call_expr(
    tokens: &[Token],
    start_idx: usize,
    file_id: u32,
    ast: &mut NormalizedAst,
) -> Option<(u32, usize)> {
    let token = tokens.get(start_idx)?;
    if !token.is_ident() {
        return None;
    }
    if start_idx > 0 && tokens[start_idx - 1].is_keyword("new") {
        return None;
    }

    let mut names = Vec::new();
    let mut idx = start_idx;
    names.push(tokens[idx].text.clone());
    idx += 1;
    while idx + 1 < tokens.len() && tokens[idx].is_symbol('.') && tokens[idx + 1].is_ident() {
        names.push(tokens[idx + 1].text.clone());
        idx += 2;
    }
    if idx >= tokens.len() || !tokens[idx].is_symbol('(') {
        return None;
    }

    let end_idx = find_matching_paren(tokens, idx)?;
    let (callee_id, chain) = build_member_chain(tokens, ast, file_id, start_idx, &names);
    let target = call_target_from_chain(&chain);
    let mut chain_with_call = chain.clone();
    chain_with_call.push(ChainSegment::Call);
    let call_meta = ExprMeta {
        chain: Some(chain_with_call),
        call: Some(CallMeta {
            target,
            chain,
            options: Vec::new(),
        }),
    };

    let call_expr = Expr {
        kind: ExprKind::Call {
            callee: callee_id,
            args: Vec::new(),
        },
        span: span_for(file_id, tokens[start_idx].start, tokens[end_idx].end),
        meta: call_meta,
    };
    let call_id = push_expr(ast, call_expr);
    Some((call_id, end_idx))
}

fn parse_return_stmt(
    tokens: &[Token],
    start_idx: usize,
    file_id: u32,
    ast: &mut NormalizedAst,
    limit: usize,
) -> Option<(u32, usize)> {
    let token = tokens.get(start_idx)?;
    if !token.is_keyword("return") {
        return None;
    }
    let semi = find_semicolon(tokens, start_idx + 1, limit)?;
    let expr = if semi == start_idx + 1 {
        None
    } else {
        let expr_id = parse_simple_expr_in_range(tokens, start_idx + 1, semi - 1, file_id, ast)
            .map(|(expr_id, _)| expr_id)
            .unwrap_or_else(|| push_expr(ast, Expr::unknown(span_for(file_id, token.start, token.end))));
        Some(expr_id)
    };
    let span = span_for(file_id, token.start, tokens[semi].end);
    Some((push_stmt(ast, StmtKind::Return(expr), span), semi))
}

fn parse_assignment_expr(
    tokens: &[Token],
    start_idx: usize,
    file_id: u32,
    ast: &mut NormalizedAst,
    limit: usize,
) -> Option<(u32, usize)> {
    let (lhs, lhs_end) = parse_chain_expr(tokens, start_idx, file_id, ast, limit)?;
    let op_idx = lhs_end + 1;
    if op_idx >= limit {
        return None;
    }
    let (op, rhs_start) = parse_assignment_operator(tokens, op_idx, limit)?;
    let semi = find_semicolon(tokens, rhs_start, limit)?;
    if rhs_start > semi {
        return None;
    }
    let rhs_expr = if rhs_start == semi {
        push_expr(ast, Expr::unknown(span_for(file_id, tokens[rhs_start].start, tokens[rhs_start].end)))
    } else {
        parse_simple_expr_in_range(tokens, rhs_start, semi - 1, file_id, ast)
            .map(|(expr_id, _)| expr_id)
            .unwrap_or_else(|| push_expr(ast, Expr::unknown(span_for(file_id, tokens[rhs_start].start, tokens[semi].end))))
    };
    let span = span_for(file_id, tokens[start_idx].start, tokens[semi].end);
    let expr_id = push_expr(
        ast,
        Expr {
            kind: ExprKind::Assign {
                op,
                lhs,
                rhs: rhs_expr,
            },
            span,
            meta: ExprMeta::default(),
        },
    );
    Some((expr_id, semi))
}

fn parse_source_expr(
    tokens: &[Token],
    start_idx: usize,
    file_id: u32,
    ast: &mut NormalizedAst,
) -> Option<(u32, usize)> {
    if start_idx + 2 >= tokens.len() {
        return None;
    }
    if !tokens[start_idx].is_ident() {
        return None;
    }
    if !tokens[start_idx + 1].is_symbol('.') || !tokens[start_idx + 2].is_ident() {
        return None;
    }
    if start_idx + 3 < tokens.len() && tokens[start_idx + 3].is_symbol('(') {
        return None;
    }

    let names = vec![
        tokens[start_idx].text.clone(),
        tokens[start_idx + 2].text.clone(),
    ];
    if !is_source_names(&names) {
        return None;
    }
    let (expr_id, _) = build_member_chain(tokens, ast, file_id, start_idx, &names);
    Some((expr_id, start_idx + 2))
}

fn parse_simple_expr_in_range(
    tokens: &[Token],
    start_idx: usize,
    end_idx: usize,
    file_id: u32,
    ast: &mut NormalizedAst,
) -> Option<(u32, usize)> {
    if start_idx > end_idx {
        return None;
    }
    if let Some((expr_id, end_idx_expr)) = parse_call_expr(tokens, start_idx, file_id, ast) {
        if end_idx_expr <= end_idx {
            return Some((expr_id, end_idx_expr));
        }
    }
    if let Some((expr_id, end_idx_expr)) = parse_chain_expr(tokens, start_idx, file_id, ast, end_idx + 1)
    {
        if end_idx_expr <= end_idx {
            return Some((expr_id, end_idx_expr));
        }
    }
    let token = tokens.get(start_idx)?;
    if token.is_number() {
        let span = span_for(file_id, token.start, token.end);
        let expr_id = push_expr(
            ast,
            Expr {
                kind: ExprKind::Literal(crate::norm::Literal {
                    kind: "number".to_string(),
                    value: token.text.clone(),
                }),
                span,
                meta: ExprMeta::default(),
            },
        );
        return Some((expr_id, start_idx));
    }
    if token.is_ident() {
        let span = span_for(file_id, token.start, token.end);
        let chain = vec![ChainSegment::Ident(token.text.clone())];
        let expr_id = push_expr(
            ast,
            Expr {
                kind: ExprKind::Ident(token.text.clone()),
                span,
                meta: ExprMeta {
                    chain: Some(chain),
                    call: None,
                },
            },
        );
        return Some((expr_id, start_idx));
    }
    None
}

fn parse_chain_expr(
    tokens: &[Token],
    start_idx: usize,
    file_id: u32,
    ast: &mut NormalizedAst,
    limit: usize,
) -> Option<(u32, usize)> {
    let token = tokens.get(start_idx)?;
    if !token.is_ident() {
        return None;
    }
    if start_idx + 1 < limit && tokens[start_idx + 1].is_symbol('(') {
        return None;
    }

    let mut idx = start_idx;
    let mut chain = vec![ChainSegment::Ident(token.text.clone())];
    let mut expr_id = push_expr(
        ast,
        Expr {
            kind: ExprKind::Ident(token.text.clone()),
            span: span_for(file_id, token.start, token.end),
            meta: ExprMeta {
                chain: Some(chain.clone()),
                call: None,
            },
        },
    );

    loop {
        if idx + 1 >= limit {
            break;
        }
        if tokens[idx + 1].is_symbol('.') {
            if idx + 2 >= limit || !tokens[idx + 2].is_ident() {
                break;
            }
            let name = tokens[idx + 2].text.clone();
            chain.push(ChainSegment::Member(name.clone()));
            let span = span_for(file_id, token.start, tokens[idx + 2].end);
            expr_id = push_expr(
                ast,
                Expr {
                    kind: ExprKind::Member {
                        base: expr_id,
                        field: name,
                    },
                    span,
                    meta: ExprMeta {
                        chain: Some(chain.clone()),
                        call: None,
                    },
                },
            );
            idx += 2;
            continue;
        }
        if tokens[idx + 1].is_symbol('[') {
            let open_idx = idx + 1;
            let Some(close_idx) = find_matching_bracket(tokens, open_idx, limit) else {
                break;
            };
            let index = if close_idx > open_idx + 1 {
                parse_simple_expr_in_range(tokens, open_idx + 1, close_idx - 1, file_id, ast)
                    .map(|(expr_id, _)| expr_id)
            } else {
                None
            };
            chain.push(ChainSegment::Index);
            let span = span_for(file_id, token.start, tokens[close_idx].end);
            expr_id = push_expr(
                ast,
                Expr {
                    kind: ExprKind::Index { base: expr_id, index },
                    span,
                    meta: ExprMeta {
                        chain: Some(chain.clone()),
                        call: None,
                    },
                },
            );
            idx = close_idx;
            continue;
        }
        break;
    }

    Some((expr_id, idx))
}

fn parse_assignment_operator(tokens: &[Token], idx: usize, limit: usize) -> Option<(String, usize)> {
    let token = tokens.get(idx)?;
    if token.is_symbol('=') {
        if idx + 1 < limit && tokens[idx + 1].is_symbol('=') {
            return None;
        }
        return Some(("=".to_string(), idx + 1));
    }
    if idx + 2 < limit && token.is_symbol('<') && tokens[idx + 1].is_symbol('<') && tokens[idx + 2].is_symbol('=') {
        return Some(("<<=".to_string(), idx + 3));
    }
    if idx + 2 < limit && token.is_symbol('>') && tokens[idx + 1].is_symbol('>') && tokens[idx + 2].is_symbol('=') {
        return Some((">>=".to_string(), idx + 3));
    }
    if idx + 1 < limit && tokens[idx + 1].is_symbol('=') {
        match token.text.as_str() {
            "+" | "-" | "*" | "/" | "%" | "|" | "&" | "^" => {
                return Some((format!("{}=", token.text), idx + 2));
            }
            _ => {}
        }
    }
    None
}

fn build_member_chain(
    tokens: &[Token],
    ast: &mut NormalizedAst,
    file_id: u32,
    start_idx: usize,
    names: &[String],
) -> (u32, Vec<ChainSegment>) {
    let mut chain = Vec::new();
    if names.is_empty() {
        return (
            push_expr(ast, Expr::unknown(span_for(file_id, 0, 0))),
            chain,
        );
    }
    chain.push(ChainSegment::Ident(names[0].clone()));
    let first_token_idx = start_idx;
    let mut expr_id = push_expr(
        ast,
        Expr {
            kind: ExprKind::Ident(names[0].clone()),
            span: span_for(
                file_id,
                tokens_start(tokens, first_token_idx),
                tokens_end(tokens, first_token_idx),
            ),
            meta: ExprMeta {
                chain: Some(chain.clone()),
                call: None,
            },
        },
    );
    for (idx, name) in names.iter().enumerate().skip(1) {
        chain.push(ChainSegment::Member(name.clone()));
        let name_token_idx = start_idx + idx * 2;
        let span = span_for(
            file_id,
            tokens_start(tokens, start_idx),
            tokens_end(tokens, name_token_idx),
        );
        expr_id = push_expr(
            ast,
            Expr {
                kind: ExprKind::Member {
                    base: expr_id,
                    field: name.clone(),
                },
                span,
                meta: ExprMeta {
                    chain: Some(chain.clone()),
                    call: None,
                },
            },
        );
    }
    (expr_id, chain)
}

fn tokens_start(tokens: &[Token], idx: usize) -> u32 {
    tokens.get(idx).map(|t| t.start).unwrap_or(0)
}

fn tokens_end(tokens: &[Token], idx: usize) -> u32 {
    tokens.get(idx).map(|t| t.end).unwrap_or(0)
}

fn span_for(file: u32, start: u32, end: u32) -> Span {
    Span { file, start, end }
}

fn push_contract(ast: &mut NormalizedAst, name: String, kind: ContractKind, span: Span) -> u32 {
    let id = ast.contracts.len() as u32;
    ast.contracts.push(Contract {
        id,
        name,
        kind,
        bases: Vec::new(),
        functions: Vec::new(),
        state_vars: Vec::new(),
        modifiers: Vec::new(),
        events: Vec::new(),
        errors: Vec::new(),
        span,
    });
    ast.items.push(Item::Contract(id));
    id
}

fn push_function(ast: &mut NormalizedAst, function: Function) -> u32 {
    let id = function.id;
    ast.functions.push(function);
    id
}

fn push_stmt(ast: &mut NormalizedAst, kind: StmtKind, span: Span) -> u32 {
    let id = ast.statements.len() as u32;
    ast.statements.push(Stmt { kind, span });
    id
}

fn push_expr(ast: &mut NormalizedAst, expr: Expr) -> u32 {
    let id = ast.expressions.len() as u32;
    ast.expressions.push(expr);
    id
}

fn contract_kind(token: &Token) -> Option<ContractKind> {
    if token.is_keyword("contract") {
        Some(ContractKind::Contract)
    } else if token.is_keyword("interface") {
        Some(ContractKind::Interface)
    } else if token.is_keyword("library") {
        Some(ContractKind::Library)
    } else {
        None
    }
}

fn is_function_keyword(token: &Token) -> bool {
    token.is_keyword("function")
        || token.is_keyword("constructor")
        || token.is_keyword("fallback")
        || token.is_keyword("receive")
}

fn is_source_names(names: &[String]) -> bool {
    if names.len() != 2 {
        return false;
    }
    let base = names[0].as_str();
    let field = names[1].as_str();
    matches!(
        (base, field),
        ("tx", "origin")
            | ("tx", "gasprice")
            | ("msg", "sender")
            | ("msg", "value")
            | ("msg", "data")
            | ("msg", "sig")
    )
}

fn call_target_from_chain(chain: &[ChainSegment]) -> CallTarget {
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

fn find_symbol(tokens: &[Token], start_idx: usize, target: char) -> Option<usize> {
    for idx in start_idx..tokens.len() {
        if tokens[idx].is_symbol(target) {
            return Some(idx);
        }
    }
    None
}

fn find_symbol_in_range(
    tokens: &[Token],
    start_idx: usize,
    end_idx: usize,
    target: char,
) -> Option<usize> {
    let end = end_idx.min(tokens.len());
    for idx in start_idx..end {
        if tokens[idx].is_symbol(target) {
            return Some(idx);
        }
    }
    None
}

fn find_matching_brace(tokens: &[Token], open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    for idx in open_idx..tokens.len() {
        if tokens[idx].is_symbol('{') {
            depth += 1;
        } else if tokens[idx].is_symbol('}') {
            depth -= 1;
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn find_matching_paren(tokens: &[Token], open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    for idx in open_idx..tokens.len() {
        if tokens[idx].is_symbol('(') {
            depth += 1;
        } else if tokens[idx].is_symbol(')') {
            depth -= 1;
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn find_matching_bracket(tokens: &[Token], open_idx: usize, limit: usize) -> Option<usize> {
    let mut depth = 0i32;
    let max = limit.min(tokens.len());
    for idx in open_idx..max {
        if tokens[idx].is_symbol('[') {
            depth += 1;
        } else if tokens[idx].is_symbol(']') {
            depth -= 1;
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn find_semicolon(tokens: &[Token], start_idx: usize, limit: usize) -> Option<usize> {
    let mut paren_depth = 0i32;
    let mut bracket_depth = 0i32;
    let max = limit.min(tokens.len());
    for idx in start_idx..max {
        if tokens[idx].is_symbol('(') {
            paren_depth += 1;
        } else if tokens[idx].is_symbol(')') {
            paren_depth -= 1;
        } else if tokens[idx].is_symbol('[') {
            bracket_depth += 1;
        } else if tokens[idx].is_symbol(']') {
            bracket_depth -= 1;
        } else if tokens[idx].is_symbol(';') && paren_depth == 0 && bracket_depth == 0 {
            return Some(idx);
        }
    }
    None
}

fn next_ident(tokens: &[Token], start_idx: usize) -> Option<usize> {
    for idx in start_idx..tokens.len() {
        if tokens[idx].is_ident() {
            return Some(idx);
        }
    }
    None
}

fn range_covering(idx: usize, ranges: &[ContractRange]) -> Option<&ContractRange> {
    ranges
        .iter()
        .find(|range| idx >= range.body_start && idx <= range.body_end)
}

fn tokenize(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut idx = 0;
    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        if ch.is_whitespace() {
            idx += 1;
            continue;
        }
        if ch.is_ascii_digit() {
            let start = idx;
            idx += 1;
            while idx < bytes.len() {
                let next = bytes[idx] as char;
                if next.is_ascii_digit() {
                    idx += 1;
                    continue;
                }
                if next == '.' && idx + 1 < bytes.len() && (bytes[idx + 1] as char).is_ascii_digit() {
                    idx += 1;
                    continue;
                }
                break;
            }
            tokens.push(Token {
                kind: TokenKind::Number,
                text: source[start..idx].to_string(),
                start: start as u32,
                end: idx as u32,
            });
            continue;
        }
        if ch == '/' && idx + 1 < bytes.len() {
            let next = bytes[idx + 1] as char;
            if next == '/' {
                idx += 2;
                while idx < bytes.len() && bytes[idx] as char != '\n' {
                    idx += 1;
                }
                continue;
            }
            if next == '*' {
                idx += 2;
                while idx + 1 < bytes.len() {
                    if bytes[idx] as char == '*' && bytes[idx + 1] as char == '/' {
                        idx += 2;
                        break;
                    }
                    idx += 1;
                }
                continue;
            }
        }
        if ch == '"' || ch == '\'' {
            let quote = ch;
            idx += 1;
            while idx < bytes.len() {
                let curr = bytes[idx] as char;
                if curr == '\\' {
                    idx += 2;
                    continue;
                }
                if curr == quote {
                    idx += 1;
                    break;
                }
                idx += 1;
            }
            continue;
        }

        if is_ident_start(ch) {
            let start = idx;
            idx += 1;
            while idx < bytes.len() && is_ident_continue(bytes[idx] as char) {
                idx += 1;
            }
            let text = &source[start..idx];
            let kind = if is_keyword(text) {
                TokenKind::Keyword
            } else {
                TokenKind::Ident
            };
            tokens.push(Token {
                kind,
                text: text.to_string(),
                start: start as u32,
                end: idx as u32,
            });
            continue;
        }

        tokens.push(Token {
            kind: TokenKind::Symbol,
            text: ch.to_string(),
            start: idx as u32,
            end: (idx + 1) as u32,
        });
        idx += 1;
    }
    tokens
}

fn is_ident_start(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphabetic()
}

fn is_ident_continue(ch: char) -> bool {
    is_ident_start(ch) || ch.is_ascii_digit()
}

fn is_keyword(value: &str) -> bool {
    matches!(
        value,
        "contract"
            | "interface"
            | "library"
            | "function"
            | "constructor"
            | "fallback"
            | "receive"
            | "returns"
            | "public"
            | "private"
            | "external"
            | "internal"
            | "pure"
            | "view"
            | "payable"
            | "if"
            | "for"
            | "while"
            | "do"
            | "return"
            | "emit"
            | "new"
    )
}

trait UnknownExpr {
    fn unknown(span: Span) -> Self;
}

impl UnknownExpr for Expr {
    fn unknown(span: Span) -> Self {
        Expr {
            kind: ExprKind::Unknown,
            span,
            meta: ExprMeta::default(),
        }
    }
}
