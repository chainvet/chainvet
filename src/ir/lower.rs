use crate::ir::{
    ControlKind, IrBlock, IrCallOption, IrFunction, IrInstr, IrModule, IrPlace, IrValue, IrVar,
    PlaceClass,
};
use crate::norm::symbols::{build_function_symbols, NameResolution, SymbolTable};
use crate::norm::{CallOption, ExprKind, Literal, NormalizedAst, Span, StmtKind};

pub fn lower_module(ast: &NormalizedAst) -> IrModule {
    let mut module = IrModule { functions: Vec::new() };

    for func in &ast.functions {
        let id = module.functions.len() as u32;
        let contract_name = func
            .contract
            .and_then(|id| ast.contracts.get(id as usize))
            .map(|contract| contract.name.as_str());
        let symbols = build_function_symbols(ast, func);
        let mut ctx = LowerCtx {
            temp_counter: 0,
            contract_name,
            symbols,
            return_count: func.returns.len(),
        };
        let mut instrs = Vec::new();
        if let Some(body) = func.body {
            lower_stmt(body, ast, &mut instrs, &mut ctx);
        } else {
            instrs.push(IrInstr::Nop { span: func.span });
        }
        let block = IrBlock { id: 0, instrs };
        module.functions.push(IrFunction {
            id,
            name: func.name.clone(),
            source: Some(func.id),
            span: func.span,
            blocks: vec![block],
        });
    }

    module
}

struct LowerCtx<'a> {
    temp_counter: u32,
    contract_name: Option<&'a str>,
    symbols: SymbolTable,
    return_count: usize,
}

fn lower_stmt(stmt_id: u32, ast: &NormalizedAst, instrs: &mut Vec<IrInstr>, ctx: &mut LowerCtx) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };

    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for child in stmts {
                lower_stmt(*child, ast, instrs, ctx);
            }
        }
        StmtKind::Expr(expr) => lower_expr_stmt(*expr, stmt.span, ast, instrs, ctx),
        StmtKind::Return(value) => {
            let values = if let Some(expr_id) = value {
                if ctx.return_count > 1 {
                    if let Some((expr, callee, args)) = call_expr(ast, *expr_id) {
                        let mut temps = Vec::new();
                        for _ in 0..ctx.return_count {
                            temps.push(new_temp(ctx));
                        }
                        lower_call_with_dests(expr, callee, args, temps.clone(), stmt.span, ast, instrs, ctx);
                        temps.into_iter().map(IrValue::Var).collect()
                    } else {
                        lower_return_values(*expr_id, ast, instrs, ctx)
                    }
                } else {
                    lower_return_values(*expr_id, ast, instrs, ctx)
                }
            } else {
                Vec::new()
            };
            instrs.push(IrInstr::Return {
                values,
                span: stmt.span,
            });
        }
        StmtKind::Emit(expr) => {
            let value = lower_value(*expr, ast, instrs, ctx);
            instrs.push(IrInstr::Emit {
                expr: value,
                span: stmt.span,
            });
        }
        StmtKind::Revert(value) => {
            let value = value.map(|expr| lower_value(expr, ast, instrs, ctx));
            instrs.push(IrInstr::Control {
                kind: ControlKind::Revert { value },
                span: stmt.span,
            });
        }
        StmtKind::VarDecl { names, init } => {
            if names.len() <= 1 {
                let init = init.map(|expr| lower_value(expr, ast, instrs, ctx));
                instrs.push(IrInstr::Declare {
                    names: names.clone(),
                    init,
                    span: stmt.span,
                });
            } else {
                instrs.push(IrInstr::Declare {
                    names: names.clone(),
                    init: None,
                    span: stmt.span,
                });
                if let Some(init_expr) = init {
                    lower_tuple_decl_init(&names, *init_expr, stmt.span, ast, instrs, ctx);
                }
            }
        }
        StmtKind::Try { call, clauses } => {
            lower_expr_stmt(*call, stmt.span, ast, instrs, ctx);
            instrs.push(IrInstr::Control {
                kind: ControlKind::Try,
                span: stmt.span,
            });
            for (idx, clause) in clauses.iter().enumerate() {
                if idx > 0 {
                    instrs.push(IrInstr::Control {
                        kind: ControlKind::Catch,
                        span: stmt.span,
                    });
                }
                lower_stmt(clause.body, ast, instrs, ctx);
            }
            instrs.push(IrInstr::Control {
                kind: ControlKind::EndTry,
                span: stmt.span,
            });
        }
        StmtKind::InlineAsm { language } => instrs.push(IrInstr::InlineAsm {
            language: language.clone(),
            span: stmt.span,
        }),
        StmtKind::If {
            cond,
            then_id,
            else_id,
        } => {
            let cond_val = lower_value(*cond, ast, instrs, ctx);
            instrs.push(IrInstr::Control {
                kind: ControlKind::If { cond: cond_val },
                span: stmt.span,
            });
            lower_stmt(*then_id, ast, instrs, ctx);
            if let Some(else_id) = else_id {
                instrs.push(IrInstr::Control {
                    kind: ControlKind::Else,
                    span: stmt.span,
                });
                lower_stmt(*else_id, ast, instrs, ctx);
            }
            instrs.push(IrInstr::Control {
                kind: ControlKind::EndIf,
                span: stmt.span,
            });
        }
        StmtKind::While { cond, body } => {
            let cond_val = lower_value(*cond, ast, instrs, ctx);
            instrs.push(IrInstr::Control {
                kind: ControlKind::Loop {
                    cond: Some(cond_val),
                },
                span: stmt.span,
            });
            lower_stmt(*body, ast, instrs, ctx);
            instrs.push(IrInstr::Control {
                kind: ControlKind::EndLoop,
                span: stmt.span,
            });
        }
        StmtKind::DoWhile { body, cond } => {
            let cond_val = lower_value(*cond, ast, instrs, ctx);
            instrs.push(IrInstr::Control {
                kind: ControlKind::Loop {
                    cond: Some(cond_val),
                },
                span: stmt.span,
            });
            lower_stmt(*body, ast, instrs, ctx);
            instrs.push(IrInstr::Control {
                kind: ControlKind::EndLoop,
                span: stmt.span,
            });
        }
        StmtKind::For {
            init,
            cond,
            step,
            body,
        } => {
            if let Some(init_id) = init {
                lower_stmt(*init_id, ast, instrs, ctx);
            }
            let cond_val = cond.map(|expr| lower_value(expr, ast, instrs, ctx));
            instrs.push(IrInstr::Control {
                kind: ControlKind::Loop { cond: cond_val },
                span: stmt.span,
            });
            lower_stmt(*body, ast, instrs, ctx);
            if let Some(step_id) = step {
                lower_expr_stmt(*step_id, stmt.span, ast, instrs, ctx);
            }
            instrs.push(IrInstr::Control {
                kind: ControlKind::EndLoop,
                span: stmt.span,
            });
        }
        StmtKind::Break => instrs.push(IrInstr::Control {
            kind: ControlKind::Break,
            span: stmt.span,
        }),
        StmtKind::Continue => instrs.push(IrInstr::Control {
            kind: ControlKind::Continue,
            span: stmt.span,
        }),
    }
}

fn lower_expr_stmt(
    expr_id: u32,
    span: Span,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        instrs.push(IrInstr::Eval {
            expr: IrValue::Unknown,
            span,
        });
        return;
    };

    match &expr.kind {
        ExprKind::Assign { op, lhs, rhs } => {
            lower_assign_expr(*lhs, *rhs, op, span, ast, instrs, ctx);
        }
        ExprKind::Call { callee, args } => {
            if is_revert_call(expr, ast) {
                let value = args.first().map(|arg| lower_value(*arg, ast, instrs, ctx));
                instrs.push(IrInstr::Control {
                    kind: ControlKind::Revert { value },
                    span,
                });
            } else {
                let (callee_id, options) = resolve_call(ast, expr, *callee);
                let callee_val = lower_callee_value(expr, callee_id, ast, instrs, ctx);
                let mut args_val = Vec::new();
                for arg in args {
                    args_val.push(lower_value(*arg, ast, instrs, ctx));
                }
                let options_val = lower_call_options(ast, &options, instrs, ctx);
                instrs.push(IrInstr::Call {
                    dest: Vec::new(),
                    callee: callee_val,
                    args: args_val,
                    options: options_val,
                    span,
                });
            }
        }
        _ => {
            let value = lower_value(expr_id, ast, instrs, ctx);
            instrs.push(IrInstr::Eval { expr: value, span });
        }
    }
}

fn lower_value(
    expr_id: u32,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> IrValue {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return IrValue::Unknown;
    };
    let span = expr.span;

    match &expr.kind {
        ExprKind::Literal(lit) => IrValue::Literal(lit.clone()),
        ExprKind::Ident(name) => {
            let place = place_from_ident(name, ctx);
            load_place_value(&place, span, instrs, ctx)
        }
        ExprKind::Member { base, field } => {
            let base_val = lower_place_base_value(*base, ast, instrs, ctx);
            let root = root_name_for_place(ast, expr_id, ctx.contract_name);
            let class = class_for_root(root.as_ref(), &base_val, ctx);
            let place = IrPlace::Member {
                base: base_val,
                field: field.clone(),
                root,
                class,
            };
            load_place_value(&place, span, instrs, ctx)
        }
        ExprKind::Index { base, index } => {
            let base_val = lower_place_base_value(*base, ast, instrs, ctx);
            let index_val = index.map(|id| lower_value(id, ast, instrs, ctx));
            let root = root_name_for_place(ast, expr_id, ctx.contract_name);
            let class = class_for_root(root.as_ref(), &base_val, ctx);
            let place = IrPlace::Index {
                base: base_val,
                index: index_val,
                root,
                class,
            };
            load_place_value(&place, span, instrs, ctx)
        }
        ExprKind::Call { callee, args } => {
            let (callee_id, options) = resolve_call(ast, expr, *callee);
            let callee_val = lower_callee_value(expr, callee_id, ast, instrs, ctx);
            let args_val = args
                .iter()
                .map(|arg| lower_value(*arg, ast, instrs, ctx))
                .collect();
            let options_val = lower_call_options(ast, &options, instrs, ctx);
            let temp = new_temp(ctx);
            instrs.push(IrInstr::Call {
                dest: vec![temp.clone()],
                callee: callee_val,
                args: args_val,
                options: options_val,
                span,
            });
            IrValue::Var(temp)
        }
        ExprKind::CallOptions { callee, .. } => lower_value(*callee, ast, instrs, ctx),
        ExprKind::Binary { op, lhs, rhs } => {
            let lhs_val = lower_value(*lhs, ast, instrs, ctx);
            let rhs_val = lower_value(*rhs, ast, instrs, ctx);
            let temp = new_temp(ctx);
            instrs.push(IrInstr::Binary {
                dest: temp.clone(),
                op: op.clone(),
                lhs: lhs_val,
                rhs: rhs_val,
                span,
            });
            IrValue::Var(temp)
        }
        ExprKind::Unary { op, expr, prefix } => {
            if op == "++" || op == "--" {
                return lower_unary_update(*expr, op, *prefix, span, ast, instrs, ctx);
            }
            let expr_val = lower_value(*expr, ast, instrs, ctx);
            let temp = new_temp(ctx);
            instrs.push(IrInstr::Unary {
                dest: temp.clone(),
                op: op.clone(),
                expr: expr_val,
                prefix: *prefix,
                span,
            });
            IrValue::Var(temp)
        }
        ExprKind::Assign { op, lhs, rhs } => {
            lower_assign_expr(*lhs, *rhs, op, span, ast, instrs, ctx)
        }
        ExprKind::Tuple(entries) => {
            if entries.len() == 1 {
                lower_value(entries[0], ast, instrs, ctx)
            } else {
                IrValue::Unknown
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            let cond_val = lower_value(*cond, ast, instrs, ctx);
            let then_val = lower_value(*then_expr, ast, instrs, ctx);
            let else_val = lower_value(*else_expr, ast, instrs, ctx);
            let temp = new_temp(ctx);
            instrs.push(IrInstr::Select {
                dest: temp.clone(),
                cond: cond_val,
                then_val,
                else_val,
                span,
            });
            IrValue::Var(temp)
        }
        ExprKind::New { type_name } => IrValue::Literal(Literal {
            kind: "type".to_string(),
            value: type_name.clone(),
        }),
        ExprKind::Unknown => IrValue::Unknown,
    }
}

fn lower_return_values(
    expr_id: u32,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> Vec<IrValue> {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return vec![IrValue::Unknown];
    };
    match &expr.kind {
        ExprKind::Tuple(entries) => entries
            .iter()
            .map(|entry| lower_value(*entry, ast, instrs, ctx))
            .collect(),
        _ => vec![lower_value(expr_id, ast, instrs, ctx)],
    }
}

fn lower_assign_expr(
    lhs: u32,
    rhs: u32,
    op: &str,
    span: Span,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> IrValue {
    if op == "=" {
        if let Some(tuple_entries) = tuple_entries(ast, lhs) {
            lower_tuple_assign(&tuple_entries, rhs, span, ast, instrs, ctx);
            return IrValue::Unknown;
        }
    }
    let target = lower_lvalue(lhs, ast, instrs, ctx);
    let rhs_val = lower_value(rhs, ast, instrs, ctx);
    if op == "=" {
        emit_store_or_assign(&target, rhs_val.clone(), span, instrs);
        return rhs_val;
    }
    if let Some(base_op) = op.strip_suffix('=') {
        let lhs_val = match &target {
            LValue::Var(var) => IrValue::Var(var.clone()),
            LValue::Place(place) => load_place_value(place, span, instrs, ctx),
        };
        let temp = new_temp(ctx);
        instrs.push(IrInstr::Binary {
            dest: temp.clone(),
            op: base_op.to_string(),
            lhs: lhs_val,
            rhs: rhs_val,
            span,
        });
        let result = IrValue::Var(temp.clone());
        emit_store_or_assign(&target, result.clone(), span, instrs);
        return result;
    }
    emit_store_or_assign(&target, rhs_val.clone(), span, instrs);
    rhs_val
}

fn lower_tuple_decl_init(
    names: &[String],
    init_expr: u32,
    span: Span,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) {
    if let Some((expr, callee, args)) = call_expr(ast, init_expr) {
        let mut temps = Vec::new();
        for _ in 0..names.len() {
            temps.push(new_temp(ctx));
        }
        lower_call_with_dests(expr, callee, args, temps.clone(), span, ast, instrs, ctx);
        for (idx, name) in names.iter().enumerate() {
            let value = temps
                .get(idx)
                .cloned()
                .map(IrValue::Var)
                .unwrap_or(IrValue::Unknown);
            let target = LValue::Var(IrVar::Named(name.clone()));
            emit_store_or_assign(&target, value, span, instrs);
        }
        return;
    }
    if let Some(entries) = tuple_entries(ast, init_expr) {
        let mut values = Vec::new();
        for entry in &entries {
            let value = lower_value(*entry, ast, instrs, ctx);
            values.push(materialize_value(value, span, instrs, ctx));
        }
        for (idx, name) in names.iter().enumerate() {
            let value = values
                .get(idx)
                .cloned()
                .unwrap_or(IrValue::Unknown);
            let target = LValue::Var(IrVar::Named(name.clone()));
            emit_store_or_assign(&target, value, span, instrs);
        }
        return;
    }

    let _ = lower_value(init_expr, ast, instrs, ctx);
    for name in names {
        let target = LValue::Var(IrVar::Named(name.clone()));
        emit_store_or_assign(&target, IrValue::Unknown, span, instrs);
    }
}

fn lower_tuple_assign(
    entries: &[u32],
    rhs: u32,
    span: Span,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) {
    if let Some((expr, callee, args)) = call_expr(ast, rhs) {
        let mut temps = Vec::new();
        for _ in 0..entries.len() {
            temps.push(new_temp(ctx));
        }
        lower_call_with_dests(expr, callee, args, temps.clone(), span, ast, instrs, ctx);
        for (idx, lhs_entry) in entries.iter().enumerate() {
            let target = lower_lvalue(*lhs_entry, ast, instrs, ctx);
            let value = temps
                .get(idx)
                .cloned()
                .map(IrValue::Var)
                .unwrap_or(IrValue::Unknown);
            emit_store_or_assign(&target, value, span, instrs);
        }
        return;
    }
    if let Some(rhs_entries) = tuple_entries(ast, rhs) {
        let mut values = Vec::new();
        for entry in &rhs_entries {
            let value = lower_value(*entry, ast, instrs, ctx);
            values.push(materialize_value(value, span, instrs, ctx));
        }
        for (idx, lhs_entry) in entries.iter().enumerate() {
            let target = lower_lvalue(*lhs_entry, ast, instrs, ctx);
            let value = values
                .get(idx)
                .cloned()
                .unwrap_or(IrValue::Unknown);
            emit_store_or_assign(&target, value, span, instrs);
        }
        return;
    }

    let _ = lower_value(rhs, ast, instrs, ctx);
    for lhs_entry in entries {
        let target = lower_lvalue(*lhs_entry, ast, instrs, ctx);
        emit_store_or_assign(&target, IrValue::Unknown, span, instrs);
    }
}

fn tuple_entries(ast: &NormalizedAst, expr_id: u32) -> Option<Vec<u32>> {
    let expr = ast.expressions.get(expr_id as usize)?;
    match &expr.kind {
        ExprKind::Tuple(entries) => Some(entries.clone()),
        _ => None,
    }
}

fn emit_store_or_assign(
    target: &LValue,
    src: IrValue,
    span: Span,
    instrs: &mut Vec<IrInstr>,
) {
    match target {
        LValue::Var(var) => instrs.push(IrInstr::Assign {
            dest: var.clone(),
            src,
            span,
        }),
        LValue::Place(place) => instrs.push(IrInstr::Store {
            dest: place.clone(),
            src,
            span,
        }),
    }
}

fn lower_unary_update(
    expr_id: u32,
    op: &str,
    prefix: bool,
    span: Span,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> IrValue {
    let target = lower_lvalue(expr_id, ast, instrs, ctx);
    let current = match &target {
        LValue::Var(var) => IrValue::Var(var.clone()),
        LValue::Place(place) => load_place_value(place, span, instrs, ctx),
    };
    let one = IrValue::Literal(Literal {
        kind: "number".to_string(),
        value: "1".to_string(),
    });
    let temp = new_temp(ctx);
    let bin_op = if op == "++" { "+" } else { "-" };
    instrs.push(IrInstr::Binary {
        dest: temp.clone(),
        op: bin_op.to_string(),
        lhs: current.clone(),
        rhs: one,
        span,
    });
    let updated = IrValue::Var(temp.clone());
    emit_store_or_assign(&target, updated.clone(), span, instrs);
    if prefix {
        updated
    } else {
        current
    }
}

enum LValue {
    Var(IrVar),
    Place(IrPlace),
}

fn lower_lvalue(
    expr_id: u32,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> LValue {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return LValue::Var(new_temp(ctx));
    };

    match &expr.kind {
        ExprKind::Ident(name) => {
            let var = IrVar::Named(name.clone());
            if is_storage_ident(name, ctx) {
                LValue::Place(IrPlace::Var {
                    var,
                    class: PlaceClass::Storage,
                })
            } else {
                LValue::Var(var)
            }
        }
        ExprKind::Member { base, field } => {
            let base_val = lower_place_base_value(*base, ast, instrs, ctx);
            let root = root_name_for_place(ast, expr_id, ctx.contract_name);
            let class = class_for_root(root.as_ref(), &base_val, ctx);
            LValue::Place(IrPlace::Member {
                base: base_val,
                field: field.clone(),
                root,
                class,
            })
        }
        ExprKind::Index { base, index } => {
            let base_val = lower_place_base_value(*base, ast, instrs, ctx);
            let index_val = index.map(|id| lower_value(id, ast, instrs, ctx));
            let root = root_name_for_place(ast, expr_id, ctx.contract_name);
            let class = class_for_root(root.as_ref(), &base_val, ctx);
            LValue::Place(IrPlace::Index {
                base: base_val,
                index: index_val,
                root,
                class,
            })
        }
        _ => LValue::Var(new_temp(ctx)),
    }
}

fn lower_place_base_value(
    expr_id: u32,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> IrValue {
    let Some(expr) = ast.expressions.get(expr_id as usize) else {
        return IrValue::Unknown;
    };
    match &expr.kind {
        ExprKind::Ident(name) => IrValue::Var(IrVar::Named(name.clone())),
        _ => lower_value(expr_id, ast, instrs, ctx),
    }
}

fn place_from_ident(name: &str, ctx: &LowerCtx) -> IrPlace {
    let class = class_for_ident(name, ctx);
    IrPlace::Var {
        var: IrVar::Named(name.to_string()),
        class,
    }
}

fn class_for_ident(name: &str, ctx: &LowerCtx) -> PlaceClass {
    match ctx.symbols.resolve(name) {
        NameResolution::State => PlaceClass::Storage,
        NameResolution::Local => PlaceClass::Memory,
        NameResolution::Unknown => PlaceClass::Unknown,
    }
}

fn class_for_root(root: Option<&String>, base: &IrValue, ctx: &LowerCtx) -> PlaceClass {
    if is_contract_receiver_value(base, ctx.contract_name) {
        return PlaceClass::Storage;
    }
    let Some(root) = root else {
        return PlaceClass::Unknown;
    };
    class_for_ident(root, ctx)
}

fn is_storage_ident(name: &str, ctx: &LowerCtx) -> bool {
    matches!(ctx.symbols.resolve(name), NameResolution::State)
}

fn load_place_value(
    place: &IrPlace,
    span: Span,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> IrValue {
    match place {
        IrPlace::Var { var, class } => match class {
            PlaceClass::Storage => {
                let temp = new_temp(ctx);
                instrs.push(IrInstr::Load {
                    dest: temp.clone(),
                    src: place.clone(),
                    span,
                });
                IrValue::Var(temp)
            }
            PlaceClass::Memory | PlaceClass::Unknown => IrValue::Var(var.clone()),
        },
        _ => {
            let temp = new_temp(ctx);
            instrs.push(IrInstr::Load {
                dest: temp.clone(),
                src: place.clone(),
                span,
            });
            IrValue::Var(temp)
        }
    }
}

fn new_temp(ctx: &mut LowerCtx) -> IrVar {
    let id = ctx.temp_counter;
    ctx.temp_counter += 1;
    IrVar::Temp(id)
}

fn unwrap_call_options(ast: &NormalizedAst, expr_id: u32) -> (u32, Vec<CallOption>) {
    let mut current = expr_id;
    let mut options = Vec::new();
    loop {
        let Some(expr) = ast.expressions.get(current as usize) else {
            break;
        };
        if let ExprKind::CallOptions { callee, options: opts } = &expr.kind {
            options.extend(opts.clone());
            current = *callee;
        } else {
            break;
        }
    }
    (current, options)
}

fn lower_call_options(
    ast: &NormalizedAst,
    options: &[CallOption],
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> Vec<IrCallOption> {
    options
        .iter()
        .map(|opt| match opt {
            CallOption::Value(expr) => IrCallOption::Value(lower_value(*expr, ast, instrs, ctx)),
            CallOption::Gas(expr) => IrCallOption::Gas(lower_value(*expr, ast, instrs, ctx)),
            CallOption::Salt(expr) => IrCallOption::Salt(lower_value(*expr, ast, instrs, ctx)),
        })
        .collect()
}

fn lower_call_with_dests(
    expr: &crate::norm::Expr,
    callee_id: u32,
    args: &[u32],
    dests: Vec<IrVar>,
    span: Span,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) {
    let (callee_id, options) = resolve_call(ast, expr, callee_id);
    let callee_val = lower_callee_value(expr, callee_id, ast, instrs, ctx);
    let args_val = args
        .iter()
        .map(|arg| lower_value(*arg, ast, instrs, ctx))
        .collect();
    let options_val = lower_call_options(ast, &options, instrs, ctx);
    instrs.push(IrInstr::Call {
        dest: dests,
        callee: callee_val,
        args: args_val,
        options: options_val,
        span,
    });
}

fn resolve_call(
    ast: &NormalizedAst,
    expr: &crate::norm::Expr,
    callee_id: u32,
) -> (u32, Vec<CallOption>) {
    let (callee_id, mut options) = unwrap_call_options(ast, callee_id);
    if options.is_empty() {
        if let Some(call) = expr.meta.call.as_ref() {
            if !call.options.is_empty() {
                options = call.options.clone();
            }
        }
    }
    (callee_id, options)
}

fn lower_callee_value(
    expr: &crate::norm::Expr,
    callee_id: u32,
    ast: &NormalizedAst,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> IrValue {
    let value = lower_value(callee_id, ast, instrs, ctx);
    if matches!(value, IrValue::Unknown) {
        if let Some(fallback) = call_target_value(expr) {
            return fallback;
        }
    }
    value
}

fn call_target_value(expr: &crate::norm::Expr) -> Option<IrValue> {
    let call = expr.meta.call.as_ref()?;
    match &call.target {
        crate::norm::CallTarget::Direct { name } => {
            Some(IrValue::Var(IrVar::Named(name.clone())))
        }
        crate::norm::CallTarget::Member { receiver, name } => {
            let mut full = receiver.join(".");
            if !full.is_empty() {
                full.push('.');
            }
            full.push_str(name);
            Some(IrValue::Var(IrVar::Named(full)))
        }
        crate::norm::CallTarget::Unknown => None,
    }
}

fn call_expr<'a>(
    ast: &'a NormalizedAst,
    expr_id: u32,
) -> Option<(&'a crate::norm::Expr, u32, &'a [u32])> {
    let expr = ast.expressions.get(expr_id as usize)?;
    match &expr.kind {
        ExprKind::Call { callee, args } => Some((expr, *callee, args.as_slice())),
        _ => None,
    }
}

fn is_revert_call(expr: &crate::norm::Expr, ast: &NormalizedAst) -> bool {
    let ExprKind::Call { callee, .. } = &expr.kind else {
        return false;
    };
    if let Some(callee_expr) = ast.expressions.get(*callee as usize) {
        if let ExprKind::Ident(name) = &callee_expr.kind {
            return name == "revert";
        }
    }
    match expr.meta.call.as_ref().map(|call| &call.target) {
        Some(crate::norm::CallTarget::Direct { name }) => name == "revert",
        _ => false,
    }
}

fn materialize_value(
    value: IrValue,
    span: Span,
    instrs: &mut Vec<IrInstr>,
    ctx: &mut LowerCtx,
) -> IrValue {
    match value {
        IrValue::Var(IrVar::Named(_)) => {
            let temp = new_temp(ctx);
            instrs.push(IrInstr::Assign {
                dest: temp.clone(),
                src: value,
                span,
            });
            IrValue::Var(temp)
        }
        IrValue::Var(IrVar::Temp(_)) | IrValue::Literal(_) => value,
        IrValue::Unknown => IrValue::Unknown,
    }
}

fn root_name_for_place(
    ast: &NormalizedAst,
    expr_id: u32,
    contract_name: Option<&str>,
) -> Option<String> {
    let expr = ast.expressions.get(expr_id as usize)?;
    match &expr.kind {
        ExprKind::Ident(name) => Some(name.clone()),
        ExprKind::Member { base, field } => {
            if is_contract_receiver_expr(ast, *base, contract_name) {
                Some(field.clone())
            } else {
                root_name_for_place(ast, *base, contract_name)
            }
        }
        ExprKind::Index { base, .. } => root_name_for_place(ast, *base, contract_name),
        _ => None,
    }
}

fn is_contract_receiver_expr(
    ast: &NormalizedAst,
    expr_id: u32,
    contract_name: Option<&str>,
) -> bool {
    let expr = match ast.expressions.get(expr_id as usize) {
        Some(expr) => expr,
        None => return false,
    };
    match &expr.kind {
        ExprKind::Ident(name) => {
            if name == "this" || name == "super" {
                return true;
            }
            contract_name.map(|value| value == name).unwrap_or(false)
        }
        _ => false,
    }
}

fn is_contract_receiver_value(value: &IrValue, contract_name: Option<&str>) -> bool {
    match value {
        IrValue::Var(IrVar::Named(name)) => {
            if name == "this" || name == "super" {
                return true;
            }
            contract_name.map(|value| value == name).unwrap_or(false)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::norm::{
        Expr, ExprKind, ExprMeta, Function, FunctionKind, Literal, Mutability, NormalizedAst,
        SourceFile, Span, Stmt, StmtKind, Visibility,
    };

    #[test]
    fn lowers_tuple_var_decl() {
        let mut ast = new_ast();
        let lit1 = push_expr(&mut ast, ExprKind::Literal(Literal {
            kind: "number".to_string(),
            value: "1".to_string(),
        }));
        let lit2 = push_expr(&mut ast, ExprKind::Literal(Literal {
            kind: "number".to_string(),
            value: "2".to_string(),
        }));
        let tuple = push_expr(&mut ast, ExprKind::Tuple(vec![lit1, lit2]));
        let stmt = push_stmt(
            &mut ast,
            StmtKind::VarDecl {
                names: vec!["a".to_string(), "b".to_string()],
                init: Some(tuple),
            },
        );
        let body = push_stmt(&mut ast, StmtKind::Block(vec![stmt]));
        push_function(&mut ast, "f", body);

        let module = lower_module(&ast);
        let instrs = &module.functions[0].blocks[0].instrs;
        let mut assigns = Vec::new();
        for instr in instrs {
            if let IrInstr::Assign {
                dest: IrVar::Named(name),
                src: IrValue::Literal(lit),
                ..
            } = instr
            {
                assigns.push((name.clone(), lit.value.clone()));
            }
        }
        assert!(assigns.contains(&("a".to_string(), "1".to_string())));
        assert!(assigns.contains(&("b".to_string(), "2".to_string())));
    }

    #[test]
    fn lowers_tuple_assignment() {
        let mut ast = new_ast();
        let lhs_a = push_expr(&mut ast, ExprKind::Ident("a".to_string()));
        let lhs_b = push_expr(&mut ast, ExprKind::Ident("b".to_string()));
        let lhs = push_expr(&mut ast, ExprKind::Tuple(vec![lhs_a, lhs_b]));
        let rhs1 = push_expr(&mut ast, ExprKind::Literal(Literal {
            kind: "number".to_string(),
            value: "3".to_string(),
        }));
        let rhs2 = push_expr(&mut ast, ExprKind::Literal(Literal {
            kind: "number".to_string(),
            value: "4".to_string(),
        }));
        let rhs = push_expr(&mut ast, ExprKind::Tuple(vec![rhs1, rhs2]));
        let assign = push_expr(
            &mut ast,
            ExprKind::Assign {
                op: "=".to_string(),
                lhs,
                rhs,
            },
        );
        let stmt = push_stmt(&mut ast, StmtKind::Expr(assign));
        let body = push_stmt(&mut ast, StmtKind::Block(vec![stmt]));
        push_function(&mut ast, "g", body);

        let module = lower_module(&ast);
        let instrs = &module.functions[0].blocks[0].instrs;
        let mut assigns = Vec::new();
        for instr in instrs {
            if let IrInstr::Assign {
                dest: IrVar::Named(name),
                src: IrValue::Literal(lit),
                ..
            } = instr
            {
                assigns.push((name.clone(), lit.value.clone()));
            }
        }
        assert!(assigns.contains(&("a".to_string(), "3".to_string())));
        assert!(assigns.contains(&("b".to_string(), "4".to_string())));
    }

    fn new_ast() -> NormalizedAst {
        NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: String::new(),
        }])
    }

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 0,
        }
    }

    fn push_expr(ast: &mut NormalizedAst, kind: ExprKind) -> u32 {
        let id = ast.expressions.len() as u32;
        ast.expressions.push(Expr {
            kind,
            span: span(),
            meta: ExprMeta::default(),
        });
        id
    }

    fn push_stmt(ast: &mut NormalizedAst, kind: StmtKind) -> u32 {
        let id = ast.statements.len() as u32;
        ast.statements.push(Stmt { kind, span: span() });
        id
    }

    fn push_function(ast: &mut NormalizedAst, name: &str, body: u32) -> u32 {
        let id = ast.functions.len() as u32;
        ast.functions.push(Function {
            id,
            contract: None,
            name: Some(name.to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: Some(body),
            span: span(),
        });
        id
    }
}
