use std::collections::HashSet;

use crate::norm::{Function, NormalizedAst, StmtKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameResolution {
    Local,
    State,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    pub locals: HashSet<String>,
    pub state_vars: HashSet<String>,
}

impl SymbolTable {
    pub fn resolve(&self, name: &str) -> NameResolution {
        if self.locals.contains(name) {
            NameResolution::Local
        } else if self.state_vars.contains(name) {
            NameResolution::State
        } else {
            NameResolution::Unknown
        }
    }
}

pub fn build_function_symbols(ast: &NormalizedAst, func: &Function) -> SymbolTable {
    let mut table = SymbolTable::default();
    table.state_vars = collect_state_vars(ast, func.contract);
    for name in &func.params {
        if !name.is_empty() {
            table.locals.insert(name.clone());
        }
    }
    for name in &func.returns {
        if !name.is_empty() {
            table.locals.insert(name.clone());
        }
    }
    if let Some(body) = func.body {
        collect_local_vars_stmt(body, ast, &mut table.locals);
    }
    table
}

fn collect_state_vars(ast: &NormalizedAst, contract_id: Option<u32>) -> HashSet<String> {
    let mut vars = HashSet::new();
    let Some(contract_id) = contract_id else {
        return vars;
    };
    for var in &ast.state_vars {
        if var.contract == contract_id {
            vars.insert(var.name.clone());
        }
    }
    vars
}

fn collect_local_vars_stmt(stmt_id: u32, ast: &NormalizedAst, vars: &mut HashSet<String>) {
    let Some(stmt) = ast.statements.get(stmt_id as usize) else {
        return;
    };
    match &stmt.kind {
        StmtKind::Block(stmts) => {
            for child in stmts {
                collect_local_vars_stmt(*child, ast, vars);
            }
        }
        StmtKind::If {
            then_id,
            else_id,
            ..
        } => {
            collect_local_vars_stmt(*then_id, ast, vars);
            if let Some(else_id) = else_id {
                collect_local_vars_stmt(*else_id, ast, vars);
            }
        }
        StmtKind::While { body, .. } => collect_local_vars_stmt(*body, ast, vars),
        StmtKind::DoWhile { body, .. } => collect_local_vars_stmt(*body, ast, vars),
        StmtKind::For { init, body, .. } => {
            if let Some(init) = init {
                collect_local_vars_stmt(*init, ast, vars);
            }
            collect_local_vars_stmt(*body, ast, vars);
        }
        StmtKind::Try { clauses, .. } => {
            for clause in clauses {
                if let Some(name) = &clause.name {
                    vars.insert(name.clone());
                }
                for param in &clause.params {
                    vars.insert(param.clone());
                }
                collect_local_vars_stmt(clause.body, ast, vars);
            }
        }
        StmtKind::VarDecl { names, .. } => {
            for name in names {
                vars.insert(name.clone());
            }
        }
        StmtKind::Expr(_)
        | StmtKind::Return(_)
        | StmtKind::Emit(_)
        | StmtKind::Revert(_)
        | StmtKind::InlineAsm { .. }
        | StmtKind::Break
        | StmtKind::Continue => {}
    }
}
