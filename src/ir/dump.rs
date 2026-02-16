use std::fmt::Write;

use super::{
    ControlKind, IrBlock, IrCallOption, IrFunction, IrInstr, IrModule, IrPlace, IrValue, IrVar,
    PlaceClass,
};

#[derive(Debug, Clone, Copy)]
pub enum DumpFormat {
    Text,
    Json,
}

pub fn dump_module(module: &IrModule, format: DumpFormat) -> String {
    match format {
        DumpFormat::Text => dump_text(module),
        DumpFormat::Json => match serde_json::to_string_pretty(module) {
            Ok(payload) => payload,
            Err(err) => format!("{{\"error\":\"{err}\"}}"),
        },
    }
}

fn dump_text(module: &IrModule) -> String {
    let mut out = String::new();
    for func in &module.functions {
        let header = fmt_function_header(func);
        let _ = writeln!(out, "fn {header} {{");
        for block in &func.blocks {
            dump_block(block, &mut out);
        }
        let _ = writeln!(out, "}}");
    }
    out
}

fn dump_block(block: &IrBlock, out: &mut String) {
    let _ = writeln!(out, "  block {}:", block.id);
    for instr in &block.instrs {
        let _ = writeln!(out, "    {}", fmt_instr(instr));
    }
}

fn fmt_function_header(func: &IrFunction) -> String {
    let name = func.name.as_deref().unwrap_or("<anon>");
    match func.source {
        Some(source) => format!("{name} (id {}, source {})", func.id, source),
        None => format!("{name} (id {})", func.id),
    }
}

fn fmt_instr(instr: &IrInstr) -> String {
    match instr {
        IrInstr::Nop { .. } => "nop".to_string(),
        IrInstr::Eval { expr, .. } => format!("eval {}", fmt_value(expr)),
        IrInstr::Declare { names, init, .. } => {
            if let Some(init) = init {
                format!("declare {} = {}", names.join(", "), fmt_value(init))
            } else {
                format!("declare {}", names.join(", "))
            }
        }
        IrInstr::Assign { dest, src, .. } => format!("{} = {}", fmt_var(dest), fmt_value(src)),
        IrInstr::Store { dest, src, .. } => {
            format!("store {} = {}", fmt_place(dest), fmt_value(src))
        }
        IrInstr::Load { dest, src, .. } => format!("{} = load {}", fmt_var(dest), fmt_place(src)),
        IrInstr::Binary {
            dest, op, lhs, rhs, ..
        } => format!(
            "{} = {} {} {}",
            fmt_var(dest),
            fmt_value(lhs),
            op,
            fmt_value(rhs)
        ),
        IrInstr::Unary {
            dest,
            op,
            expr,
            prefix,
            ..
        } => {
            if *prefix {
                format!("{} = {}{}", fmt_var(dest), op, fmt_value(expr))
            } else {
                format!("{} = {}{}", fmt_var(dest), fmt_value(expr), op)
            }
        }
        IrInstr::Call {
            dest,
            callee,
            args,
            options,
            ..
        } => {
            let prefix = if dest.is_empty() {
                String::new()
            } else {
                let names = fmt_list(dest, fmt_var);
                format!("{names} = ")
            };
            let args = fmt_list(args, fmt_value);
            let options = fmt_call_options(options);
            format!("{prefix}call {}({}){}", fmt_value(callee), args, options)
        }
        IrInstr::Select {
            dest,
            cond,
            then_val,
            else_val,
            ..
        } => format!(
            "{} = select {} ? {} : {}",
            fmt_var(dest),
            fmt_value(cond),
            fmt_value(then_val),
            fmt_value(else_val)
        ),
        IrInstr::Emit { expr, .. } => format!("emit {}", fmt_value(expr)),
        IrInstr::Return { values, .. } => {
            if values.is_empty() {
                "return".to_string()
            } else {
                format!("return {}", fmt_list(values, fmt_value))
            }
        }
        IrInstr::Control { kind, .. } => fmt_control(kind),
        IrInstr::InlineAsm { language, .. } => match language {
            Some(language) => format!("inline-asm {}", language),
            None => "inline-asm".to_string(),
        },
    }
}

fn fmt_control(kind: &ControlKind) -> String {
    match kind {
        ControlKind::If { cond } => format!("if {}", fmt_value(cond)),
        ControlKind::Else => "else".to_string(),
        ControlKind::EndIf => "endif".to_string(),
        ControlKind::Loop { cond } => match cond {
            Some(cond) => format!("loop {}", fmt_value(cond)),
            None => "loop".to_string(),
        },
        ControlKind::EndLoop => "endloop".to_string(),
        ControlKind::Break => "break".to_string(),
        ControlKind::Continue => "continue".to_string(),
        ControlKind::Revert { value } => match value {
            Some(value) => format!("revert {}", fmt_value(value)),
            None => "revert".to_string(),
        },
        ControlKind::Try => "try".to_string(),
        ControlKind::Catch => "catch".to_string(),
        ControlKind::EndTry => "endtry".to_string(),
    }
}

fn fmt_value(value: &IrValue) -> String {
    match value {
        IrValue::Var(var) => fmt_var(var),
        IrValue::Literal(lit) => format!("{}({})", lit.kind, lit.value),
        IrValue::Unknown => "unknown".to_string(),
    }
}

fn fmt_var(var: &IrVar) -> String {
    match var {
        IrVar::Named(name) => name.clone(),
        IrVar::Temp(id) => format!("t{}", id),
    }
}

fn fmt_place(place: &IrPlace) -> String {
    match place {
        IrPlace::Var { var, class } => {
            format!("{}{}", fmt_var(var), fmt_class_suffix(*class))
        }
        IrPlace::Member {
            base,
            field,
            root,
            class,
        } => {
            let mut out = format!("{}.{}", fmt_value(base), field);
            if let Some(root) = root {
                let _ = write!(out, " [root={}]", root);
            }
            out.push_str(fmt_class_suffix(*class));
            out
        }
        IrPlace::Index {
            base,
            index,
            root,
            class,
        } => {
            let index = index
                .as_ref()
                .map(fmt_value)
                .unwrap_or_else(|| "_".to_string());
            let mut out = format!("{}[{}]", fmt_value(base), index);
            if let Some(root) = root {
                let _ = write!(out, " [root={}]", root);
            }
            out.push_str(fmt_class_suffix(*class));
            out
        }
    }
}

fn fmt_call_options(options: &[IrCallOption]) -> String {
    if options.is_empty() {
        return String::new();
    }
    let parts = fmt_list(options, fmt_call_option);
    format!(" {{ {parts} }}")
}

fn fmt_call_option(option: &IrCallOption) -> String {
    match option {
        IrCallOption::Value(value) => format!("value={}", fmt_value(value)),
        IrCallOption::Gas(value) => format!("gas={}", fmt_value(value)),
        IrCallOption::Salt(value) => format!("salt={}", fmt_value(value)),
    }
}

fn fmt_list<T, F>(items: &[T], mut fmt: F) -> String
where
    F: FnMut(&T) -> String,
{
    let mut out = String::new();
    for (idx, item) in items.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&fmt(item));
    }
    out
}

fn fmt_class_suffix(class: PlaceClass) -> &'static str {
    match class {
        PlaceClass::Storage => "@storage",
        PlaceClass::Memory => "@memory",
        PlaceClass::Unknown => "@unknown",
    }
}
