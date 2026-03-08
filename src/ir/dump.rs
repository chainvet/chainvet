use std::fmt::Write;

use super::{
    ControlKind, IrBlock, IrCallOption, IrFunction, IrInstr, IrModule, IrPlace, IrValue, IrVar,
    PlaceClass,
};

#[derive(Debug, Clone, Copy)]
pub enum DumpFormat {
    Text,
    Json,
    Tuple,
}

pub fn dump_module(module: &IrModule, format: DumpFormat) -> String {
    match format {
        DumpFormat::Text => dump_text(module),
        DumpFormat::Json => match serde_json::to_string_pretty(module) {
            Ok(payload) => payload,
            Err(err) => format!("{{\"error\":\"{err}\"}}"),
        },
        DumpFormat::Tuple => dump_tuple(module),
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

fn dump_tuple(module: &IrModule) -> String {
    let mut out = String::new();
    for func in &module.functions {
        let header = fmt_function_header(func);
        let _ = writeln!(out, "fn {header} {{");
        for block in &func.blocks {
            let _ = writeln!(out, "  block {}:", block.id);
            for instr in &block.instrs {
                let _ = writeln!(out, "    {}", fmt_tuple_instr(instr));
            }
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

fn fmt_tuple_instr(instr: &IrInstr) -> String {
    match instr {
        IrInstr::Nop { .. } => "(\"nop\")".to_string(),
        IrInstr::Eval { expr, .. } => format!("(\"eval\", {})", fmt_tuple_value(expr)),
        IrInstr::Declare { names, init, .. } => match init {
            Some(init) => format!(
                "(\"declare\", {}, {})",
                fmt_tuple_string_list(names),
                fmt_tuple_value(init)
            ),
            None => format!("(\"declare\", {})", fmt_tuple_string_list(names)),
        },
        IrInstr::Assign { dest, src, .. } => {
            format!(
                "(\"assign\", {}, {})",
                fmt_tuple_var(dest),
                fmt_tuple_value(src)
            )
        }
        IrInstr::Store { dest, src, .. } => {
            format!(
                "(\"store\", {}, {})",
                fmt_tuple_place(dest),
                fmt_tuple_value(src)
            )
        }
        IrInstr::Load { dest, src, .. } => {
            format!(
                "(\"load\", {}, {})",
                fmt_tuple_var(dest),
                fmt_tuple_place(src)
            )
        }
        IrInstr::Binary {
            dest, op, lhs, rhs, ..
        } => format!(
            "(\"binary\", {}, {}, {}, {})",
            fmt_tuple_var(dest),
            fmt_tuple_string(op),
            fmt_tuple_value(lhs),
            fmt_tuple_value(rhs)
        ),
        IrInstr::Unary {
            dest,
            op,
            expr,
            prefix,
            ..
        } => format!(
            "(\"unary\", {}, {}, {}, {})",
            fmt_tuple_var(dest),
            fmt_tuple_string(op),
            fmt_tuple_value(expr),
            prefix
        ),
        IrInstr::Call {
            dest,
            callee,
            args,
            options,
            ..
        } => format!(
            "(\"call\", {}, {}, {}, {})",
            fmt_tuple_var_list(dest),
            fmt_tuple_value(callee),
            fmt_tuple_value_list(args),
            fmt_tuple_call_options(options)
        ),
        IrInstr::Select {
            dest,
            cond,
            then_val,
            else_val,
            ..
        } => format!(
            "(\"select\", {}, {}, {}, {})",
            fmt_tuple_var(dest),
            fmt_tuple_value(cond),
            fmt_tuple_value(then_val),
            fmt_tuple_value(else_val)
        ),
        IrInstr::Emit { expr, .. } => format!("(\"emit\", {})", fmt_tuple_value(expr)),
        IrInstr::Return { values, .. } => {
            format!("(\"return\", {})", fmt_tuple_value_list(values))
        }
        IrInstr::Control { kind, .. } => format!("(\"control\", {})", fmt_tuple_control(kind)),
        IrInstr::InlineAsm { language, .. } => match language {
            Some(language) => format!("(\"inline_asm\", {})", fmt_tuple_string(language)),
            None => "(\"inline_asm\")".to_string(),
        },
    }
}

fn fmt_tuple_control(kind: &ControlKind) -> String {
    match kind {
        ControlKind::If { cond } => format!("(\"if\", {})", fmt_tuple_value(cond)),
        ControlKind::Else => "(\"else\")".to_string(),
        ControlKind::EndIf => "(\"endif\")".to_string(),
        ControlKind::Loop { cond } => match cond {
            Some(cond) => format!("(\"loop\", {})", fmt_tuple_value(cond)),
            None => "(\"loop\")".to_string(),
        },
        ControlKind::EndLoop => "(\"endloop\")".to_string(),
        ControlKind::Break => "(\"break\")".to_string(),
        ControlKind::Continue => "(\"continue\")".to_string(),
        ControlKind::Revert { value } => match value {
            Some(value) => format!("(\"revert\", {})", fmt_tuple_value(value)),
            None => "(\"revert\")".to_string(),
        },
        ControlKind::Try => "(\"try\")".to_string(),
        ControlKind::Catch => "(\"catch\")".to_string(),
        ControlKind::EndTry => "(\"endtry\")".to_string(),
    }
}

fn fmt_value(value: &IrValue) -> String {
    match value {
        IrValue::Var(var) => fmt_var(var),
        IrValue::Literal(lit) => format!("{}({})", lit.kind, lit.value),
        IrValue::Unknown => "unknown".to_string(),
    }
}

fn fmt_tuple_value(value: &IrValue) -> String {
    match value {
        IrValue::Var(var) => format!("(\"var\", {})", fmt_tuple_var(var)),
        IrValue::Literal(lit) => format!(
            "(\"lit\", {}, {})",
            fmt_tuple_string(&lit.kind),
            fmt_tuple_string(&lit.value)
        ),
        IrValue::Unknown => "(\"unknown\")".to_string(),
    }
}

fn fmt_var(var: &IrVar) -> String {
    match var {
        IrVar::Named(name) => name.clone(),
        IrVar::Temp(id) => format!("t{}", id),
    }
}

fn fmt_tuple_var(var: &IrVar) -> String {
    match var {
        IrVar::Named(name) => format!("(\"named\", {})", fmt_tuple_string(name)),
        IrVar::Temp(id) => format!("(\"temp\", {id})"),
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

fn fmt_tuple_place(place: &IrPlace) -> String {
    match place {
        IrPlace::Var { var, class } => format!(
            "(\"place_var\", {}, {})",
            fmt_tuple_var(var),
            fmt_tuple_string(fmt_class_name(*class))
        ),
        IrPlace::Member {
            base,
            field,
            root,
            class,
        } => format!(
            "(\"place_member\", {}, {}, {}, {})",
            fmt_tuple_value(base),
            fmt_tuple_string(field),
            fmt_tuple_optional_string(root.as_deref()),
            fmt_tuple_string(fmt_class_name(*class))
        ),
        IrPlace::Index {
            base,
            index,
            root,
            class,
        } => format!(
            "(\"place_index\", {}, {}, {}, {})",
            fmt_tuple_value(base),
            fmt_tuple_optional_value(index.as_ref()),
            fmt_tuple_optional_string(root.as_deref()),
            fmt_tuple_string(fmt_class_name(*class))
        ),
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

fn fmt_tuple_call_options(options: &[IrCallOption]) -> String {
    format!("[{}]", fmt_list(options, fmt_tuple_call_option))
}

fn fmt_tuple_call_option(option: &IrCallOption) -> String {
    match option {
        IrCallOption::Value(value) => format!("(\"value\", {})", fmt_tuple_value(value)),
        IrCallOption::Gas(value) => format!("(\"gas\", {})", fmt_tuple_value(value)),
        IrCallOption::Salt(value) => format!("(\"salt\", {})", fmt_tuple_value(value)),
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

fn fmt_tuple_string(value: &str) -> String {
    format!("{value:?}")
}

fn fmt_tuple_string_list(values: &[String]) -> String {
    format!("[{}]", fmt_list(values, |value| fmt_tuple_string(value)))
}

fn fmt_tuple_var_list(vars: &[IrVar]) -> String {
    format!("[{}]", fmt_list(vars, fmt_tuple_var))
}

fn fmt_tuple_value_list(values: &[IrValue]) -> String {
    format!("[{}]", fmt_list(values, fmt_tuple_value))
}

fn fmt_tuple_optional_value(value: Option<&IrValue>) -> String {
    match value {
        Some(value) => fmt_tuple_value(value),
        None => "null".to_string(),
    }
}

fn fmt_tuple_optional_string(value: Option<&str>) -> String {
    match value {
        Some(value) => fmt_tuple_string(value),
        None => "null".to_string(),
    }
}

fn fmt_class_suffix(class: PlaceClass) -> &'static str {
    match class {
        PlaceClass::Storage => "@storage",
        PlaceClass::Memory => "@memory",
        PlaceClass::Unknown => "@unknown",
    }
}

fn fmt_class_name(class: PlaceClass) -> &'static str {
    match class {
        PlaceClass::Storage => "storage",
        PlaceClass::Memory => "memory",
        PlaceClass::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::norm::{Literal, Span};

    #[test]
    fn tuple_dump_uses_literal_tuple_notation() {
        let span = span();
        let module = IrModule {
            functions: vec![IrFunction {
                id: 0,
                name: Some("calc".to_string()),
                source: Some(7),
                span,
                blocks: vec![IrBlock {
                    id: 0,
                    instrs: vec![
                        IrInstr::Load {
                            dest: IrVar::Temp(0),
                            src: IrPlace::Var {
                                var: IrVar::Named("counter".to_string()),
                                class: PlaceClass::Storage,
                            },
                            span,
                        },
                        IrInstr::Binary {
                            dest: IrVar::Temp(1),
                            op: "+".to_string(),
                            lhs: IrValue::Var(IrVar::Named("x".to_string())),
                            rhs: IrValue::Var(IrVar::Temp(0)),
                            span,
                        },
                        IrInstr::Store {
                            dest: IrPlace::Member {
                                base: IrValue::Var(IrVar::Temp(1)),
                                field: "score".to_string(),
                                root: None,
                                class: PlaceClass::Unknown,
                            },
                            src: IrValue::Literal(Literal {
                                kind: "number".to_string(),
                                value: "1".to_string(),
                            }),
                            span,
                        },
                        IrInstr::Call {
                            dest: vec![IrVar::Temp(2)],
                            callee: IrValue::Var(IrVar::Named("foo".to_string())),
                            args: vec![IrValue::Unknown],
                            options: vec![IrCallOption::Value(IrValue::Literal(Literal {
                                kind: "number".to_string(),
                                value: "1".to_string(),
                            }))],
                            span,
                        },
                        IrInstr::Control {
                            kind: ControlKind::If {
                                cond: IrValue::Var(IrVar::Temp(1)),
                            },
                            span,
                        },
                        IrInstr::InlineAsm {
                            language: None,
                            span,
                        },
                    ],
                }],
            }],
        };

        let dump = dump_module(&module, DumpFormat::Tuple);
        let expected = concat!(
            "fn calc (id 0, source 7) {\n",
            "  block 0:\n",
            "    (\"load\", (\"temp\", 0), (\"place_var\", (\"named\", \"counter\"), \"storage\"))\n",
            "    (\"binary\", (\"temp\", 1), \"+\", (\"var\", (\"named\", \"x\")), (\"var\", (\"temp\", 0)))\n",
            "    (\"store\", (\"place_member\", (\"var\", (\"temp\", 1)), \"score\", null, \"unknown\"), (\"lit\", \"number\", \"1\"))\n",
            "    (\"call\", [(\"temp\", 2)], (\"var\", (\"named\", \"foo\")), [(\"unknown\")], [(\"value\", (\"lit\", \"number\", \"1\"))])\n",
            "    (\"control\", (\"if\", (\"var\", (\"temp\", 1))))\n",
            "    (\"inline_asm\")\n",
            "}\n"
        );

        assert_eq!(dump, expected);
    }

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 0,
        }
    }
}
