pub mod dump;
pub mod lower;

pub use dump::{DumpFormat, dump_module};
pub use lower::lower_module;

use crate::norm::{Literal, Span};
use serde::Serialize;

pub type IrFunctionId = u32;
pub type IrBlockId = u32;

#[derive(Debug, Clone, Serialize)]
pub struct IrModule {
    pub functions: Vec<IrFunction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IrFunction {
    pub id: IrFunctionId,
    pub name: Option<String>,
    pub source: Option<u32>,
    pub span: Span,
    pub blocks: Vec<IrBlock>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IrBlock {
    pub id: IrBlockId,
    pub instrs: Vec<IrInstr>,
}

#[derive(Debug, Clone, Serialize)]
pub enum IrInstr {
    Nop {
        span: Span,
    },
    Eval {
        expr: IrValue,
        span: Span,
    },
    Declare {
        names: Vec<String>,
        init: Option<IrValue>,
        span: Span,
    },
    Assign {
        dest: IrVar,
        src: IrValue,
        span: Span,
    },
    Store {
        dest: IrPlace,
        src: IrValue,
        span: Span,
    },
    Load {
        dest: IrVar,
        src: IrPlace,
        span: Span,
    },
    Binary {
        dest: IrVar,
        op: String,
        lhs: IrValue,
        rhs: IrValue,
        span: Span,
    },
    Unary {
        dest: IrVar,
        op: String,
        expr: IrValue,
        prefix: bool,
        span: Span,
    },
    Call {
        dest: Vec<IrVar>,
        callee: IrValue,
        args: Vec<IrValue>,
        options: Vec<IrCallOption>,
        span: Span,
    },
    Select {
        dest: IrVar,
        cond: IrValue,
        then_val: IrValue,
        else_val: IrValue,
        span: Span,
    },
    Emit {
        expr: IrValue,
        span: Span,
    },
    Return {
        values: Vec<IrValue>,
        span: Span,
    },
    Control {
        kind: ControlKind,
        span: Span,
    },
    InlineAsm {
        language: Option<String>,
        span: Span,
    },
}

#[derive(Debug, Clone, Serialize)]
pub enum ControlKind {
    If { cond: IrValue },
    Else,
    EndIf,
    Loop { cond: Option<IrValue> },
    EndLoop,
    Break,
    Continue,
    Revert { value: Option<IrValue> },
    Try,
    Catch,
    EndTry,
}

#[derive(Debug, Clone, Serialize)]
pub enum IrVar {
    Named(String),
    Temp(u32),
}

#[derive(Debug, Clone, Serialize)]
pub enum IrValue {
    Var(IrVar),
    Literal(Literal),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PlaceClass {
    Storage,
    Memory,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub enum IrPlace {
    Var {
        var: IrVar,
        class: PlaceClass,
    },
    Member {
        base: IrValue,
        field: String,
        root: Option<String>,
        class: PlaceClass,
    },
    Index {
        base: IrValue,
        index: Option<IrValue>,
        root: Option<String>,
        class: PlaceClass,
    },
}

#[derive(Debug, Clone, Serialize)]
pub enum IrCallOption {
    Value(IrValue),
    Gas(IrValue),
    Salt(IrValue),
}
