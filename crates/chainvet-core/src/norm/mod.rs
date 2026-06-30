pub type FileId = u32;
pub type ItemId = u32;
pub type ContractId = u32;
pub type FunctionId = u32;
pub type StateVarId = u32;
pub type ModifierId = u32;
pub type EventId = u32;
pub type ErrorId = u32;
pub type TypeId = u32;
pub type VarId = u32;
pub type StmtId = u32;
pub type ExprId = u32;

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq, Hash)]
pub struct Span {
    pub file: FileId,
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub id: FileId,
    pub path: String,
    pub source: String,
}

#[derive(Debug, Default, Clone)]
pub struct NormalizedAst {
    pub files: Vec<SourceFile>,
    pub items: Vec<Item>,
    pub contracts: Vec<Contract>,
    pub functions: Vec<Function>,
    pub state_vars: Vec<StateVariable>,
    pub modifiers: Vec<Modifier>,
    pub events: Vec<Event>,
    pub errors: Vec<ErrorDefinition>,
    pub statements: Vec<Stmt>,
    pub expressions: Vec<Expr>,
}

impl NormalizedAst {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_sources(files: Vec<SourceFile>) -> Self {
        Self {
            files,
            items: Vec::new(),
            contracts: Vec::new(),
            functions: Vec::new(),
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            statements: Vec::new(),
            expressions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Item {
    Contract(ContractId),
    Function(FunctionId),
    StateVar(StateVarId),
    Modifier(ModifierId),
    Event(EventId),
    Error(ErrorId),
    Struct(ItemId),
    Enum(ItemId),
}

#[derive(Debug, Clone)]
pub struct Contract {
    pub id: ContractId,
    pub name: String,
    pub kind: ContractKind,
    pub bases: Vec<ContractBase>,
    pub functions: Vec<FunctionId>,
    pub state_vars: Vec<StateVarId>,
    pub modifiers: Vec<ModifierId>,
    pub events: Vec<EventId>,
    pub errors: Vec<ErrorId>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ContractBase {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub id: FunctionId,
    pub contract: Option<ContractId>,
    pub name: Option<String>,
    pub kind: FunctionKind,
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub params: Vec<String>,
    pub returns: Vec<String>,
    pub modifiers: Vec<String>,
    pub body: Option<StmtId>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct StateVariable {
    pub id: StateVarId,
    pub contract: ContractId,
    pub name: String,
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub constant: bool,
    pub immutable: bool,
    pub type_string: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Modifier {
    pub id: ModifierId,
    pub contract: ContractId,
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub id: EventId,
    pub contract: ContractId,
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ErrorDefinition {
    pub id: ErrorId,
    pub contract: Option<ContractId>,
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum StmtKind {
    Block(Vec<StmtId>),
    Expr(ExprId),
    Return(Option<ExprId>),
    If {
        cond: ExprId,
        then_id: StmtId,
        else_id: Option<StmtId>,
    },
    While {
        cond: ExprId,
        body: StmtId,
    },
    DoWhile {
        body: StmtId,
        cond: ExprId,
    },
    For {
        init: Option<StmtId>,
        cond: Option<ExprId>,
        step: Option<ExprId>,
        body: StmtId,
    },
    Emit(ExprId),
    Revert(Option<ExprId>),
    VarDecl {
        names: Vec<String>,
        init: Option<ExprId>,
    },
    Try {
        call: ExprId,
        clauses: Vec<TryClause>,
    },
    InlineAsm {
        language: Option<String>,
    },
    Break,
    Continue,
}

#[derive(Debug, Clone)]
pub struct TryClause {
    pub kind: String,
    pub name: Option<String>,
    pub params: Vec<String>,
    pub body: StmtId,
}

#[derive(Debug, Clone)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
    pub meta: ExprMeta,
}

#[derive(Debug, Clone)]
pub enum ExprKind {
    Literal(Literal),
    Ident(String),
    Member {
        base: ExprId,
        field: String,
    },
    Call {
        callee: ExprId,
        args: Vec<ExprId>,
    },
    CallOptions {
        callee: ExprId,
        options: Vec<CallOption>,
    },
    Binary {
        op: String,
        lhs: ExprId,
        rhs: ExprId,
    },
    Unary {
        op: String,
        expr: ExprId,
        prefix: bool,
    },
    Assign {
        op: String,
        lhs: ExprId,
        rhs: ExprId,
    },
    Index {
        base: ExprId,
        index: Option<ExprId>,
    },
    Tuple(Vec<ExprId>),
    Conditional {
        cond: ExprId,
        then_expr: ExprId,
        else_expr: ExprId,
    },
    New {
        type_name: String,
    },
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct ExprMeta {
    pub chain: Option<Vec<ChainSegment>>,
    pub call: Option<CallMeta>,
}

#[derive(Debug, Clone)]
pub enum ChainSegment {
    Ident(String),
    Member(String),
    Index,
    Call,
}

#[derive(Debug, Clone)]
pub struct CallMeta {
    pub target: CallTarget,
    pub chain: Vec<ChainSegment>,
    pub options: Vec<CallOption>,
}

#[derive(Debug, Clone)]
pub enum CallTarget {
    Direct { name: String },
    Member { receiver: Vec<String>, name: String },
    Unknown,
}

#[derive(Debug, Clone)]
pub enum CallOption {
    Value(ExprId),
    Gas(ExprId),
    Salt(ExprId),
}

#[derive(Debug, Clone, Serialize)]
pub struct Literal {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    Contract,
    Interface,
    Library,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionKind {
    Function,
    Constructor,
    Fallback,
    Receive,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    External,
    Internal,
    Private,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    Pure,
    View,
    Payable,
    NonPayable,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum Type {
    Unknown,
}
use serde::Serialize;

pub mod symbols;
