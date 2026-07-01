//! Chainvet core: the shared types every engine and frontend agrees on.
//!
//! Normalized AST (`norm`), the SlithIR-style instruction set (`ir`), control-flow
//! graphs (`cfg`), SSA form (`ssa`), the finding/report model (`artifacts`), and
//! error types (`util`). Pure data and lowering — no engine logic, no I/O.

// Style/complexity clippy lints tolerated across this crate's hand-written
// analysis code (index-based token/graph loops, multi-parameter engine entry
// points, match-arm shapes). Correctness lints stay enforced (-D warnings).
#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::needless_range_loop,
    clippy::manual_find,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::question_mark,
    clippy::while_let_loop,
    clippy::field_reassign_with_default,
    clippy::manual_checked_ops
)]

pub mod artifacts;
pub mod cfg;
pub mod ir;
pub mod norm;
pub mod ssa;
pub mod util;

/// How a frontend renders results. Shared so engines can accept a requested
/// format without depending on any particular frontend's rendering crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}
