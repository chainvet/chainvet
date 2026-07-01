//! Chainvet frontend: load Solidity into a `chainvet_core::norm::NormalizedAst`.
//!
//! Primary path is the solc compiler; fallback is the tree-sitter parser; an
//! optional third tier (env-gated) enriches a partial AST via a local LLM.

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

pub mod frontend;
