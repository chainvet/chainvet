//! ChainVet frontend: load Solidity into a `chainvet_core::norm::NormalizedAst`.
//!
//! Primary path is the solc compiler; fallback is the tree-sitter parser; an
//! optional third tier (env-gated) enriches a partial AST via a local LLM.
pub mod frontend;
