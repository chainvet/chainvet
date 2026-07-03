//! Chainvet LLM adapter: a tiny, dependency-light client for talking to a Large
//! Language Model.
//!
//! Transport only — no analysis types, no finding model — so both the frontend
//! (AST-enrichment fallback) and the orchestrator (report review) can share one
//! LLM client without creating a dependency cycle. Everything here is opt-in and
//! degrades to an error string the caller treats as "AI unavailable".
//!
//! # Adding a provider
//!
//! Today the only provider is [`providers::ollama`] (a local Ollama server). To
//! add another (e.g. a hosted API), add a module under [`providers`] whose
//! client implements [`LlmProvider`], reusing the shared [`http`] transport and
//! the [`parse_json_object`] / [`debug_enabled`] helpers. Callers depend only on
//! the trait, so nothing else in the crate — or its consumers — has to change.

pub mod http;
pub mod provider;
pub mod providers;

pub use provider::{LlmProvider, debug_enabled, parse_json_object};

// Convenience re-export so callers can keep writing `chainvet_llm::ollama::…`.
pub use providers::ollama;
