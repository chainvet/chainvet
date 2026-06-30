//! ChainVet AI adapter: a tiny, dependency-light client for a local LLM.
//!
//! Transport only — no analysis types, no finding model — so both the frontend
//! (AST-enrichment fallback) and the orchestrator (report review) can share one
//! Ollama client without creating a dependency cycle. Everything here is opt-in
//! and degrades to an error string the caller treats as "AI unavailable".
pub mod ollama;
