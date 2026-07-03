//! The provider-agnostic contract every LLM backend implements, plus the helpers
//! that are shared across providers (response parsing, debug gating).

use serde_json::Value;
use std::env;

/// Common prefix for every Chainvet LLM environment variable (`CHAINVET_LLM_*`).
pub const ENV_PREFIX: &str = "CHAINVET_LLM";

/// A one-shot, JSON-mode text generator backed by some LLM.
///
/// Consumers depend only on this trait, so selecting — or adding — a provider is
/// purely additive. Implementations own their own transport and configuration
/// (see [`crate::providers::ollama::OllamaConfig`] for the reference impl).
pub trait LlmProvider {
    /// Short, human-readable provider name, for logs and error messages.
    fn name(&self) -> &'static str;

    /// One-shot JSON-mode generation. Returns the model's response text, or an
    /// error string the caller can log and treat as "AI unavailable".
    fn generate(&self, prompt: &str) -> Result<String, String>;
}

/// Extract a JSON object from a possibly-noisy LLM response (models sometimes
/// wrap JSON in prose despite being asked for JSON only).
pub fn parse_json_object(raw: &str) -> Result<Value, String> {
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        return Ok(value);
    }
    let start = raw
        .find('{')
        .ok_or_else(|| "AI response had no JSON object".to_string())?;
    let end = raw
        .rfind('}')
        .ok_or_else(|| "AI response had no JSON object end".to_string())?;
    serde_json::from_str(&raw[start..=end])
        .map_err(|err| format!("failed to parse AI JSON response: {err}"))
}

/// Whether LLM debug logging is on (`CHAINVET_LLM_DEBUG=1`).
pub fn debug_enabled() -> bool {
    env::var("CHAINVET_LLM_DEBUG").ok().as_deref() == Some("1")
}
