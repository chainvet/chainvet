//! [Ollama](https://ollama.com) provider: one-shot JSON-mode generation against
//! a local Ollama server, over the shared raw-TCP [`crate::http`] transport.

use crate::LlmProvider;
use crate::http;
use serde_json::{Value, json};
use std::env;
use std::time::Duration;

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";
pub const DEFAULT_MODEL: &str = "qwen2.5-coder:7b";

/// Connection + decoding parameters for a one-shot Ollama generate call.
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    pub endpoint: String,
    pub model: String,
    pub timeout: Duration,
    pub num_predict: u32,
}

impl OllamaConfig {
    /// Build a config from the shared `CHAINVET_LLM_*` environment variables,
    /// falling back to the supplied defaults for timeout and prediction length.
    pub fn from_env(default_timeout_ms: u64, default_num_predict: u32) -> Self {
        let endpoint =
            env::var("CHAINVET_LLM_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        let model = env::var("CHAINVET_LLM_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
        let timeout_ms = env::var("CHAINVET_LLM_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default_timeout_ms);
        let num_predict = env::var("CHAINVET_LLM_NUM_PREDICT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(default_num_predict);
        Self {
            endpoint,
            model,
            timeout: Duration::from_millis(timeout_ms),
            num_predict,
        }
    }
}

impl LlmProvider for OllamaConfig {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn generate(&self, prompt: &str) -> Result<String, String> {
        generate(self, prompt)
    }
}

/// One-shot JSON-mode generation. Returns the model's `response` text, or an
/// error string the caller can log and treat as "AI unavailable".
pub fn generate(config: &OllamaConfig, prompt: &str) -> Result<String, String> {
    let body = json!({
        "model": config.model,
        "prompt": prompt,
        "stream": false,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "num_ctx": 16384,
            "num_predict": config.num_predict
        }
    })
    .to_string();

    let response = http::post_json(&config.endpoint, "/api/generate", &body, config.timeout)?;
    let parsed = serde_json::from_str::<Value>(&response)
        .map_err(|err| format!("failed to parse Ollama response: {err}"))?;
    parsed
        .get("response")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Ollama response did not contain a response field".to_string())
}
