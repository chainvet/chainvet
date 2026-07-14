//! LLM provider implementations. Each provider's client implements
//! [`crate::LlmProvider`]; today only [`ollama`] is wired up. New providers go
//! here as sibling modules.

pub mod ollama;
