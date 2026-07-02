//! Minimal Ollama client over a raw `TcpStream` (no HTTP-client dependency).

use serde_json::{Value, json};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";
pub const DEFAULT_MODEL: &str = "qwen2.5-coder:7b";

/// Connection + decoding parameters for a one-shot generate call.
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    pub endpoint: String,
    pub model: String,
    pub timeout: Duration,
    pub num_predict: u32,
}

impl OllamaConfig {
    /// Build a config from the shared `CHAINVET_AI_*` environment variables,
    /// falling back to the supplied defaults for timeout and prediction length.
    pub fn from_env(default_timeout_ms: u64, default_num_predict: u32) -> Self {
        let endpoint =
            env::var("CHAINVET_AI_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
        let model = env::var("CHAINVET_AI_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
        let timeout_ms = env::var("CHAINVET_AI_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default_timeout_ms);
        let num_predict = env::var("CHAINVET_AI_NUM_PREDICT")
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

    let response = http_post_json(&config.endpoint, "/api/generate", &body, config.timeout)?;
    let parsed = serde_json::from_str::<Value>(&response)
        .map_err(|err| format!("failed to parse Ollama response: {err}"))?;
    parsed
        .get("response")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Ollama response did not contain a response field".to_string())
}

/// Extract a JSON object from a possibly-noisy LLM response (models sometimes
/// wrap JSON in prose despite `format: json`).
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

/// Whether AI debug logging is on (`CHAINVET_AI_DEBUG=1`).
pub fn debug_enabled() -> bool {
    env::var("CHAINVET_AI_DEBUG").ok().as_deref() == Some("1")
}

fn http_post_json(
    endpoint: &str,
    path: &str,
    body: &str,
    timeout: Duration,
) -> Result<String, String> {
    let endpoint = endpoint
        .trim()
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let mut parts = endpoint.splitn(2, '/');
    let host_port = parts.next().unwrap_or("127.0.0.1:11434");
    let extra_path = parts.next().unwrap_or("");
    let request_path = if extra_path.is_empty() {
        path.to_string()
    } else {
        format!("/{extra_path}{path}")
    };

    let mut stream = TcpStream::connect(host_port)
        .map_err(|err| format!("failed to connect to Ollama at {endpoint}: {err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("failed to set Ollama read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("failed to set Ollama write timeout: {err}"))?;

    let request = format!(
        "POST {request_path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("failed to write Ollama request: {err}"))?;

    // Read raw bytes: a chunked body must be de-framed on byte boundaries (the
    // JSON payload can contain multibyte UTF-8, so we can't slice a String).
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|err| format!("failed to read Ollama response: {err}"))?;
    let Some(sep) = find_subslice(&response, b"\r\n\r\n") else {
        return Err("invalid HTTP response from Ollama".to_string());
    };
    let headers = String::from_utf8_lossy(&response[..sep]);
    let body = &response[sep + 4..];
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(format!(
            "Ollama returned non-200 response: {}",
            headers.lines().next().unwrap_or("unknown status")
        ));
    }
    // Ollama switches to `Transfer-Encoding: chunked` once the response outgrows
    // its ~4 KB buffer (which real review prompts do). De-chunk before decoding.
    let is_chunked = headers.lines().any(|line| {
        line.to_ascii_lowercase().starts_with("transfer-encoding:")
            && line.to_ascii_lowercase().contains("chunked")
    });
    let body = if is_chunked {
        dechunk(body)
    } else {
        body.to_vec()
    };
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Find the first occurrence of `needle` in `haystack`, returning its start.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Decode an HTTP/1.1 chunked-transfer body: each chunk is `<hex-size>[;ext]\r\n`
/// then that many payload bytes then `\r\n`, terminated by a zero-size chunk.
/// Tolerant of a truncated tail (returns what was decoded so far).
fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = find_subslice(data, b"\r\n") {
        let size_line = String::from_utf8_lossy(&data[..eol]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        data = &data[eol + 2..]; // past the size line's CRLF
        if size == 0 {
            break; // last chunk
        }
        let take = size.min(data.len());
        out.extend_from_slice(&data[..take]);
        data = &data[take..];
        if data.starts_with(b"\r\n") {
            data = &data[2..]; // CRLF trailing the chunk data
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_reassembles_multiple_chunks() {
        // "{\"a\":1}" split as 3 + 4 bytes, then a zero terminator.
        let raw = b"3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw), b"{\"a\":1}");
    }

    #[test]
    fn dechunk_preserves_multibyte_utf8_across_the_boundary() {
        // The payload is `{"r":"✓"}` — the ✓ is 3 bytes; a chunk size counts
        // bytes, so splitting mid-string must not corrupt the character.
        let payload = "{\"r\":\"✓ ok\"}".as_bytes();
        let (a, b) = payload.split_at(6); // splits inside the multibyte region
        let mut raw = Vec::new();
        raw.extend_from_slice(format!("{:x}\r\n", a.len()).as_bytes());
        raw.extend_from_slice(a);
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(format!("{:x}\r\n", b.len()).as_bytes());
        raw.extend_from_slice(b);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        let decoded = dechunk(&raw);
        assert_eq!(decoded, payload);
        // And the reassembled bytes parse as the JSON we started with.
        let value: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(value["r"], "✓ ok");
    }

    #[test]
    fn dechunk_tolerates_a_truncated_tail() {
        // Missing the terminating zero-chunk: return what decoded cleanly.
        let raw = b"5\r\nhello\r\n";
        assert_eq!(dechunk(raw), b"hello");
    }
}
