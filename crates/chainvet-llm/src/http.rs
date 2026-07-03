//! Minimal HTTP/1.1 over a raw `TcpStream` — a shared transport for LLM
//! providers that speak plain HTTP (e.g. a local Ollama server) without pulling
//! in an HTTP-client dependency. De-frames chunked responses on byte boundaries
//! so multibyte UTF-8 payloads survive a split.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// POST a JSON `body` to `endpoint` + `path` and return the (de-chunked)
/// response body as a String.
///
/// `endpoint` is `http://host:port` with an optional base path (the scheme is
/// stripped; `https` is not supported — providers here talk to local servers).
pub fn post_json(
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
        .map_err(|err| format!("failed to connect to {endpoint}: {err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("failed to set read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("failed to set write timeout: {err}"))?;

    let request = format!(
        "POST {request_path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("failed to write request: {err}"))?;

    // Read raw bytes: a chunked body must be de-framed on byte boundaries (the
    // JSON payload can contain multibyte UTF-8, so we can't slice a String).
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|err| format!("failed to read response: {err}"))?;
    let Some(sep) = find_subslice(&response, b"\r\n\r\n") else {
        return Err(format!("invalid HTTP response from {endpoint}"));
    };
    let headers = String::from_utf8_lossy(&response[..sep]);
    let body = &response[sep + 4..];
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(format!(
            "server returned non-200 response: {}",
            headers.lines().next().unwrap_or("unknown status")
        ));
    }
    // Servers switch to `Transfer-Encoding: chunked` once the response outgrows
    // their write buffer (which real review prompts do). De-chunk before decoding.
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
    use serde_json::Value;

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
