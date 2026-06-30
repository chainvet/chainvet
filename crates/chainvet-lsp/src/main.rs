//! Chainvet language server: publishes findings as diagnostics as you edit
//! Solidity. A thin tower-lsp shell over `orchestrator::scan` (static mode for
//! interactive latency); the VS Code extension and any LSP client consume it.

use std::sync::atomic::{AtomicU64, Ordering};

use chainvet_orchestrator::{HybridBudget, ScanFinding, ScanMode, scan_path};
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server, jsonrpc::Result};

struct Backend {
    client: Client,
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "chainvet-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..ServerCapabilities::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "chainvet-lsp ready")
            .await;
    }

    async fn did_open(&self, p: DidOpenTextDocumentParams) {
        self.publish(p.text_document.uri, p.text_document.text)
            .await;
    }

    async fn did_change(&self, mut p: DidChangeTextDocumentParams) {
        // FULL sync: the last change carries the whole document.
        if let Some(change) = p.content_changes.pop() {
            self.publish(p.text_document.uri, change.text).await;
        }
    }

    async fn did_save(&self, p: DidSaveTextDocumentParams) {
        if let Some(text) = p.text {
            self.publish(p.text_document.uri, text).await;
        }
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

impl Backend {
    async fn publish(&self, uri: Url, text: String) {
        let diagnostics = tokio::task::spawn_blocking(move || diagnostics(&text))
            .await
            .unwrap_or_default();
        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }
}

/// Run a static scan of `text` and map findings to LSP diagnostics.
fn diagnostics(text: &str) -> Vec<Diagnostic> {
    let Ok(path) = write_temp(text) else {
        return Vec::new();
    };
    let result = scan_path(&path, ScanMode::Static, &HybridBudget::default());
    let _ = std::fs::remove_file(&path);
    match result {
        Ok(result) => result
            .findings
            .iter()
            .map(|f| to_diagnostic(f, text))
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn to_diagnostic(f: &ScanFinding, text: &str) -> Diagnostic {
    let start = position_at(text, f.start.unwrap_or(0) as usize);
    let end_off = f.end.or(f.start).unwrap_or(0) as usize;
    let end = position_at(text, end_off);
    Diagnostic {
        range: Range { start, end },
        severity: Some(severity_for(f.severity.as_deref())),
        code: Some(NumberOrString::String(f.kind.clone())),
        source: Some("chainvet".to_string()),
        message: format!("[{}/{}] {}", f.tier, f.provenance, f.message),
        ..Diagnostic::default()
    }
}

fn severity_for(severity: Option<&str>) -> DiagnosticSeverity {
    match severity {
        Some("high") => DiagnosticSeverity::ERROR,
        Some("medium") => DiagnosticSeverity::WARNING,
        _ => DiagnosticSeverity::INFORMATION,
    }
}

/// Convert a byte offset into a UTF-16 LSP `Position`.
fn position_at(text: &str, offset: usize) -> Position {
    let offset = offset.min(text.len());
    let mut line = 0u32;
    let mut line_start = 0usize;
    for (i, b) in text.bytes().enumerate() {
        if i >= offset {
            break;
        }
        if b == b'\n' {
            line += 1;
            line_start = i + 1;
        }
    }
    let mut character = 0u32;
    for (i, ch) in text[line_start..].char_indices() {
        if line_start + i >= offset {
            break;
        }
        character += ch.len_utf16() as u32;
    }
    Position { line, character }
}

fn write_temp(source: &str) -> std::io::Result<String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("chainvet-lsp-{}-{}.sol", std::process::id(), n));
    std::fs::write(&path, source)?;
    Ok(path.to_string_lossy().into_owned())
}

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = LspService::new(|client| Backend { client });
    Server::new(stdin, stdout, socket).serve(service).await;
}
