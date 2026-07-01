//! Chainvet language server: live static diagnostics as you edit Solidity, plus
//! an on-demand `chainvet.hybridScan` command that runs the full hybrid pipeline
//! (symbolic + fuzzing). A tower-lsp shell over `orchestrator::scan`.
//!
//! Findings reach clients two ways: as standard LSP **diagnostics** (universal —
//! every editor renders them, with tier/provenance in `Diagnostic.data`), and as
//! a `chainvet/publishFindings` **notification** carrying the structured rows a
//! rich client (the VS Code tree) groups and filters by tier. Plain LSP clients
//! ignore the notification and just use the diagnostics.

use std::sync::atomic::{AtomicU64, Ordering};

use chainvet_orchestrator::{HybridBudget, ScanFinding, ScanMode, scan_path};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_lsp::lsp_types::notification::Notification;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server, jsonrpc::Result};

const HYBRID_SCAN_COMMAND: &str = "chainvet.hybridScan";

struct Backend {
    client: Client,
}

/// A structured finding for the `chainvet/publishFindings` notification — the
/// tier/provenance/severity the tree groups and filters by, plus a resolved
/// range so clients don't recompute byte offsets.
#[derive(Serialize, Deserialize)]
struct FindingItem {
    tier: String,
    provenance: String,
    kind: String,
    severity: String,
    category: String,
    message: String,
    range: Range,
}

#[derive(Serialize, Deserialize)]
struct PublishFindingsParams {
    uri: Url,
    findings: Vec<FindingItem>,
}

/// Server → client notification with the structured findings for one file.
enum PublishFindings {}
impl Notification for PublishFindings {
    type Params = PublishFindingsParams;
    const METHOD: &'static str = "chainvet/publishFindings";
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
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec![HYBRID_SCAN_COMMAND.to_string()],
                    ..Default::default()
                }),
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
        self.analyze(p.text_document.uri, p.text_document.text, ScanMode::Static)
            .await;
    }

    async fn did_change(&self, mut p: DidChangeTextDocumentParams) {
        // FULL sync: the last change carries the whole document.
        if let Some(change) = p.content_changes.pop() {
            self.analyze(p.text_document.uri, change.text, ScanMode::Static)
                .await;
        }
    }

    async fn did_save(&self, p: DidSaveTextDocumentParams) {
        if let Some(text) = p.text {
            self.analyze(p.text_document.uri, text, ScanMode::Static)
                .await;
        }
    }

    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        if params.command == HYBRID_SCAN_COMMAND
            && let Some(uri) = params.arguments.first().and_then(parse_uri)
            && let Ok(path) = uri.to_file_path()
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            self.analyze(uri, text, ScanMode::Hybrid).await;
        }
        Ok(None)
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

impl Backend {
    /// Scan `text` in `mode`, then publish both the diagnostics and the
    /// structured findings notification for `uri`.
    async fn analyze(&self, uri: Url, text: String, mode: ScanMode) {
        let (diagnostics, findings) = tokio::task::spawn_blocking(move || run_scan(&text, mode))
            .await
            .unwrap_or_default();
        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;
        self.client
            .send_notification::<PublishFindings>(PublishFindingsParams { uri, findings })
            .await;
    }
}

/// A command argument may be a URI string or an object `{ "uri": "..." }`.
fn parse_uri(arg: &Value) -> Option<Url> {
    if let Some(s) = arg.as_str() {
        return Url::parse(s).ok();
    }
    arg.get("uri")
        .and_then(Value::as_str)
        .and_then(|s| Url::parse(s).ok())
}

fn run_scan(text: &str, mode: ScanMode) -> (Vec<Diagnostic>, Vec<FindingItem>) {
    let Ok(path) = write_temp(text) else {
        return (Vec::new(), Vec::new());
    };
    let result = scan_path(&path, mode, &HybridBudget::default());
    let _ = std::fs::remove_file(&path);
    match result {
        Ok(result) => {
            let diagnostics = result
                .findings
                .iter()
                .map(|f| to_diagnostic(f, text))
                .collect();
            let findings = result.findings.iter().map(|f| to_item(f, text)).collect();
            (diagnostics, findings)
        }
        Err(_) => (Vec::new(), Vec::new()),
    }
}

fn finding_range(f: &ScanFinding, text: &str) -> Range {
    let start = position_at(text, f.start.unwrap_or(0) as usize);
    let end = position_at(text, f.end.or(f.start).unwrap_or(0) as usize);
    Range { start, end }
}

fn to_diagnostic(f: &ScanFinding, text: &str) -> Diagnostic {
    Diagnostic {
        range: finding_range(f, text),
        severity: Some(severity_for(f.severity.as_deref())),
        code: Some(NumberOrString::String(f.kind.clone())),
        source: Some("chainvet".to_string()),
        message: format!("[{}/{}] {}", f.tier, f.provenance, f.message),
        data: Some(serde_json::json!({
            "tier": f.tier,
            "provenance": f.provenance,
            "category": f.category,
            "kind": f.kind,
        })),
        ..Diagnostic::default()
    }
}

fn to_item(f: &ScanFinding, text: &str) -> FindingItem {
    FindingItem {
        tier: f.tier.clone(),
        provenance: f.provenance.clone(),
        kind: f.kind.clone(),
        severity: f.severity.clone().unwrap_or_else(|| "low".to_string()),
        category: f.category.clone().unwrap_or_default(),
        message: f.message.clone(),
        range: finding_range(f, text),
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
