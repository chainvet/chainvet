use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::artifacts::Finding;
use crate::util::error::{Error, Result};

const DEFAULT_PORT: u16 = 7878;
const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const STYLES_CSS: &str = include_str!("assets/styles.css");

struct AppState {
    root_dir: PathBuf,
    executable: PathBuf,
    active_job: Mutex<Option<Arc<RunningAnalysis>>>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Deserialize)]
struct FilesQuery {
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FileQuery {
    path: String,
}

#[derive(Debug, Deserialize, Clone)]
struct AnalyzeRequest {
    path: String,
    mode: String,
}

#[derive(Debug, Serialize)]
struct CancelResponse {
    cancelled: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct FilesResponse {
    root_dir: String,
    current_path: String,
    parent_path: Option<String>,
    entries: Vec<FileEntry>,
}

#[derive(Debug, Serialize)]
struct FileEntry {
    name: String,
    relative_path: String,
    is_dir: bool,
}

#[derive(Debug, Serialize)]
struct FileContentResponse {
    relative_path: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct SummaryCard {
    label: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct WebFinding {
    kind: String,
    layer: String,
    severity: Option<String>,
    confidence: Option<String>,
    category: Option<String>,
    function: Option<String>,
    file: Option<String>,
    start: Option<u32>,
    end: Option<u32>,
    message: String,
    evidence: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebArtifact {
    name: String,
    relative_path: String,
}

#[derive(Debug, Serialize)]
struct AnalyzeResponse {
    root_dir: String,
    target_path: String,
    mode: String,
    summary_cards: Vec<SummaryCard>,
    findings: Vec<WebFinding>,
    raw_json: String,
    raw_report: Value,
    warnings: Vec<String>,
    run_dir: Option<String>,
    artifacts: Vec<WebArtifact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebMode {
    Static,
    Symbolic,
    Fuzzing,
    Hybrid,
}

impl WebMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "static" => Some(Self::Static),
            "symbolic" => Some(Self::Symbolic),
            "fuzzing" => Some(Self::Fuzzing),
            "hybrid" => Some(Self::Hybrid),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Symbolic => "symbolic",
            Self::Fuzzing => "fuzzing",
            Self::Hybrid => "hybrid",
        }
    }

    fn flag(self) -> &'static str {
        match self {
            Self::Static => "--static",
            Self::Symbolic => "--symbolic",
            Self::Fuzzing => "--fuzzing",
            Self::Hybrid => "--hybrid",
        }
    }
}

struct CommandResult {
    raw_json: String,
    raw_report: Value,
    warnings: Vec<String>,
    run_dir: Option<PathBuf>,
}

#[derive(Debug)]
struct RunningAnalysis {
    mode: String,
    target_path: String,
    pid: u32,
    cancelled: AtomicBool,
}

impl RunningAnalysis {
    fn new(mode: String, target_path: String, pid: u32) -> Self {
        Self {
            mode,
            target_path,
            pid,
            cancelled: AtomicBool::new(false),
        }
    }

    fn describe(&self) -> String {
        let target = if self.target_path.is_empty() {
            ".".to_string()
        } else {
            self.target_path.clone()
        };
        format!("{} analysis on {}", self.mode, target)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn was_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl AppState {
    fn active_job(&self) -> ApiResult<Option<Arc<RunningAnalysis>>> {
        self.active_job
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| ApiError::internal("analysis state lock poisoned"))
    }

    fn spawn_job(&self, mode: WebMode, target: &Path) -> ApiResult<(Arc<RunningAnalysis>, Child)> {
        let mut active_job = self
            .active_job
            .lock()
            .map_err(|_| ApiError::internal("analysis state lock poisoned"))?;
        if let Some(current) = active_job.as_ref() {
            return Err(ApiError::conflict(format!(
                "{} is already running",
                current.describe()
            )));
        }

        let child = Command::new(&self.executable)
            .current_dir(&self.root_dir)
            .arg(mode.flag())
            .arg(target)
            .arg("--json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(ApiError::internal_from_io)?;

        let job = Arc::new(RunningAnalysis::new(
            mode.as_str().to_string(),
            relative_display(&self.root_dir, target),
            child.id(),
        ));
        *active_job = Some(job.clone());
        Ok((job, child))
    }

    fn clear_job(&self, current: &Arc<RunningAnalysis>) {
        if let Ok(mut active_job) = self.active_job.lock() {
            if active_job
                .as_ref()
                .is_some_and(|running| Arc::ptr_eq(running, current))
            {
                *active_job = None;
            }
        }
    }
}

pub fn serve(root_dir: PathBuf) -> Result<()> {
    let root_dir = root_dir.canonicalize().unwrap_or(root_dir);
    let executable = std::env::current_exe()?;
    let state = Arc::new(AppState {
        root_dir: root_dir.clone(),
        executable,
        active_job: Mutex::new(None),
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| Error::msg(format!("failed to build async runtime: {err}")))?;

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", DEFAULT_PORT)).await?;
        let url = format!("http://127.0.0.1:{DEFAULT_PORT}");
        println!("web ui root: {}", root_dir.display());
        println!("web ui url: {url}");
        try_open_browser(&url);

        let app = Router::new()
            .route("/", get(index))
            .route("/app.js", get(app_js))
            .route("/styles.css", get(styles_css))
            .route("/api/files", get(api_files))
            .route("/api/file", get(api_file))
            .route("/api/analyze", post(api_analyze))
            .route("/api/analyze/cancel", post(api_cancel_analysis))
            .with_state(state);

        axum::serve(listener, app)
            .await
            .map_err(|err| Error::msg(format!("web server failed: {err}")))
    })
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn styles_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLES_CSS,
    )
}

async fn api_files(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FilesQuery>,
) -> ApiResult<Json<FilesResponse>> {
    let dir = resolve_existing_path(&state.root_dir, query.path.as_deref().unwrap_or(""))?;
    let metadata = fs::metadata(&dir).map_err(ApiError::internal_from_io)?;
    if !metadata.is_dir() {
        return Err(ApiError::bad_request("requested path is not a directory"));
    }

    let mut entries = fs::read_dir(&dir)
        .map_err(ApiError::internal_from_io)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            let path = entry.path();
            let is_dir = file_type.is_dir();
            let is_solidity = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("sol"))
                .unwrap_or(false);
            if !is_dir && !is_solidity {
                return None;
            }
            Some(FileEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                relative_path: relative_display(&state.root_dir, &path),
                is_dir,
            })
        })
        .collect::<Vec<_>>();

    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()),
    });

    let current_path = relative_display(&state.root_dir, &dir);
    let parent_path = if dir == state.root_dir {
        None
    } else {
        dir.parent().map(|parent| relative_display(&state.root_dir, parent))
    };

    Ok(Json(FilesResponse {
        root_dir: state.root_dir.display().to_string(),
        current_path,
        parent_path,
        entries,
    }))
}

async fn api_file(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FileQuery>,
) -> ApiResult<Json<FileContentResponse>> {
    let path = resolve_existing_path(&state.root_dir, &query.path)?;
    let metadata = fs::metadata(&path).map_err(ApiError::internal_from_io)?;
    if !metadata.is_file() {
        return Err(ApiError::bad_request("requested path is not a file"));
    }
    let content = fs::read_to_string(&path).map_err(ApiError::internal_from_io)?;
    Ok(Json(FileContentResponse {
        relative_path: relative_display(&state.root_dir, &path),
        content,
    }))
}

async fn api_analyze(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AnalyzeRequest>,
) -> ApiResult<Json<AnalyzeResponse>> {
    let state = state.clone();
    let response = tokio::task::spawn_blocking(move || analyze_sync(&state, request))
        .await
        .map_err(|err| ApiError::internal(format!("analysis task join failure: {err}")))??;
    Ok(Json(response))
}

async fn api_cancel_analysis(State(state): State<Arc<AppState>>) -> ApiResult<Json<CancelResponse>> {
    let Some(job) = state.active_job()? else {
        return Ok(Json(CancelResponse {
            cancelled: false,
            message: "No analysis job is currently running.".to_string(),
        }));
    };

    job.cancel();
    request_process_termination(job.pid).map_err(ApiError::internal_from_io)?;

    Ok(Json(CancelResponse {
        cancelled: true,
        message: format!("Cancellation requested for {}.", job.describe()),
    }))
}

fn analyze_sync(state: &AppState, request: AnalyzeRequest) -> ApiResult<AnalyzeResponse> {
    let mode = WebMode::parse(request.mode.trim())
        .ok_or_else(|| ApiError::bad_request("unknown analysis mode"))?;
    let target = resolve_existing_path(&state.root_dir, request.path.trim())?;
    let command_result = run_analysis_command(state, mode, &target)?;
    let findings = match mode {
        WebMode::Static => extract_static_findings(&command_result.raw_report),
        WebMode::Symbolic => extract_symbolic_findings(&command_result.raw_report),
        WebMode::Fuzzing => extract_fuzzing_findings(&command_result.raw_report),
        WebMode::Hybrid => extract_hybrid_findings(&command_result.run_dir)?,
    };
    let summary_cards = build_summary_cards(mode, &command_result.raw_report, findings.len());
    let artifacts = collect_artifacts(&state.root_dir, command_result.run_dir.as_deref())?;

    Ok(AnalyzeResponse {
        root_dir: state.root_dir.display().to_string(),
        target_path: relative_display(&state.root_dir, &target),
        mode: mode.as_str().to_string(),
        summary_cards,
        findings,
        raw_json: command_result.raw_json,
        raw_report: command_result.raw_report,
        warnings: command_result.warnings,
        run_dir: command_result
            .run_dir
            .as_deref()
            .map(|run_dir| relative_display(&state.root_dir, run_dir)),
        artifacts,
    })
}

fn run_analysis_command(state: &AppState, mode: WebMode, target: &Path) -> ApiResult<CommandResult> {
    let run_dirs_before = if mode == WebMode::Hybrid {
        snapshot_run_dirs(&state.root_dir)
    } else {
        HashSet::new()
    };

    let (job, child) = state.spawn_job(mode, target)?;
    let output_result = child.wait_with_output();
    state.clear_job(&job);
    let output = match output_result {
        Ok(output) => output,
        Err(_err) if job.was_cancelled() => {
            return Err(ApiError::cancelled(format!(
                "analysis cancelled: {}",
                job.describe()
            )))
        }
        Err(err) => return Err(ApiError::internal_from_io(err)),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if job.was_cancelled() {
        return Err(ApiError::cancelled(format!(
            "analysis cancelled: {}",
            job.describe()
        )));
    }
    if !output.status.success() {
        let detail = if stderr.is_empty() { stdout.as_str() } else { stderr.as_str() };
        return Err(ApiError::internal(format!("analysis command failed: {detail}")));
    }

    let raw_report = serde_json::from_str::<Value>(&stdout)
        .map_err(|err| ApiError::internal(format!("analyzer produced invalid JSON: {err}")))?;
    let warnings = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();

    let run_dir = if mode == WebMode::Hybrid {
        detect_hybrid_run_dir(&state.root_dir, &run_dirs_before)
    } else {
        None
    };

    Ok(CommandResult {
        raw_json: stdout,
        raw_report,
        warnings,
        run_dir,
    })
}

fn build_summary_cards(mode: WebMode, report: &Value, finding_count: usize) -> Vec<SummaryCard> {
    let mut cards = vec![
        SummaryCard {
            label: "Mode".to_string(),
            value: mode.as_str().to_string(),
        },
        SummaryCard {
            label: "Displayed Findings".to_string(),
            value: finding_count.to_string(),
        },
    ];

    match mode {
        WebMode::Static => {
            push_json_card(&mut cards, report, "Files", "files");
            push_json_card(&mut cards, report, "Functions", "functions");
            push_json_card(&mut cards, report, "Calls", "calls");
        }
        WebMode::Symbolic => {
            push_json_card(&mut cards, report, "Functions", "functions");
            push_json_card(&mut cards, report, "Runtime Findings", "vulnerability_count");
            push_json_card(&mut cards, report, "Meta Findings", "meta_finding_count");
            push_json_card(&mut cards, report, "Explored States", "explored_states");
        }
        WebMode::Fuzzing => {
            push_json_card(&mut cards, report, "Iterations", "iterations");
            push_json_card(&mut cards, report, "Coverage", "coverage_pct");
            push_json_card(&mut cards, report, "Runtime Findings", "findings");
            push_json_card(&mut cards, report, "Meta Findings", "meta_findings");
        }
        WebMode::Hybrid => {
            push_json_card(&mut cards, report, "Epochs", "total_epochs");
            push_json_card(&mut cards, report, "Runtime Findings", "runtime_findings_unique");
            push_json_card(&mut cards, report, "Meta Findings", "meta_findings_unique");
            push_json_card(&mut cards, report, "Runtime ms", "runtime_ms");
        }
    }

    cards
}

fn push_json_card(cards: &mut Vec<SummaryCard>, report: &Value, label: &str, key: &str) {
    let value = match report.get(key) {
        Some(Value::Array(items)) => items.len().to_string(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => return,
    };
    cards.push(SummaryCard {
        label: label.to_string(),
        value,
    });
}

fn extract_static_findings(report: &Value) -> Vec<WebFinding> {
    report
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|finding| WebFinding {
            kind: json_string(finding, "kind"),
            layer: "static".to_string(),
            severity: json_string_opt(finding, "severity"),
            confidence: json_metadata_string_opt(finding, "confidence"),
            category: json_string_opt(finding, "category"),
            function: json_string_opt(finding, "function"),
            file: json_string_opt(finding, "file"),
            start: finding
                .get("span")
                .and_then(|span| span.get("start"))
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            end: finding
                .get("span")
                .and_then(|span| span.get("end"))
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            message: json_string(finding, "message"),
            evidence: None,
        })
        .collect()
}

fn extract_symbolic_findings(report: &Value) -> Vec<WebFinding> {
    let mut findings = Vec::new();

    if let Some(runtime) = report.get("vulnerabilities").and_then(Value::as_array) {
        findings.extend(runtime.iter().map(|finding| WebFinding {
            kind: json_string(finding, "kind"),
            layer: "runtime".to_string(),
            severity: None,
            confidence: json_string_opt(finding, "confidence"),
            category: None,
            function: json_string_opt(finding, "function_name"),
            file: finding
                .get("location")
                .and_then(|location| location.get("file"))
                .and_then(Value::as_str)
                .map(str::to_string),
            start: finding
                .get("location")
                .and_then(|location| location.get("start"))
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            end: finding
                .get("location")
                .and_then(|location| location.get("end"))
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            message: json_string(finding, "message"),
            evidence: None,
        }));
    }

    if let Some(meta) = report.get("meta_findings").and_then(Value::as_array) {
        findings.extend(meta.iter().map(|finding| WebFinding {
            kind: json_string(finding, "finding_type"),
            layer: "meta".to_string(),
            severity: json_string_opt(finding, "severity"),
            confidence: json_metadata_string_opt(finding, "confidence"),
            category: json_metadata_string_opt(finding, "category"),
            function: finding
                .get("location")
                .and_then(|location| location.get("function_name"))
                .and_then(Value::as_str)
                .map(str::to_string),
            file: finding
                .get("location")
                .and_then(|location| location.get("file"))
                .and_then(Value::as_str)
                .map(str::to_string),
            start: finding
                .get("location")
                .and_then(|location| location.get("start"))
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            end: finding
                .get("location")
                .and_then(|location| location.get("end"))
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            message: json_string(finding, "message"),
            evidence: json_string_opt(finding, "evidence_kind"),
        }));
    }

    findings
}

fn extract_fuzzing_findings(report: &Value) -> Vec<WebFinding> {
    let mut findings = Vec::new();

    if let Some(runtime) = report.get("findings").and_then(Value::as_array) {
        findings.extend(runtime.iter().map(|finding| WebFinding {
            kind: json_string(finding, "canonical_kind"),
            layer: "runtime".to_string(),
            severity: json_string_opt(finding, "severity"),
            confidence: json_string_opt(finding, "confidence"),
            category: json_string_opt(finding, "category"),
            function: None,
            file: None,
            start: None,
            end: None,
            message: json_string(finding, "message"),
            evidence: None,
        }));
    }

    if let Some(meta) = report.get("meta_findings").and_then(Value::as_array) {
        findings.extend(meta.iter().map(|finding| WebFinding {
            kind: json_string(finding, "finding_type"),
            layer: "meta".to_string(),
            severity: json_string_opt(finding, "severity"),
            confidence: json_metadata_string_opt(finding, "confidence"),
            category: json_metadata_string_opt(finding, "category"),
            function: finding
                .get("location")
                .and_then(|location| location.get("function_name"))
                .and_then(Value::as_str)
                .map(str::to_string),
            file: finding
                .get("location")
                .and_then(|location| location.get("file"))
                .and_then(Value::as_str)
                .map(str::to_string),
            start: finding
                .get("location")
                .and_then(|location| location.get("start"))
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            end: finding
                .get("location")
                .and_then(|location| location.get("end"))
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            message: json_string(finding, "message"),
            evidence: json_string_opt(finding, "evidence_kind"),
        }));
    }

    findings
}

fn extract_hybrid_findings(run_dir: &Option<PathBuf>) -> ApiResult<Vec<WebFinding>> {
    let Some(run_dir) = run_dir else {
        return Ok(Vec::new());
    };
    let findings_path = run_dir.join("findings.json");
    if !findings_path.exists() {
        return Ok(Vec::new());
    }
    let findings_raw = fs::read_to_string(&findings_path).map_err(ApiError::internal_from_io)?;
    let findings = serde_json::from_str::<Vec<Finding>>(&findings_raw)
        .map_err(|err| ApiError::internal(format!("failed to decode hybrid findings.json: {err}")))?;
    Ok(findings
        .into_iter()
        .map(|finding| WebFinding {
            kind: finding.finding_type,
            layer: finding.analysis_layer,
            severity: Some(finding.severity),
            confidence: finding.metadata.get("confidence").cloned(),
            category: finding.metadata.get("category").cloned(),
            function: finding
                .location
                .as_ref()
                .and_then(|location| location.function_name.clone()),
            file: finding
                .location
                .as_ref()
                .and_then(|location| location.file.clone()),
            start: finding
                .location
                .as_ref()
                .and_then(|location| location.start),
            end: finding
                .location
                .as_ref()
                .and_then(|location| location.end),
            message: finding.message,
            evidence: Some(finding.evidence_kind),
        })
        .collect())
}

fn collect_artifacts(root_dir: &Path, run_dir: Option<&Path>) -> ApiResult<Vec<WebArtifact>> {
    let Some(run_dir) = run_dir else {
        return Ok(Vec::new());
    };
    let mut artifacts = fs::read_dir(run_dir)
        .map_err(ApiError::internal_from_io)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            Some(WebArtifact {
                name: entry.file_name().to_string_lossy().to_string(),
                relative_path: relative_display(root_dir, &entry.path()),
            })
        })
        .collect::<Vec<_>>();
    artifacts.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(artifacts)
}

fn resolve_existing_path(root_dir: &Path, requested: &str) -> ApiResult<PathBuf> {
    let candidate = if requested.trim().is_empty() || requested.trim() == "." {
        root_dir.to_path_buf()
    } else {
        let requested_path = Path::new(requested);
        if requested_path.is_absolute() {
            return Err(ApiError::bad_request("absolute paths are not allowed"));
        }
        root_dir.join(requested_path)
    };

    let canonical = candidate
        .canonicalize()
        .map_err(|_| ApiError::bad_request("requested path does not exist"))?;
    if !canonical.starts_with(root_dir) {
        return Err(ApiError::bad_request(
            "requested path escapes the working directory root",
        ));
    }
    Ok(canonical)
}

fn relative_display(root_dir: &Path, path: &Path) -> String {
    match path.strip_prefix(root_dir) {
        Ok(relative) => {
            let rendered = relative.to_string_lossy().replace('\\', "/");
            if rendered == "." {
                String::new()
            } else {
                rendered
            }
        }
        Err(_) => path.display().to_string(),
    }
}

fn snapshot_run_dirs(root_dir: &Path) -> HashSet<String> {
    let runs_dir = root_dir.join("runs");
    fs::read_dir(runs_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if entry.file_type().ok()?.is_dir() && name.starts_with("run-") {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}

fn detect_hybrid_run_dir(root_dir: &Path, before: &HashSet<String>) -> Option<PathBuf> {
    let runs_dir = root_dir.join("runs");
    let mut after = fs::read_dir(&runs_dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if entry.file_type().ok()?.is_dir() && name.starts_with("run-") {
                Some((name, entry.path()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    after.sort_by(|a, b| a.0.cmp(&b.0));
    after
        .iter()
        .filter(|(name, _)| !before.contains(name))
        .map(|(_, path)| path.clone())
        .next_back()
        .or_else(|| after.pop().map(|(_, path)| path))
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn json_string_opt(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn json_metadata_string_opt(value: &Value, key: &str) -> Option<String> {
    value.get("metadata")
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_str)
        .map(str::to_string)
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn cancelled(message: impl Into<String>) -> Self {
        Self::conflict(message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn internal_from_io(err: std::io::Error) -> Self {
        Self::internal(format!("io error: {err}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let payload = Json(json!({ "error": self.message }));
        (self.status, payload).into_response()
    }
}

#[cfg(target_family = "unix")]
fn request_process_termination(pid: u32) -> std::io::Result<()> {
    let pid = pid.to_string();
    let term_status = Command::new("kill").arg("-TERM").arg(&pid).status()?;
    if term_status.success() {
        return Ok(());
    }

    let _ = Command::new("kill").arg("-KILL").arg(&pid).status()?;
    Ok(())
}

#[cfg(target_family = "windows")]
fn request_process_termination(pid: u32) -> std::io::Result<()> {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status()?;
    Ok(())
}

fn try_open_browser(url: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("rundll32")
            .arg("url.dll,FileProtocolHandler")
            .arg(url)
            .spawn();
    }
}
