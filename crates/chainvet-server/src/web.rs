//! The web-app API: file browser + async analyze/status/cancel, matching the
//! ChainVet web UI's contract. Unlike the old coupled server this drives the
//! orchestrator library directly (iterating the project's .sol files for real
//! per-file progress) instead of shelling a CLI, and serves no static assets —
//! the UI is a separate app that calls these endpoints (CORS-enabled in main).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chainvet_orchestrator::{HybridBudget, ScanMode, ScanResult, scan_path};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ---------- error ----------

pub struct ApiError {
    status: StatusCode,
    message: String,
}

type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, m)
    }
    fn internal(m: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, m)
    }
    fn internal_from_io(e: std::io::Error) -> Self {
        Self::internal(e.to_string())
    }
    fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, m)
    }
    fn cancelled(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, m)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

// ---------- request/response shapes (the UI's contract) ----------

#[derive(Deserialize)]
struct FilesQuery {
    path: Option<String>,
}

#[derive(Deserialize)]
struct FileQuery {
    path: String,
}

#[derive(Deserialize)]
struct AnalyzeRequest {
    path: String,
    mode: String,
}

#[derive(Serialize)]
struct CancelResponse {
    cancelled: bool,
    message: String,
}

#[derive(Serialize)]
struct AnalyzeStatusResponse {
    running: bool,
    mode: Option<String>,
    target_path: Option<String>,
    elapsed_ms: Option<u64>,
    cancel_requested: bool,
    phase: String,
    total_targets: Option<usize>,
    completed_targets: Option<usize>,
    remaining_targets: Option<usize>,
    current_target: Option<String>,
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    relative_path: String,
    is_dir: bool,
}

#[derive(Serialize)]
struct FilesResponse {
    root_dir: String,
    current_path: String,
    parent_path: Option<String>,
    direct_subdirectories: usize,
    direct_solidity_files: usize,
    recursive_solidity_files: usize,
    entries: Vec<FileEntry>,
}

#[derive(Serialize)]
struct FileContentResponse {
    relative_path: String,
    content: String,
}

#[derive(Serialize)]
struct SummaryCard {
    label: String,
    value: String,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
struct AnalyzeResponse {
    root_dir: String,
    target_path: String,
    mode: String,
    summary_cards: Vec<SummaryCard>,
    findings: Vec<WebFinding>,
    raw_json: String,
    raw_report: Value,
}

// ---------- mode ----------

#[derive(Clone, Copy)]
enum WebMode {
    Static,
    Fuzzing,
    Symbolic,
    Hybrid,
}

impl WebMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "static" => Some(Self::Static),
            "fuzzing" => Some(Self::Fuzzing),
            "symbolic" => Some(Self::Symbolic),
            "hybrid" => Some(Self::Hybrid),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Fuzzing => "fuzzing",
            Self::Symbolic => "symbolic",
            Self::Hybrid => "hybrid",
        }
    }
    fn scan_mode(self) -> ScanMode {
        match self {
            Self::Static => ScanMode::Static,
            Self::Fuzzing => ScanMode::Fuzzing,
            Self::Symbolic => ScanMode::Symbolic,
            Self::Hybrid => ScanMode::Hybrid,
        }
    }
}

// ---------- state / job ----------

pub struct AppState {
    root_dir: PathBuf,
    active_job: Mutex<Option<Arc<Job>>>,
}

struct Progress {
    phase: String,
    total_targets: usize,
    completed_targets: usize,
    current_target: Option<String>,
}

struct Job {
    mode: String,
    target_path: String,
    cancelled: AtomicBool,
    started_at: Instant,
    progress: Mutex<Progress>,
}

impl Job {
    fn new(mode: &str, target_path: String, total_targets: usize) -> Self {
        Self {
            mode: mode.to_string(),
            target_path,
            cancelled: AtomicBool::new(false),
            started_at: Instant::now(),
            progress: Mutex::new(Progress {
                phase: "preparing".to_string(),
                total_targets,
                completed_targets: 0,
                current_target: None,
            }),
        }
    }
    fn describe(&self) -> String {
        format!(
            "{} analysis on {}",
            self.mode,
            if self.target_path.is_empty() {
                "."
            } else {
                &self.target_path
            }
        )
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    fn was_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
    fn elapsed_ms(&self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }
    fn start_target(&self, current: String) {
        if let Ok(mut p) = self.progress.lock() {
            p.phase = "analyzing".to_string();
            p.current_target = Some(current);
        }
    }
    fn finish_target(&self) {
        if let Ok(mut p) = self.progress.lock() {
            p.completed_targets += 1;
        }
    }
}

impl AppState {
    pub fn new(root_dir: PathBuf) -> Self {
        let root_dir = root_dir.canonicalize().unwrap_or(root_dir);
        Self {
            root_dir,
            active_job: Mutex::new(None),
        }
    }

    fn active_job(&self) -> ApiResult<Option<Arc<Job>>> {
        self.active_job
            .lock()
            .map(|g| g.clone())
            .map_err(|_| ApiError::internal("analysis state lock poisoned"))
    }

    fn begin_job(&self, mode: WebMode, target: &Path, total: usize) -> ApiResult<Arc<Job>> {
        let mut active = self
            .active_job
            .lock()
            .map_err(|_| ApiError::internal("analysis state lock poisoned"))?;
        if let Some(current) = active.as_ref() {
            return Err(ApiError::conflict(format!(
                "{} is already running",
                current.describe()
            )));
        }
        let job = Arc::new(Job::new(
            mode.as_str(),
            relative_display(&self.root_dir, target),
            total,
        ));
        *active = Some(job.clone());
        Ok(job)
    }

    fn clear_job(&self, current: &Arc<Job>) {
        if let Ok(mut active) = self.active_job.lock() {
            if active.as_ref().is_some_and(|j| Arc::ptr_eq(j, current)) {
                *active = None;
            }
        }
    }
}

/// API routes for the web UI, to be mounted (with state + CORS) by `main`.
pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/files", get(api_files))
        .route("/api/file", get(api_file))
        .route("/api/analyze", post(api_analyze))
        .route("/api/analyze/status", get(api_analysis_status))
        .route("/api/analyze/cancel", post(api_cancel))
        .with_state(state)
}

// ---------- handlers ----------

async fn api_files(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FilesQuery>,
) -> ApiResult<Json<FilesResponse>> {
    let dir = resolve_existing_path(&state.root_dir, query.path.as_deref().unwrap_or(""))?;
    if !fs::metadata(&dir)
        .map_err(ApiError::internal_from_io)?
        .is_dir()
    {
        return Err(ApiError::bad_request("requested path is not a directory"));
    }

    let mut direct_subdirectories = 0;
    let mut direct_solidity_files = 0;
    let mut entries = fs::read_dir(&dir)
        .map_err(ApiError::internal_from_io)?
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let is_dir = entry.file_type().ok()?.is_dir();
            let path = entry.path();
            let is_sol = is_solidity(&path);
            if is_dir {
                direct_subdirectories += 1;
            } else if is_sol {
                direct_solidity_files += 1;
            }
            if !is_dir && !is_sol {
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
        _ => a
            .name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase()),
    });

    let parent_path = if dir == state.root_dir {
        None
    } else {
        dir.parent().map(|p| relative_display(&state.root_dir, p))
    };

    Ok(Json(FilesResponse {
        root_dir: state.root_dir.display().to_string(),
        current_path: relative_display(&state.root_dir, &dir),
        parent_path,
        direct_subdirectories,
        direct_solidity_files,
        recursive_solidity_files: count_solidity_recursive(&dir),
        entries,
    }))
}

async fn api_file(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FileQuery>,
) -> ApiResult<Json<FileContentResponse>> {
    let path = resolve_existing_path(&state.root_dir, &query.path)?;
    if !fs::metadata(&path)
        .map_err(ApiError::internal_from_io)?
        .is_file()
    {
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
    let response = tokio::task::spawn_blocking(move || analyze(&state, request))
        .await
        .map_err(|e| ApiError::internal(format!("analysis task join failure: {e}")))??;
    Ok(Json(response))
}

async fn api_analysis_status(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<AnalyzeStatusResponse>> {
    let Some(job) = state.active_job()? else {
        return Ok(Json(AnalyzeStatusResponse {
            running: false,
            mode: None,
            target_path: None,
            elapsed_ms: None,
            cancel_requested: false,
            phase: "idle".to_string(),
            total_targets: None,
            completed_targets: None,
            remaining_targets: None,
            current_target: None,
        }));
    };
    let cancel_requested = job.was_cancelled();
    let (phase, total, completed, current) = {
        let p = job
            .progress
            .lock()
            .map_err(|_| ApiError::internal("progress lock poisoned"))?;
        (
            p.phase.clone(),
            p.total_targets,
            p.completed_targets,
            p.current_target.clone(),
        )
    };
    Ok(Json(AnalyzeStatusResponse {
        running: true,
        mode: Some(job.mode.clone()),
        target_path: Some(job.target_path.clone()),
        elapsed_ms: Some(job.elapsed_ms()),
        cancel_requested,
        phase: if cancel_requested {
            "cancelling".to_string()
        } else {
            phase
        },
        total_targets: Some(total),
        completed_targets: Some(completed),
        remaining_targets: Some(total.saturating_sub(completed)),
        current_target: current,
    }))
}

async fn api_cancel(State(state): State<Arc<AppState>>) -> ApiResult<Json<CancelResponse>> {
    let Some(job) = state.active_job()? else {
        return Ok(Json(CancelResponse {
            cancelled: false,
            message: "No analysis job is currently running.".to_string(),
        }));
    };
    job.cancel();
    Ok(Json(CancelResponse {
        cancelled: true,
        message: format!("Cancellation requested for {}.", job.describe()),
    }))
}

// ---------- analysis (library-driven) ----------

fn analyze(state: &AppState, request: AnalyzeRequest) -> ApiResult<AnalyzeResponse> {
    let mode = WebMode::parse(request.mode.trim())
        .ok_or_else(|| ApiError::bad_request("unknown analysis mode"))?;
    let target = resolve_existing_path(&state.root_dir, request.path.trim())?;
    let targets = collect_targets(&target)?;
    let job = state.begin_job(mode, &target, targets.len())?;

    let result = (|| {
        let mut findings = Vec::new();
        for file in &targets {
            if job.was_cancelled() {
                return Err(ApiError::cancelled(format!(
                    "analysis cancelled: {}",
                    job.describe()
                )));
            }
            job.start_target(relative_display(&state.root_dir, file));
            let scan = scan_path(
                &file.to_string_lossy(),
                mode.scan_mode(),
                &HybridBudget::default(),
            )
            .map_err(|e| ApiError::internal(format!("analysis failed: {e}")))?;
            findings.extend(web_findings(&scan));
            job.finish_target();
        }
        findings.sort_by(|a, b| {
            severity_rank(a.severity.as_deref())
                .cmp(&severity_rank(b.severity.as_deref()))
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.start.unwrap_or(0).cmp(&b.start.unwrap_or(0)))
        });
        let summary_cards = build_summary_cards(mode, &findings);
        let raw_report = serde_json::to_value(&findings).unwrap_or(Value::Null);
        let raw_json = raw_report.to_string();
        Ok(AnalyzeResponse {
            root_dir: state.root_dir.display().to_string(),
            target_path: relative_display(&state.root_dir, &target),
            mode: mode.as_str().to_string(),
            summary_cards,
            findings,
            raw_json,
            raw_report,
        })
    })();

    state.clear_job(&job);
    result
}

fn web_findings(scan: &ScanResult) -> Vec<WebFinding> {
    scan.findings
        .iter()
        .map(|f| WebFinding {
            kind: f.kind.clone(),
            layer: f.provenance.clone(),
            severity: f.severity.clone(),
            confidence: f.confidence.clone(),
            category: f.category.clone(),
            function: f.function_id.map(|id| id.to_string()),
            file: f.file.clone(),
            start: f.start,
            end: f.end,
            message: f.message.clone(),
            evidence: None,
        })
        .collect()
}

fn build_summary_cards(mode: WebMode, findings: &[WebFinding]) -> Vec<SummaryCard> {
    let high = findings
        .iter()
        .filter(|f| f.severity.as_deref() == Some("high"))
        .count();
    let confirmed = findings.iter().filter(|f| f.layer != "static").count();
    let card = |label: &str, value: String| SummaryCard {
        label: label.to_string(),
        value,
    };
    vec![
        card("Mode", mode.as_str().to_string()),
        card("Findings", findings.len().to_string()),
        card("High Severity", high.to_string()),
        card("Confirmed", confirmed.to_string()),
        card("Candidate", (findings.len() - confirmed).to_string()),
    ]
}

fn severity_rank(severity: Option<&str>) -> u8 {
    match severity {
        Some("high") => 0,
        Some("medium") => 1,
        Some("low") => 2,
        _ => 3,
    }
}

// ---------- fs helpers ----------

fn is_solidity(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("sol"))
        .unwrap_or(false)
}

fn collect_targets(target: &Path) -> ApiResult<Vec<PathBuf>> {
    let metadata = fs::metadata(target).map_err(ApiError::internal_from_io)?;
    if metadata.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if !metadata.is_dir() {
        return Err(ApiError::bad_request(
            "target must be a Solidity file or directory",
        ));
    }
    let mut files = Vec::new();
    collect_solidity_recursive(target, &mut files);
    files.sort();
    if files.is_empty() {
        return Err(ApiError::bad_request(
            "directory contains no Solidity files",
        ));
    }
    Ok(files)
}

fn collect_solidity_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = read.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_solidity_recursive(&path, out);
        } else if is_solidity(&path) {
            out.push(path);
        }
    }
}

fn count_solidity_recursive(dir: &Path) -> usize {
    let mut out = Vec::new();
    collect_solidity_recursive(dir, &mut out);
    out.len()
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
