use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::util::error::{Error, Result};

const DEFAULT_PORT: u16 = 7878;
const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const STYLES_CSS: &str = include_str!("assets/styles.css");
const LOGO_PNG: &[u8] = include_bytes!("assets/logo.png");

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

#[derive(Debug, Serialize)]
struct FilesResponse {
    root_dir: String,
    current_path: String,
    parent_path: Option<String>,
    direct_subdirectories: usize,
    direct_solidity_files: usize,
    recursive_solidity_files: usize,
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Serialize, Clone)]
struct WebWarning {
    title: String,
    message: String,
    category: String,
    suppressed_by_default: bool,
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
    warnings: Vec<WebWarning>,
    run_dir: Option<String>,
    artifacts: Vec<WebArtifact>,
    report_markdown: String,
    report_markdown_filename: String,
    report_pdf_base64: String,
    report_pdf_error: Option<String>,
    report_filename: String,
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
    cancelled: AtomicBool,
    started_at: Instant,
    progress: Mutex<RunningProgress>,
}

#[derive(Debug, Clone)]
struct RunningProgressSnapshot {
    phase: String,
    total_targets: usize,
    completed_targets: usize,
    current_target: Option<String>,
}

#[derive(Debug)]
struct RunningProgress {
    pid: Option<u32>,
    phase: String,
    total_targets: usize,
    completed_targets: usize,
    current_target: Option<String>,
}

impl RunningAnalysis {
    fn new(mode: String, target_path: String, total_targets: usize) -> Self {
        Self {
            mode,
            target_path,
            cancelled: AtomicBool::new(false),
            started_at: Instant::now(),
            progress: Mutex::new(RunningProgress {
                pid: None,
                phase: "preparing".to_string(),
                total_targets,
                completed_targets: 0,
                current_target: None,
            }),
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
        if let Ok(progress) = self.progress.lock() {
            if let Some(pid) = progress.pid {
                let _ = request_process_termination(pid);
            }
        }
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

    fn set_phase(&self, phase: impl Into<String>) -> ApiResult<()> {
        let mut progress = self
            .progress
            .lock()
            .map_err(|_| ApiError::internal("analysis progress lock poisoned"))?;
        progress.phase = phase.into();
        Ok(())
    }

    fn start_target(&self, pid: u32, current_target: String) -> ApiResult<()> {
        let mut progress = self
            .progress
            .lock()
            .map_err(|_| ApiError::internal("analysis progress lock poisoned"))?;
        progress.pid = Some(pid);
        progress.phase = "running".to_string();
        progress.current_target = Some(current_target);
        Ok(())
    }

    fn finish_target(&self) -> ApiResult<()> {
        let mut progress = self
            .progress
            .lock()
            .map_err(|_| ApiError::internal("analysis progress lock poisoned"))?;
        progress.pid = None;
        progress.completed_targets = progress.completed_targets.saturating_add(1);
        progress.current_target = None;
        progress.phase = "finalizing".to_string();
        Ok(())
    }

    fn snapshot(&self) -> ApiResult<RunningProgressSnapshot> {
        let progress = self
            .progress
            .lock()
            .map_err(|_| ApiError::internal("analysis progress lock poisoned"))?;
        Ok(RunningProgressSnapshot {
            phase: progress.phase.clone(),
            total_targets: progress.total_targets,
            completed_targets: progress.completed_targets,
            current_target: progress.current_target.clone(),
        })
    }
}

impl AppState {
    fn active_job(&self) -> ApiResult<Option<Arc<RunningAnalysis>>> {
        self.active_job
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| ApiError::internal("analysis state lock poisoned"))
    }

    fn begin_job(
        &self,
        mode: WebMode,
        target: &Path,
        total_targets: usize,
    ) -> ApiResult<Arc<RunningAnalysis>> {
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

        let job = Arc::new(RunningAnalysis::new(
            mode.as_str().to_string(),
            relative_display(&self.root_dir, target),
            total_targets,
        ));
        *active_job = Some(job.clone());
        Ok(job)
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
        println!("web ui launch: open the URL manually in your browser");

        let app = Router::new()
            .route("/", get(index))
            .route("/app.js", get(app_js))
            .route("/styles.css", get(styles_css))
            .route("/logo.png", get(logo_png))
            .route("/api/files", get(api_files))
            .route("/api/file", get(api_file))
            .route("/api/analyze", post(api_analyze))
            .route("/api/analyze/status", get(api_analysis_status))
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

async fn logo_png() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        LOGO_PNG,
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

    let mut direct_subdirectories = 0usize;
    let mut direct_solidity_files = 0usize;
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
            if is_dir {
                direct_subdirectories += 1;
            } else if is_solidity {
                direct_solidity_files += 1;
            }
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
    let recursive_solidity_files = count_solidity_files_recursive(&dir)?;

    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a
            .name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase()),
    });

    let current_path = relative_display(&state.root_dir, &dir);
    let parent_path = if dir == state.root_dir {
        None
    } else {
        dir.parent()
            .map(|parent| relative_display(&state.root_dir, parent))
    };

    Ok(Json(FilesResponse {
        root_dir: state.root_dir.display().to_string(),
        current_path,
        parent_path,
        direct_subdirectories,
        direct_solidity_files,
        recursive_solidity_files,
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
    let snapshot = job.snapshot()?;
    Ok(Json(AnalyzeStatusResponse {
        running: true,
        mode: Some(job.mode.clone()),
        target_path: Some(job.target_path.clone()),
        elapsed_ms: Some(job.elapsed_ms()),
        cancel_requested,
        phase: if cancel_requested {
            "cancelling".to_string()
        } else {
            snapshot.phase
        },
        total_targets: Some(snapshot.total_targets),
        completed_targets: Some(snapshot.completed_targets),
        remaining_targets: Some(
            snapshot
                .total_targets
                .saturating_sub(snapshot.completed_targets),
        ),
        current_target: snapshot.current_target,
    }))
}

async fn api_cancel_analysis(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<CancelResponse>> {
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

fn analyze_sync(state: &AppState, request: AnalyzeRequest) -> ApiResult<AnalyzeResponse> {
    let mode = WebMode::parse(request.mode.trim())
        .ok_or_else(|| ApiError::bad_request("unknown analysis mode"))?;
    let target = resolve_existing_path(&state.root_dir, request.path.trim())?;
    let targets = collect_analysis_targets(&target)?;
    let job = state.begin_job(mode, &target, targets.len())?;

    let result = if targets.len() == 1 {
        let command_result = run_analysis_command(state, mode, &targets[0], &job)?;
        let findings = extract_web_findings(mode, &command_result.raw_report)?;
        let artifacts = collect_artifacts(&state.root_dir, command_result.run_dir.as_deref())?;
        let warnings = classify_warnings(command_result.warnings);
        let summary_cards = build_summary_cards(mode, &findings, &warnings);
        let (raw_findings, suppressed_findings) =
            report_finding_totals(mode, &command_result.raw_report);
        let target_path = relative_display(&state.root_dir, &target);
        let report = build_report_outputs(
            &target_path,
            mode,
            &findings,
            raw_findings,
            suppressed_findings,
            &summary_cards,
        );

        Ok(AnalyzeResponse {
            root_dir: state.root_dir.display().to_string(),
            target_path,
            mode: mode.as_str().to_string(),
            summary_cards,
            findings,
            raw_json: command_result.raw_json,
            raw_report: command_result.raw_report,
            warnings,
            run_dir: command_result
                .run_dir
                .as_deref()
                .map(|run_dir| relative_display(&state.root_dir, run_dir)),
            artifacts,
            report_markdown: report.markdown,
            report_markdown_filename: report.markdown_filename,
            report_pdf_base64: report.pdf_base64,
            report_pdf_error: report.pdf_error,
            report_filename: report.pdf_filename,
        })
    } else {
        aggregate_directory_analysis(state, mode, &target, &targets, &job)
    };

    state.clear_job(&job);
    result
}

fn run_analysis_command(
    state: &AppState,
    mode: WebMode,
    target: &Path,
    job: &Arc<RunningAnalysis>,
) -> ApiResult<CommandResult> {
    let run_dirs_before = if mode == WebMode::Hybrid {
        snapshot_run_dirs(&state.root_dir)
    } else {
        HashSet::new()
    };

    if job.was_cancelled() {
        return Err(ApiError::cancelled(format!(
            "analysis cancelled: {}",
            job.describe()
        )));
    }

    job.set_phase("starting")?;
    let child = Command::new(&state.executable)
        .current_dir(&state.root_dir)
        .arg(mode.flag())
        .arg(target)
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(ApiError::internal_from_io)?;

    job.start_target(child.id(), relative_display(&state.root_dir, target))?;
    let output_result = child.wait_with_output();
    let output = match output_result {
        Ok(output) => output,
        Err(_err) if job.was_cancelled() => {
            return Err(ApiError::cancelled(format!(
                "analysis cancelled: {}",
                job.describe()
            )));
        }
        Err(err) => return Err(ApiError::internal_from_io(err)),
    };
    job.finish_target()?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if job.was_cancelled() {
        return Err(ApiError::cancelled(format!(
            "analysis cancelled: {}",
            job.describe()
        )));
    }
    if !output.status.success() {
        let detail = if stderr.is_empty() {
            stdout.as_str()
        } else {
            stderr.as_str()
        };
        return Err(ApiError::internal(format!(
            "analysis command failed: {detail}"
        )));
    }

    let raw_report = serde_json::from_str::<Value>(&stdout)
        .map_err(|err| ApiError::internal(format!("analyzer produced invalid JSON: {err}")))?;
    let warnings = extract_warning_blocks(&stderr);

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

fn aggregate_directory_analysis(
    state: &AppState,
    mode: WebMode,
    target: &Path,
    targets: &[PathBuf],
    job: &Arc<RunningAnalysis>,
) -> ApiResult<AnalyzeResponse> {
    let mut all_findings = Vec::new();
    let mut warnings = Vec::new();
    let mut artifacts = Vec::new();
    let mut report_entries = Vec::new();
    let mut run_dirs = Vec::new();
    let mut raw_finding_count = 0usize;
    let mut suppressed_count = 0usize;

    for file_target in targets {
        if job.was_cancelled() {
            return Err(ApiError::cancelled(format!(
                "analysis cancelled: {}",
                job.describe()
            )));
        }

        let command_result = run_analysis_command(state, mode, file_target, job)?;
        let relative_target = relative_display(&state.root_dir, file_target);
        let findings = extract_web_findings(mode, &command_result.raw_report)?;
        let (raw_count, suppressed) = report_finding_totals(mode, &command_result.raw_report);
        raw_finding_count += raw_count;
        suppressed_count += suppressed;
        all_findings.extend(findings);

        if let Some(run_dir) = command_result.run_dir.clone() {
            run_dirs.push(relative_display(&state.root_dir, &run_dir));
            artifacts.extend(collect_artifacts(&state.root_dir, Some(&run_dir))?);
        }

        warnings.extend(
            command_result
                .warnings
                .into_iter()
                .map(|warning| format!("[{}] {}", relative_target, warning)),
        );

        report_entries.push(json!({
            "target_path": relative_target,
            "report": command_result.raw_report,
        }));
    }

    all_findings.sort_by(|left, right| {
        (
            severity_rank(left.severity.as_deref()),
            left.kind.as_str(),
            left.file.as_deref().unwrap_or(""),
            left.function.as_deref().unwrap_or(""),
            left.start.unwrap_or(0),
            left.message.as_str(),
        )
            .cmp(&(
                severity_rank(right.severity.as_deref()),
                right.kind.as_str(),
                right.file.as_deref().unwrap_or(""),
                right.function.as_deref().unwrap_or(""),
                right.start.unwrap_or(0),
                right.message.as_str(),
            ))
    });

    artifacts.sort_by(|left, right| {
        left.relative_path
            .cmp(&right.relative_path)
            .then_with(|| left.name.cmp(&right.name))
    });
    artifacts.dedup_by(|left, right| left.relative_path == right.relative_path);

    let raw_report = json!({
        "mode": mode.as_str(),
        "target_path": relative_display(&state.root_dir, target),
        "target_count": targets.len(),
        "targets": targets
            .iter()
            .map(|path| relative_display(&state.root_dir, path))
            .collect::<Vec<_>>(),
        "run_dirs": run_dirs,
        "finding_count_raw": raw_finding_count,
        "suppressed_findings": suppressed_count,
        "reports": report_entries,
    });
    let raw_json = serde_json::to_string_pretty(&raw_report).map_err(|err| {
        ApiError::internal(format!("failed to serialize aggregate report: {err}"))
    })?;
    let warnings = classify_warnings(warnings);
    let summary_cards = build_summary_cards(mode, &all_findings, &warnings);
    let target_path = relative_display(&state.root_dir, target);
    let report = build_report_outputs(
        &target_path,
        mode,
        &all_findings,
        raw_finding_count,
        suppressed_count,
        &summary_cards,
    );

    Ok(AnalyzeResponse {
        root_dir: state.root_dir.display().to_string(),
        target_path,
        mode: mode.as_str().to_string(),
        summary_cards,
        findings: all_findings,
        raw_json,
        raw_report,
        warnings,
        run_dir: None,
        artifacts,
        report_markdown: report.markdown,
        report_markdown_filename: report.markdown_filename,
        report_pdf_base64: report.pdf_base64,
        report_pdf_error: report.pdf_error,
        report_filename: report.pdf_filename,
    })
}

fn build_summary_cards(
    mode: WebMode,
    findings: &[WebFinding],
    warnings: &[WebWarning],
) -> Vec<SummaryCard> {
    let unique_kinds = findings
        .iter()
        .map(|finding| finding.kind.as_str())
        .collect::<HashSet<_>>()
        .len();
    let high_severity = findings
        .iter()
        .filter(|finding| severity_bucket(finding.severity.as_deref()) == "high")
        .count();
    let high_confidence = findings
        .iter()
        .filter(|finding| severity_bucket(finding.confidence.as_deref()) == "high")
        .count();
    let warning_count = warnings
        .iter()
        .filter(|warning| !warning.suppressed_by_default)
        .count();

    vec![
        SummaryCard {
            label: "Mode".to_string(),
            value: mode.as_str().to_string(),
        },
        SummaryCard {
            label: "Displayed Findings".to_string(),
            value: findings.len().to_string(),
        },
        SummaryCard {
            label: "Unique Kinds".to_string(),
            value: unique_kinds.to_string(),
        },
        SummaryCard {
            label: "High Severity".to_string(),
            value: high_severity.to_string(),
        },
        SummaryCard {
            label: "High Confidence".to_string(),
            value: high_confidence.to_string(),
        },
        SummaryCard {
            label: "Warnings".to_string(),
            value: warning_count.to_string(),
        },
    ]
}

struct ReportOutputs {
    markdown: String,
    markdown_filename: String,
    pdf_base64: String,
    pdf_error: Option<String>,
    pdf_filename: String,
}

fn build_report_outputs(
    target_path: &str,
    mode: WebMode,
    findings: &[WebFinding],
    raw_findings: usize,
    suppressed_findings: usize,
    summary_cards: &[SummaryCard],
) -> ReportOutputs {
    let mut metrics = summary_cards
        .iter()
        .map(|card| crate::report::AuditMetric::new(card.label.clone(), card.value.clone()))
        .collect::<Vec<_>>();
    metrics.push(crate::report::AuditMetric::new(
        "Generated from",
        "ChainVet Web UI",
    ));

    let audit_report = crate::report::AuditReport {
        project_name: crate::report::project_name_from_path(target_path),
        target: target_path.to_string(),
        analysis_mode: mode.as_str().to_string(),
        raw_findings,
        suppressed_findings,
        metrics,
        findings: findings.iter().map(web_finding_to_audit).collect(),
        review_summary: None,
    };
    let audit_report = crate::ai_report::enhance_report_if_enabled(&audit_report);
    let markdown = crate::report::render_audit_markdown(&audit_report);
    let (pdf_base64, pdf_error) = match crate::report::render_audit_pdf_base64(&audit_report) {
        Ok(pdf) => (pdf, None),
        Err(err) => (String::new(), Some(err.to_string())),
    };
    ReportOutputs {
        markdown,
        markdown_filename: report_filename_for_target(target_path, mode, "md"),
        pdf_base64,
        pdf_error,
        pdf_filename: report_filename_for_target(target_path, mode, "pdf"),
    }
}

fn web_finding_to_audit(finding: &WebFinding) -> crate::report::AuditFinding {
    crate::report::AuditFinding {
        category: finding.category.clone().unwrap_or_else(|| {
            crate::surfaced::default_category_for_kind(&finding.kind).to_string()
        }),
        kind: finding.kind.clone(),
        severity: finding
            .severity
            .clone()
            .unwrap_or_else(|| "informational".to_string()),
        confidence: finding.confidence.clone(),
        message: finding.message.clone(),
        file: finding.file.clone(),
        start: finding.start,
        end: finding.end,
        function_name: finding.function.clone(),
        analysis_layer: finding.layer.clone(),
        evidence_kind: finding.evidence.clone(),
        ai_review: None,
    }
}

fn report_filename_for_target(target_path: &str, mode: WebMode, extension: &str) -> String {
    let base = crate::report::project_name_from_path(target_path);
    let safe = base
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let safe = if safe.is_empty() {
        "chainvet-report".to_string()
    } else {
        safe
    };
    format!("{safe}-{}-chainvet-report.{extension}", mode.as_str())
}

fn report_finding_totals(mode: WebMode, report: &Value) -> (usize, usize) {
    match mode {
        WebMode::Static => (
            json_usize(report, "finding_count_raw"),
            json_usize(report, "suppressed_findings"),
        ),
        WebMode::Symbolic => (
            json_usize(report, "vulnerability_count_raw")
                + json_usize(report, "meta_finding_count_raw"),
            json_usize(report, "suppressed_vulnerabilities")
                + json_usize(report, "suppressed_meta_findings"),
        ),
        WebMode::Fuzzing | WebMode::Hybrid => (
            json_usize(report, "finding_count_raw") + json_usize(report, "meta_finding_count_raw"),
            json_usize(report, "suppressed_findings")
                + json_usize(report, "suppressed_meta_findings"),
        ),
    }
}

fn extract_warning_blocks(stderr: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();

    for raw_line in stderr.lines() {
        let line = raw_line.trim_end();
        if line.trim().is_empty() {
            continue;
        }

        if starts_new_warning_block(line) && !current.is_empty() {
            blocks.push(current.trim().to_string());
            current.clear();
        }

        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(line);
    }

    if !current.is_empty() {
        blocks.push(current.trim().to_string());
    }

    blocks
}

fn starts_new_warning_block(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("solc frontend unavailable; using tree-sitter fallback:")
        || trimmed.starts_with("solc frontend failed:")
        || (trimmed.starts_with('[')
            && trimmed.contains("] solc frontend unavailable; using tree-sitter fallback:"))
        || (trimmed.starts_with('[') && trimmed.contains("] solc frontend failed:"))
        || trimmed.starts_with("analysis command failed:")
        || trimmed.starts_with("analysis cancelled:")
}

fn classify_warnings(warnings: Vec<String>) -> Vec<WebWarning> {
    warnings.into_iter().map(classify_warning).collect()
}

fn classify_warning(warning: String) -> WebWarning {
    if is_known_benchmark_compatibility_warning(&warning) {
        return WebWarning {
            title: "Known Benchmark Compatibility Warning".to_string(),
            message: warning,
            category: "compatibility".to_string(),
            suppressed_by_default: true,
        };
    }

    if warning.contains("solc frontend unavailable; using tree-sitter fallback:")
        || warning.contains("solc frontend failed:")
    {
        return WebWarning {
            title: "Compiler Fallback".to_string(),
            message: warning,
            category: "compatibility".to_string(),
            suppressed_by_default: false,
        };
    }

    WebWarning {
        title: "Analyzer Warning".to_string(),
        message: warning,
        category: "general".to_string(),
        suppressed_by_default: false,
    }
}

fn is_known_benchmark_compatibility_warning(warning: &str) -> bool {
    const KNOWN_PATHS: [&str; 3] = [
        "Benchmarks/Not-so-smart/not-so-smart-contracts-master/denial_of_service/list_dos.sol",
        "Benchmarks/Not-so-smart/not-so-smart-contracts-master/reentrancy/DAO_source_code/DAO.sol",
        "Benchmarks/Not-so-smart/not-so-smart-contracts-master/unprotected_function/WalletLibrary_source_code/WalletLibrary.sol",
    ];

    warning.contains("solc frontend failed:")
        && KNOWN_PATHS.iter().any(|path| warning.contains(path))
}

fn extract_web_findings(mode: WebMode, report: &Value) -> ApiResult<Vec<WebFinding>> {
    let mut findings = match mode {
        WebMode::Static => extract_static_findings(report),
        WebMode::Symbolic => extract_surfaced_findings(report, "vulnerabilities", "meta_findings"),
        WebMode::Fuzzing => extract_surfaced_findings(report, "findings", "meta_findings"),
        WebMode::Hybrid => extract_surfaced_findings(report, "findings", "meta_findings"),
    };
    findings.sort_by(|left, right| {
        (
            severity_rank(left.severity.as_deref()),
            left.kind.as_str(),
            left.file.as_deref().unwrap_or(""),
            left.function.as_deref().unwrap_or(""),
            left.start.unwrap_or(0),
            left.message.as_str(),
        )
            .cmp(&(
                severity_rank(right.severity.as_deref()),
                right.kind.as_str(),
                right.file.as_deref().unwrap_or(""),
                right.function.as_deref().unwrap_or(""),
                right.start.unwrap_or(0),
                right.message.as_str(),
            ))
    });
    Ok(findings)
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
            confidence: json_string_opt(finding, "confidence"),
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

fn extract_surfaced_findings(report: &Value, runtime_key: &str, meta_key: &str) -> Vec<WebFinding> {
    let mut findings = Vec::new();

    if let Some(runtime) = report.get(runtime_key).and_then(Value::as_array) {
        findings.extend(
            runtime
                .iter()
                .map(|finding| extract_surfaced_finding(finding, "runtime")),
        );
    }

    if let Some(meta) = report.get(meta_key).and_then(Value::as_array) {
        findings.extend(
            meta.iter()
                .map(|finding| extract_surfaced_finding(finding, "meta")),
        );
    }

    findings
}

fn extract_surfaced_finding(finding: &Value, default_layer: &str) -> WebFinding {
    WebFinding {
        kind: json_string(finding, "kind"),
        layer: json_string_opt(finding, "analysis_layer")
            .unwrap_or_else(|| default_layer.to_string()),
        severity: json_string_opt(finding, "severity"),
        confidence: json_string_opt(finding, "confidence"),
        category: json_string_opt(finding, "category"),
        function: json_string_opt(finding, "function_name"),
        file: json_string_opt(finding, "file"),
        start: json_u32_opt(finding, "start"),
        end: json_u32_opt(finding, "end"),
        message: json_string(finding, "message"),
        evidence: json_string_opt(finding, "evidence_kind"),
    }
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

fn collect_analysis_targets(target: &Path) -> ApiResult<Vec<PathBuf>> {
    let metadata = fs::metadata(target).map_err(ApiError::internal_from_io)?;
    if metadata.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if !metadata.is_dir() {
        return Err(ApiError::bad_request(
            "selected target must be a Solidity file or directory",
        ));
    }

    let mut files = Vec::new();
    collect_solidity_files_recursive(target, &mut files)?;
    files.sort();
    if files.is_empty() {
        return Err(ApiError::bad_request(
            "selected directory does not contain Solidity files",
        ));
    }
    Ok(files)
}

fn count_solidity_files_recursive(dir: &Path) -> ApiResult<usize> {
    let mut count = 0usize;
    collect_solidity_file_count_recursive(dir, &mut count)?;
    Ok(count)
}

fn collect_solidity_file_count_recursive(dir: &Path, count: &mut usize) -> ApiResult<()> {
    let mut entries = fs::read_dir(dir)
        .map_err(ApiError::internal_from_io)?
        .filter_map(|entry| entry.ok())
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name().to_string_lossy().to_string());

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(ApiError::internal_from_io)?;
        if file_type.is_dir() {
            collect_solidity_file_count_recursive(&path, count)?;
            continue;
        }
        let is_solidity = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("sol"))
            .unwrap_or(false);
        if is_solidity {
            *count += 1;
        }
    }
    Ok(())
}

fn collect_solidity_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> ApiResult<()> {
    let mut entries = fs::read_dir(dir)
        .map_err(ApiError::internal_from_io)?
        .filter_map(|entry| entry.ok())
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name().to_string_lossy().to_string());

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(ApiError::internal_from_io)?;
        if file_type.is_dir() {
            collect_solidity_files_recursive(&path, out)?;
            continue;
        }
        let is_solidity = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("sol"))
            .unwrap_or(false);
        if is_solidity {
            out.push(path);
        }
    }
    Ok(())
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

fn json_u32_opt(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as u32)
}

fn json_usize(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(0)
}

fn severity_bucket(value: Option<&str>) -> &'static str {
    let normalized = value.unwrap_or("unknown").trim().to_ascii_lowercase();
    if normalized.contains("critical") || normalized.contains("high") {
        "high"
    } else if normalized.contains("medium") || normalized.contains("moderate") {
        "medium"
    } else if normalized.contains("low") {
        "low"
    } else {
        "unknown"
    }
}

fn severity_rank(value: Option<&str>) -> u8 {
    match severity_bucket(value) {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
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
