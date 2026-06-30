//! Chainvet HTTP server frontend: a thin REST API over `orchestrator::scan` so
//! web apps and other clients can analyze Solidity without linking the engines.
//!
//! Endpoints:
//!   GET  /health        -> {"status":"ok", ...}
//!   POST /scan          -> body {"source": "...", "mode": "hybrid"} -> ScanResult
//!
//! Listen address is `CHAINVET_SERVER_ADDR` (default 127.0.0.1:8080).

mod web;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use chainvet_orchestrator::{HybridBudget, ScanMode, ScanResult, scan_path};
use serde::Deserialize;
use serde_json::{Value, json};

#[tokio::main]
async fn main() {
    let root = std::env::var("CHAINVET_SERVER_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let state = Arc::new(web::AppState::new(root));

    let app = Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan))
        .merge(web::routes(state))
        .layer(tower_http::cors::CorsLayer::permissive());

    let addr =
        std::env::var("CHAINVET_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("chainvet-server listening on http://{addr}");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("error: server failed: {e}");
        std::process::exit(1);
    }
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "name": "Chainvet",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Deserialize)]
struct ScanRequest {
    /// Solidity source to analyze.
    source: String,
    /// Analysis mode (default "hybrid").
    #[serde(default)]
    mode: Option<String>,
}

async fn scan(Json(req): Json<ScanRequest>) -> Result<Json<ScanResult>, (StatusCode, String)> {
    let mode = parse_mode(req.mode.as_deref().unwrap_or("hybrid"))
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let path = write_temp(&req.source).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Scans are CPU-bound (Z3 / fuzzing) — run off the async worker threads.
    let result = tokio::task::spawn_blocking(move || {
        let r = scan_path(&path, mode, &HybridBudget::default());
        let _ = std::fs::remove_file(&path);
        r
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("scan task failed: {e}"),
        )
    })?
    .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    Ok(Json(result))
}

fn parse_mode(value: &str) -> Result<ScanMode, String> {
    match value {
        "static" => Ok(ScanMode::Static),
        "symbolic" => Ok(ScanMode::Symbolic),
        "fuzzing" => Ok(ScanMode::Fuzzing),
        "hybrid" => Ok(ScanMode::Hybrid),
        other => Err(format!("unknown mode: {other}")),
    }
}

/// Write the request source to a unique temp `.sol` file and return its path.
fn write_temp(source: &str) -> Result<String, String> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("chainvet-scan-{}-{}.sol", std::process::id(), n));
    std::fs::write(&path, source).map_err(|e| format!("failed to write temp source: {e}"))?;
    Ok(path.to_string_lossy().into_owned())
}
