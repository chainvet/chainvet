use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::core::artifacts::{
    AssistEvent, ContractTarget, CoverageSummary, EpochResultArtifact, Finding, HybridReport, Seed,
    StaticHints,
};
use crate::util::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    run_id: String,
    run_dir: PathBuf,
}

impl ArtifactStore {
    pub fn create(base_dir: &Path) -> Result<Self> {
        let run_id = format!("run-{}", now_ms());
        let run_dir = base_dir.join(&run_id);
        fs::create_dir_all(&run_dir)?;
        Ok(Self { run_id, run_dir })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    pub fn save_target(&self, target: &ContractTarget) -> Result<()> {
        self.write_json("target.json", target)
    }

    pub fn save_static_hints(&self, hints: &StaticHints) -> Result<()> {
        self.write_json("static_hints.json", hints)
    }

    pub fn save_seed_corpus(&self, seeds: &[Seed]) -> Result<()> {
        self.write_json("seed_corpus.json", seeds)
    }

    pub fn save_findings(&self, findings: &[Finding]) -> Result<()> {
        self.write_json("findings.json", findings)
    }

    pub fn save_coverage_history(&self, coverage: &[CoverageSummary]) -> Result<()> {
        self.write_json("coverage_history.json", coverage)
    }

    pub fn save_epochs(&self, epochs: &[EpochResultArtifact]) -> Result<()> {
        self.write_json("epochs.json", epochs)
    }

    pub fn save_assists(&self, assists: &[AssistEvent]) -> Result<()> {
        self.write_json("se_assists.json", assists)
    }

    pub fn save_report(&self, report: &HybridReport) -> Result<()> {
        self.write_json("report.json", report)
    }

    pub fn read_latest_coverage_summary(&self) -> Result<Option<CoverageSummary>> {
        let all: Option<Vec<CoverageSummary>> = self.read_json("coverage_history.json")?;
        Ok(all.and_then(|v| v.into_iter().last()))
    }

    fn write_json<T: Serialize + ?Sized>(&self, name: &str, value: &T) -> Result<()> {
        let path = self.run_dir.join(name);
        let payload = serde_json::to_vec_pretty(value)
            .map_err(|err| Error::msg(format!("failed to encode {name}: {err}")))?;
        fs::write(path, payload)?;
        Ok(())
    }

    fn read_json<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.run_dir.join(name);
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read(&path)?;
        let value = serde_json::from_slice::<T>(&data)
            .map_err(|err| Error::msg(format!("failed to decode {name}: {err}")))?;
        Ok(Some(value))
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
