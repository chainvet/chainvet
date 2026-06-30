use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTarget {
    pub id: String,
    pub input_path: String,
    pub source_paths: Vec<String>,
    pub chain_id: Option<u64>,
    pub address: Option<String>,
    pub abi: Option<String>,
    pub bytecode: Option<String>,
    pub compiler: CompilerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerInfo {
    pub frontend_mode: String,
    pub compiler_name: String,
    pub compiler_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticHints {
    pub function_whitelist: Vec<u32>,
    pub function_blacklist: Vec<u32>,
    pub hotspots: Vec<Hotspot>,
    pub sinks: Vec<SinkRef>,
    pub callgraph: CallGraphHint,
    pub taint: TaintHint,
    pub storage_rw_map: Vec<FunctionStorageRwHint>,
    pub arg_domains: Vec<ArgDomainHint>,
    pub address_roles: Vec<AddressRoleHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hotspot {
    pub function_id: u32,
    pub function_name: Option<String>,
    pub score: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkRef {
    pub function_id: u32,
    pub function_name: Option<String>,
    pub sink_kind: String,
    pub severity: String,
    pub file: Option<String>,
    pub start: Option<u32>,
    pub end: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallGraphHint {
    pub total_sites: usize,
    pub resolved: usize,
    pub ambiguous: usize,
    pub external: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintHint {
    pub source_functions: usize,
    pub tainted_functions: usize,
    pub tainted_vars: usize,
    pub tainted_calls: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionStorageRwHint {
    pub function_id: u32,
    pub function_name: Option<String>,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgDomainHint {
    pub function_id: u32,
    pub function_name: Option<String>,
    pub param_index: usize,
    pub param_name: String,
    pub candidate_values: Vec<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRoleHint {
    pub role: String,
    pub indices: Vec<usize>,
    pub evidence: Vec<String>,
    pub target_functions: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seed {
    pub id: String,
    pub txs: Vec<TxSeed>,
    pub state_snapshot_id: Option<String>,
    pub score: f64,
}

impl Seed {
    pub fn tx_len(&self) -> usize {
        self.txs.len()
    }

    pub fn key(&self) -> String {
        let mut out = String::new();
        for tx in &self.txs {
            out.push_str(&format!(
                "{}|{}|{}|{}|{};",
                tx.function_id,
                tx.sender,
                tx.value,
                tx.args.join(","),
                tx.selector.as_deref().unwrap_or("")
            ));
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSeed {
    pub function_id: u32,
    pub selector: Option<String>,
    pub calldata: Option<String>,
    pub args: Vec<String>,
    pub sender: String,
    pub value: String,
    pub env: TxEnv,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxEnv {
    pub block_timestamp: Option<u128>,
    pub block_number: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontierGoal {
    pub id: String,
    pub function_id: u32,
    pub function_name: Option<String>,
    pub block_id: Option<u32>,
    pub edge_from: Option<u32>,
    pub edge_to: Option<u32>,
    pub sink_kind: Option<String>,
    pub reason: String,
    pub priority: f64,
    pub attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub epoch: u32,
    pub covered_edges: usize,
    pub total_edges: usize,
    pub coverage_pct: f64,
    pub delta_edges: i64,
    pub edge_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub engine: String,
    pub finding_type: String,
    pub severity: String,
    pub message: String,
    pub location: Option<FindingLocation>,
    pub reproduction: Option<Seed>,
    pub signature: String,
    #[serde(default = "default_analysis_layer")]
    pub analysis_layer: String,
    #[serde(default = "default_evidence_kind")]
    pub evidence_kind: String,
    pub metadata: BTreeMap<String, String>,
}

fn default_analysis_layer() -> String {
    "runtime".to_string()
}

fn default_evidence_kind() -> String {
    "rule".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLocation {
    pub file: Option<String>,
    pub start: Option<u32>,
    pub end: Option<u32>,
    pub pc: Option<usize>,
    pub function_id: Option<u32>,
    pub function_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePrefix {
    pub id: String,
    pub txs: Vec<TxSeed>,
    pub last_function_id: Option<u32>,
    pub covered_edges: Vec<(u32, u32)>,
    pub last_block: Option<u32>,
    pub distance_hint: Option<u32>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallMetrics {
    pub edge_rate: f64,
    pub stagnant_epochs: u32,
    pub coverage_delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochResultArtifact {
    pub epoch: u32,
    pub coverage: CoverageSummary,
    pub new_seed_ids: Vec<String>,
    pub findings: Vec<Finding>,
    pub frontier_goals: Vec<FrontierGoal>,
    pub stall: StallMetrics,
    pub trace_prefix: Option<TracePrefix>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverStats {
    pub elapsed_ms: u64,
    pub states_explored: u64,
    pub max_depth_reached: u32,
    pub satisfiable_paths: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistEvent {
    pub epoch: u32,
    pub goal: FrontierGoal,
    pub injected_seed_ids: Vec<String>,
    pub solver: SolverStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridReport {
    pub run_id: String,
    pub runtime_ms: u128,
    pub total_epochs: u32,
    pub coverage_curve: Vec<CoverageSummary>,
    pub findings_total: usize,
    pub findings_unique: usize,
    pub runtime_findings_total: usize,
    pub runtime_findings_unique: usize,
    pub meta_findings_total: usize,
    pub meta_findings_unique: usize,
    pub se_assists: usize,
    pub seeds_injected_by_se: usize,
    #[serde(default)]
    pub se_new_edges_from_injected: usize,
    pub time_to_first_finding_ms: Option<u128>,
}
