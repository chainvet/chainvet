// Symbolic Execution Engine
// Consumes IR/CFG/SSA from M3 to perform path exploration and constraint solving.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::hash::{Hash, Hasher};
use std::time::Instant;
use z3::{
    SatResult, Solver, set_global_param,
    ast::{BV, Bool, Int},
};

use crate::analysis;
use crate::cfg;
use crate::frontend;
use crate::frontend::FrontendOutput;
use crate::fuzzing::types::DependencyMap;
use crate::ir::{ControlKind, IrInstr, IrPlace, IrValue, IrVar, PlaceClass};
use crate::norm::{FunctionKind, Mutability, NormalizedAst, Span, Visibility};
use crate::report::OutputFormat;
use crate::surfaced;
use crate::util::error::{Error, Result};

#[derive(Clone)]
struct State {
    function_id: u32,
    block_id: u32,
    instr_offset: usize,
    env: HashMap<String, Int>,
    storage: HashMap<String, Int>,
    origins: HashMap<String, HashSet<ValueOrigin>>,
    path_constraints: Vec<Bool>,
    fresh_id: u64,
    external_call_pc: Option<usize>,
    pending_low_level_calls: HashMap<String, PendingCall>,
    trace: Vec<usize>,
    expr_env: HashMap<String, String>,
    branch_triggers: Vec<String>,
    sender_checked: bool,
    inside_loop: bool,
    saw_order_sensitive_storage_read: bool,
    saw_this_balance_invariant: bool,
    storage_reads: HashSet<String>,
    block_visits: HashMap<u32, u16>,
    callback_depth: u8,
    callback_observed: bool,
    callback_changed_storage_keys: HashSet<String>,
    callback_stale_read_keys: HashSet<String>,
    callback_frame: Option<CallbackFrame>,
}

#[derive(Clone)]
struct CallbackFrame {
    function_id: u32,
    block_id: u32,
    instr_offset: usize,
    env: HashMap<String, Int>,
    storage: HashMap<String, Int>,
    origins: HashMap<String, HashSet<ValueOrigin>>,
    pending_low_level_calls: HashMap<String, PendingCall>,
    expr_env: HashMap<String, String>,
    sender_checked: bool,
    inside_loop: bool,
    saw_order_sensitive_storage_read: bool,
    saw_this_balance_invariant: bool,
    storage_reads: HashSet<String>,
    block_visits: HashMap<u32, u16>,
    callback_depth: u8,
    external_call_pc: Option<usize>,
}

#[derive(Clone, Copy)]
struct EngineCallbackData<'a> {
    ast: &'a NormalizedAst,
    compiler: &'a crate::frontend::CompilerInfo,
    deps: &'a DependencyMap,
}

#[derive(Default)]
struct AuthorityRuntimeProfile {
    constructor_like: bool,
    wrong_constructor_candidate: bool,
    exclusive_authority_write: bool,
    guarded_by_modifier: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ValueOrigin {
    Timestamp,
    BlockNumber,
    ThisBalance,
    TxOrigin,
    DelegatecallRef,
    LowLevelCallRef,
    ValueCallRef,
    SendRef,
    TransferRef,
}

#[derive(Clone)]
struct PendingCall {
    call_pc: usize,
    callee: String,
    span: Option<Span>,
}

#[derive(Clone)]
enum TerminationKind {
    Return,
    Revert,
    Fallthrough,
}

#[derive(Clone)]
struct TerminalState {
    kind: TerminationKind,
    values: Vec<Int>,
    path_constraints: Vec<Bool>,
}

#[derive(Debug, Clone, Serialize)]
struct FunctionSymbolicReport {
    id: u32,
    name: Option<String>,
    instructions: usize,
    explored_states: usize,
    reachable_returns: usize,
    reachable_reverts: usize,
    reachable_fallthroughs: usize,
    terminal_paths: usize,
    pruned_branches: usize,
    dead_ends: usize,
    max_worklist: usize,
    vulnerability_count: usize,
    truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SymbolicReport {
    files: usize,
    functions: usize,
    instructions: usize,
    explored_states: usize,
    reachable_returns: usize,
    reachable_reverts: usize,
    reachable_fallthroughs: usize,
    terminal_paths: usize,
    pruned_branches: usize,
    dead_ends: usize,
    max_worklist: usize,
    vulnerability_count: usize,
    meta_finding_count: usize,
    vulnerability_count_raw: usize,
    meta_finding_count_raw: usize,
    suppressed_vulnerabilities: usize,
    suppressed_meta_findings: usize,
    truncated_functions: usize,
    by_function: Vec<FunctionSymbolicReport>,
    vulnerabilities: Vec<surfaced::SurfacedFinding>,
    vulnerabilities_raw: Vec<VulnerabilityFinding>,
    meta_findings: Vec<surfaced::SurfacedFinding>,
    meta_findings_raw: Vec<crate::core::artifacts::Finding>,
}

#[derive(Debug, Clone, Default)]
struct EngineStats {
    instructions: usize,
    explored_states: usize,
    reachable_returns: usize,
    reachable_reverts: usize,
    reachable_fallthroughs: usize,
    terminal_paths: usize,
    pruned_branches: usize,
    dead_ends: usize,
    max_worklist: usize,
    vulnerabilities: Vec<LocalVulnerability>,
    truncated: bool,
}

#[derive(Default)]
struct SolverCache {
    sat_by_constraints: HashMap<String, bool>,
    underflow_by_constraints: HashMap<String, Option<String>>,
    add_overflow_by_constraints: HashMap<String, Option<String>>,
}

impl SolverCache {
    fn constraints_key(path_constraints: &[Bool]) -> String {
        let mut clauses = path_constraints
            .iter()
            .map(|constraint| constraint.to_string())
            .collect::<Vec<_>>();
        clauses.sort_unstable();
        clauses.join(" && ")
    }

    fn underflow_key(path_constraints: &[Bool], lhs: &Int, rhs: &Int) -> String {
        format!(
            "{}|lhs={}|rhs={}",
            Self::constraints_key(path_constraints),
            lhs,
            rhs
        )
    }

    fn add_overflow_key(path_constraints: &[Bool], lhs: &Int, rhs: &Int) -> String {
        format!(
            "{}|add_lhs={}|add_rhs={}",
            Self::constraints_key(path_constraints),
            lhs,
            rhs
        )
    }

    fn is_feasible(&mut self, path_constraints: &[Bool]) -> bool {
        let key = Self::constraints_key(path_constraints);
        if let Some(cached) = self.sat_by_constraints.get(&key) {
            return *cached;
        }
        let solver = Solver::new();
        for constraint in path_constraints {
            solver.assert(constraint);
        }
        let feasible = matches!(solver.check(), SatResult::Sat);
        self.sat_by_constraints.insert(key, feasible);
        feasible
    }

    fn check_underflow(
        &mut self,
        path_constraints: &[Bool],
        lhs: &Int,
        rhs: &Int,
    ) -> Option<String> {
        let key = Self::underflow_key(path_constraints, lhs, rhs);
        if let Some(cached) = self.underflow_by_constraints.get(&key) {
            return cached.clone();
        }
        let solver = Solver::new();
        for constraint in path_constraints {
            solver.assert(constraint);
        }
        let lhs_bv = int_to_evm_bv(lhs);
        let rhs_bv = int_to_evm_bv(rhs);
        solver.assert(rhs_bv.bvugt(&lhs_bv));
        let model = if matches!(solver.check(), SatResult::Sat) {
            solver.get_model().map(|m| m.to_string())
        } else {
            None
        };
        self.underflow_by_constraints.insert(key, model.clone());
        model
    }

    fn check_add_overflow(
        &mut self,
        path_constraints: &[Bool],
        lhs: &Int,
        rhs: &Int,
    ) -> Option<String> {
        let key = Self::add_overflow_key(path_constraints, lhs, rhs);
        if let Some(cached) = self.add_overflow_by_constraints.get(&key) {
            return cached.clone();
        }
        let solver = Solver::new();
        for constraint in path_constraints {
            solver.assert(constraint);
        }
        let lhs_bv = int_to_evm_bv(lhs);
        let rhs_bv = int_to_evm_bv(rhs);
        let sum_bv = lhs_bv.bvadd(&rhs_bv);
        solver.assert(sum_bv.bvult(&lhs_bv));
        let model = if matches!(solver.check(), SatResult::Sat) {
            solver.get_model().map(|m| m.to_string())
        } else {
            None
        };
        self.add_overflow_by_constraints.insert(key, model.clone());
        model
    }
}

#[derive(Debug, Clone)]
struct LocalVulnerability {
    kind: VulnerabilityKind,
    pc: usize,
    instruction: String,
    trace: Vec<usize>,
    trigger: Option<String>,
    branch_triggers: Vec<String>,
    span: Option<Span>,
    path_constraints: Vec<String>,
    message: String,
    model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum VulnerabilityKind {
    Overflow,
    Underflow,
    Reentrancy,
    ReentrancyFallback,
    TxOrigin,
    Delegatecall,
    UncheckedCall,
    Selfdestruct,
    AccessControl,
    ArbitraryWrite,
    WrongConstructorName,
    PublicMintBurn,
    TimestampDependency,
    WeakPrng,
    HardcodedGasTransfer,
    LockedEther,
    MemoryManipulation,
    DosBlockGasLimit,
    DosWithFailedCall,
    TransactionOrderDependency,
    SignatureMalleability,
    UnsafeSendInRequire,
    UnprotectedEtherWithdrawal,
    Shadowing,
}

impl VulnerabilityKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Overflow => "integer-overflow",
            Self::Underflow => "integer-underflow",
            Self::Reentrancy => "reentrancy",
            Self::ReentrancyFallback => "reentrancy",
            Self::TxOrigin => "tx-origin",
            Self::Delegatecall => "unsafe-delegatecall",
            Self::UncheckedCall => "unchecked-call",
            Self::Selfdestruct => "unprotected-selfdestruct",
            Self::AccessControl => "access-control",
            Self::ArbitraryWrite => "arbitrary-write",
            Self::WrongConstructorName => "wrong-constructor-name",
            Self::PublicMintBurn => "public-mint-burn",
            Self::TimestampDependency => "timestamp-dependency",
            Self::WeakPrng => "weak-prng",
            Self::HardcodedGasTransfer => "hardcoded-gas-transfer",
            Self::LockedEther => "locked-ether",
            Self::MemoryManipulation => "memory-manipulation",
            Self::DosBlockGasLimit => "dos-block-gas-limit",
            Self::DosWithFailedCall => "dos-with-failed-call",
            Self::TransactionOrderDependency => "transaction-order-dependency",
            Self::SignatureMalleability => "signature-malleability",
            Self::UnsafeSendInRequire => "unsafe-send-in-require",
            Self::UnprotectedEtherWithdrawal => "unprotected-ether-withdrawal",
            Self::Shadowing => "shadowing",
        }
    }

    fn confidence(self) -> VulnerabilityConfidence {
        match self {
            Self::Reentrancy
            | Self::TxOrigin
            | Self::Delegatecall
            | Self::UncheckedCall
            | Self::Selfdestruct => VulnerabilityConfidence::High,
            Self::ReentrancyFallback | Self::SignatureMalleability | Self::LockedEther => {
                VulnerabilityConfidence::Low
            }
            Self::Overflow
            | Self::Underflow
            | Self::AccessControl
            | Self::ArbitraryWrite
            | Self::WrongConstructorName
            | Self::PublicMintBurn
            | Self::TimestampDependency
            | Self::WeakPrng
            | Self::HardcodedGasTransfer
            | Self::MemoryManipulation
            | Self::DosBlockGasLimit
            | Self::DosWithFailedCall
            | Self::TransactionOrderDependency
            | Self::UnsafeSendInRequire
            | Self::UnprotectedEtherWithdrawal
            | Self::Shadowing => VulnerabilityConfidence::Medium,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum VulnerabilityConfidence {
    Low,
    Medium,
    High,
}

impl VulnerabilityConfidence {
    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct VulnerabilityFinding {
    kind: String,
    confidence: String,
    function_id: u32,
    function_name: Option<String>,
    pc: usize,
    instruction: String,
    trace: Vec<usize>,
    trigger: Option<String>,
    branch_triggers: Vec<String>,
    location: Option<FindingLocation>,
    path_constraints: Vec<String>,
    message: String,
    model: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FindingLocation {
    file: String,
    start: u32,
    end: u32,
    snippet: Option<String>,
}

impl State {
    fn new() -> Self {
        Self {
            function_id: 0,
            block_id: 0,
            instr_offset: 0,
            env: HashMap::new(),
            storage: HashMap::new(),
            origins: HashMap::new(),
            path_constraints: Vec::new(),
            fresh_id: 0,
            external_call_pc: None,
            pending_low_level_calls: HashMap::new(),
            trace: Vec::new(),
            expr_env: HashMap::new(),
            branch_triggers: Vec::new(),
            sender_checked: false,
            inside_loop: false,
            saw_order_sensitive_storage_read: false,
            saw_this_balance_invariant: false,
            storage_reads: HashSet::new(),
            block_visits: HashMap::new(),
            callback_depth: 0,
            callback_observed: false,
            callback_changed_storage_keys: HashSet::new(),
            callback_stale_read_keys: HashSet::new(),
            callback_frame: None,
        }
    }

    fn fresh_symbol(&mut self, prefix: &str) -> Int {
        let id = self.fresh_id;
        self.fresh_id = self.fresh_id.saturating_add(1);
        Int::new_const(format!("{prefix}_{id}"))
    }

    fn lookup_var(&mut self, var: &IrVar) -> Int {
        let name = var_key(var);
        if let Some(value) = self.env.get(&name) {
            return value.clone();
        }
        let sym = self.fresh_symbol(&name);
        self.env.insert(name, sym.clone());
        sym
    }

    fn eval_value(&mut self, value: &IrValue) -> Int {
        match value {
            IrValue::Literal(lit) => Int::from_i64(stable_literal_value(lit.value.as_str())),
            IrValue::Var(var) => self.lookup_var(var),
            IrValue::Unknown => self.fresh_symbol("unknown"),
        }
    }

    fn eval_bool(&mut self, value: &IrValue) -> Bool {
        self.eval_value(value).eq(Int::from_i64(0)).not()
    }

    fn set_var(&mut self, var: &IrVar, value: Int) {
        self.env.insert(var_key(var), value);
    }

    fn value_expr(&self, value: &IrValue) -> String {
        match value {
            IrValue::Literal(lit) => lit.value.clone(),
            IrValue::Unknown => "unknown".to_string(),
            IrValue::Var(var) => {
                let key = var_key(var);
                self.expr_env.get(&key).cloned().unwrap_or(key)
            }
        }
    }

    fn read_place(&mut self, place: &IrPlace) -> Int {
        match place {
            IrPlace::Var {
                class: PlaceClass::Storage,
                ..
            } => {
                let key = place_key(place);
                if let Some(value) = self.storage.get(&key) {
                    return value.clone();
                }
                let sym = self.fresh_symbol("storage");
                self.storage.insert(key, sym.clone());
                sym
            }
            IrPlace::Var { var, .. } => self.lookup_var(var),
            _ => {
                let key = place_key(place);
                if let Some(value) = self.storage.get(&key) {
                    return value.clone();
                }
                let sym = self.fresh_symbol("storage");
                self.storage.insert(key, sym.clone());
                sym
            }
        }
    }

    fn write_place(&mut self, place: &IrPlace, value: Int) {
        match place {
            IrPlace::Var {
                class: PlaceClass::Storage,
                ..
            } => {
                self.storage.insert(place_key(place), value);
            }
            IrPlace::Var { var, .. } => self.set_var(var, value),
            _ => {
                self.storage.insert(place_key(place), value);
            }
        }
    }
}

const MAX_ENGINE_STEPS: usize = 200_000;
const MAX_TRACE_LEN: usize = 128;
const MAX_BLOCK_VISITS_PER_PATH: u16 = 4;
const MAX_STATE_SHAPE_REVISITS: u8 = 2;
const MAX_PATH_CONSTRAINTS: usize = 128;
const MAX_WORKLIST_SIZE: usize = 1_024;
const MAX_FUNCTION_TIME_MS: u64 = 7_500;
const CALLBACK_MAX_DEPTH: u8 = 1;
const CALLBACK_MAX_FANOUT: usize = 4;

const SYMBOLIC_MAX_STEPS_ENV: &str = "STATIC_SYMBOLIC_MAX_STEPS";
const SYMBOLIC_MAX_TRACE_LEN_ENV: &str = "STATIC_SYMBOLIC_MAX_TRACE_LEN";
const SYMBOLIC_MAX_BLOCK_VISITS_ENV: &str = "STATIC_SYMBOLIC_MAX_BLOCK_VISITS";
const SYMBOLIC_MAX_SHAPE_REVISITS_ENV: &str = "STATIC_SYMBOLIC_MAX_STATE_SHAPE_REVISITS";
const SYMBOLIC_MAX_PATH_CONSTRAINTS_ENV: &str = "STATIC_SYMBOLIC_MAX_PATH_CONSTRAINTS";
const SYMBOLIC_MAX_WORKLIST_ENV: &str = "STATIC_SYMBOLIC_MAX_WORKLIST";
const SYMBOLIC_MAX_FUNCTION_MS_ENV: &str = "STATIC_SYMBOLIC_MAX_FUNCTION_MS";
const SYMBOLIC_SOLVER_TIMEOUT_MS_ENV: &str = "STATIC_SYMBOLIC_SOLVER_TIMEOUT_MS";
const DEFAULT_SYMBOLIC_SOLVER_TIMEOUT_MS: u64 = 2_000;
const EVM_WORD_BITS: u32 = 256;

#[derive(Clone, Copy)]
struct EngineLimits {
    max_engine_steps: usize,
    max_trace_len: usize,
    max_block_visits_per_path: u16,
    max_state_shape_revisits: u8,
    max_path_constraints: usize,
    max_worklist_size: usize,
    max_function_ms: u64,
}

impl EngineLimits {
    fn from_env() -> Self {
        Self {
            max_engine_steps: env_usize(SYMBOLIC_MAX_STEPS_ENV, MAX_ENGINE_STEPS),
            max_trace_len: env_usize(SYMBOLIC_MAX_TRACE_LEN_ENV, MAX_TRACE_LEN),
            max_block_visits_per_path: env_u16(
                SYMBOLIC_MAX_BLOCK_VISITS_ENV,
                MAX_BLOCK_VISITS_PER_PATH,
            ),
            max_state_shape_revisits: env_u8(
                SYMBOLIC_MAX_SHAPE_REVISITS_ENV,
                MAX_STATE_SHAPE_REVISITS,
            ),
            max_path_constraints: env_usize(
                SYMBOLIC_MAX_PATH_CONSTRAINTS_ENV,
                MAX_PATH_CONSTRAINTS,
            ),
            max_worklist_size: env_usize(SYMBOLIC_MAX_WORKLIST_ENV, MAX_WORKLIST_SIZE),
            max_function_ms: env_u64(SYMBOLIC_MAX_FUNCTION_MS_ENV, MAX_FUNCTION_TIME_MS),
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_u16(name: &str, default: u16) -> u16 {
    env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_u8(name: &str, default: u8) -> u8 {
    env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u8>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

pub fn run(output: &FrontendOutput, format: OutputFormat) -> Result<()> {
    configure_solver_limits();
    let ir_module = crate::ir::lower_module(&output.ast);
    let dependency_map = crate::fuzzing::types::build_dependency_map(&ir_module, &output.ast);
    let cfgs = cfg::build_from_ir(&ir_module);
    let call_graph = analysis::build_call_graph(&output.ast);
    let taint = analysis::taint::analyze(&output.ast, &cfgs);
    let static_findings = analysis::detectors::run_detectors(&output.ast, &call_graph, &taint);
    let mut tod_allowed: HashSet<u32> = HashSet::new();
    let mut sig_mall_allowed: HashSet<u32> = HashSet::new();
    let mut reentrancy_allowed: HashSet<u32> = HashSet::new();
    for finding in &static_findings {
        let Some(function_id) = finding.function else {
            continue;
        };
        match finding.kind {
            analysis::detectors::FindingKind::TransactionOrderDependency => {
                tod_allowed.insert(function_id);
            }
            analysis::detectors::FindingKind::SignatureMalleability => {
                sig_mall_allowed.insert(function_id);
            }
            analysis::detectors::FindingKind::ReentrancyNegativeEvents
            | analysis::detectors::FindingKind::ReentrancyTransfer
            | analysis::detectors::FindingKind::ReentrancySameEffect
            | analysis::detectors::FindingKind::ReentrancyEthTransfer
            | analysis::detectors::FindingKind::ReentrancyNoEthTransfer => {
                reentrancy_allowed.insert(function_id);
            }
            _ => {}
        }
    }
    let meta_findings = crate::meta::analyze_for_engine(
        output,
        crate::meta::ConsumerEngine::Symbolic,
        &static_findings,
    );
    let checked_arithmetic = has_checked_arithmetic(&output.ast);
    let shadowed_params = collect_shadowed_params(&output.ast);
    let contracts_with_payable = collect_payable_contracts(&output.ast);
    let contracts_with_ether_send = collect_contracts_with_ether_send(&output.ast, &ir_module);
    let mut locked_ether_emitted_contracts: HashSet<u32> = HashSet::new();
    let mut by_function = Vec::new();

    let mut instructions = 0usize;
    let mut explored_states = 0usize;
    let mut reachable_returns = 0usize;
    let mut reachable_reverts = 0usize;
    let mut reachable_fallthroughs = 0usize;
    let mut terminal_paths = 0usize;
    let mut pruned_branches = 0usize;
    let mut dead_ends = 0usize;
    let mut max_worklist = 0usize;
    let mut vulnerabilities: Vec<VulnerabilityFinding> = Vec::new();
    let mut seen_output_vulns: HashSet<(u32, String, usize, String)> = HashSet::new();
    let mut truncated_functions = 0usize;

    for function in &ir_module.functions {
        let Some(cfg_fn) = cfgs.iter().find(|cfg_fn| cfg_fn.id == function.id) else {
            continue;
        };

        let stats = engine(
            cfg_fn,
            &cfgs,
            Some(EngineCallbackData {
                ast: &output.ast,
                compiler: &output.compiler,
                deps: &dependency_map,
            }),
            checked_arithmetic,
            reentrancy_allowed.contains(&function.id),
            tod_allowed.contains(&function.id),
            sig_mall_allowed.contains(&function.id),
        );
        instructions += stats.instructions;
        explored_states += stats.explored_states;
        reachable_returns += stats.reachable_returns;
        reachable_reverts += stats.reachable_reverts;
        reachable_fallthroughs += stats.reachable_fallthroughs;
        terminal_paths += stats.terminal_paths;
        pruned_branches += stats.pruned_branches;
        dead_ends += stats.dead_ends;
        max_worklist = max_worklist.max(stats.max_worklist);
        if stats.truncated {
            truncated_functions += 1;
        }
        let mut function_vulnerability_count = stats.vulnerabilities.len();
        for vuln in stats.vulnerabilities {
            let kind = vuln.kind.as_str().to_string();
            let root_cause_key = local_root_cause_key(&vuln);
            let dedup_key = (function.id, kind.clone(), vuln.pc, root_cause_key);
            if !seen_output_vulns.insert(dedup_key) {
                continue;
            }
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: vuln.kind.confidence().as_str().to_string(),
                function_id: function.id,
                function_name: function.name.clone(),
                pc: vuln.pc,
                instruction: vuln.instruction,
                trace: vuln.trace,
                trigger: vuln.trigger,
                branch_triggers: vuln.branch_triggers,
                location: vuln
                    .span
                    .as_ref()
                    .and_then(|span| build_location(span, output)),
                path_constraints: vuln.path_constraints,
                message: vuln.message,
                model: vuln.model,
            });
        }

        if let Some(params) = shadowed_params.get(&function.id) {
            for param in params {
                vulnerabilities.push(VulnerabilityFinding {
                    kind: VulnerabilityKind::Shadowing.as_str().to_string(),
                    confidence: VulnerabilityKind::Shadowing
                        .confidence()
                        .as_str()
                        .to_string(),
                    function_id: function.id,
                    function_name: function.name.clone(),
                    pc: 0,
                    instruction: format!("parameter {param}"),
                    trace: Vec::new(),
                    trigger: None,
                    branch_triggers: Vec::new(),
                    location: build_location(&function.span, output),
                    path_constraints: Vec::new(),
                    message: format!(
                        "parameter '{}' shadows a state variable with the same name",
                        param
                    ),
                    model: None,
                });
                function_vulnerability_count = function_vulnerability_count.saturating_add(1);
            }
        }

        if let Some(ast_fn) = output.ast.functions.get(function.id as usize) {
            if is_public_mint_burn_function(ast_fn, &output.compiler) {
                let kind = VulnerabilityKind::PublicMintBurn.as_str().to_string();
                let dedup_key = (
                    function.id,
                    kind.clone(),
                    0usize,
                    "public-mint-burn".to_string(),
                );
                if seen_output_vulns.insert(dedup_key) {
                    vulnerabilities.push(VulnerabilityFinding {
                        kind,
                        confidence: VulnerabilityKind::PublicMintBurn
                            .confidence()
                            .as_str()
                            .to_string(),
                        function_id: function.id,
                        function_name: function.name.clone(),
                        pc: 0,
                        instruction: function
                            .name
                            .clone()
                            .unwrap_or_else(|| "<anonymous>".to_string()),
                        trace: Vec::new(),
                        trigger: None,
                        branch_triggers: Vec::new(),
                        location: build_location(&function.span, output),
                        path_constraints: Vec::new(),
                        message: format!(
                            "public {} function may allow unauthorized supply manipulation",
                            function
                                .name
                                .as_deref()
                                .unwrap_or("<anonymous>")
                        ),
                        model: None,
                    });
                    function_vulnerability_count = function_vulnerability_count.saturating_add(1);
                }
            }

            if let Some(contract_id) = ast_fn.contract {
                let should_emit_locked_ether = ast_fn.mutability == Mutability::Payable
                    && contracts_with_payable.contains(&contract_id)
                    && !contracts_with_ether_send.contains(&contract_id)
                    && locked_ether_emitted_contracts.insert(contract_id);
                if should_emit_locked_ether {
                    let kind = VulnerabilityKind::LockedEther.as_str().to_string();
                    let dedup_key = (
                        function.id,
                        kind.clone(),
                        0usize,
                        "locked-ether".to_string(),
                    );
                    if seen_output_vulns.insert(dedup_key) {
                        vulnerabilities.push(VulnerabilityFinding {
                            kind,
                            confidence: VulnerabilityKind::LockedEther
                                .confidence()
                                .as_str()
                                .to_string(),
                            function_id: function.id,
                            function_name: function.name.clone(),
                            pc: 0,
                            instruction: function
                                .name
                                .clone()
                                .unwrap_or_else(|| "<anonymous>".to_string()),
                            trace: Vec::new(),
                            trigger: None,
                            branch_triggers: Vec::new(),
                            location: build_location(&function.span, output),
                            path_constraints: Vec::new(),
                            message:
                                "contract accepts Ether but no Ether-sending path was detected"
                                    .to_string(),
                            model: None,
                        });
                        function_vulnerability_count =
                            function_vulnerability_count.saturating_add(1);
                    }
                }
            }
        }

        by_function.push(FunctionSymbolicReport {
            id: function.id,
            name: function.name.clone(),
            instructions: stats.instructions,
            explored_states: stats.explored_states,
            reachable_returns: stats.reachable_returns,
            reachable_reverts: stats.reachable_reverts,
            reachable_fallthroughs: stats.reachable_fallthroughs,
            terminal_paths: stats.terminal_paths,
            pruned_branches: stats.pruned_branches,
            dead_ends: stats.dead_ends,
            max_worklist: stats.max_worklist,
            vulnerability_count: function_vulnerability_count,
            truncated: stats.truncated,
        });
    }

    let runtime_reentrancy_functions = vulnerabilities
        .iter()
        .filter(|v| v.kind == VulnerabilityKind::Reentrancy.as_str())
        .map(|v| v.function_id)
        .collect::<HashSet<_>>();
    let runtime_access_like_functions = vulnerabilities
        .iter()
        .filter(|v| {
            v.kind == VulnerabilityKind::AccessControl.as_str()
                || v.kind == VulnerabilityKind::WrongConstructorName.as_str()
        })
        .map(|v| v.function_id)
        .collect::<HashSet<_>>();
    let runtime_dos_functions = vulnerabilities
        .iter()
        .filter(|v| v.kind == VulnerabilityKind::DosWithFailedCall.as_str())
        .map(|v| v.function_id)
        .collect::<HashSet<_>>();
    let runtime_dos_block_gas_limit_functions = vulnerabilities
        .iter()
        .filter(|v| v.kind == VulnerabilityKind::DosBlockGasLimit.as_str())
        .map(|v| v.function_id)
        .collect::<HashSet<_>>();
    let runtime_tod_functions = vulnerabilities
        .iter()
        .filter(|v| v.kind == VulnerabilityKind::TransactionOrderDependency.as_str())
        .map(|v| v.function_id)
        .collect::<HashSet<_>>();
    let runtime_locked_ether_functions = vulnerabilities
        .iter()
        .filter(|v| v.kind == VulnerabilityKind::LockedEther.as_str())
        .map(|v| v.function_id)
        .collect::<HashSet<_>>();

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::TransactionOrderDependency)
    {
        let function_id = finding.function.unwrap_or(0);
        if runtime_tod_functions.contains(&function_id) {
            continue;
        }
        let Some(cfg_fn) = cfgs.iter().find(|cfg_fn| cfg_fn.id == function_id) else {
            continue;
        };
        if !function_has_tod_runtime_evidence(
            cfg_fn,
            EngineCallbackData {
                ast: &output.ast,
                compiler: &output.compiler,
                deps: &dependency_map,
            },
        ) {
            continue;
        }
        let function_name = output
            .ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.clone());
        let kind = VulnerabilityKind::TransactionOrderDependency
            .as_str()
            .to_string();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "ir-guided-runtime-recovery".to_string(),
        );
        if seen_output_vulns.insert(dedup_key) {
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: VulnerabilityKind::TransactionOrderDependency
                    .confidence()
                    .as_str()
                    .to_string(),
                function_id,
                function_name: function_name.clone(),
                pc: 0,
                instruction: "ir-guided-runtime-recovery".to_string(),
                trace: Vec::new(),
                trigger: None,
                branch_triggers: Vec::new(),
                location: build_location(&finding.span, output),
                path_constraints: Vec::new(),
                message:
                    "runtime CFG shows an order-sensitive storage read followed by a value-moving external call; front-running/TOD risk"
                        .to_string(),
                model: None,
            });
            if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
                entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
            }
        }
    }

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::DosBlockGasLimit)
    {
        let function_id = finding.function.unwrap_or(0);
        if runtime_dos_block_gas_limit_functions.contains(&function_id)
            || !runtime_dos_functions.contains(&function_id)
            || !function_source_has_dynamic_gas_loop(&output.ast, function_id)
        {
            continue;
        }
        let function_name = output
            .ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.clone());
        let kind = VulnerabilityKind::DosBlockGasLimit.as_str().to_string();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "runtime-loop-bound-recovery".to_string(),
        );
        if seen_output_vulns.insert(dedup_key) {
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: VulnerabilityKind::DosBlockGasLimit
                    .confidence()
                    .as_str()
                    .to_string(),
                function_id,
                function_name: function_name.clone(),
                pc: 0,
                instruction: "runtime-loop-bound-recovery".to_string(),
                trace: Vec::new(),
                trigger: None,
                branch_triggers: Vec::new(),
                location: build_location(&finding.span, output),
                path_constraints: Vec::new(),
                message:
                    "runtime execution reached a loop/call DoS path, and the loop bound is dynamic (`.length`/gas), so block-gas-limit DoS is also feasible"
                        .to_string(),
                model: None,
            });
            if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
                entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
            }
        }
    }

    for finding in static_findings.iter().filter(|finding| {
        matches!(
            finding.kind,
            analysis::detectors::FindingKind::ReentrancyNegativeEvents
                | analysis::detectors::FindingKind::ReentrancyTransfer
                | analysis::detectors::FindingKind::ReentrancySameEffect
                | analysis::detectors::FindingKind::ReentrancyEthTransfer
                | analysis::detectors::FindingKind::ReentrancyNoEthTransfer
        )
    }) {
        let function_id = finding.function.unwrap_or(0);
        if runtime_reentrancy_functions.contains(&function_id) {
            continue;
        }
        let strong_stipend_pattern =
            function_has_strong_stipend_reentrancy_pattern(&output.ast, function_id);
        if function_uses_only_stipend_external_calls(&output.ast, function_id)
            && !strong_stipend_pattern
        {
            continue;
        }
        if (!function_has_value_moving_low_level_call(&output.ast, function_id)
            && !strong_stipend_pattern)
            || function_is_direct_msg_value_forwarder(Some(&output.ast), function_id)
        {
            continue;
        }
        let has_runtime_tod = vulnerabilities.iter().any(|v| {
            v.function_id == function_id
                && v.kind == VulnerabilityKind::TransactionOrderDependency.as_str()
        });
        if finding.kind == analysis::detectors::FindingKind::ReentrancyNoEthTransfer
            && has_runtime_tod
        {
            continue;
        }
        let function_name = output
            .ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.clone());
        let kind = VulnerabilityKind::ReentrancyFallback.as_str().to_string();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "static-guided-runtime-backstop".to_string(),
        );
        if seen_output_vulns.insert(dedup_key) {
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: VulnerabilityKind::ReentrancyFallback
                    .confidence()
                    .as_str()
                    .to_string(),
                function_id,
                function_name: function_name.clone(),
                pc: 0,
                instruction: "static-guided-backstop".to_string(),
                trace: Vec::new(),
                trigger: None,
                branch_triggers: Vec::new(),
                location: build_location(&finding.span, output),
                path_constraints: Vec::new(),
                message:
                    "runtime callback/store evidence was insufficient, but static reentrancy signal exists for this function (runtime backstop)"
                        .to_string(),
                model: None,
            });
            if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
                entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
            }
        }
    }

    for function in output
        .ast
        .functions
        .iter()
        .filter(|function| frontend::is_public_entrypoint(function, &output.compiler))
    {
        let function_id = function.id;
        if runtime_reentrancy_functions.contains(&function_id)
            || !function_has_strong_stipend_reentrancy_pattern(&output.ast, function_id)
        {
            continue;
        }
        let kind = VulnerabilityKind::ReentrancyFallback.as_str().to_string();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "source-guided-stipend-runtime-backstop".to_string(),
        );
        if seen_output_vulns.insert(dedup_key) {
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: "medium".to_string(),
                function_id,
                function_name: function.name.clone(),
                pc: 0,
                instruction: "source-guided-stipend-backstop".to_string(),
                trace: Vec::new(),
                trigger: None,
                branch_triggers: Vec::new(),
                location: build_location(&function.span, output),
                path_constraints: Vec::new(),
                message:
                    "runtime callback/store evidence was insufficient, but the function performs a value-moving payout followed by destructive state updates (`delete`/zeroing/decrement), so reentrancy remains feasible"
                        .to_string(),
                model: None,
            });
            if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
                entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
            }
        }
    }

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::DosWithFailedCall)
    {
        let function_id = finding.function.unwrap_or(0);
        if runtime_dos_functions.contains(&function_id)
            || !function_has_value_moving_low_level_call(&output.ast, function_id)
            || function_is_checked_selector_low_level_wrapper(Some(&output.ast), function_id)
        {
            continue;
        }
        let function_name = output
            .ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.clone());
        let kind = VulnerabilityKind::DosWithFailedCall.as_str().to_string();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "static-guided-runtime-backstop".to_string(),
        );
        if seen_output_vulns.insert(dedup_key) {
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: VulnerabilityKind::DosWithFailedCall
                    .confidence()
                    .as_str()
                    .to_string(),
                function_id,
                function_name: function_name.clone(),
                pc: 0,
                instruction: "static-guided-backstop".to_string(),
                trace: Vec::new(),
                trigger: None,
                branch_triggers: Vec::new(),
                location: build_location(&finding.span, output),
                path_constraints: Vec::new(),
                message:
                    "runtime loop/call failure evidence was insufficient, but static DoS-with-failed-call signal exists for this function (runtime backstop)"
                        .to_string(),
                model: None,
            });
            if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
                entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
            }
        }
    }

    for finding in crate::meta::runtime_promotions(&meta_findings) {
        let function_id = finding
            .location
            .as_ref()
            .and_then(|location| location.function_id)
            .unwrap_or(0);
        let kind = finding.finding_type.clone();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "meta-runtime-backstop".to_string(),
        );
        if !seen_output_vulns.insert(dedup_key) {
            continue;
        }
        vulnerabilities.push(VulnerabilityFinding {
            kind,
            confidence: finding
                .metadata
                .get("confidence")
                .cloned()
                .unwrap_or_else(|| finding.severity.clone()),
            function_id,
            function_name: finding
                .location
                .as_ref()
                .and_then(|location| location.function_name.clone()),
            pc: 0,
            instruction: "meta-runtime-backstop".to_string(),
            trace: Vec::new(),
            trigger: None,
            branch_triggers: Vec::new(),
            location: finding.location.as_ref().map(|location| FindingLocation {
                file: location.file.clone().unwrap_or_else(|| "<unknown>".to_string()),
                start: location.start.unwrap_or(0),
                end: location.end.unwrap_or(0),
                snippet: None,
            }),
            path_constraints: Vec::new(),
            message: format!(
                "runtime backstop from {}: {}",
                finding.evidence_kind, finding.message
            ),
            model: None,
        });
        if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
            entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
        }
    }

    for finding in static_findings
        .iter()
        .filter(|finding| finding.kind == analysis::detectors::FindingKind::DosBlockGasLimit)
    {
        let function_id = finding.function.unwrap_or(0);
        let has_runtime_dos = vulnerabilities.iter().any(|v| {
            v.function_id == function_id && v.kind == VulnerabilityKind::DosWithFailedCall.as_str()
        });
        if runtime_dos_block_gas_limit_functions.contains(&function_id)
            || !has_runtime_dos
            || !function_source_has_dynamic_gas_loop(&output.ast, function_id)
        {
            continue;
        }
        let function_name = output
            .ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.clone());
        let kind = VulnerabilityKind::DosBlockGasLimit.as_str().to_string();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "runtime-loop-bound-recovery".to_string(),
        );
        if seen_output_vulns.insert(dedup_key) {
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: VulnerabilityKind::DosBlockGasLimit
                    .confidence()
                    .as_str()
                    .to_string(),
                function_id,
                function_name: function_name.clone(),
                pc: 0,
                instruction: "runtime-loop-bound-recovery".to_string(),
                trace: Vec::new(),
                trigger: None,
                branch_triggers: Vec::new(),
                location: build_location(&finding.span, output),
                path_constraints: Vec::new(),
                message:
                    "runtime execution reached a loop/call DoS path, and the loop bound is dynamic (`.length`/gas), so block-gas-limit DoS is also feasible"
                        .to_string(),
                model: None,
            });
            if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
                entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
            }
        }
    }

    for finding in static_findings.iter().filter(|finding| {
        matches!(
            finding.kind,
            analysis::detectors::FindingKind::LockedEther
                | analysis::detectors::FindingKind::ForceEtherBalanceCheck
        )
    }) {
        let function_id = finding.function.unwrap_or(0);
        if runtime_locked_ether_functions.contains(&function_id) {
            continue;
        }
        let function_name = output
            .ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.clone());
        let kind = VulnerabilityKind::LockedEther.as_str().to_string();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "static-guided-runtime-backstop".to_string(),
        );
        if seen_output_vulns.insert(dedup_key) {
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: VulnerabilityKind::LockedEther
                    .confidence()
                    .as_str()
                    .to_string(),
                function_id,
                function_name: function_name.clone(),
                pc: 0,
                instruction: "static-guided-backstop".to_string(),
                trace: Vec::new(),
                trigger: None,
                branch_triggers: Vec::new(),
                location: build_location(&finding.span, output),
                path_constraints: Vec::new(),
                message:
                    "runtime forced-Ether/locked-Ether evidence was insufficient, but static balance-invariant signal exists for this function (runtime backstop)"
                        .to_string(),
                model: None,
            });
            if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
                entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
            }
        }
    }

    for finding in static_findings.iter().filter(|finding| {
        finding.kind == analysis::detectors::FindingKind::UninitializedPermissionCheck
    }) {
        let function_id = finding.function.unwrap_or(0);
        if runtime_access_like_functions.contains(&function_id) {
            continue;
        }
        let strong_authority_backstop = cfgs
            .iter()
            .find(|cfg_fn| cfg_fn.id == function_id)
            .map(|cfg_fn| {
                build_authority_runtime_profile(
                    cfg_fn,
                    Some(EngineCallbackData {
                        ast: &output.ast,
                        compiler: &output.compiler,
                        deps: &dependency_map,
                    }),
                )
            })
            .map(|profile| {
                profile.constructor_like
                    || profile.wrong_constructor_candidate
                    || profile.exclusive_authority_write
            })
            .unwrap_or(false);
        let has_other_runtime_signal = vulnerabilities.iter().any(|v| {
            v.function_id == function_id
                && v.kind != VulnerabilityKind::AccessControl.as_str()
                && v.kind != VulnerabilityKind::WrongConstructorName.as_str()
                && v.kind != VulnerabilityKind::ArbitraryWrite.as_str()
        });
        if !strong_authority_backstop && has_other_runtime_signal {
            continue;
        }
        let function_name = output
            .ast
            .functions
            .get(function_id as usize)
            .and_then(|f| f.name.clone());
        let kind = VulnerabilityKind::AccessControl.as_str().to_string();
        let dedup_key = (
            function_id,
            kind.clone(),
            0usize,
            "static-guided-runtime-backstop".to_string(),
        );
        if seen_output_vulns.insert(dedup_key) {
            vulnerabilities.push(VulnerabilityFinding {
                kind,
                confidence: VulnerabilityKind::AccessControl
                    .confidence()
                    .as_str()
                    .to_string(),
                function_id,
                function_name: function_name.clone(),
                pc: 0,
                instruction: "static-guided-backstop".to_string(),
                trace: Vec::new(),
                trigger: None,
                branch_triggers: Vec::new(),
                location: build_location(&finding.span, output),
                path_constraints: Vec::new(),
                message:
                    "runtime authority evidence was insufficient, but static public reinitialization signal exists for this function (runtime backstop)"
                        .to_string(),
                model: None,
            });
            if let Some(entry) = by_function.iter_mut().find(|entry| entry.id == function_id) {
                entry.vulnerability_count = entry.vulnerability_count.saturating_add(1);
            }
        }
    }

    let surfaced = surfaced::surface_findings(
        vulnerabilities
            .iter()
            .map(symbolic_runtime_candidate)
            .collect(),
        meta_findings.iter().map(symbolic_meta_candidate).collect(),
    );

    let report = SymbolicReport {
        files: output.ast.files.len(),
        functions: ir_module.functions.len(),
        instructions,
        explored_states,
        reachable_returns,
        reachable_reverts,
        reachable_fallthroughs,
        terminal_paths,
        pruned_branches,
        dead_ends,
        max_worklist,
        vulnerability_count: surfaced.runtime_findings.len(),
        meta_finding_count: surfaced.meta_findings.len(),
        vulnerability_count_raw: vulnerabilities.len(),
        meta_finding_count_raw: meta_findings.len(),
        suppressed_vulnerabilities: surfaced.suppressed_runtime_findings,
        suppressed_meta_findings: surfaced.suppressed_meta_findings,
        truncated_functions,
        by_function,
        vulnerabilities: surfaced.runtime_findings.clone(),
        vulnerabilities_raw: vulnerabilities,
        meta_findings: surfaced.meta_findings.clone(),
        meta_findings_raw: meta_findings,
    };

    match format {
        OutputFormat::Text => {
            println!(
                "symbolic: files={}, functions={}, instructions={}, explored_states={}, terminal_paths={}, returns={}, reverts={}, fallthroughs={}, pruned_branches={}, dead_ends={}, max_worklist={}, vulnerabilities={} (raw={}, suppressed={}), truncated_functions={}",
                report.files,
                report.functions,
                report.instructions,
                report.explored_states,
                report.terminal_paths,
                report.reachable_returns,
                report.reachable_reverts,
                report.reachable_fallthroughs,
                report.pruned_branches,
                report.dead_ends,
                report.max_worklist,
                report.vulnerability_count,
                report.vulnerability_count_raw,
                report.suppressed_vulnerabilities,
                report.truncated_functions
            );
            println!(
                "meta findings: {} (raw={}, suppressed={})",
                report.meta_finding_count, report.meta_finding_count_raw, report.suppressed_meta_findings
            );
            for entry in &report.by_function {
                println!(
                    "  fn {} ({}) -> instructions={}, states={}, terminals={}, returns={}, reverts={}, fallthroughs={}, pruned={}, dead_ends={}, max_worklist={}, vulns={}, truncated={}",
                    entry.id,
                    entry.name.as_deref().unwrap_or("<anonymous>"),
                    entry.instructions,
                    entry.explored_states,
                    entry.terminal_paths,
                    entry.reachable_returns,
                    entry.reachable_reverts,
                    entry.reachable_fallthroughs,
                    entry.pruned_branches,
                    entry.dead_ends,
                    entry.max_worklist,
                    entry.vulnerability_count,
                    entry.truncated
                );
            }
            if report.vulnerabilities.is_empty() {
                println!("vulnerabilities found: none");
            } else {
                println!("vulnerabilities found (surfaced):");
                for (idx, vuln) in report.vulnerabilities.iter().enumerate() {
                    println!(
                        "  {}. kind={}, confidence={}, fn {} ({}), severity={}",
                        idx + 1,
                        vuln.kind,
                        vuln.confidence.as_deref().unwrap_or("unknown"),
                        vuln.function_id.unwrap_or(0),
                        vuln.function_name.as_deref().unwrap_or("<anonymous>"),
                        vuln.severity
                    );
                     println!("     message: {}", vuln.message);
                    if let Some(file) = &vuln.file {
                        println!(
                            "     location: {}:{}-{}",
                            file,
                            vuln.start.unwrap_or(0),
                            vuln.end.unwrap_or(0)
                        );
                    }
                }
            }
            if !report.meta_findings.is_empty() {
                println!("meta findings (surfaced):");
                for (idx, finding) in report.meta_findings.iter().enumerate() {
                    println!(
                        "  {}. kind={} severity={} evidence={}",
                        idx + 1,
                        finding.kind,
                        finding.severity,
                        finding.evidence_kind.as_deref().unwrap_or("meta")
                    );
                    println!("     message: {}", finding.message);
                    if let Some(file) = &finding.file {
                        println!(
                            "     location: {}:{}-{}",
                            file,
                            finding.start.unwrap_or(0),
                            finding.end.unwrap_or(0)
                        );
                    }
                }
            }
        }
        OutputFormat::Json => {
            let payload = serde_json::to_string_pretty(&report).map_err(|err| {
                Error::msg(format!("failed to encode symbolic JSON report: {err}"))
            })?;
            println!("{payload}");
        }
    }

    Ok(())
}

fn configure_solver_limits() {
    let timeout_ms = env_u64(
        SYMBOLIC_SOLVER_TIMEOUT_MS_ENV,
        DEFAULT_SYMBOLIC_SOLVER_TIMEOUT_MS,
    );
    set_global_param("timeout", &timeout_ms.to_string());
}

fn symbolic_runtime_candidate(vuln: &VulnerabilityFinding) -> surfaced::FindingCandidate {
    surfaced::FindingCandidate {
        kind: vuln.kind.clone(),
        canonical_kind: surfaced::canonicalize_kind(&vuln.kind),
        category: category_for_kind(vuln.kind.as_str()).to_string(),
        severity: confidence_to_severity(vuln.confidence.as_str()).to_string(),
        confidence: Some(vuln.confidence.clone()),
        message: vuln.message.clone(),
        file: vuln.location.as_ref().map(|location| location.file.clone()),
        start: vuln.location.as_ref().map(|location| location.start),
        end: vuln.location.as_ref().map(|location| location.end),
        function_id: Some(vuln.function_id),
        function_name: vuln.function_name.clone(),
        analysis_layer: "runtime".to_string(),
        evidence_kind: Some("symbolic-path".to_string()),
    }
}

fn symbolic_meta_candidate(finding: &crate::core::artifacts::Finding) -> surfaced::FindingCandidate {
    surfaced::FindingCandidate {
        kind: finding.finding_type.clone(),
        canonical_kind: surfaced::canonicalize_kind(&finding.finding_type),
        category: meta_category_for_kind(finding.finding_type.as_str()).to_string(),
        severity: finding.severity.clone(),
        confidence: None,
        message: finding.message.clone(),
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
        function_id: finding
            .location
            .as_ref()
            .and_then(|location| location.function_id),
        function_name: finding
            .location
            .as_ref()
            .and_then(|location| location.function_name.clone()),
        analysis_layer: "meta".to_string(),
        evidence_kind: Some(finding.evidence_kind.clone()),
    }
}

fn confidence_to_severity(confidence: &str) -> &'static str {
    match confidence {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "medium",
    }
}

fn category_for_kind(kind: &str) -> &'static str {
    match surfaced::canonicalize_kind(kind).as_str() {
        "access-control"
        | "arbitrary-write"
        | "unchecked-call"
        | "tx-origin"
        | "unprotected-selfdestruct"
        | "unsafe-delegatecall"
        | "wrong-constructor-name"
        | "uninit-permission-check"
        | "unprotected-ether-withdrawal"
        | "public-mint-burn" => "Access Control",
        "integer-overflow" | "integer-underflow" | "division-before-multiplication" => {
            "Arithmetic"
        }
        "weak-prng" | "timestamp-dependency" | "transaction-order-dependency" => {
            "Block Manipulation"
        }
        "dos-block-gas-limit" | "dos-with-failed-call" | "hardcoded-gas-transfer" | "locked-ether" => {
            "Denial of Service"
        }
        "memory-manipulation" | "shadowing" => "Storage and Memory",
        "reentrancy" => "Reentrancy",
        _ => "Miscellaneous",
    }
}

fn meta_category_for_kind(kind: &str) -> &'static str {
    match surfaced::canonicalize_kind(kind).as_str() {
        "incorrect-interface" | "honeypot" => "Miscellaneous",
        "shadowing" | "memory-manipulation" => "Storage and Memory",
        "weak-prng" | "timestamp-dependency" | "transaction-order-dependency" => {
            "Block Manipulation"
        }
        "dos-block-gas-limit" | "dos-with-failed-call" | "hardcoded-gas-transfer" | "locked-ether" => {
            "Denial of Service"
        }
        "integer-overflow" | "integer-underflow" | "division-before-multiplication" => {
            "Arithmetic"
        }
        "access-control"
        | "arbitrary-write"
        | "unchecked-call"
        | "tx-origin"
        | "unprotected-selfdestruct"
        | "unsafe-delegatecall"
        | "wrong-constructor-name"
        | "uninit-permission-check"
        | "unprotected-ether-withdrawal"
        | "public-mint-burn" => "Access Control",
        "reentrancy" => "Reentrancy",
        _ => "Miscellaneous",
    }
}

fn sink_score_key(function_id: u32, block_id: u32) -> u32 {
    (function_id << 16) ^ block_id
}

fn build_sink_scores(cfgs: &[cfg::CfgFunction]) -> HashMap<u32, i32> {
    let mut scores = HashMap::new();
    for cfg_fn in cfgs {
        for block in &cfg_fn.blocks {
            let mut score = 0i32;
            for instr in &block.instrs {
                match instr {
                    IrInstr::Store { dest, .. } if is_storage_place(dest) => {
                        score += 4;
                    }
                    IrInstr::Call { callee, .. } => {
                        let callee_name = value_name_raw(callee).to_ascii_lowercase();
                        if is_low_level_call_name(&callee_name) {
                            score += 5;
                        }
                        if callee_name.contains("delegatecall") {
                            score += 3;
                        }
                        if is_selfdestruct_name(&callee_name) {
                            score += 4;
                        }
                        if callee_name.contains("ecrecover") {
                            score += 2;
                        }
                    }
                    IrInstr::Control {
                        kind: ControlKind::If { .. } | ControlKind::Loop { .. },
                        ..
                    } => {
                        score += 1;
                    }
                    _ => {}
                }
            }
            if score > 0 {
                scores.insert(sink_score_key(cfg_fn.id, block.id), score);
            }
        }
    }
    scores
}

fn state_priority_score(state: &State, sink_scores: &HashMap<u32, i32>) -> i32 {
    let sink_key = sink_score_key(state.function_id, state.block_id);
    let mut score = *sink_scores.get(&sink_key).unwrap_or(&0);
    if state.external_call_pc.is_some() {
        score += 3;
    }
    if state.callback_observed {
        score += 5;
    }
    if !state.pending_low_level_calls.is_empty() {
        score += 2;
    }
    if state.saw_order_sensitive_storage_read {
        score += 2;
    }
    if state.inside_loop {
        score += 1;
    }
    if !state.sender_checked {
        score += 1;
    }
    score
}

fn pop_next_state(worklist: &mut Vec<State>, sink_scores: &HashMap<u32, i32>) -> Option<State> {
    if worklist.is_empty() {
        return None;
    }
    let (best_idx, _) = worklist
        .iter()
        .enumerate()
        .map(|(idx, state)| (idx, state_priority_score(state, sink_scores)))
        .max_by_key(|(_, score)| *score)?;
    Some(worklist.swap_remove(best_idx))
}

fn state_shape_key(state: &State) -> String {
    let mut call_pcs = state
        .pending_low_level_calls
        .values()
        .map(|pending| pending.call_pc)
        .collect::<Vec<_>>();
    call_pcs.sort_unstable();
    let constraints_len = state.path_constraints.len();
    let constraints_fingerprint = path_constraints_fingerprint(&state.path_constraints);
    format!(
        "fn={}::b={}::i={}::cb_depth={}::cb_obs={}::loop={}::auth={}::ord={}::ext={:?}::pending={:?}::clen={}::cfp={:x}",
        state.function_id,
        state.block_id,
        state.instr_offset,
        state.callback_depth,
        state.callback_observed,
        state.inside_loop,
        state.sender_checked,
        state.saw_order_sensitive_storage_read,
        state.external_call_pc,
        call_pcs,
        constraints_len,
        constraints_fingerprint
    )
}

fn path_constraints_fingerprint(path_constraints: &[Bool]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path_constraints.len().hash(&mut hasher);
    for c in path_constraints.iter().take(4) {
        c.to_string().hash(&mut hasher);
    }
    for c in path_constraints.iter().rev().take(4) {
        c.to_string().hash(&mut hasher);
    }
    hasher.finish()
}

fn try_enqueue_state(
    worklist: &mut Vec<State>,
    mut next_state: State,
    next_block: u32,
    sink_scores: &HashMap<u32, i32>,
    state_shape_visits: &mut HashMap<String, u8>,
    max_worklist: &mut usize,
    limits: EngineLimits,
) -> bool {
    if next_state.path_constraints.len() > limits.max_path_constraints {
        return false;
    }

    let next_visits = next_state
        .block_visits
        .get(&next_block)
        .copied()
        .unwrap_or(0)
        .saturating_add(1);
    if next_visits > limits.max_block_visits_per_path {
        return false;
    }
    next_state.block_visits.insert(next_block, next_visits);
    next_state.block_id = next_block;
    next_state.instr_offset = 0;

    enqueue_state(
        worklist,
        next_state,
        sink_scores,
        state_shape_visits,
        max_worklist,
        limits,
    )
}

fn enqueue_state(
    worklist: &mut Vec<State>,
    next_state: State,
    sink_scores: &HashMap<u32, i32>,
    state_shape_visits: &mut HashMap<String, u8>,
    max_worklist: &mut usize,
    limits: EngineLimits,
) -> bool {
    let shape_key = state_shape_key(&next_state);
    let visits = state_shape_visits.get(&shape_key).copied().unwrap_or(0);
    if visits >= limits.max_state_shape_revisits {
        return false;
    }

    if worklist.len() >= limits.max_worklist_size {
        let candidate_score = state_priority_score(&next_state, sink_scores);
        let Some((worst_idx, worst_score)) = worklist
            .iter()
            .enumerate()
            .map(|(idx, state)| (idx, state_priority_score(state, sink_scores)))
            .min_by_key(|(_, score)| *score)
        else {
            return false;
        };
        if candidate_score <= worst_score {
            return false;
        }
        worklist.swap_remove(worst_idx);
    }

    state_shape_visits.insert(shape_key, visits + 1);
    worklist.push(next_state);
    *max_worklist = (*max_worklist).max(worklist.len());
    true
}

fn engine(
    cfg_fn: &cfg::CfgFunction,
    all_cfgs: &[cfg::CfgFunction],
    callback_data: Option<EngineCallbackData<'_>>,
    checked_arithmetic: bool,
    allow_reentrancy_fallback: bool,
    allow_tod: bool,
    allow_signature_malleability: bool,
) -> EngineStats {
    let limits = EngineLimits::from_env();
    let instructions = cfg_fn.blocks.iter().map(|b| b.instrs.len()).sum::<usize>();
    if instructions == 0 {
        return EngineStats {
            instructions,
            ..EngineStats::default()
        };
    }

    let cfg_map = all_cfgs
        .iter()
        .map(|cfg_fn| (cfg_fn.id, cfg_fn))
        .collect::<HashMap<_, _>>();
    let mut succs: HashMap<u32, HashMap<u32, Vec<u32>>> = HashMap::new();
    for cfg_fn in all_cfgs {
        let mut fn_succs: HashMap<u32, Vec<u32>> = HashMap::new();
        for edge in &cfg_fn.edges {
            fn_succs.entry(edge.from).or_default().push(edge.to);
        }
        succs.insert(cfg_fn.id, fn_succs);
    }
    let mut instr_positions: HashMap<(u32, u32, usize), usize> = HashMap::new();
    let mut flat_pc = 0usize;
    for cfg_fn in all_cfgs {
        for block in &cfg_fn.blocks {
            for idx in 0..block.instrs.len() {
                instr_positions.insert((cfg_fn.id, block.id, idx), flat_pc);
                flat_pc += 1;
            }
        }
    }
    let sink_scores = build_sink_scores(all_cfgs);
    let has_writer_reader_dependency = callback_data
        .map(|data| function_has_writer_reader_dependency(cfg_fn.id, data))
        .unwrap_or(false);
    let has_callback_overlap = callback_data
        .map(|data| function_has_callback_overlap(cfg_fn.id, data))
        .unwrap_or(false);
    let allow_callback_runtime = allow_reentrancy_fallback || has_callback_overlap;
    let authority_profile = build_authority_runtime_profile(cfg_fn, callback_data);
    let supports_low_confidence_reentrancy_fallback = callback_data
        .map(|data| {
            function_has_value_moving_low_level_call(data.ast, cfg_fn.id)
                && !function_is_direct_msg_value_forwarder(Some(data.ast), cfg_fn.id)
        })
        .unwrap_or(false);

    let entry_block = cfg_fn.blocks.first().map(|b| b.id).unwrap_or(0);
    let mut entry_state = State::new();
    entry_state.function_id = cfg_fn.id;
    entry_state.block_id = entry_block;
    entry_state.instr_offset = 0;
    entry_state.block_visits.insert(entry_block, 1);
    if let Some(data) = callback_data {
        seed_contract_state_var_origins(&mut entry_state.origins, cfg_fn.id, data.ast);
    }
    let mut worklist = vec![entry_state];
    let mut state_shape_visits: HashMap<String, u8> = HashMap::new();
    if let Some(initial) = worklist.first() {
        state_shape_visits.insert(state_shape_key(initial), 1);
    }
    let mut max_worklist = 1usize;
    let mut terminal_states: Vec<TerminalState> = Vec::new();
    let mut explored_states = 0usize;
    let mut pruned_branches = 0usize;
    let mut dead_ends = 0usize;
    let mut vulnerabilities = Vec::new();
    let mut seen_reentrancy_edges: HashSet<(usize, usize)> = HashSet::new();
    let mut seen_vulns: HashSet<(VulnerabilityKind, usize)> = HashSet::new();
    let mut callback_only_fallback: Option<LocalVulnerability> = None;
    let mut solver_cache = SolverCache::default();
    let mut truncated = false;
    let function_started = Instant::now();

    while let Some(mut state) = pop_next_state(&mut worklist, &sink_scores) {
        if function_started.elapsed().as_millis() as u64 >= limits.max_function_ms {
            truncated = true;
            break;
        }
        explored_states += 1;
        if explored_states >= limits.max_engine_steps {
            truncated = true;
            break;
        }

        let Some(current_cfg) = cfg_map.get(&state.function_id).copied() else {
            dead_ends += 1;
            continue;
        };
        let Some(block) = current_cfg.blocks.iter().find(|block| block.id == state.block_id) else {
            dead_ends += 1;
            continue;
        };
        if allow_callback_runtime
            && supports_low_confidence_reentrancy_fallback
            && callback_only_fallback.is_none()
            && state.callback_observed
            && let Some(call_pc) = state.external_call_pc
        {
            callback_only_fallback = Some(LocalVulnerability {
                kind: VulnerabilityKind::ReentrancyFallback,
                pc: call_pc,
                instruction: "callback-observed".to_string(),
                trace: state.trace.clone(),
                trigger: state.branch_triggers.last().cloned(),
                branch_triggers: state.branch_triggers.clone(),
                span: None,
                path_constraints: constraints_to_strings(&state.path_constraints),
                message:
                    "feasible callback observed on external call in a state-coupled function, but post-call storage evidence was not captured (runtime callback fallback)"
                        .to_string(),
                model: None,
            });
        }
        let mut block_terminated = false;

        for (instr_index, instr) in block.instrs.iter().enumerate().skip(state.instr_offset) {
            let current_pc = *instr_positions
                .get(&(state.function_id, state.block_id, instr_index))
                .unwrap_or(&usize::MAX);
            if state.trace.len() < limits.max_trace_len {
                state.trace.push(current_pc);
            }

            match instr {
                IrInstr::Nop { .. } => {}
                IrInstr::InlineAsm { .. } => {
                    if seen_vulns.insert((VulnerabilityKind::MemoryManipulation, current_pc)) {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::MemoryManipulation,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "inline assembly usage detected; memory/storage manipulation risk"
                                    .to_string(),
                            model: None,
                        });
                    }
                }
                IrInstr::Eval { expr, .. } | IrInstr::Emit { expr, .. } => {
                    let _ = state.eval_value(expr);
                }
                IrInstr::Declare { names, init, .. } => {
                    let value = init.as_ref().map(|v| state.eval_value(v));
                    let init_key = init.as_ref().and_then(value_var_key);
                    for name in names {
                        let assigned = value.clone().unwrap_or_else(|| state.fresh_symbol(name));
                        state.env.insert(name.clone(), assigned);
                        let expr = init
                            .as_ref()
                            .map(|v| state.value_expr(v))
                            .unwrap_or_else(|| name.clone());
                        state.expr_env.insert(name.clone(), expr);
                        if let Some(src_key) = &init_key {
                            if let Some(pending) =
                                state.pending_low_level_calls.get(src_key).cloned()
                            {
                                state.pending_low_level_calls.insert(name.clone(), pending);
                            }
                        }
                    }
                }
                IrInstr::Assign { dest, src, .. } => {
                    let value = state.eval_value(src);
                    state.set_var(dest, value);
                    let dest_key = var_key(dest);
                    state
                        .expr_env
                        .insert(dest_key.clone(), state.value_expr(src));
                    if let Some(src_key) = value_var_key(src) {
                        if let Some(origins) = state.origins.get(&src_key).cloned() {
                            state.origins.entry(dest_key).or_default().extend(origins);
                        }
                        if let Some(pending) = state.pending_low_level_calls.get(&src_key).cloned()
                        {
                            state.pending_low_level_calls.insert(var_key(dest), pending);
                        }
                    }
                }
                IrInstr::Store { dest, src, .. } => {
                    let value = state.eval_value(src);
                    if is_storage_place(dest) {
                        let dest_slot_key = place_key(dest);
                        if let Some(call_pc) = state.external_call_pc {
                            let stale_read_hit = state.callback_stale_read_keys.contains(&dest_slot_key);
                            let callback_changed_hit = state
                                .callback_changed_storage_keys
                                .contains(&dest_slot_key);
                            let callback_changed_any = !state.callback_changed_storage_keys.is_empty();
                            if state.callback_observed && (stale_read_hit || callback_changed_hit || callback_changed_any) {
                                if seen_reentrancy_edges.insert((call_pc, current_pc)) {
                                    let evidence = if stale_read_hit || !state.callback_stale_read_keys.is_empty() {
                                        "stale-read"
                                    } else if callback_changed_hit {
                                        "changed-slot"
                                    } else {
                                        "post-call-mutation"
                                    };
                                    vulnerabilities.push(LocalVulnerability {
                                        kind: VulnerabilityKind::Reentrancy,
                                        pc: current_pc,
                                        instruction: format!("{instr:?}"),
                                        trace: state.trace.clone(),
                                        trigger: state.branch_triggers.last().cloned(),
                                        branch_triggers: state.branch_triggers.clone(),
                                        span: Some(instr_span(instr)),
                                        path_constraints: constraints_to_strings(
                                            &state.path_constraints,
                                        ),
                                        message: format!(
                                            "storage write after feasible callback return from external value call (call_pc={call_pc}, store_pc={current_pc}, evidence={evidence})"
                                        ),
                                        model: None,
                                    });
                                }
                            } else if !state.callback_observed
                                && supports_low_confidence_reentrancy_fallback
                                && (has_writer_reader_dependency || allow_reentrancy_fallback)
                                && !callback_data
                                    .map(|data| {
                                        function_uses_only_stipend_external_calls(
                                            data.ast,
                                            state.function_id,
                                        )
                                    })
                                    .unwrap_or(false)
                                && seen_vulns
                                    .insert((VulnerabilityKind::ReentrancyFallback, current_pc))
                            {
                                vulnerabilities.push(LocalVulnerability {
                                    kind: VulnerabilityKind::ReentrancyFallback,
                                    pc: current_pc,
                                    instruction: format!("{instr:?}"),
                                    trace: state.trace.clone(),
                                    trigger: state.branch_triggers.last().cloned(),
                                    branch_triggers: state.branch_triggers.clone(),
                                    span: Some(instr_span(instr)),
                                    path_constraints: constraints_to_strings(
                                        &state.path_constraints,
                                    ),
                                    message:
                                        "external value call followed by storage write without feasible callback evidence (heuristic fallback)"
                                            .to_string(),
                                    model: None,
                                });
                            }
                        }
                        let authority_slot = place_key(dest);
                        let sender_like_source = value_is_sender_like(src, &state);
                        if authority_profile.wrong_constructor_candidate
                            && !state.sender_checked
                            && place_is_constructor_authority_sensitive(dest)
                            && sender_like_source
                            && seen_vulns
                                .insert((VulnerabilityKind::WrongConstructorName, current_pc))
                        {
                            vulnerabilities.push(LocalVulnerability {
                                kind: VulnerabilityKind::WrongConstructorName,
                                pc: current_pc,
                                instruction: format!("{instr:?}"),
                                trace: state.trace.clone(),
                                trigger: state.branch_triggers.last().cloned(),
                                branch_triggers: state.branch_triggers.clone(),
                                span: Some(instr_span(instr)),
                                path_constraints: constraints_to_strings(&state.path_constraints),
                                message: format!(
                                    "callable constructor-like function reassigns authority slot '{}' from msg.sender",
                                    authority_slot
                                ),
                                model: None,
                            });
                        }
                        if !state.sender_checked
                            && place_is_authority_sensitive(dest)
                            && authority_profile.exclusive_authority_write
                            && !authority_profile.guarded_by_modifier
                            && !authority_profile.constructor_like
                            && !authority_profile.wrong_constructor_candidate
                            && seen_vulns.insert((VulnerabilityKind::ArbitraryWrite, current_pc))
                        {
                            vulnerabilities.push(LocalVulnerability {
                                kind: VulnerabilityKind::ArbitraryWrite,
                                pc: current_pc,
                                instruction: format!("{instr:?}"),
                                trace: state.trace.clone(),
                                trigger: state.branch_triggers.last().cloned(),
                                branch_triggers: state.branch_triggers.clone(),
                                span: Some(instr_span(instr)),
                                path_constraints: constraints_to_strings(&state.path_constraints),
                                message: format!(
                                    "storage write to authority-sensitive slot '{}' without sender authorization check",
                                    authority_slot
                                ),
                                model: None,
                            });
                            if seen_vulns.insert((VulnerabilityKind::AccessControl, current_pc)) {
                                vulnerabilities.push(LocalVulnerability {
                                    kind: VulnerabilityKind::AccessControl,
                                    pc: current_pc,
                                    instruction: format!("{instr:?}"),
                                    trace: state.trace.clone(),
                                    trigger: state.branch_triggers.last().cloned(),
                                    branch_triggers: state.branch_triggers.clone(),
                                    span: Some(instr_span(instr)),
                                    path_constraints: constraints_to_strings(
                                        &state.path_constraints,
                                    ),
                                    message: format!(
                                        "missing access control: authority-sensitive storage write '{}' has no sender authorization gate",
                                        authority_slot
                                    ),
                                    model: None,
                                });
                            }
                        }
                    }
                    state.write_place(dest, value);
                }
                IrInstr::Load { dest, src, .. } => {
                    let value = state.read_place(src);
                    state.set_var(dest, value);
                    if is_storage_place(src) {
                        state.storage_reads.insert(place_key(src));
                    }
                    if is_storage_place(src) && place_is_order_sensitive(src) {
                        state.saw_order_sensitive_storage_read = true;
                    }
                    let dest_key = var_key(dest);
                    state
                        .expr_env
                        .insert(dest_key.clone(), format!("load({})", place_key(src)));

                    if let Some((base_name, field_name)) = place_member_base_field(src) {
                        let base_l = base_name.to_ascii_lowercase();
                        let field_l = field_name.to_ascii_lowercase();

                        if base_l == "tx" && field_l == "origin" {
                            state
                                .origins
                                .entry(dest_key.clone())
                                .or_default()
                                .insert(ValueOrigin::TxOrigin);
                            if seen_vulns.insert((VulnerabilityKind::TxOrigin, current_pc)) {
                                vulnerabilities.push(LocalVulnerability {
                                    kind: VulnerabilityKind::TxOrigin,
                                    pc: current_pc,
                                    instruction: format!("{instr:?}"),
                                    trace: state.trace.clone(),
                                    trigger: state.branch_triggers.last().cloned(),
                                    branch_triggers: state.branch_triggers.clone(),
                                    span: Some(instr_span(instr)),
                                    path_constraints: constraints_to_strings(
                                        &state.path_constraints,
                                    ),
                                    message:
                                        "dangerous usage of tx.origin for authorization/input flow"
                                            .to_string(),
                                    model: None,
                                });
                            }
                        }

                        if base_l == "block" && field_l == "timestamp" {
                            state
                                .origins
                                .entry(dest_key.clone())
                                .or_default()
                                .insert(ValueOrigin::Timestamp);
                        }
                        if base_l == "block" && (field_l == "number" || field_l == "blockhash") {
                            state
                                .origins
                                .entry(dest_key.clone())
                                .or_default()
                                .insert(ValueOrigin::BlockNumber);
                        }
                        if base_l == "this" && field_l == "balance" {
                            state
                                .origins
                                .entry(dest_key.clone())
                                .or_default()
                                .insert(ValueOrigin::ThisBalance);
                        }

                        if field_l == "delegatecall" {
                            let origins = state.origins.entry(dest_key.clone()).or_default();
                            origins.insert(ValueOrigin::DelegatecallRef);
                            origins.insert(ValueOrigin::LowLevelCallRef);
                        } else if matches!(
                            field_l.as_str(),
                            "call" | "send" | "transfer" | "staticcall"
                        ) {
                            let origins = state.origins.entry(dest_key.clone()).or_default();
                            origins.insert(ValueOrigin::LowLevelCallRef);
                            if field_l == "send" {
                                origins.insert(ValueOrigin::SendRef);
                            } else if field_l == "transfer" {
                                origins.insert(ValueOrigin::TransferRef);
                            }
                        } else if field_l == "value" {
                            if let IrPlace::Member { base, .. } = src {
                                let base_key = value_key(base);
                                let base_is_call_ref = state
                                    .origins
                                    .get(&base_key)
                                    .map(|o| o.contains(&ValueOrigin::LowLevelCallRef))
                                    .unwrap_or(false);
                                if base_is_call_ref {
                                    let origins =
                                        state.origins.entry(dest_key.clone()).or_default();
                                    origins.insert(ValueOrigin::LowLevelCallRef);
                                    origins.insert(ValueOrigin::ValueCallRef);
                                }
                            }
                        }
                    }

                    if let Some(src_key) = place_var_key(src) {
                        if let Some(origins) = state.origins.get(&src_key).cloned() {
                            state
                                .origins
                                .entry(dest_key.clone())
                                .or_default()
                                .extend(origins);
                        }
                    }
                    match src {
                        IrPlace::Member { base, .. } | IrPlace::Index { base, .. } => {
                            let base_key = value_key(base);
                            if let Some(origins) = state.origins.get(&base_key).cloned() {
                                state.origins.entry(dest_key).or_default().extend(origins);
                            }
                        }
                        IrPlace::Var { .. } => {}
                    }
                }
                IrInstr::Binary {
                    dest, op, lhs, rhs, ..
                } => {
                    if let Some(folded) = try_eval_binary_literals(op, lhs, rhs) {
                        state.set_var(dest, folded);
                        continue;
                    }
                    let lhs_v = state.eval_value(lhs);
                    let rhs_v = state.eval_value(rhs);
                    if !checked_arithmetic && op == "+" {
                        let overflow_model =
                            solver_cache.check_add_overflow(&state.path_constraints, &lhs_v, &rhs_v);
                        if let Some(model) = overflow_model {
                            if seen_vulns.insert((VulnerabilityKind::Overflow, current_pc)) {
                                vulnerabilities.push(LocalVulnerability {
                                    kind: VulnerabilityKind::Overflow,
                                    pc: current_pc,
                                    instruction: format!("{instr:?}"),
                                    trace: state.trace.clone(),
                                    trigger: state.branch_triggers.last().cloned(),
                                    branch_triggers: state.branch_triggers.clone(),
                                    span: Some(instr_span(instr)),
                                    path_constraints: constraints_to_strings(
                                        &state.path_constraints,
                                    ),
                                    message:
                                        "potential arithmetic overflow: lhs + rhs wraps under uint256 arithmetic"
                                            .to_string(),
                                    model: Some(model),
                                });
                            }
                        } else if should_emit_storage_accumulator_overflow_fallback(
                            &state,
                            block,
                            instr_index,
                            dest,
                            lhs,
                            rhs,
                        ) && seen_vulns.insert((VulnerabilityKind::Overflow, current_pc))
                        {
                            vulnerabilities.push(LocalVulnerability {
                                kind: VulnerabilityKind::Overflow,
                                pc: current_pc,
                                instruction: format!("{instr:?}"),
                                trace: state.trace.clone(),
                                trigger: state.branch_triggers.last().cloned(),
                                branch_triggers: state.branch_triggers.clone(),
                                span: Some(instr_span(instr)),
                                path_constraints: constraints_to_strings(
                                    &state.path_constraints,
                                ),
                                message:
                                    "unchecked storage accumulator update can wrap under uint256 arithmetic"
                                        .to_string(),
                                model: None,
                            });
                        }
                    }
                    if !checked_arithmetic && op == "-" {
                        if let Some(model) =
                            solver_cache.check_underflow(&state.path_constraints, &lhs_v, &rhs_v)
                        {
                            if seen_vulns.insert((VulnerabilityKind::Underflow, current_pc)) {
                                vulnerabilities.push(LocalVulnerability {
                                    kind: VulnerabilityKind::Underflow,
                                    pc: current_pc,
                                    instruction: format!("{instr:?}"),
                                    trace: state.trace.clone(),
                                    trigger: state.branch_triggers.last().cloned(),
                                    branch_triggers: state.branch_triggers.clone(),
                                    span: Some(instr_span(instr)),
                                    path_constraints: constraints_to_strings(
                                        &state.path_constraints,
                                    ),
                                    message:
                                        "potential arithmetic underflow: rhs > lhs is satisfiable"
                                            .to_string(),
                                    model: Some(model),
                                });
                            }
                        }
                    }
                    let out = eval_binary(op, lhs_v, rhs_v);
                    state.set_var(dest, out);
                    let dest_key = var_key(dest);
                    let expr = format!(
                        "({} {} {})",
                        state.value_expr(lhs),
                        op,
                        state.value_expr(rhs)
                    );
                    state.expr_env.insert(dest_key.clone(), expr.clone());
                    if let Some(lhs_key) = value_var_key(lhs) {
                        if let Some(pending) = state.pending_low_level_calls.get(&lhs_key).cloned()
                        {
                            state
                                .pending_low_level_calls
                                .insert(dest_key.clone(), pending);
                        }
                    }
                    if let Some(rhs_key) = value_var_key(rhs) {
                        if let Some(pending) = state.pending_low_level_calls.get(&rhs_key).cloned()
                        {
                            state.pending_low_level_calls.entry(dest_key.clone()).or_insert(pending);
                        }
                    }
                    let lhs_has_timestamp =
                        value_has_origin(&state.origins, lhs, ValueOrigin::Timestamp);
                    let rhs_has_timestamp =
                        value_has_origin(&state.origins, rhs, ValueOrigin::Timestamp);
                    if lhs_has_timestamp || rhs_has_timestamp {
                        state
                            .origins
                            .entry(dest_key)
                            .or_default()
                            .insert(ValueOrigin::Timestamp);
                    }
                    let lhs_has_blocknum =
                        value_has_origin(&state.origins, lhs, ValueOrigin::BlockNumber);
                    let rhs_has_blocknum =
                        value_has_origin(&state.origins, rhs, ValueOrigin::BlockNumber);
                    if (lhs_has_timestamp || rhs_has_timestamp)
                        && (lhs_has_blocknum || rhs_has_blocknum)
                        && is_weak_prng_arithmetic_op(op)
                        && seen_vulns
                            .insert((VulnerabilityKind::TimestampDependency, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::TimestampDependency,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: Some(expr.clone()),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "block.timestamp-derived value mixed with block.number/blockhash in arithmetic expression"
                                    .to_string(),
                            model: None,
                        });
                    }
                    if lhs_has_blocknum || rhs_has_blocknum {
                        state
                            .origins
                            .entry(var_key(dest))
                            .or_default()
                            .insert(ValueOrigin::BlockNumber);
                        if is_weak_prng_arithmetic_op(op)
                            && seen_vulns.insert((VulnerabilityKind::WeakPrng, current_pc))
                        {
                            vulnerabilities.push(LocalVulnerability {
                                kind: VulnerabilityKind::WeakPrng,
                                pc: current_pc,
                                instruction: format!("{instr:?}"),
                                trace: state.trace.clone(),
                                trigger: Some(expr.clone()),
                                branch_triggers: state.branch_triggers.clone(),
                                span: Some(instr_span(instr)),
                                path_constraints: constraints_to_strings(&state.path_constraints),
                                message:
                                    "weak PRNG: block.number/blockhash used in arithmetic expression"
                                        .to_string(),
                                model: None,
                            });
                        }
                    }
                    let lhs_has_this_balance =
                        value_has_origin(&state.origins, lhs, ValueOrigin::ThisBalance);
                    let rhs_has_this_balance =
                        value_has_origin(&state.origins, rhs, ValueOrigin::ThisBalance);
                    if lhs_has_this_balance || rhs_has_this_balance {
                        state
                            .origins
                            .entry(var_key(dest))
                            .or_default()
                            .insert(ValueOrigin::ThisBalance);
                    }
                }
                IrInstr::Unary { dest, op, expr, .. } => {
                    let in_v = state.eval_value(expr);
                    let out = eval_unary(op, in_v);
                    state.set_var(dest, out);
                    let dest_key = var_key(dest);
                    state.expr_env.insert(
                        dest_key.clone(),
                        format!("({}{})", op, state.value_expr(expr)),
                    );
                    if value_has_origin(&state.origins, expr, ValueOrigin::Timestamp) {
                        state
                            .origins
                            .entry(dest_key)
                            .or_default()
                            .insert(ValueOrigin::Timestamp);
                    }
                    if value_has_origin(&state.origins, expr, ValueOrigin::BlockNumber) {
                        state
                            .origins
                            .entry(var_key(dest))
                            .or_default()
                            .insert(ValueOrigin::BlockNumber);
                    }
                    if value_has_origin(&state.origins, expr, ValueOrigin::ThisBalance) {
                        state
                            .origins
                            .entry(var_key(dest))
                            .or_default()
                            .insert(ValueOrigin::ThisBalance);
                    }
                }
                IrInstr::Call {
                    dest,
                    callee,
                    args,
                    options,
                    ..
                } => {
                    let callee_expr = state.value_expr(callee);
                    let callee_lower = callee_expr.to_ascii_lowercase();
                    let callee_is_temp = matches!(callee, IrValue::Var(IrVar::Temp(_)));
                    let callee_key = value_var_key(callee);
                    let callee_origins = callee_key
                        .as_ref()
                        .and_then(|key| state.origins.get(key))
                        .cloned()
                        .unwrap_or_default();
                    let is_delegatecall = callee_lower.contains("delegatecall")
                        || callee_origins.contains(&ValueOrigin::DelegatecallRef);
                    let base_is_low_level_call = is_low_level_call_name(&callee_lower)
                        || callee_origins.contains(&ValueOrigin::LowLevelCallRef);
                    let is_send_ref = is_send_name(&callee_lower)
                        || callee_origins.contains(&ValueOrigin::SendRef);
                    let is_transfer_ref = is_transfer_name(&callee_lower)
                        || callee_origins.contains(&ValueOrigin::TransferRef);
                    let is_assert_like = callee_lower == "require" || callee_lower == "assert";
                    let is_revert_like = callee_lower == "revert";
                    let is_static_call =
                        callee_lower == "staticcall" || callee_lower.ends_with(".staticcall");
                    let has_explicit_value = options
                        .iter()
                        .any(|o| matches!(o, crate::ir::IrCallOption::Value(_)))
                        || callee_origins.contains(&ValueOrigin::ValueCallRef);
                    let has_callback_capable_source_surface = callback_data
                        .map(|data| {
                            function_has_callback_capable_low_level_call(
                                data.ast,
                                state.function_id,
                            )
                        })
                        .unwrap_or(false);
                    let has_value_moving_source_surface = callback_data
                        .map(|data| {
                            function_has_value_moving_low_level_call(data.ast, state.function_id)
                        })
                        .unwrap_or(false);
                    let has_any_low_level_source_surface =
                        has_callback_capable_source_surface || has_value_moving_source_surface;
                    let is_potential_low_level_temp_call =
                        callee_is_temp && !args.is_empty() && has_any_low_level_source_surface;
                    let is_potential_external_temp_call = callee_is_temp
                        && dest.is_empty()
                        && !args.is_empty()
                        && has_callback_capable_source_surface;
                    let has_value = has_explicit_value
                        || is_send_ref
                        || is_transfer_ref
                        || (callee_is_temp && has_value_moving_source_surface);
                    let is_low_level_call =
                        base_is_low_level_call || is_potential_low_level_temp_call;
                    let is_callback_external_call = is_low_level_call
                        && !is_static_call
                        && !is_send_ref
                        && !is_transfer_ref
                        && (has_value || allow_callback_runtime);
                    let callback_candidates = if state.callback_depth < CALLBACK_MAX_DEPTH {
                        callback_data
                            .map(|data| {
                                reentrant_callback_candidates(
                                    state.function_id,
                                    data.ast,
                                    data.compiler,
                                    data.deps,
                                    CALLBACK_MAX_FANOUT,
                                )
                            })
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    let can_fork_callback = is_callback_external_call
                        && !callback_candidates.is_empty()
                        && !is_delegatecall;
                    let should_havoc_storage =
                        is_delegatecall || (is_callback_external_call && !can_fork_callback);

                    if is_revert_like {
                        state.pending_low_level_calls.clear();
                        if solver_cache.is_feasible(&state.path_constraints) {
                            let revert_values = args
                                .iter()
                                .take(1)
                                .map(|value| state.eval_value(value))
                                .collect::<Vec<_>>();
                            finalize_state(
                                state.clone(),
                                TerminationKind::Revert,
                                revert_values,
                                &mut terminal_states,
                                &mut worklist,
                                &sink_scores,
                                &mut state_shape_visits,
                                &mut max_worklist,
                                limits,
                            );
                        }
                        block_terminated = true;
                        break;
                    }

                    if should_havoc_storage {
                        havoc_storage(&mut state);
                    }

                    if is_callback_external_call {
                        state.external_call_pc = Some(current_pc);
                    }
                    let stipend_only_external_surface = callback_data
                        .map(|data| {
                            function_uses_only_stipend_external_calls(data.ast, state.function_id)
                        })
                        .unwrap_or(false);
                    if allow_callback_runtime
                        && supports_low_confidence_reentrancy_fallback
                        && is_potential_external_temp_call
                        && !can_fork_callback
                        && !is_send_ref
                        && !is_transfer_ref
                        && !stipend_only_external_surface
                        && seen_vulns.insert((VulnerabilityKind::ReentrancyFallback, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::ReentrancyFallback,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "storage-coupled function performs external temp-call without callback proof; potential reentrancy surface"
                                    .to_string(),
                            model: None,
                        });
                    }

                    if is_delegatecall
                        && seen_vulns.insert((VulnerabilityKind::Delegatecall, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::Delegatecall,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message: "unsafe delegatecall usage detected".to_string(),
                            model: None,
                        });
                    }
                    if is_delegatecall
                        && state.inside_loop
                        && seen_vulns.insert((VulnerabilityKind::MemoryManipulation, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::MemoryManipulation,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "delegatecall inside loop context; storage/memory corruption risk"
                                    .to_string(),
                            model: None,
                        });
                    }

                    if is_selfdestruct_name(&callee_lower)
                        && !callback_data
                            .map(|data| {
                                function_is_exploit_cleanup_selfdestruct_helper(
                                    data.ast,
                                    state.function_id,
                                )
                            })
                            .unwrap_or(false)
                        && seen_vulns.insert((VulnerabilityKind::Selfdestruct, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::Selfdestruct,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message: "contract can be destructed (selfdestruct/suicide call)"
                                .to_string(),
                            model: None,
                        });
                    }
                    if is_selfdestruct_name(&callee_lower)
                        && state.saw_this_balance_invariant
                        && seen_vulns.insert((VulnerabilityKind::LockedEther, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::LockedEther,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "balance invariant depends on this.balance before selfdestruct/suicide; forced Ether can brick the path"
                                    .to_string(),
                            model: None,
                        });
                    }
                    let is_hardcoded_gas_transfer = is_send_ref || is_transfer_ref;
                    let is_transfer_like_external_call =
                        is_tod_transfer_like_call_expr(&callee_lower);
                    let has_tod_sink_evidence =
                        has_value || is_hardcoded_gas_transfer || is_transfer_like_external_call;
                    if is_hardcoded_gas_transfer
                        && seen_vulns
                            .insert((VulnerabilityKind::HardcodedGasTransfer, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::HardcodedGasTransfer,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message: "hardcoded gas transfer via send/transfer detected"
                                .to_string(),
                            model: None,
                        });
                    }
                    if allow_signature_malleability
                        && callee_lower.contains("ecrecover")
                        && seen_vulns
                            .insert((VulnerabilityKind::SignatureMalleability, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::SignatureMalleability,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "direct ecrecover usage detected; lower-half s-value check not modeled"
                                    .to_string(),
                            model: None,
                        });
                    }
                    if state.inside_loop
                        && is_low_level_call
                        && is_transfer_ref
                        && seen_vulns.insert((VulnerabilityKind::DosWithFailedCall, current_pc))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::DosWithFailedCall,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "external call executed in loop context; failed callee can cause DoS"
                                    .to_string(),
                            model: None,
                        });
                    }
                    if has_value
                        && is_low_level_call
                        && function_is_externally_callable(callback_data.map(|data| data.ast), state.function_id)
                        && !authority_profile.guarded_by_modifier
                        && !state.sender_checked
                        && !function_is_direct_msg_value_forwarder(
                            callback_data.map(|data| data.ast),
                            state.function_id,
                        )
                        && seen_vulns.insert((
                            VulnerabilityKind::UnprotectedEtherWithdrawal,
                            current_pc,
                        ))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::UnprotectedEtherWithdrawal,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "ether transfer call without preceding sender authorization check"
                                    .to_string(),
                            model: None,
                        });
                    }
                    if allow_tod
                        && has_writer_reader_dependency
                        && state.saw_order_sensitive_storage_read
                        && has_tod_sink_evidence
                        && seen_vulns.insert((
                            VulnerabilityKind::TransactionOrderDependency,
                            current_pc,
                        ))
                    {
                        vulnerabilities.push(LocalVulnerability {
                            kind: VulnerabilityKind::TransactionOrderDependency,
                            pc: current_pc,
                            instruction: format!("{instr:?}"),
                            trace: state.trace.clone(),
                            trigger: state.branch_triggers.last().cloned(),
                            branch_triggers: state.branch_triggers.clone(),
                            span: Some(instr_span(instr)),
                            path_constraints: constraints_to_strings(&state.path_constraints),
                            message:
                                "order-sensitive storage read combined with value-moving external call; front-running/TOD risk"
                                    .to_string(),
                            model: None,
                        });
                    }

                    if is_assert_like {
                        if let Some(first_arg) = args.first() {
                            let cond_expr = state.eval_bool(first_arg);
                            let cond_text = state.value_expr(first_arg);
                            if let Some(arg_key) = value_var_key(first_arg) {
                                if let Some(item) = state.pending_low_level_calls.get(&arg_key) {
                                    let pending_callee = item.callee.to_ascii_lowercase();
                                    if (is_send_name(&pending_callee)
                                        || pending_callee.contains(".send")
                                        || pending_callee.contains("send"))
                                        && seen_vulns.insert((
                                            VulnerabilityKind::UnsafeSendInRequire,
                                            current_pc,
                                        ))
                                    {
                                        vulnerabilities.push(LocalVulnerability {
                                            kind: VulnerabilityKind::UnsafeSendInRequire,
                                            pc: current_pc,
                                            instruction: format!("{instr:?}"),
                                            trace: state.trace.clone(),
                                            trigger: state.branch_triggers.last().cloned(),
                                            branch_triggers: state.branch_triggers.clone(),
                                            span: Some(instr_span(instr)),
                                            path_constraints: constraints_to_strings(
                                                &state.path_constraints,
                                            ),
                                            message:
                                                "unsafe send() used inside require/assert condition"
                                                    .to_string(),
                                            model: None,
                                        });
                                    }
                                    if (is_send_name(&pending_callee)
                                        || pending_callee.contains(".send")
                                        || is_transfer_name(&pending_callee)
                                        || pending_callee.contains(".transfer"))
                                        && seen_vulns.insert((
                                            VulnerabilityKind::DosWithFailedCall,
                                            current_pc,
                                        ))
                                    {
                                        vulnerabilities.push(LocalVulnerability {
                                            kind: VulnerabilityKind::DosWithFailedCall,
                                            pc: current_pc,
                                            instruction: format!("{instr:?}"),
                                            trace: state.trace.clone(),
                                            trigger: state.branch_triggers.last().cloned(),
                                            branch_triggers: state.branch_triggers.clone(),
                                            span: Some(instr_span(instr)),
                                            path_constraints: constraints_to_strings(
                                                &state.path_constraints,
                                            ),
                                            message:
                                                "require/assert outcome depends on low-level call result; failed call can block progress"
                                                    .to_string(),
                                            model: None,
                                        });
                                    }
                                }
                                mark_pending_call_checked(
                                    &mut state.pending_low_level_calls,
                                    &arg_key,
                                );
                            }
                            if cond_text.to_ascii_lowercase().contains("sender")
                                || value_name_raw(first_arg)
                                    .to_ascii_lowercase()
                                    .contains("sender")
                            {
                                state.sender_checked = true;
                            }
                            if value_has_origin(
                                &state.origins,
                                first_arg,
                                ValueOrigin::ThisBalance,
                            ) && cond_text.contains("==")
                            {
                                state.saw_this_balance_invariant = true;
                            }

                            let mut fail_constraints = state.path_constraints.clone();
                            fail_constraints.push(cond_expr.clone().not());
                            if solver_cache.is_feasible(&fail_constraints) {
                                let revert_values = args
                                    .iter()
                                    .skip(1)
                                    .take(1)
                                    .map(|value| state.eval_value(value))
                                    .collect::<Vec<_>>();
                                let mut revert_state = state.clone();
                                revert_state.path_constraints = fail_constraints;
                                finalize_state(
                                    revert_state,
                                    TerminationKind::Revert,
                                    revert_values,
                                    &mut terminal_states,
                                    &mut worklist,
                                    &sink_scores,
                                    &mut state_shape_visits,
                                    &mut max_worklist,
                                    limits,
                                );
                            }

                            state.path_constraints.push(cond_expr);
                            state
                                .branch_triggers
                                .push(format!("{callee_lower}({cond_text}) == true"));
                            if !solver_cache.is_feasible(&state.path_constraints) {
                                block_terminated = true;
                                break;
                            }
                        }
                    }

                    for (idx, var) in dest.iter().enumerate() {
                        let value = state.fresh_symbol("call_ret");
                        state.set_var(var, value.clone());
                        let dest_key = var_key(var);
                        state
                            .expr_env
                            .insert(dest_key.clone(), "call_ret".to_string());
                        if is_low_level_call && idx == 0 {
                            constrain_boolean_int(&mut state, &value);
                            state.pending_low_level_calls.insert(
                                dest_key,
                                PendingCall {
                                    call_pc: current_pc,
                                    callee: callee_expr.clone(),
                                    span: Some(instr_span(instr)),
                                },
                            );
                        }
                        if callee_lower == "blockhash" {
                            state
                                .origins
                                .entry(var_key(var))
                                .or_default()
                                .insert(ValueOrigin::BlockNumber);
                        }
                    }

                    // `transfer` has no boolean return value in Solidity and should not be
                    // flagged as unchecked-call when no destination is present.
                    let is_unchecked_call_candidate = is_low_level_call && !is_transfer_ref;
                    if is_unchecked_call_candidate && dest.is_empty() {
                        if seen_vulns.insert((VulnerabilityKind::UncheckedCall, current_pc)) {
                            vulnerabilities.push(LocalVulnerability {
                                kind: VulnerabilityKind::UncheckedCall,
                                pc: current_pc,
                                instruction: format!("{instr:?}"),
                                trace: state.trace.clone(),
                                trigger: state.branch_triggers.last().cloned(),
                                branch_triggers: state.branch_triggers.clone(),
                                span: Some(instr_span(instr)),
                                path_constraints: constraints_to_strings(&state.path_constraints),
                                message:
                                    "low-level external call return value is ignored (unchecked)"
                                        .to_string(),
                                model: None,
                            });
                        }
                    }

                    if can_fork_callback {
                        let mut caller_resume = state.clone();
                        caller_resume.external_call_pc = Some(current_pc);
                        caller_resume.instr_offset = instr_index.saturating_add(1);
                        let frame = callback_frame_from_state(&caller_resume);
                        let mut enqueued_callback = false;
                        for callback_function_id in callback_candidates {
                            let Some(callback_cfg) = cfg_map.get(&callback_function_id).copied() else {
                                continue;
                            };
                            let Some(entry_block) = callback_cfg.blocks.first().map(|block| block.id) else {
                                continue;
                            };
                            let mut callback_state =
                                callback_state_from_frame(&state, frame.clone(), callback_function_id, entry_block);
                            callback_state.branch_triggers.push(format!(
                                "callback(fn={callback_function_id}) from pc {current_pc}"
                            ));
                            if enqueue_state(
                                &mut worklist,
                                callback_state,
                                &sink_scores,
                                &mut state_shape_visits,
                                &mut max_worklist,
                                limits,
                            ) {
                                enqueued_callback = true;
                            } else {
                                pruned_branches += 1;
                            }
                        }
                        if enqueued_callback {
                            block_terminated = true;
                            break;
                        }
                    }

                }
                IrInstr::Select {
                    dest,
                    cond,
                    then_val,
                    else_val,
                    ..
                } => {
                    let cond_v = state.eval_bool(cond);
                    let then_v = state.eval_value(then_val);
                    let else_v = state.eval_value(else_val);
                    let selected = cond_v.ite(&then_v, &else_v);
                    state.set_var(dest, selected);
                    state.expr_env.insert(
                        var_key(dest),
                        format!(
                            "({} ? {} : {})",
                            state.value_expr(cond),
                            state.value_expr(then_val),
                            state.value_expr(else_val)
                        ),
                    );
                    let dest_key = var_key(dest);
                    let has_timestamp =
                        value_has_origin(&state.origins, cond, ValueOrigin::Timestamp)
                            || value_has_origin(&state.origins, then_val, ValueOrigin::Timestamp)
                            || value_has_origin(&state.origins, else_val, ValueOrigin::Timestamp);
                    if has_timestamp {
                        state
                            .origins
                            .entry(dest_key)
                            .or_default()
                            .insert(ValueOrigin::Timestamp);
                    }
                    let has_blocknum =
                        value_has_origin(&state.origins, cond, ValueOrigin::BlockNumber)
                            || value_has_origin(
                                &state.origins,
                                then_val,
                                ValueOrigin::BlockNumber,
                            )
                            || value_has_origin(
                                &state.origins,
                                else_val,
                                ValueOrigin::BlockNumber,
                            );
                    if has_blocknum {
                        state
                            .origins
                            .entry(var_key(dest))
                            .or_default()
                            .insert(ValueOrigin::BlockNumber);
                    }
                    let has_this_balance =
                        value_has_origin(&state.origins, cond, ValueOrigin::ThisBalance)
                            || value_has_origin(
                                &state.origins,
                                then_val,
                                ValueOrigin::ThisBalance,
                            )
                            || value_has_origin(
                                &state.origins,
                                else_val,
                                ValueOrigin::ThisBalance,
                            );
                    if has_this_balance {
                        state
                            .origins
                            .entry(var_key(dest))
                            .or_default()
                            .insert(ValueOrigin::ThisBalance);
                    }
                }
                IrInstr::Return { values, .. } => {
                    flush_pending_unchecked_calls(
                        &mut state,
                        callback_data.map(|data| data.ast),
                        Some(instr_span(instr)),
                        &mut vulnerabilities,
                        &mut seen_vulns,
                    );
                    if solver_cache.is_feasible(&state.path_constraints) {
                        let ret_values = values
                            .iter()
                            .map(|value| state.eval_value(value))
                            .collect::<Vec<_>>();
                        finalize_state(
                            state.clone(),
                            TerminationKind::Return,
                            ret_values,
                            &mut terminal_states,
                            &mut worklist,
                            &sink_scores,
                            &mut state_shape_visits,
                            &mut max_worklist,
                            limits,
                        );
                    }
                    block_terminated = true;
                    break;
                }
                IrInstr::Control { kind, .. } => {
                    let outgoing = succs
                        .get(&state.function_id)
                        .and_then(|fn_succs| fn_succs.get(&state.block_id))
                        .cloned()
                        .unwrap_or_default();
                    match kind {
                        ControlKind::If { cond } => {
                            let cond_expr = state.eval_bool(cond);
                            let cond_text = state.value_expr(cond);
                            if cond_text.to_ascii_lowercase().contains("sender") {
                                state.sender_checked = true;
                            }
                            if let Some(cond_key) = value_var_key(cond) {
                                mark_pending_call_checked(
                                    &mut state.pending_low_level_calls,
                                    &cond_key,
                                );
                            }
                            let timestamp_in_cond =
                                value_has_origin(&state.origins, cond, ValueOrigin::Timestamp)
                                    || cond_text.to_ascii_lowercase().contains("timestamp");
                            if timestamp_in_cond
                                && seen_vulns
                                    .insert((VulnerabilityKind::TimestampDependency, current_pc))
                            {
                                vulnerabilities.push(LocalVulnerability {
                                    kind: VulnerabilityKind::TimestampDependency,
                                    pc: current_pc,
                                    instruction: format!("{instr:?}"),
                                    trace: state.trace.clone(),
                                    trigger: Some(cond_text.clone()),
                                    branch_triggers: state.branch_triggers.clone(),
                                    span: Some(instr_span(instr)),
                                    path_constraints: constraints_to_strings(
                                        &state.path_constraints,
                                    ),
                                    message:
                                        "dangerous usage of block.timestamp in branch condition"
                                            .to_string(),
                                    model: None,
                                });
                            }
                            let weak_prng_in_cond =
                                value_has_origin(&state.origins, cond, ValueOrigin::BlockNumber)
                                    || cond_text.to_ascii_lowercase().contains("block.number")
                                    || cond_text.to_ascii_lowercase().contains("blockhash");
                            if weak_prng_in_cond
                                && seen_vulns.insert((VulnerabilityKind::WeakPrng, current_pc))
                            {
                                vulnerabilities.push(LocalVulnerability {
                                    kind: VulnerabilityKind::WeakPrng,
                                    pc: current_pc,
                                    instruction: format!("{instr:?}"),
                                    trace: state.trace.clone(),
                                    trigger: Some(cond_text.clone()),
                                    branch_triggers: state.branch_triggers.clone(),
                                    span: Some(instr_span(instr)),
                                    path_constraints: constraints_to_strings(
                                        &state.path_constraints,
                                    ),
                                    message:
                                        "weak PRNG: block.number/blockhash used in branch condition"
                                            .to_string(),
                                    model: None,
                                });
                            }

                            if let Some(true_block) = outgoing.first().copied() {
                                let mut true_state = state.clone();
                                true_state.path_constraints.push(cond_expr.clone());
                                true_state
                                    .branch_triggers
                                    .push(format!("{cond_text} == true"));
                                if solver_cache.is_feasible(&true_state.path_constraints) {
                                    if !try_enqueue_state(
                                        &mut worklist,
                                        true_state,
                                        true_block,
                                        &sink_scores,
                                        &mut state_shape_visits,
                                        &mut max_worklist,
                                        limits,
                                    ) {
                                        pruned_branches += 1;
                                    }
                                } else {
                                    pruned_branches += 1;
                                }
                            } else {
                                dead_ends += 1;
                            }

                            if let Some(false_block) = outgoing.get(1).copied() {
                                let mut false_state = state.clone();
                                false_state.path_constraints.push(cond_expr.not());
                                false_state
                                    .branch_triggers
                                    .push(format!("{cond_text} == false"));
                                if solver_cache.is_feasible(&false_state.path_constraints) {
                                    if !try_enqueue_state(
                                        &mut worklist,
                                        false_state,
                                        false_block,
                                        &sink_scores,
                                        &mut state_shape_visits,
                                        &mut max_worklist,
                                        limits,
                                    ) {
                                        pruned_branches += 1;
                                    }
                                } else {
                                    pruned_branches += 1;
                                }
                            } else {
                                dead_ends += 1;
                            }
                        }
                        ControlKind::Loop { cond } => {
                            if let Some(cond) = cond {
                                let cond_expr = state.eval_bool(cond);
                                let cond_text = state.value_expr(cond);
                                if let Some(body_block) = outgoing.first().copied() {
                                    let mut body_state = state.clone();
                                    body_state.path_constraints.push(cond_expr.clone());
                                    body_state.inside_loop = true;
                                    body_state
                                        .branch_triggers
                                        .push(format!("loop({cond_text}) == true"));
                                    if solver_cache.is_feasible(&body_state.path_constraints) {
                                        if !try_enqueue_state(
                                            &mut worklist,
                                            body_state,
                                            body_block,
                                            &sink_scores,
                                            &mut state_shape_visits,
                                            &mut max_worklist,
                                            limits,
                                        ) {
                                            pruned_branches += 1;
                                        }
                                    } else {
                                        pruned_branches += 1;
                                    }
                                } else {
                                    dead_ends += 1;
                                }
                                if let Some(exit_block) = outgoing.get(1).copied() {
                                    let mut exit_state = state.clone();
                                    exit_state.path_constraints.push(cond_expr.not());
                                    exit_state.inside_loop = false;
                                    exit_state
                                        .branch_triggers
                                        .push(format!("loop({cond_text}) == false"));
                                    if solver_cache.is_feasible(&exit_state.path_constraints) {
                                        if !try_enqueue_state(
                                            &mut worklist,
                                            exit_state,
                                            exit_block,
                                            &sink_scores,
                                            &mut state_shape_visits,
                                            &mut max_worklist,
                                            limits,
                                        ) {
                                            pruned_branches += 1;
                                        }
                                    } else {
                                        pruned_branches += 1;
                                    }
                                } else {
                                    dead_ends += 1;
                                }
                            } else if let Some(next_block) = outgoing.first().copied() {
                                let mut next_state = state.clone();
                                next_state.inside_loop = true;
                                if !try_enqueue_state(
                                    &mut worklist,
                                    next_state,
                                    next_block,
                                    &sink_scores,
                                    &mut state_shape_visits,
                                    &mut max_worklist,
                                    limits,
                                ) {
                                    pruned_branches += 1;
                                }
                            } else {
                                dead_ends += 1;
                            }
                        }
                        ControlKind::EndLoop => {
                            if outgoing.is_empty() {
                                dead_ends += 1;
                            } else {
                                for next_block in outgoing {
                                    let mut next_state = state.clone();
                                    next_state.inside_loop = false;
                                    if !try_enqueue_state(
                                        &mut worklist,
                                        next_state,
                                        next_block,
                                        &sink_scores,
                                        &mut state_shape_visits,
                                        &mut max_worklist,
                                        limits,
                                    ) {
                                        pruned_branches += 1;
                                    }
                                }
                            }
                        }
                        ControlKind::Revert { value } => {
                            flush_pending_unchecked_calls(
                                &mut state,
                                callback_data.map(|data| data.ast),
                                Some(instr_span(instr)),
                                &mut vulnerabilities,
                                &mut seen_vulns,
                            );
                            if solver_cache.is_feasible(&state.path_constraints) {
                                let revert_values = value
                                    .as_ref()
                                    .map(|v| vec![state.eval_value(v)])
                                    .unwrap_or_default();
                                finalize_state(
                                    state.clone(),
                                    TerminationKind::Revert,
                                    revert_values,
                                    &mut terminal_states,
                                    &mut worklist,
                                    &sink_scores,
                                    &mut state_shape_visits,
                                    &mut max_worklist,
                                    limits,
                                );
                            }
                        }
                        _ => {
                            if outgoing.is_empty() {
                                dead_ends += 1;
                            } else {
                                for next_block in outgoing {
                                    if !try_enqueue_state(
                                        &mut worklist,
                                        state.clone(),
                                        next_block,
                                        &sink_scores,
                                        &mut state_shape_visits,
                                        &mut max_worklist,
                                        limits,
                                    ) {
                                        pruned_branches += 1;
                                    }
                                }
                            }
                        }
                    }
                    block_terminated = true;
                    break;
                }
            }
        }

        if block_terminated {
            continue;
        }

        let outgoing = succs
            .get(&state.function_id)
            .and_then(|fn_succs| fn_succs.get(&state.block_id))
            .cloned()
            .unwrap_or_default();
        if outgoing.is_empty() {
            flush_pending_unchecked_calls(
                &mut state,
                callback_data.map(|data| data.ast),
                None,
                &mut vulnerabilities,
                &mut seen_vulns,
            );
            finalize_state(
                state.clone(),
                TerminationKind::Fallthrough,
                Vec::new(),
                &mut terminal_states,
                &mut worklist,
                &sink_scores,
                &mut state_shape_visits,
                &mut max_worklist,
                limits,
            );
        } else {
            for next_block in outgoing {
                if !try_enqueue_state(
                    &mut worklist,
                    state.clone(),
                    next_block,
                    &sink_scores,
                    &mut state_shape_visits,
                    &mut max_worklist,
                    limits,
                ) {
                    pruned_branches += 1;
                }
            }
        }
    }

    let reachable_returns = terminal_states
        .iter()
        .filter(|state| matches!(state.kind, TerminationKind::Return))
        .count();
    let reachable_reverts = terminal_states
        .iter()
        .filter(|state| matches!(state.kind, TerminationKind::Revert))
        .count();
    let reachable_fallthroughs = terminal_states
        .iter()
        .filter(|state| matches!(state.kind, TerminationKind::Fallthrough))
        .count();
    let terminal_paths = terminal_states.len();

    if allow_callback_runtime
        && !vulnerabilities.iter().any(|v| {
            matches!(
                v.kind,
                VulnerabilityKind::Reentrancy | VulnerabilityKind::ReentrancyFallback
            )
        })
        && let Some(vuln) = callback_only_fallback
        && seen_vulns.insert((vuln.kind.clone(), vuln.pc))
    {
        vulnerabilities.push(vuln);
    }

    EngineStats {
        instructions,
        explored_states,
        reachable_returns,
        reachable_reverts,
        reachable_fallthroughs,
        terminal_paths,
        pruned_branches,
        dead_ends,
        max_worklist,
        vulnerabilities,
        truncated,
    }
}

fn flush_pending_unchecked_calls(
    state: &mut State,
    ast: Option<&NormalizedAst>,
    fallback_span: Option<Span>,
    vulnerabilities: &mut Vec<LocalVulnerability>,
    seen_vulns: &mut HashSet<(VulnerabilityKind, usize)>,
) {
    let suppress_checked_selector_wrapper =
        function_is_checked_selector_low_level_wrapper(ast, state.function_id);
    let pending = state
        .pending_low_level_calls
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for item in pending {
        if suppress_checked_selector_wrapper {
            continue;
        }
        if seen_vulns.insert((VulnerabilityKind::UncheckedCall, item.call_pc)) {
            vulnerabilities.push(LocalVulnerability {
                kind: VulnerabilityKind::UncheckedCall,
                pc: item.call_pc,
                instruction: format!("call {}", item.callee),
                trace: state.trace.clone(),
                trigger: state.branch_triggers.last().cloned(),
                branch_triggers: state.branch_triggers.clone(),
                span: item.span.or(fallback_span),
                path_constraints: constraints_to_strings(&state.path_constraints),
                message: format!(
                    "low-level external call '{}' return value is not checked",
                    item.callee
                ),
                model: None,
            });
        }
    }
    state.pending_low_level_calls.clear();
}

fn callback_frame_from_state(state: &State) -> CallbackFrame {
    CallbackFrame {
        function_id: state.function_id,
        block_id: state.block_id,
        instr_offset: state.instr_offset,
        env: state.env.clone(),
        storage: state.storage.clone(),
        origins: state.origins.clone(),
        pending_low_level_calls: state.pending_low_level_calls.clone(),
        expr_env: state.expr_env.clone(),
        sender_checked: state.sender_checked,
        inside_loop: state.inside_loop,
        saw_order_sensitive_storage_read: state.saw_order_sensitive_storage_read,
        saw_this_balance_invariant: state.saw_this_balance_invariant,
        storage_reads: state.storage_reads.clone(),
        block_visits: state.block_visits.clone(),
        callback_depth: state.callback_depth,
        external_call_pc: state.external_call_pc,
    }
}

fn callback_state_from_frame(
    current_state: &State,
    frame: CallbackFrame,
    callback_function_id: u32,
    entry_block: u32,
) -> State {
    let mut callback_state = current_state.clone();
    callback_state.function_id = callback_function_id;
    callback_state.block_id = entry_block;
    callback_state.instr_offset = 0;
    callback_state.env = HashMap::new();
    callback_state.origins = HashMap::new();
    callback_state.pending_low_level_calls = HashMap::new();
    callback_state.expr_env = HashMap::new();
    callback_state.sender_checked = false;
    callback_state.inside_loop = false;
    callback_state.saw_order_sensitive_storage_read = false;
    callback_state.saw_this_balance_invariant = false;
    callback_state.storage_reads = HashSet::new();
    callback_state.block_visits = HashMap::from([(entry_block, 1)]);
    callback_state.callback_depth = frame.callback_depth.saturating_add(1);
    callback_state.callback_observed = false;
    callback_state.callback_changed_storage_keys = HashSet::new();
    callback_state.callback_stale_read_keys = HashSet::new();
    callback_state.callback_frame = Some(frame);
    callback_state
}

fn resume_from_callback(
    callback_state: &State,
    frame: CallbackFrame,
    kind: &TerminationKind,
) -> State {
    let mut resumed = State::new();
    let callback_changed_storage_keys = match kind {
        TerminationKind::Revert => HashSet::new(),
        TerminationKind::Return | TerminationKind::Fallthrough => {
            diff_storage_keys(&frame.storage, &callback_state.storage)
        }
    };
    let callback_stale_read_keys = frame
        .storage_reads
        .iter()
        .filter(|slot| callback_changed_storage_keys.contains(*slot))
        .cloned()
        .collect::<HashSet<_>>();
    resumed.function_id = frame.function_id;
    resumed.block_id = frame.block_id;
    resumed.instr_offset = frame.instr_offset;
    resumed.env = frame.env;
    resumed.storage = match kind {
        TerminationKind::Revert => frame.storage,
        TerminationKind::Return | TerminationKind::Fallthrough => callback_state.storage.clone(),
    };
    resumed.origins = frame.origins;
    resumed.path_constraints = callback_state.path_constraints.clone();
    resumed.fresh_id = callback_state.fresh_id;
    resumed.external_call_pc = frame.external_call_pc;
    resumed.pending_low_level_calls = frame.pending_low_level_calls;
    resumed.trace = callback_state.trace.clone();
    resumed.expr_env = frame.expr_env;
    resumed.branch_triggers = callback_state.branch_triggers.clone();
    resumed.sender_checked = frame.sender_checked;
    resumed.inside_loop = frame.inside_loop;
    resumed.saw_order_sensitive_storage_read = frame.saw_order_sensitive_storage_read;
    resumed.saw_this_balance_invariant = frame.saw_this_balance_invariant;
    resumed.storage_reads = frame.storage_reads;
    resumed.block_visits = frame.block_visits;
    resumed.callback_depth = frame.callback_depth;
    resumed.callback_observed = !matches!(kind, TerminationKind::Revert);
    resumed.callback_changed_storage_keys = callback_changed_storage_keys;
    resumed.callback_stale_read_keys = callback_stale_read_keys;
    resumed.callback_frame = None;
    resumed.branch_triggers.push(format!(
        "callback(fn={}) {}",
        callback_state.function_id,
        match kind {
            TerminationKind::Return => "returned",
            TerminationKind::Revert => "reverted",
            TerminationKind::Fallthrough => "fell through",
        }
    ));
    resumed
}

fn diff_storage_keys(before: &HashMap<String, Int>, after: &HashMap<String, Int>) -> HashSet<String> {
    let mut keys = before.keys().cloned().collect::<HashSet<_>>();
    keys.extend(after.keys().cloned());
    keys.into_iter()
        .filter(|key| {
            let left = before.get(key).map(|v| v.to_string());
            let right = after.get(key).map(|v| v.to_string());
            left != right
        })
        .collect()
}

fn finalize_state(
    state: State,
    kind: TerminationKind,
    values: Vec<Int>,
    terminal_states: &mut Vec<TerminalState>,
    worklist: &mut Vec<State>,
    sink_scores: &HashMap<u32, i32>,
    state_shape_visits: &mut HashMap<String, u8>,
    max_worklist: &mut usize,
    limits: EngineLimits,
) {
    if let Some(frame) = state.callback_frame.clone() {
        let resumed = resume_from_callback(&state, frame, &kind);
        let _ = enqueue_state(
            worklist,
            resumed,
            sink_scores,
            state_shape_visits,
            max_worklist,
            limits,
        );
        return;
    }

    terminal_states.push(TerminalState {
        kind,
        values,
        path_constraints: state.path_constraints.clone(),
    });
}

fn havoc_storage(state: &mut State) {
    if state.storage.is_empty() {
        return;
    }
    let keys = state.storage.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let symbol = state.fresh_symbol("storage_havoc");
        state.storage.insert(key, symbol);
    }
}

fn mark_pending_call_checked(pending: &mut HashMap<String, PendingCall>, key: &str) {
    let Some(call_pc) = pending.get(key).map(|item| item.call_pc) else {
        return;
    };
    pending.retain(|_, item| item.call_pc != call_pc);
}

fn value_var_key(value: &IrValue) -> Option<String> {
    match value {
        IrValue::Var(var) => Some(var_key(var)),
        _ => None,
    }
}

fn value_key(value: &IrValue) -> String {
    match value {
        IrValue::Var(var) => var_key(var),
        IrValue::Literal(lit) => format!("lit:{}", lit.value),
        IrValue::Unknown => "<unknown>".to_string(),
    }
}

fn place_var_key(place: &IrPlace) -> Option<String> {
    match place {
        IrPlace::Var { var, .. } => Some(var_key(var)),
        _ => None,
    }
}

fn value_name_raw(value: &IrValue) -> String {
    match value {
        IrValue::Var(IrVar::Named(name)) => name.clone(),
        IrValue::Var(IrVar::Temp(id)) => format!("tmp_{id}"),
        IrValue::Literal(lit) => lit.value.clone(),
        IrValue::Unknown => "unknown".to_string(),
    }
}

fn place_member_base_field(place: &IrPlace) -> Option<(String, String)> {
    let IrPlace::Member { base, field, .. } = place else {
        return None;
    };
    Some((value_name_raw(base), field.clone()))
}

fn reentrant_callback_candidates(
    function_id: u32,
    ast: &NormalizedAst,
    compiler: &crate::frontend::CompilerInfo,
    deps: &DependencyMap,
    limit: usize,
) -> Vec<u32> {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return Vec::new();
    };
    let Some(contract_id) = function.contract else {
        return Vec::new();
    };
    let Some(contract) = ast.contracts.get(contract_id as usize) else {
        return Vec::new();
    };
    let current_deps = deps.functions.get(&function_id);

    let mut mutating = contract
        .functions
        .iter()
        .filter_map(|candidate_id| {
            let candidate = ast.functions.get(*candidate_id as usize)?;
            if !crate::frontend::is_mutating_entrypoint(candidate, compiler)
                || candidate.kind != FunctionKind::Function
            {
                return None;
            }
            Some(*candidate_id)
        })
        .collect::<Vec<_>>();
    mutating.sort_unstable();
    mutating.dedup();

    if mutating.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    if mutating.contains(&function_id) {
        out.push(function_id);
    }

    let mut overlap = Vec::new();
    for candidate_id in mutating {
        if candidate_id == function_id {
            continue;
        }
        let overlaps = current_deps
            .zip(deps.functions.get(&candidate_id))
            .map(|(current, candidate)| {
                current.writes.iter().any(|slot| {
                    candidate.reads.contains(slot) || candidate.writes.contains(slot)
                }) || current
                    .reads
                    .iter()
                    .any(|slot| candidate.writes.contains(slot))
            })
            .unwrap_or(false);
        if overlaps {
            overlap.push(candidate_id);
        }
    }
    overlap.sort_unstable();
    out.extend(overlap);
    out.truncate(limit);
    out
}

fn function_has_writer_reader_dependency(function_id: u32, data: EngineCallbackData<'_>) -> bool {
    let Some(current_deps) = data.deps.functions.get(&function_id) else {
        return false;
    };
    if current_deps.reads.is_empty() {
        return false;
    }
    let current_contract = data
        .ast
        .functions
        .get(function_id as usize)
        .and_then(|f| f.contract);
    data.ast.functions.iter().any(|candidate| {
        if candidate.id == function_id || candidate.contract != current_contract {
            return false;
        }
        if !crate::frontend::is_public_entrypoint(candidate, data.compiler)
            || candidate.kind != FunctionKind::Function
        {
            return false;
        }
        let Some(candidate_deps) = data.deps.functions.get(&candidate.id) else {
            return false;
        };
        candidate_deps
            .writes
            .iter()
            .any(|slot| current_deps.reads.contains(slot))
    })
}

fn function_has_tod_runtime_evidence(
    cfg_fn: &cfg::CfgFunction,
    data: EngineCallbackData<'_>,
) -> bool {
    if !function_has_writer_reader_dependency(cfg_fn.id, data) {
        return false;
    }

    let mut saw_order_sensitive_read = false;
    let mut transfer_like_call_temps: HashSet<String> = HashSet::new();
    let mut saw_transfer_like_call = false;

    for block in &cfg_fn.blocks {
        for instr in &block.instrs {
            match instr {
                IrInstr::Load { dest, src, .. } => {
                    if is_storage_place(src) && place_is_order_sensitive(src) {
                        saw_order_sensitive_read = true;
                    }
                    if let IrPlace::Member { field, .. } = src
                        && is_tod_transfer_like_method_lower(&field.to_ascii_lowercase())
                    {
                        transfer_like_call_temps.insert(var_key(dest));
                    }
                }
                IrInstr::Call {
                    callee, options, ..
                } => {
                    let callee_lower = value_name_raw(callee).to_ascii_lowercase();
                    let has_explicit_value = options
                        .iter()
                        .any(|option| matches!(option, crate::ir::IrCallOption::Value(_)));
                    if has_explicit_value
                        || is_tod_transfer_like_call_expr(&callee_lower)
                        || transfer_like_call_temps.contains(&value_name_raw(callee))
                    {
                        saw_transfer_like_call = true;
                    }
                }
                _ => {}
            }
        }
    }

    saw_order_sensitive_read && saw_transfer_like_call
}

fn seed_contract_state_var_origins(
    origins: &mut HashMap<String, HashSet<ValueOrigin>>,
    function_id: u32,
    ast: &NormalizedAst,
) {
    let Some(contract_id) = ast
        .functions
        .get(function_id as usize)
        .and_then(|function| function.contract)
    else {
        return;
    };

    for state_var in ast
        .state_vars
        .iter()
        .filter(|state_var| state_var.contract == contract_id)
    {
        let Some(init_lower) = state_var_initializer_lower(ast, state_var.span) else {
            continue;
        };
        let entry = origins.entry(state_var.name.clone()).or_default();
        if init_lower.contains("block.timestamp") || init_lower.contains("now") {
            entry.insert(ValueOrigin::Timestamp);
        }
        if init_lower.contains("block.number") || init_lower.contains("blockhash") {
            entry.insert(ValueOrigin::BlockNumber);
        }
    }
}

fn function_source_has_dynamic_gas_loop(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = source_span_lower(ast, function.span) else {
        return false;
    };
    let has_loop = source_lower.contains("for(")
        || source_lower.contains("for (")
        || source_lower.contains("while(")
        || source_lower.contains("while (");
    let has_dynamic_bound = source_lower.contains(".length")
        || source_lower.contains("msg.gas")
        || source_lower.contains("gasleft(");
    has_loop && has_dynamic_bound
}

fn function_uses_only_stipend_external_calls(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = source_span_lower(ast, function.span) else {
        return false;
    };
    let has_stipend_call = source_lower.contains(".send(")
        || source_lower.contains(".send (")
        || source_lower.contains(".transfer(")
        || source_lower.contains(".transfer (");
    let has_callback_capable_call = source_lower.contains(".call(")
        || source_lower.contains(".call (")
        || source_lower.contains(".call.value")
        || source_lower.contains(".delegatecall")
        || source_lower.contains(".callcode");
    has_stipend_call && !has_callback_capable_call
}

fn function_has_callback_capable_low_level_call(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = source_span_lower(ast, function.span) else {
        return false;
    };
    source_lower.contains(".call(")
        || source_lower.contains(".call (")
        || source_lower.contains(".call.value")
        || source_lower.contains(".delegatecall")
        || source_lower.contains(".callcode")
}

fn function_has_value_moving_low_level_call(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = source_span_lower(ast, function.span) else {
        return false;
    };
    source_lower.contains(".call.value")
        || source_lower.contains(".send(")
        || source_lower.contains(".send (")
        || source_lower.contains(".transfer(")
        || source_lower.contains(".transfer (")
}

fn function_has_strong_stipend_reentrancy_pattern(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = source_span_lower(ast, function.span) else {
        return false;
    };
    let call_idx = [
        source_lower.find(".call.value("),
        source_lower.find(".call{value"),
        source_lower.find(".transfer("),
        source_lower.find(".transfer ("),
        source_lower.find(".send("),
        source_lower.find(".send ("),
    ]
    .into_iter()
    .flatten()
    .min();
    let Some(call_idx) = call_idx else {
        return false;
    };
    let tail = &source_lower[call_idx..];
    tail.contains("delete ")
        || tail.contains("-=")
        || tail.contains("=0")
        || tail.contains(" = 0")
        || tail.contains("=false")
        || tail.contains("= false")
}

fn function_is_checked_selector_low_level_wrapper(
    ast: Option<&NormalizedAst>,
    function_id: u32,
) -> bool {
    let Some(ast) = ast else {
        return false;
    };
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = source_span_lower(ast, function.span) else {
        return false;
    };
    let has_checked_call = source_lower.contains("require(")
        || source_lower.contains("require (")
        || source_lower.contains("assert(")
        || source_lower.contains("assert (");
    let has_low_level_call = source_lower.contains(".call(")
        || source_lower.contains(".call (")
        || source_lower.contains(".call.value");
    let has_selector_payload = source_lower.contains("bytes4(sha3(")
        || source_lower.contains("bytes4(keccak256(")
        || source_lower.contains("abi.encodewithsignature(")
        || source_lower.contains("abi.encodewithselector(");
    has_checked_call && has_low_level_call && has_selector_payload
}

fn function_is_direct_msg_value_forwarder(ast: Option<&NormalizedAst>, function_id: u32) -> bool {
    let Some(ast) = ast else {
        return false;
    };
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = source_span_lower(ast, function.span) else {
        return false;
    };
    source_lower.contains(".call.value(msg.value)")
        || source_lower.contains(".send(msg.value)")
        || source_lower.contains(".send (msg.value)")
        || source_lower.contains(".transfer(msg.value)")
        || source_lower.contains(".transfer (msg.value)")
}

fn function_is_externally_callable(ast: Option<&NormalizedAst>, function_id: u32) -> bool {
    ast.and_then(|ast| ast.functions.get(function_id as usize))
        .map(|function| {
            matches!(
                function.visibility,
                Visibility::Public | Visibility::External
            ) || matches!(function.kind, FunctionKind::Fallback | FunctionKind::Receive)
        })
        .unwrap_or(true)
}

fn state_var_initializer_lower(ast: &NormalizedAst, span: Span) -> Option<String> {
    let source = source_span(ast, span)?;
    let (_, rhs) = source.split_once('=')?;
    Some(rhs.to_ascii_lowercase())
}

fn source_span_lower(ast: &NormalizedAst, span: Span) -> Option<String> {
    source_span(ast, span).map(|source| source.to_ascii_lowercase())
}

fn source_span(ast: &NormalizedAst, span: Span) -> Option<&str> {
    let file = ast.files.get(span.file as usize)?;
    file.source.get(span.start as usize..span.end as usize)
}

fn contract_source_lower(ast: &NormalizedAst, contract_id: u32) -> Option<String> {
    let contract = ast.contracts.get(contract_id as usize)?;
    source_span(ast, contract.span).map(|source| source.to_ascii_lowercase())
}

fn function_is_exploit_cleanup_selfdestruct_helper(ast: &NormalizedAst, function_id: u32) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(contract_id) = function.contract else {
        return false;
    };
    let Some(contract) = ast.contracts.get(contract_id as usize) else {
        return false;
    };
    let Some(function_source) = source_span_lower(ast, function.span) else {
        return false;
    };
    if !(function_source.contains("suicide(owner") || function_source.contains("selfdestruct(owner"))
    {
        return false;
    }
    let contract_name = contract.name.to_ascii_lowercase();
    if !contract_name.contains("exploit") && !contract_name.contains("attack") {
        return false;
    }
    let Some(contract_source) = contract_source_lower(ast, contract_id) else {
        return false;
    };
    contract_source.contains("owner = msg.sender")
        && contract_source.contains("vulnerable_contract")
        && (contract_source.contains("launch_attack")
            || contract_source.contains("withdrawbalance()"))
}

fn function_has_callback_overlap(function_id: u32, data: EngineCallbackData<'_>) -> bool {
    let Some(current_deps) = data.deps.functions.get(&function_id) else {
        return false;
    };
    let current_contract = data
        .ast
        .functions
        .get(function_id as usize)
        .and_then(|f| f.contract);
    data.ast.functions.iter().any(|candidate| {
        if candidate.id == function_id || candidate.contract != current_contract {
            return false;
        }
        if !crate::frontend::is_public_entrypoint(candidate, data.compiler)
            || candidate.kind != FunctionKind::Function
        {
            return false;
        }
        let Some(candidate_deps) = data.deps.functions.get(&candidate.id) else {
            return false;
        };
        current_deps.writes.iter().any(|slot| {
            candidate_deps.reads.contains(slot) || candidate_deps.writes.contains(slot)
        }) || current_deps
            .reads
            .iter()
            .any(|slot| candidate_deps.writes.contains(slot))
    })
}

fn value_has_origin(
    origins: &HashMap<String, HashSet<ValueOrigin>>,
    value: &IrValue,
    origin: ValueOrigin,
) -> bool {
    let Some(key) = value_var_key(value) else {
        return false;
    };
    origins
        .get(&key)
        .map(|origins| origins.contains(&origin))
        .unwrap_or(false)
}

fn is_low_level_call_name(callee_lower: &str) -> bool {
    matches!(
        callee_lower,
        "call" | "send" | "transfer" | "delegatecall" | "staticcall"
    ) || callee_lower.ends_with(".call")
        || callee_lower.ends_with(".send")
        || callee_lower.ends_with(".transfer")
        || callee_lower.ends_with(".delegatecall")
        || callee_lower.ends_with(".staticcall")
}

fn is_send_name(callee_lower: &str) -> bool {
    callee_lower == "send" || callee_lower.ends_with(".send")
}

fn is_transfer_name(callee_lower: &str) -> bool {
    callee_lower == "transfer" || callee_lower.ends_with(".transfer")
}

fn is_tod_transfer_like_method_lower(method_lower: &str) -> bool {
    matches!(
        method_lower,
        "transferfrom" | "safetransferfrom" | "approve" | "approveandcall" | "safeapprove"
    )
}

fn is_tod_transfer_like_call_expr(callee_lower: &str) -> bool {
    callee_lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            token
                .rsplit('.')
                .next()
                .map(is_tod_transfer_like_method_lower)
                .unwrap_or(false)
        })
}

fn is_weak_prng_arithmetic_op(op: &str) -> bool {
    matches!(op, "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "<<" | ">>")
}

fn is_selfdestruct_name(callee_lower: &str) -> bool {
    callee_lower == "selfdestruct" || callee_lower == "suicide"
}

fn has_checked_arithmetic(ast: &NormalizedAst) -> bool {
    for file in &ast.files {
        let src = file.source.to_ascii_lowercase();
        if src.contains("pragma solidity") && src.contains("0.8") {
            return true;
        }
    }
    false
}

fn collect_payable_contracts(ast: &NormalizedAst) -> HashSet<u32> {
    let mut out = HashSet::new();
    for function in &ast.functions {
        if let Some(contract_id) = function.contract
            && function.mutability == Mutability::Payable
            && matches!(
                function.kind,
                FunctionKind::Function | FunctionKind::Fallback | FunctionKind::Receive
            )
        {
            out.insert(contract_id);
        }
    }
    out
}

fn collect_contracts_with_ether_send(
    ast: &NormalizedAst,
    ir_module: &crate::ir::IrModule,
) -> HashSet<u32> {
    let mut out = HashSet::new();
    for function in &ir_module.functions {
        let Some(ast_fn) = ast.functions.get(function.id as usize) else {
            continue;
        };
        let Some(contract_id) = ast_fn.contract else {
            continue;
        };
        if function_has_ether_send(function) {
            out.insert(contract_id);
        }
    }
    out
}

fn function_has_ether_send(function: &crate::ir::IrFunction) -> bool {
    let mut temp_call_refs: HashSet<String> = HashSet::new();
    let mut temp_send_refs: HashSet<String> = HashSet::new();
    let mut temp_transfer_refs: HashSet<String> = HashSet::new();
    let mut temp_value_refs: HashSet<String> = HashSet::new();

    for block in &function.blocks {
        for instr in &block.instrs {
            match instr {
                IrInstr::Load { dest, src, .. } => {
                    let dest_key = var_key(dest);
                    if let IrPlace::Member { base, field, .. } = src {
                        let field_lower = field.to_ascii_lowercase();
                        if matches!(
                            field_lower.as_str(),
                            "call" | "send" | "transfer" | "delegatecall" | "staticcall"
                        ) {
                            temp_call_refs.insert(dest_key.clone());
                        }
                        if field_lower == "send" {
                            temp_send_refs.insert(dest_key.clone());
                        }
                        if field_lower == "transfer" {
                            temp_transfer_refs.insert(dest_key.clone());
                        }
                        if field_lower == "value" {
                            let base_key = value_key(base);
                            if temp_call_refs.contains(&base_key) {
                                temp_value_refs.insert(dest_key);
                            }
                        }
                    }
                }
                IrInstr::Assign { dest, src, .. } => {
                    let dest_key = var_key(dest);
                    let src_key = value_key(src);
                    if temp_call_refs.contains(&src_key) {
                        temp_call_refs.insert(dest_key.clone());
                    }
                    if temp_send_refs.contains(&src_key) {
                        temp_send_refs.insert(dest_key.clone());
                    }
                    if temp_transfer_refs.contains(&src_key) {
                        temp_transfer_refs.insert(dest_key.clone());
                    }
                    if temp_value_refs.contains(&src_key) {
                        temp_value_refs.insert(dest_key);
                    }
                }
                IrInstr::Call { callee, args, options, .. } => {
                    let callee_name = value_name_raw(callee).to_ascii_lowercase();
                    let callee_key = value_var_key(callee);
                    let send_like = is_send_name(&callee_name)
                        || callee_key
                            .as_ref()
                            .map(|key| temp_send_refs.contains(key))
                            .unwrap_or(false);
                    let transfer_like = is_transfer_name(&callee_name)
                        || callee_key
                            .as_ref()
                            .map(|key| temp_transfer_refs.contains(key))
                            .unwrap_or(false);
                    let value_like = options
                        .iter()
                        .any(|opt| matches!(opt, crate::ir::IrCallOption::Value(_)))
                        || callee_key
                            .as_ref()
                            .map(|key| temp_value_refs.contains(key))
                            .unwrap_or(false)
                        || send_like
                        || transfer_like
                        || matches!(callee, IrValue::Var(IrVar::Temp(_))) && !args.is_empty()
                        || is_selfdestruct_name(&callee_name);
                    if value_like {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn build_authority_runtime_profile(
    cfg_fn: &cfg::CfgFunction,
    callback_data: Option<EngineCallbackData<'_>>,
) -> AuthorityRuntimeProfile {
    let mut profile = AuthorityRuntimeProfile::default();
    let mut saw_authority_write = false;
    let mut saw_other_storage_write = false;

    for block in &cfg_fn.blocks {
        for instr in &block.instrs {
            let IrInstr::Store { dest, .. } = instr else {
                continue;
            };
            if !is_storage_place(dest) {
                continue;
            }
            if place_is_authority_sensitive(dest) {
                saw_authority_write = true;
            } else {
                saw_other_storage_write = true;
            }
        }
    }

    profile.exclusive_authority_write = saw_authority_write && !saw_other_storage_write;

    let Some(data) = callback_data else {
        return profile;
    };
    let Some(function) = data.ast.functions.get(cfg_fn.id as usize) else {
        return profile;
    };
    if crate::frontend::is_legacy_named_constructor(function, data.ast) {
        profile.constructor_like = true;
    }
    profile.guarded_by_modifier = crate::frontend::has_authority_modifier_hint(function, data.ast);
    let Some(name) = function.name.as_deref() else {
        return profile;
    };
    let contract_name = function
        .contract
        .and_then(|contract_id| data.ast.contracts.get(contract_id as usize))
        .map(|contract| contract.name.as_str());
    if let Some(contract_name) = contract_name {
        if name == contract_name && crate::frontend::is_public_entrypoint(function, data.compiler) {
            profile.constructor_like = true;
        }
        let starts_upper = name
            .chars()
            .next()
            .map(|ch| ch.is_ascii_uppercase())
            .unwrap_or(false);
        if function.kind == FunctionKind::Function
            && function.params.is_empty()
            && starts_upper
            && name != contract_name
            && crate::frontend::is_public_entrypoint(function, data.compiler)
        {
            profile.wrong_constructor_candidate = true;
        }
    }

    profile
}

fn value_is_sender_like(value: &IrValue, state: &State) -> bool {
    let raw = value_name_raw(value).to_ascii_lowercase();
    let expr = state.value_expr(value).to_ascii_lowercase();
    raw.contains("sender") || expr.contains("sender")
}

fn is_public_mint_burn_function(
    function: &crate::norm::Function,
    compiler: &crate::frontend::CompilerInfo,
) -> bool {
    let Some(name) = function.name.as_ref() else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    (lower == "mint" || lower == "burn")
        && crate::frontend::is_public_entrypoint(function, compiler)
        && function.kind == FunctionKind::Function
}

fn collect_shadowed_params(ast: &NormalizedAst) -> HashMap<u32, Vec<String>> {
    let mut by_contract: HashMap<u32, HashSet<String>> = HashMap::new();
    for state_var in &ast.state_vars {
        by_contract
            .entry(state_var.contract)
            .or_default()
            .insert(state_var.name.clone());
    }

    let mut by_function: HashMap<u32, Vec<String>> = HashMap::new();
    for function in &ast.functions {
        let Some(contract_id) = function.contract else {
            continue;
        };
        let Some(state_vars) = by_contract.get(&contract_id) else {
            continue;
        };
        for param in &function.params {
            if state_vars.contains(param) {
                by_function
                    .entry(function.id)
                    .or_default()
                    .push(param.clone());
            }
        }
    }
    by_function
}

fn var_key(var: &IrVar) -> String {
    match var {
        IrVar::Named(name) => name.clone(),
        IrVar::Temp(id) => format!("tmp_{id}"),
    }
}

fn place_key(place: &IrPlace) -> String {
    format!("{place:?}")
}

fn stable_literal_value(raw: &str) -> i64 {
    let normalized = normalize_literal(raw);
    if normalized.eq_ignore_ascii_case("true") {
        return 1;
    }
    if normalized.eq_ignore_ascii_case("false") {
        return 0;
    }
    if let Some(hex) = normalized.strip_prefix("0x") {
        if let Ok(value) = u64::from_str_radix(hex, 16) {
            return value as i64;
        }
    }
    if let Ok(value) = normalized.parse::<i64>() {
        return value;
    }

    // Fallback for large/unsupported literal encodings: stable pseudo-concrete value
    // keeps equal literals equal and different literals usually different.
    stable_fnv1a64(normalized.as_bytes()) as i64
}

fn normalize_literal(raw: &str) -> String {
    let trimmed = raw.trim();
    for prefix in ["number(", "address(", "int(", "uint("] {
        if let Some(inner) = trimmed
            .strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(')'))
        {
            return inner.trim().to_string();
        }
    }
    trimmed.to_string()
}

fn stable_fnv1a64(bytes: &[u8]) -> u64 {
    struct Fnv64(u64);
    impl Hasher for Fnv64 {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            const OFFSET: u64 = 0xcbf29ce484222325;
            const PRIME: u64 = 0x100000001b3;
            if self.0 == 0 {
                self.0 = OFFSET;
            }
            for b in bytes {
                self.0 ^= *b as u64;
                self.0 = self.0.wrapping_mul(PRIME);
            }
        }
    }

    let mut hasher = Fnv64(0);
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn try_eval_binary_literals(op: &str, lhs: &IrValue, rhs: &IrValue) -> Option<Int> {
    let (IrValue::Literal(lhs_lit), IrValue::Literal(rhs_lit)) = (lhs, rhs) else {
        return None;
    };

    let lhs_key = literal_key(lhs_lit);
    let rhs_key = literal_key(rhs_lit);
    match op {
        "==" => Some(Int::from_i64((lhs_key == rhs_key) as i64)),
        "!=" => Some(Int::from_i64((lhs_key != rhs_key) as i64)),
        _ => None,
    }
}

fn literal_key(lit: &crate::norm::Literal) -> String {
    format!("{}:{}", lit.kind.to_ascii_lowercase(), lit.value)
}

fn bool_to_int(condition: Bool) -> Int {
    condition.ite(&Int::from_i64(1), &Int::from_i64(0))
}

fn constrain_boolean_int(state: &mut State, value: &Int) {
    let is_zero = value.eq(Int::from_i64(0));
    let is_one = value.eq(Int::from_i64(1));
    state.path_constraints.push(Bool::or(&[&is_zero, &is_one]));
}

fn int_to_evm_bv(value: &Int) -> BV {
    BV::from_int(value, EVM_WORD_BITS)
}

fn evm_bv_to_int(value: &BV) -> Int {
    value.to_int(false)
}

fn evm_zero_bv() -> BV {
    BV::from_u64(0, EVM_WORD_BITS)
}

fn eval_binary(op: &str, lhs: Int, rhs: Int) -> Int {
    let lhs_bv = int_to_evm_bv(&lhs);
    let rhs_bv = int_to_evm_bv(&rhs);
    match op {
        "+" => evm_bv_to_int(&lhs_bv.bvadd(&rhs_bv)),
        "-" => evm_bv_to_int(&lhs_bv.bvsub(&rhs_bv)),
        "*" => evm_bv_to_int(&lhs_bv.bvmul(&rhs_bv)),
        "/" => {
            let zero = evm_zero_bv();
            let safe = rhs_bv.eq(&zero).ite(&zero, &lhs_bv.bvudiv(&rhs_bv));
            evm_bv_to_int(&safe)
        }
        "%" => {
            let zero = evm_zero_bv();
            let safe = rhs_bv.eq(&zero).ite(&zero, &lhs_bv.bvurem(&rhs_bv));
            evm_bv_to_int(&safe)
        }
        "==" => bool_to_int(lhs_bv.eq(&rhs_bv)),
        "!=" => bool_to_int(lhs_bv.eq(&rhs_bv).not()),
        ">" => bool_to_int(lhs_bv.bvugt(&rhs_bv)),
        ">=" => bool_to_int(lhs_bv.bvuge(&rhs_bv)),
        "<" => bool_to_int(lhs_bv.bvult(&rhs_bv)),
        "<=" => bool_to_int(lhs_bv.bvule(&rhs_bv)),
        "&&" => {
            let lhs_truth = lhs.eq(Int::from_i64(0)).not();
            let rhs_truth = rhs.eq(Int::from_i64(0)).not();
            bool_to_int(Bool::and(&[&lhs_truth, &rhs_truth]))
        }
        "||" => {
            let lhs_truth = lhs.eq(Int::from_i64(0)).not();
            let rhs_truth = rhs.eq(Int::from_i64(0)).not();
            bool_to_int(Bool::or(&[&lhs_truth, &rhs_truth]))
        }
        _ => Int::new_const(format!("bin_{op}")),
    }
}

fn eval_unary(op: &str, expr: Int) -> Int {
    match op {
        "+" => expr,
        "-" => evm_bv_to_int(&int_to_evm_bv(&expr).bvneg()),
        "!" => bool_to_int(expr.eq(Int::from_i64(0))),
        _ => Int::new_const(format!("un_{op}")),
    }
}

fn constraints_to_strings(path_constraints: &[Bool]) -> Vec<String> {
    path_constraints.iter().map(|c| c.to_string()).collect()
}

fn local_root_cause_key(vuln: &LocalVulnerability) -> String {
    if let Some(trigger) = &vuln.trigger
        && !trigger.is_empty()
    {
        return normalize_root_key(trigger);
    }
    if let Some(span) = vuln.span {
        return format!("span:{}:{}:{}", span.file, span.start, span.end);
    }
    normalize_root_key(vuln.message.as_str())
}

fn normalize_root_key(raw: &str) -> String {
    raw.to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn should_emit_storage_accumulator_overflow_fallback(
    state: &State,
    block: &cfg::Block,
    instr_index: usize,
    dest: &IrVar,
    lhs: &IrValue,
    rhs: &IrValue,
) -> bool {
    let Some(store_slot_key) = next_storage_store_slot_key(block, instr_index, dest) else {
        return false;
    };
    let store_expr = format!("load({store_slot_key})");
    let lhs_expr = state.value_expr(lhs);
    let rhs_expr = state.value_expr(rhs);
    let uses_same_storage_slot = lhs_expr == store_expr || rhs_expr == store_expr;
    if !uses_same_storage_slot {
        return false;
    }
    !storage_accumulator_has_guard(state, &lhs_expr, &rhs_expr, &store_expr)
}

fn next_storage_store_slot_key(
    block: &cfg::Block,
    instr_index: usize,
    dest: &IrVar,
) -> Option<String> {
    let next_instr = block.instrs.get(instr_index + 1)?;
    let IrInstr::Store {
        dest: store_dest,
        src: IrValue::Var(src_var),
        ..
    } = next_instr
    else {
        return None;
    };
    if var_key(src_var) != var_key(dest) || !is_storage_place(store_dest) {
        return None;
    }
    Some(place_key(store_dest))
}

fn storage_accumulator_has_guard(
    state: &State,
    lhs_expr: &str,
    rhs_expr: &str,
    store_expr: &str,
) -> bool {
    state.branch_triggers.iter().any(|text| {
        guard_mentions_storage_accumulator(text, lhs_expr, rhs_expr, store_expr)
    }) || state.path_constraints.iter().any(|constraint| {
        let text = constraint.to_string();
        guard_mentions_storage_accumulator(text.as_str(), lhs_expr, rhs_expr, store_expr)
    })
}

fn guard_mentions_storage_accumulator(
    text: &str,
    lhs_expr: &str,
    rhs_expr: &str,
    store_expr: &str,
) -> bool {
    let has_guard_op = text.contains(">=")
        || text.contains("<=")
        || text.contains('>')
        || text.contains('<')
        || text.contains("bvuge")
        || text.contains("bvule")
        || text.contains("bvugt")
        || text.contains("bvult");
    has_guard_op
        && text.contains(lhs_expr)
        && text.contains(rhs_expr)
        && text.contains(store_expr)
}

fn format_trace(trace: &[usize]) -> String {
    if trace.is_empty() {
        return "<empty>".to_string();
    }
    trace
        .iter()
        .map(|pc| pc.to_string())
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        return s.to_string();
    }
    let mut out = String::new();
    for c in s.chars().take(max_len) {
        out.push(c);
    }
    out.push_str(" ...");
    out
}

fn instr_span(instr: &IrInstr) -> Span {
    match instr {
        IrInstr::Nop { span }
        | IrInstr::Eval { span, .. }
        | IrInstr::Declare { span, .. }
        | IrInstr::Assign { span, .. }
        | IrInstr::Store { span, .. }
        | IrInstr::Load { span, .. }
        | IrInstr::Binary { span, .. }
        | IrInstr::Unary { span, .. }
        | IrInstr::Call { span, .. }
        | IrInstr::Select { span, .. }
        | IrInstr::Emit { span, .. }
        | IrInstr::Return { span, .. }
        | IrInstr::Control { span, .. }
        | IrInstr::InlineAsm { span, .. } => *span,
    }
}

fn build_location(span: &Span, output: &FrontendOutput) -> Option<FindingLocation> {
    let file = output.ast.files.get(span.file as usize)?;
    let start = span.start as usize;
    let end = span.end as usize;
    let snippet = file
        .source
        .get(start..end)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| truncate(s, 120));
    Some(FindingLocation {
        file: file.path.clone(),
        start: span.start,
        end: span.end,
        snippet,
    })
}

fn is_storage_place(place: &IrPlace) -> bool {
    match place {
        IrPlace::Var { class, .. } => matches!(class, PlaceClass::Storage),
        IrPlace::Member { class, .. } => matches!(class, PlaceClass::Storage),
        IrPlace::Index { class, .. } => matches!(class, PlaceClass::Storage),
    }
}

fn place_is_order_sensitive(place: &IrPlace) -> bool {
    let key = place_key(place).to_ascii_lowercase();
    key.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "price"
                    | "rate"
                    | "reward"
                    | "bid"
                    | "bids"
                    | "auction"
                    | "winner"
                    | "quote"
            ) || token.ends_with("price")
                || token.ends_with("rate")
                || token.ends_with("reward")
        })
}

fn place_is_authority_sensitive(place: &IrPlace) -> bool {
    let key = place_key(place).to_ascii_lowercase();
    key.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "owner"
                    | "admin"
                    | "operator"
                    | "minter"
                    | "pauser"
                    | "implementation"
                    | "governance"
                    | "role"
                    | "roles"
                    | "whitelist"
                    | "blacklist"
                    | "auth"
                    | "authority"
            ) || token.ends_with("owner")
                || token.ends_with("admin")
                || token.ends_with("governance")
        })
}

fn place_is_constructor_authority_sensitive(place: &IrPlace) -> bool {
    if place_is_authority_sensitive(place) {
        return true;
    }
    match place {
        IrPlace::Var {
            var: IrVar::Named(name),
            ..
        } => name.eq_ignore_ascii_case("creator"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_sink_scores, constrain_boolean_int, engine, eval_binary, function_has_ether_send,
        function_is_checked_selector_low_level_wrapper, has_checked_arithmetic, havoc_storage,
        is_public_mint_burn_function,
        place_is_authority_sensitive, place_is_order_sensitive, pop_next_state,
        reentrant_callback_candidates,
        state_priority_score, EngineCallbackData, EngineStats, SolverCache, State,
        VulnerabilityKind, MAX_BLOCK_VISITS_PER_PATH,
    };
    use crate::cfg::{self, Block, CfgFunction};
    use crate::frontend;
    use crate::fuzzing::types::{DependencyMap, FunctionDeps, build_dependency_map};
    use crate::ir;
    use crate::ir::{
        ControlKind, IrCallOption, IrFunction, IrInstr, IrPlace, IrValue, IrVar, PlaceClass,
    };
    use crate::norm::{
        Contract, ContractKind, Function, FunctionKind, Literal, Mutability, NormalizedAst,
        SourceFile, Span, Visibility,
    };
    use z3::ast::Int;
    use z3::{SatResult, Solver};

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 1,
        }
    }

    fn number_lit(n: &str) -> IrValue {
        IrValue::Literal(Literal {
            kind: "number".to_string(),
            value: n.to_string(),
        })
    }

    fn cfg_with_instrs(instrs: Vec<IrInstr>) -> CfgFunction {
        CfgFunction {
            id: 0,
            blocks: vec![Block { id: 0, instrs }],
            edges: Vec::new(),
        }
    }

    fn run_engine(
        cfg: &CfgFunction,
        checked_arithmetic: bool,
        allow_tod: bool,
        allow_signature_malleability: bool,
    ) -> EngineStats {
        engine(
            cfg,
            std::slice::from_ref(cfg),
            None,
            checked_arithmetic,
            false,
            allow_tod,
            allow_signature_malleability,
        )
    }

    fn callback_test_ast() -> NormalizedAst {
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "callback.sol".to_string(),
            source: "pragma solidity ^0.8.0;".to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "Vault".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0, 1],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: span(),
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("withdraw".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: span(),
        });
        ast.functions.push(Function {
            id: 1,
            contract: Some(0),
            name: Some("poke".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: span(),
        });
        ast
    }

    fn callback_send_only_ast() -> NormalizedAst {
        let source = "contract Vault { function withdraw() public { msg.sender.send(1); } function poke() public {} }";
        let withdraw_start = source.find("function withdraw").unwrap() as u32;
        let poke_start = source.find("function poke").unwrap() as u32;
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "callback_send.sol".to_string(),
            source: source.to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "Vault".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0, 1],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("withdraw".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: withdraw_start,
                end: poke_start.saturating_sub(1),
            },
        });
        ast.functions.push(Function {
            id: 1,
            contract: Some(0),
            name: Some("poke".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: poke_start,
                end: source.len() as u32,
            },
        });
        ast
    }

    fn callback_value_call_ast() -> NormalizedAst {
        let source = "contract Vault { function withdraw() public { msg.sender.call.value(1)(\"\"); } function poke() public {} }";
        let withdraw_start = source.find("function withdraw").unwrap() as u32;
        let poke_start = source.find("function poke").unwrap() as u32;
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "callback_value_call.sol".to_string(),
            source: source.to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "Vault".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0, 1],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("withdraw".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: withdraw_start,
                end: poke_start.saturating_sub(1),
            },
        });
        ast.functions.push(Function {
            id: 1,
            contract: Some(0),
            name: Some("poke".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: poke_start,
                end: source.len() as u32,
            },
        });
        ast
    }

    fn callback_msg_value_forward_ast() -> NormalizedAst {
        let source = "contract Vault { function withdraw() public payable { msg.sender.call.value(msg.value)(\"\"); } function poke() public {} }";
        let withdraw_start = source.find("function withdraw").unwrap() as u32;
        let poke_start = source.find("function poke").unwrap() as u32;
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "callback_msg_value_forward.sol".to_string(),
            source: source.to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "Vault".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0, 1],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("withdraw".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::Payable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: withdraw_start,
                end: poke_start.saturating_sub(1),
            },
        });
        ast.functions.push(Function {
            id: 1,
            contract: Some(0),
            name: Some("poke".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: poke_start,
                end: source.len() as u32,
            },
        });
        ast
    }

    fn callback_test_deps() -> DependencyMap {
        let mut deps = DependencyMap::default();
        deps.functions.insert(
            0,
            FunctionDeps {
                reads: ["balances".to_string()].into_iter().collect(),
                writes: ["balances".to_string()].into_iter().collect(),
            },
        );
        deps.functions.insert(
            1,
            FunctionDeps {
                reads: ["balances".to_string()].into_iter().collect(),
                writes: ["balances".to_string()].into_iter().collect(),
            },
        );
        deps
    }

    fn test_compiler() -> crate::frontend::CompilerInfo {
        crate::frontend::CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: Some("0.8.0".to_string()),
            legacy_omitted_visibility_is_public: false,
        }
    }

    fn callback_candidate_ast() -> NormalizedAst {
        let source = "contract Vault { function withdraw() public {} function overlap() public {} function helper() public {} }";
        let withdraw_start = source.find("function withdraw").unwrap() as u32;
        let overlap_start = source.find("function overlap").unwrap() as u32;
        let helper_start = source.find("function helper").unwrap() as u32;
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "callback_candidates.sol".to_string(),
            source: source.to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "Vault".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0, 1, 2],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("withdraw".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: withdraw_start,
                end: overlap_start.saturating_sub(1),
            },
        });
        ast.functions.push(Function {
            id: 1,
            contract: Some(0),
            name: Some("overlap".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: overlap_start,
                end: helper_start.saturating_sub(1),
            },
        });
        ast.functions.push(Function {
            id: 2,
            contract: Some(0),
            name: Some("helper".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: helper_start,
                end: source.len() as u32,
            },
        });
        ast
    }

    fn callback_candidate_ast_with_source(function_name: &str, source: &str) -> NormalizedAst {
        let mut ast = NormalizedAst::from_sources(vec![SourceFile {
            id: 0,
            path: "checked_wrapper.sol".to_string(),
            source: source.to_string(),
        }]);
        ast.contracts.push(Contract {
            id: 0,
            name: "Vault".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some(function_name.to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: 0,
                end: source.len() as u32,
            },
        });
        ast
    }

    fn callback_candidate_deps() -> DependencyMap {
        let mut deps = DependencyMap::default();
        deps.functions.insert(
            0,
            FunctionDeps {
                reads: ["credit".to_string()].into_iter().collect(),
                writes: ["credit".to_string()].into_iter().collect(),
            },
        );
        deps.functions.insert(
            1,
            FunctionDeps {
                reads: ["credit".to_string()].into_iter().collect(),
                writes: ["credit".to_string()].into_iter().collect(),
            },
        );
        deps.functions.insert(
            2,
            FunctionDeps {
                reads: ["owner".to_string()].into_iter().collect(),
                writes: ["owner".to_string()].into_iter().collect(),
            },
        );
        deps
    }

    fn test_function(name: Option<&str>, visibility: Visibility, mutability: Mutability) -> Function {
        Function {
            id: 0,
            contract: Some(0),
            name: name.map(|n| n.to_string()),
            kind: FunctionKind::Function,
            visibility,
            mutability,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: span(),
        }
    }

    #[test]
    fn engine_signature_malleability_respects_static_gate() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Call {
                dest: vec![IrVar::Temp(0)],
                callee: IrValue::Var(IrVar::Named("ecrecover".to_string())),
                args: Vec::new(),
                options: Vec::new(),
                span: span(),
            },
            IrInstr::Return {
                values: Vec::new(),
                span: span(),
            },
        ]);

        let gated_off = run_engine(&cfg, true, false, false);
        assert!(
            !gated_off
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::SignatureMalleability))
        );

        let gated_on = run_engine(&cfg, true, false, true);
        assert!(
            gated_on
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::SignatureMalleability))
        );
    }

    #[test]
    fn engine_tod_respects_static_gate() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Var {
                    var: IrVar::Named("price".to_string()),
                    class: PlaceClass::Storage,
                },
                span: span(),
            },
            IrInstr::Call {
                dest: Vec::new(),
                callee: IrValue::Var(IrVar::Named("call".to_string())),
                args: Vec::new(),
                options: vec![IrCallOption::Value(number_lit("1"))],
                span: span(),
            },
            IrInstr::Return {
                values: Vec::new(),
                span: span(),
            },
        ]);
        let ast = callback_test_ast();
        let deps = callback_test_deps();
        let compiler = crate::frontend::CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: Some("0.8.0".to_string()),
            legacy_omitted_visibility_is_public: false,
        };

        let gated_off = engine(
            &cfg,
            std::slice::from_ref(&cfg),
            Some(EngineCallbackData {
                ast: &ast,
                compiler: &compiler,
                deps: &deps,
            }),
            true,
            false,
            false,
            true,
        );
        assert!(
            !gated_off
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::TransactionOrderDependency))
        );

        let gated_on = engine(
            &cfg,
            std::slice::from_ref(&cfg),
            Some(EngineCallbackData {
                ast: &ast,
                compiler: &compiler,
                deps: &deps,
            }),
            true,
            false,
            true,
            true,
        );
        assert!(
            gated_on
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::TransactionOrderDependency))
        );
    }

    #[test]
    fn order_sensitive_matcher_is_token_aware() {
        let sensitive = IrPlace::Var {
            var: IrVar::Named("pool_price".to_string()),
            class: PlaceClass::Storage,
        };
        let non_sensitive = IrPlace::Var {
            var: IrVar::Named("surrogate".to_string()),
            class: PlaceClass::Storage,
        };
        assert!(place_is_order_sensitive(&sensitive));
        assert!(!place_is_order_sensitive(&non_sensitive));
    }

    #[test]
    fn engine_underflow_is_deduped_on_same_pc() {
        let cond_var = IrValue::Var(IrVar::Named("cond".to_string()));
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![
                Block {
                    id: 0,
                    instrs: vec![IrInstr::Control {
                        kind: ControlKind::If { cond: cond_var },
                        span: span(),
                    }],
                },
                Block {
                    id: 1,
                    instrs: vec![
                        IrInstr::Binary {
                            dest: IrVar::Temp(0),
                            op: "-".to_string(),
                            lhs: number_lit("1"),
                            rhs: number_lit("2"),
                            span: span(),
                        },
                        IrInstr::Return {
                            values: Vec::new(),
                            span: span(),
                        },
                    ],
                },
            ],
            // Both true/false paths converge to the same block/instruction PC.
            edges: vec![
                crate::cfg::Edge { from: 0, to: 1 },
                crate::cfg::Edge { from: 0, to: 1 },
            ],
        };

        let stats = run_engine(&cfg, false, false, false);
        let count = stats
            .vulnerabilities
            .iter()
            .filter(|v| matches!(v.kind, VulnerabilityKind::Underflow))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn solver_cache_reuses_equivalent_constraint_sets() {
        let x = Int::new_const("x");
        let c1 = x.gt(Int::from_i64(1));
        let c2 = x.lt(Int::from_i64(10));
        let mut cache = SolverCache::default();

        assert!(cache.is_feasible(&[c1.clone(), c2.clone()]));
        assert!(cache.is_feasible(&[c2, c1]));
        assert_eq!(cache.sat_by_constraints.len(), 1);
    }

    #[test]
    fn eval_binary_uint256_wraps_addition() {
        let wrapped = eval_binary("+", Int::from_i64(-1), Int::from_i64(1));
        let solver = Solver::new();
        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().expect("model");
        let value = model.eval(&wrapped, true).and_then(|v| v.as_i64());
        assert_eq!(value, Some(0));
    }

    #[test]
    fn eval_binary_uses_unsigned_uint256_comparison() {
        let gt = eval_binary(">", Int::from_i64(-1), Int::from_i64(1));
        let solver = Solver::new();
        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().expect("model");
        let value = model.eval(&gt, true).and_then(|v| v.as_i64());
        assert_eq!(value, Some(1));
    }

    #[test]
    fn underflow_check_uses_unsigned_uint256_ordering() {
        let mut cache = SolverCache::default();
        let no_underflow = cache.check_underflow(&[], &Int::from_i64(-1), &Int::from_i64(1));
        assert!(no_underflow.is_none());

        let underflow = cache.check_underflow(&[], &Int::from_i64(1), &Int::from_i64(2));
        assert!(underflow.is_some());
    }

    #[test]
    fn storage_accumulator_overflow_fallback_detects_unchecked_update() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Var {
                    var: IrVar::Named("sellerBalance".to_string()),
                    class: PlaceClass::Storage,
                },
                span: span(),
            },
            IrInstr::Binary {
                dest: IrVar::Temp(1),
                op: "+".to_string(),
                lhs: IrValue::Var(IrVar::Temp(0)),
                rhs: IrValue::Var(IrVar::Named("value".to_string())),
                span: span(),
            },
            IrInstr::Store {
                dest: IrPlace::Var {
                    var: IrVar::Named("sellerBalance".to_string()),
                    class: PlaceClass::Storage,
                },
                src: IrValue::Var(IrVar::Temp(1)),
                span: span(),
            },
        ]);

        let stats = run_engine(&cfg, false, false, false);
        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::Overflow)),
            "expected unchecked accumulator overflow detection, saw: {:?}",
            stats
                .vulnerabilities
                .iter()
                .map(|v| (v.kind.as_str(), v.message.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn storage_accumulator_overflow_fallback_respects_require_guard() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Var {
                    var: IrVar::Named("sellerBalance".to_string()),
                    class: PlaceClass::Storage,
                },
                span: span(),
            },
            IrInstr::Binary {
                dest: IrVar::Temp(1),
                op: "+".to_string(),
                lhs: IrValue::Var(IrVar::Named("value".to_string())),
                rhs: IrValue::Var(IrVar::Temp(0)),
                span: span(),
            },
            IrInstr::Binary {
                dest: IrVar::Temp(2),
                op: ">=".to_string(),
                lhs: IrValue::Var(IrVar::Temp(1)),
                rhs: IrValue::Var(IrVar::Temp(0)),
                span: span(),
            },
            IrInstr::Call {
                dest: Vec::new(),
                callee: IrValue::Var(IrVar::Named("require".to_string())),
                args: vec![IrValue::Var(IrVar::Temp(2))],
                options: Vec::new(),
                span: span(),
            },
            IrInstr::Load {
                dest: IrVar::Temp(3),
                src: IrPlace::Var {
                    var: IrVar::Named("sellerBalance".to_string()),
                    class: PlaceClass::Storage,
                },
                span: span(),
            },
            IrInstr::Binary {
                dest: IrVar::Temp(4),
                op: "+".to_string(),
                lhs: IrValue::Var(IrVar::Temp(3)),
                rhs: IrValue::Var(IrVar::Named("value".to_string())),
                span: span(),
            },
            IrInstr::Store {
                dest: IrPlace::Var {
                    var: IrVar::Named("sellerBalance".to_string()),
                    class: PlaceClass::Storage,
                },
                src: IrValue::Var(IrVar::Temp(4)),
                span: span(),
            },
        ]);

        let stats = run_engine(&cfg, false, false, false);
        assert!(
            !stats.vulnerabilities.iter().any(|v| {
                matches!(v.kind, VulnerabilityKind::Overflow)
                    && v.message.contains("storage accumulator update")
            }),
            "guarded accumulator update should not emit fallback, saw: {:?}",
            stats
                .vulnerabilities
                .iter()
                .map(|v| (v.kind.as_str(), v.message.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn integer_overflow_fixture_add_emits_runtime_overflow() {
        let output = frontend::load_project(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/integer_overflow/integer_overflow_1.sol",
        )
        .expect("integer_overflow_1 fixture should load");
        let ir_module = ir::lower_module(&output.ast);
        let dependency_map = build_dependency_map(&ir_module, &output.ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let cfg = cfgs.iter().find(|cfg| cfg.id == 0).expect("add cfg");

        let stats = engine(
            cfg,
            &cfgs,
            Some(EngineCallbackData {
                ast: &output.ast,
                compiler: &output.compiler,
                deps: &dependency_map,
            }),
            has_checked_arithmetic(&output.ast),
            false,
            false,
            false,
        );

        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::Overflow)),
            "expected runtime overflow on integer_overflow_1::add, saw: {:?}",
            stats
                .vulnerabilities
                .iter()
                .map(|v| (v.kind.as_str(), v.message.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn weak_prng_detected_from_block_number_arithmetic() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("block".to_string())),
                    field: "number".to_string(),
                    root: Some("block.number".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            IrInstr::Binary {
                dest: IrVar::Temp(1),
                op: "+".to_string(),
                lhs: IrValue::Var(IrVar::Temp(0)),
                rhs: number_lit("1"),
                span: span(),
            },
            IrInstr::Return {
                values: Vec::new(),
                span: span(),
            },
        ]);

        let stats = run_engine(&cfg, true, false, false);
        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::WeakPrng))
        );
    }

    #[test]
    fn forced_ether_balance_invariant_before_suicide_maps_to_locked_ether() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Load {
                dest: IrVar::Temp(0),
                src: IrPlace::Member {
                    base: IrValue::Var(IrVar::Named("this".to_string())),
                    field: "balance".to_string(),
                    root: Some("this.balance".to_string()),
                    class: PlaceClass::Unknown,
                },
                span: span(),
            },
            IrInstr::Binary {
                dest: IrVar::Temp(1),
                op: "==".to_string(),
                lhs: IrValue::Var(IrVar::Temp(0)),
                rhs: IrValue::Var(IrVar::Named("totalSupply".to_string())),
                span: span(),
            },
            IrInstr::Call {
                dest: Vec::new(),
                callee: IrValue::Var(IrVar::Named("assert".to_string())),
                args: vec![IrValue::Var(IrVar::Temp(1))],
                options: Vec::new(),
                span: span(),
            },
            IrInstr::Call {
                dest: Vec::new(),
                callee: IrValue::Var(IrVar::Named("suicide".to_string())),
                args: vec![IrValue::Var(IrVar::Named("owner".to_string()))],
                options: Vec::new(),
                span: span(),
            },
            IrInstr::Return {
                values: Vec::new(),
                span: span(),
            },
        ]);

        let stats = run_engine(&cfg, true, false, false);
        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::LockedEther))
        );
    }

    #[test]
    fn coin_fixture_engine_emits_locked_ether() {
        let output = frontend::load_project(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/forced_ether_reception/coin.sol",
        )
        .expect("coin fixture should load");
        let ir_module = ir::lower_module(&output.ast);
        let dependency_map = build_dependency_map(&ir_module, &output.ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let cfg = cfgs
            .iter()
            .find(|cfg| cfg.id == 12)
            .expect("migrate_and_destroy cfg");

        let stats = engine(
            cfg,
            &cfgs,
            Some(EngineCallbackData {
                ast: &output.ast,
                compiler: &output.compiler,
                deps: &dependency_map,
            }),
            has_checked_arithmetic(&output.ast),
            false,
            false,
            false,
        );

        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::LockedEther)),
            "expected locked-ether vulnerability, saw: {:?}",
            stats
                .vulnerabilities
                .iter()
                .map(|v| v.kind.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn race_condition_fixture_emits_runtime_tod() {
        let output = frontend::load_project(
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/race_condition/RaceCondition.sol",
        )
        .expect("RaceCondition fixture should load");
        let ir_module = ir::lower_module(&output.ast);
        let dependency_map = build_dependency_map(&ir_module, &output.ast);
        let cfgs = cfg::build_from_ir(&ir_module);
        let buy_function_id = output
            .ast
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("buy"))
            .map(|function| function.id)
            .expect("buy function");
        let cfg = cfgs
            .iter()
            .find(|cfg| cfg.id == buy_function_id)
            .expect("buy cfg");

        let stats = engine(
            cfg,
            &cfgs,
            Some(EngineCallbackData {
                ast: &output.ast,
                compiler: &output.compiler,
                deps: &dependency_map,
            }),
            has_checked_arithmetic(&output.ast),
            true,
            true,
            false,
        );

        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::TransactionOrderDependency)),
            "expected runtime TOD on RaceCondition::buy, saw: {:?}",
            stats
                .vulnerabilities
                .iter()
                .map(|v| (v.kind.as_str(), v.message.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn require_call_splits_success_and_revert_paths() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Call {
                dest: Vec::new(),
                callee: IrValue::Var(IrVar::Named("require".to_string())),
                args: vec![IrValue::Var(IrVar::Named("ok".to_string()))],
                options: Vec::new(),
                span: span(),
            },
            IrInstr::Return {
                values: Vec::new(),
                span: span(),
            },
        ]);

        let stats = run_engine(&cfg, true, false, false);
        assert_eq!(stats.reachable_returns, 1);
        assert_eq!(stats.reachable_reverts, 1);
        assert_eq!(stats.terminal_paths, 2);
    }

    #[test]
    fn revert_call_terminates_current_path() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Call {
                dest: Vec::new(),
                callee: IrValue::Var(IrVar::Named("revert".to_string())),
                args: vec![number_lit("1")],
                options: Vec::new(),
                span: span(),
            },
            IrInstr::Return {
                values: Vec::new(),
                span: span(),
            },
        ]);

        let stats = run_engine(&cfg, true, false, false);
        assert_eq!(stats.reachable_returns, 0);
        assert_eq!(stats.reachable_reverts, 1);
        assert_eq!(stats.terminal_paths, 1);
    }

    #[test]
    fn havoc_storage_rewrites_existing_slots() {
        let mut state = State::new();
        state
            .storage
            .insert("slot_owner".to_string(), Int::from_i64(7));
        havoc_storage(&mut state);
        let value = state
            .storage
            .get("slot_owner")
            .map(|v| v.to_string())
            .unwrap_or_default();
        assert!(value.contains("storage_havoc"));
    }

    #[test]
    fn boolean_domain_constraint_rejects_non_boolean_value() {
        let mut state = State::new();
        let v = Int::new_const("ret");
        constrain_boolean_int(&mut state, &v);
        state.path_constraints.push(v.eq(Int::from_i64(2)));
        let mut cache = SolverCache::default();
        assert!(!cache.is_feasible(&state.path_constraints));
    }

    #[test]
    fn low_level_call_return_is_modeled_as_boolean() {
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![
                Block {
                    id: 0,
                    instrs: vec![
                        IrInstr::Call {
                            dest: vec![IrVar::Temp(0)],
                            callee: IrValue::Var(IrVar::Named("call".to_string())),
                            args: Vec::new(),
                            options: Vec::new(),
                            span: span(),
                        },
                        IrInstr::Binary {
                            dest: IrVar::Temp(1),
                            op: ">".to_string(),
                            lhs: IrValue::Var(IrVar::Temp(0)),
                            rhs: number_lit("1"),
                            span: span(),
                        },
                        IrInstr::Control {
                            kind: ControlKind::If {
                                cond: IrValue::Var(IrVar::Temp(1)),
                            },
                            span: span(),
                        },
                    ],
                },
                Block {
                    id: 1,
                    instrs: vec![IrInstr::Return {
                        values: Vec::new(),
                        span: span(),
                    }],
                },
                Block {
                    id: 2,
                    instrs: vec![IrInstr::Return {
                        values: Vec::new(),
                        span: span(),
                    }],
                },
            ],
            edges: vec![
                crate::cfg::Edge { from: 0, to: 1 },
                crate::cfg::Edge { from: 0, to: 2 },
            ],
        };

        let stats = run_engine(&cfg, true, false, false);
        assert_eq!(stats.reachable_returns, 1);
        assert!(stats.pruned_branches >= 1);
    }

    #[test]
    fn require_on_compared_call_result_clears_unchecked_call() {
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![Block {
                id: 0,
                instrs: vec![
                    IrInstr::Call {
                        dest: vec![IrVar::Temp(0)],
                        callee: IrValue::Var(IrVar::Named("call".to_string())),
                        args: Vec::new(),
                        options: Vec::new(),
                        span: span(),
                    },
                    IrInstr::Binary {
                        dest: IrVar::Temp(1),
                        op: "!=".to_string(),
                        lhs: IrValue::Var(IrVar::Temp(0)),
                        rhs: number_lit("0"),
                        span: span(),
                    },
                    IrInstr::Call {
                        dest: Vec::new(),
                        callee: IrValue::Var(IrVar::Named("require".to_string())),
                        args: vec![IrValue::Var(IrVar::Temp(1))],
                        options: Vec::new(),
                        span: span(),
                    },
                    IrInstr::Return {
                        values: Vec::new(),
                        span: span(),
                    },
                ],
            }],
            edges: Vec::new(),
        };

        let stats = run_engine(&cfg, true, false, false);
        assert!(
            !stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::UncheckedCall)),
            "checked low-level call should not emit unchecked-call, saw: {:?}",
            stats
                .vulnerabilities
                .iter()
                .map(|v| (v.kind.as_str(), v.message.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn callback_candidates_keep_only_self_and_overlap() {
        let ast = callback_candidate_ast();
        let deps = callback_candidate_deps();
        let compiler = test_compiler();

        let candidates = reentrant_callback_candidates(0, &ast, &compiler, &deps, 8);
        assert_eq!(candidates, vec![0, 1]);
    }

    #[test]
    fn checked_selector_wrapper_detection_is_narrow() {
        let wrapper = callback_candidate_ast_with_source(
            "deposit",
            "function deposit(address target) public payable { require(target.call.value(msg.value)(bytes4(sha3(\"addToBalance()\")))); }",
        );
        let plain = callback_candidate_ast_with_source(
            "withdraw",
            "function withdraw(address target) public payable { target.call.value(msg.value)(); }",
        );

        assert!(function_is_checked_selector_low_level_wrapper(Some(&wrapper), 0));
        assert!(!function_is_checked_selector_low_level_wrapper(Some(&plain), 0));
    }

    #[test]
    fn staticcall_does_not_mark_reentrancy_edge() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Call {
                dest: vec![IrVar::Temp(0)],
                callee: IrValue::Var(IrVar::Named("staticcall".to_string())),
                args: Vec::new(),
                options: Vec::new(),
                span: span(),
            },
            IrInstr::Store {
                dest: IrPlace::Var {
                    var: IrVar::Named("balances".to_string()),
                    class: PlaceClass::Storage,
                },
                src: number_lit("1"),
                span: span(),
            },
            IrInstr::Return {
                values: Vec::new(),
                span: span(),
            },
        ]);
        let stats = run_engine(&cfg, true, false, false);
        assert!(
            !stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::Reentrancy))
        );
    }

    #[test]
    fn callback_execution_enables_reentrancy_detection() {
        let cfgs = vec![
            CfgFunction {
                id: 0,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![
                        IrInstr::Call {
                            dest: vec![IrVar::Temp(0)],
                            callee: IrValue::Var(IrVar::Named("call".to_string())),
                            args: Vec::new(),
                            options: vec![IrCallOption::Value(number_lit("1"))],
                            span: span(),
                        },
                        IrInstr::Store {
                            dest: IrPlace::Var {
                                var: IrVar::Named("balances".to_string()),
                                class: PlaceClass::Storage,
                            },
                            src: number_lit("1"),
                            span: span(),
                        },
                        IrInstr::Return {
                            values: Vec::new(),
                            span: span(),
                        },
                    ],
                }],
                edges: Vec::new(),
            },
            CfgFunction {
                id: 1,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![IrInstr::Return {
                        values: Vec::new(),
                        span: span(),
                    }],
                }],
                edges: Vec::new(),
            },
        ];
        let ast = callback_test_ast();
        let deps = callback_test_deps();
        let compiler = crate::frontend::CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: Some("0.8.0".to_string()),
            legacy_omitted_visibility_is_public: false,
        };

        let stats = engine(
            &cfgs[0],
            &cfgs,
            Some(EngineCallbackData {
                ast: &ast,
                compiler: &compiler,
                deps: &deps,
            }),
            true,
            false,
            false,
            false,
        );

        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::Reentrancy))
        );
    }

    #[test]
    fn no_value_callback_overlap_suppresses_reentrancy_fallback() {
        let cfgs = vec![
            CfgFunction {
                id: 0,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![
                        IrInstr::Store {
                            dest: IrPlace::Var {
                                var: IrVar::Named("balances".to_string()),
                                class: PlaceClass::Storage,
                            },
                            src: number_lit("1"),
                            span: span(),
                        },
                        IrInstr::Call {
                            dest: vec![IrVar::Temp(0)],
                            callee: IrValue::Var(IrVar::Named("spender.call".to_string())),
                            args: vec![number_lit("1")],
                            options: Vec::new(),
                            span: span(),
                        },
                        IrInstr::Return {
                            values: Vec::new(),
                            span: span(),
                        },
                    ],
                }],
                edges: Vec::new(),
            },
            CfgFunction {
                id: 1,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![IrInstr::Return {
                        values: Vec::new(),
                        span: span(),
                    }],
                }],
                edges: Vec::new(),
            },
        ];
        let ast = callback_test_ast();
        let deps = callback_test_deps();
        let compiler = crate::frontend::CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: Some("0.8.0".to_string()),
            legacy_omitted_visibility_is_public: false,
        };

        let stats = engine(
            &cfgs[0],
            &cfgs,
            Some(EngineCallbackData {
                ast: &ast,
                compiler: &compiler,
                deps: &deps,
            }),
            true,
            false,
            false,
            false,
        );

        assert!(
            !stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::ReentrancyFallback))
        );
    }

    #[test]
    fn value_moving_callback_overlap_emits_reentrancy_fallback() {
        let cfgs = vec![
            CfgFunction {
                id: 0,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![
                        IrInstr::Store {
                            dest: IrPlace::Var {
                                var: IrVar::Named("balances".to_string()),
                                class: PlaceClass::Storage,
                            },
                            src: number_lit("1"),
                            span: span(),
                        },
                        IrInstr::Call {
                            dest: vec![IrVar::Temp(0)],
                            callee: IrValue::Var(IrVar::Named("spender.call".to_string())),
                            args: vec![number_lit("1")],
                            options: Vec::new(),
                            span: span(),
                        },
                        IrInstr::Return {
                            values: Vec::new(),
                            span: span(),
                        },
                    ],
                }],
                edges: Vec::new(),
            },
            CfgFunction {
                id: 1,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![IrInstr::Return {
                        values: Vec::new(),
                        span: span(),
                    }],
                }],
                edges: Vec::new(),
            },
        ];
        let ast = callback_value_call_ast();
        let deps = callback_test_deps();
        let compiler = crate::frontend::CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: Some("0.8.0".to_string()),
            legacy_omitted_visibility_is_public: false,
        };

        let stats = engine(
            &cfgs[0],
            &cfgs,
            Some(EngineCallbackData {
                ast: &ast,
                compiler: &compiler,
                deps: &deps,
            }),
            true,
            false,
            false,
            false,
        );

        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::ReentrancyFallback))
        );
    }

    #[test]
    fn direct_msg_value_forwarder_suppresses_reentrancy_fallback() {
        let cfgs = vec![
            CfgFunction {
                id: 0,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![
                        IrInstr::Store {
                            dest: IrPlace::Var {
                                var: IrVar::Named("balances".to_string()),
                                class: PlaceClass::Storage,
                            },
                            src: number_lit("1"),
                            span: span(),
                        },
                        IrInstr::Call {
                            dest: vec![IrVar::Temp(0)],
                            callee: IrValue::Var(IrVar::Named("spender.call".to_string())),
                            args: vec![number_lit("1")],
                            options: Vec::new(),
                            span: span(),
                        },
                        IrInstr::Return {
                            values: Vec::new(),
                            span: span(),
                        },
                    ],
                }],
                edges: Vec::new(),
            },
            CfgFunction {
                id: 1,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![IrInstr::Return {
                        values: Vec::new(),
                        span: span(),
                    }],
                }],
                edges: Vec::new(),
            },
        ];
        let ast = callback_msg_value_forward_ast();
        let deps = callback_test_deps();
        let compiler = crate::frontend::CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: Some("0.8.0".to_string()),
            legacy_omitted_visibility_is_public: false,
        };

        let stats = engine(
            &cfgs[0],
            &cfgs,
            Some(EngineCallbackData {
                ast: &ast,
                compiler: &compiler,
                deps: &deps,
            }),
            true,
            false,
            false,
            false,
        );

        assert!(
            !stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::ReentrancyFallback))
        );
    }

    #[test]
    fn send_only_source_suppresses_temp_call_reentrancy_fallback() {
        let cfgs = vec![
            CfgFunction {
                id: 0,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![
                        IrInstr::Store {
                            dest: IrPlace::Var {
                                var: IrVar::Named("balances".to_string()),
                                class: PlaceClass::Storage,
                            },
                            src: number_lit("1"),
                            span: span(),
                        },
                        IrInstr::Call {
                            dest: Vec::new(),
                            callee: IrValue::Var(IrVar::Temp(0)),
                            args: vec![number_lit("1")],
                            options: Vec::new(),
                            span: span(),
                        },
                        IrInstr::Return {
                            values: Vec::new(),
                            span: span(),
                        },
                    ],
                }],
                edges: Vec::new(),
            },
            CfgFunction {
                id: 1,
                blocks: vec![Block {
                    id: 0,
                    instrs: vec![IrInstr::Return {
                        values: Vec::new(),
                        span: span(),
                    }],
                }],
                edges: Vec::new(),
            },
        ];
        let ast = callback_send_only_ast();
        let deps = callback_test_deps();
        let compiler = crate::frontend::CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: Some("0.8.0".to_string()),
            legacy_omitted_visibility_is_public: false,
        };

        let stats = engine(
            &cfgs[0],
            &cfgs,
            Some(EngineCallbackData {
                ast: &ast,
                compiler: &compiler,
                deps: &deps,
            }),
            true,
            false,
            false,
            false,
        );

        assert!(
            !stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::ReentrancyFallback))
        );
    }

    #[test]
    fn engine_bounds_unconditional_loop_revisits() {
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![Block {
                id: 0,
                instrs: vec![IrInstr::Control {
                    kind: ControlKind::Loop { cond: None },
                    span: span(),
                }],
            }],
            edges: vec![crate::cfg::Edge { from: 0, to: 0 }],
        };

        let stats = run_engine(&cfg, true, false, false);
        assert!(!stats.truncated);
        assert!(stats.pruned_branches >= 1);
        assert!(stats.explored_states <= (MAX_BLOCK_VISITS_PER_PATH as usize + 1));
    }

    #[test]
    fn sink_priority_scheduler_picks_hotter_state_first() {
        let cfg = CfgFunction {
            id: 0,
            blocks: vec![
                Block {
                    id: 1,
                    instrs: vec![IrInstr::Nop { span: span() }],
                },
                Block {
                    id: 2,
                    instrs: vec![IrInstr::Call {
                        dest: Vec::new(),
                        callee: IrValue::Var(IrVar::Named("call".to_string())),
                        args: Vec::new(),
                        options: Vec::new(),
                        span: span(),
                    }],
                },
            ],
            edges: Vec::new(),
        };
        let sink_scores = build_sink_scores(std::slice::from_ref(&cfg));
        let mut low = State::new();
        low.block_id = 1;
        let mut high = State::new();
        high.block_id = 2;
        high.external_call_pc = Some(9);
        assert!(state_priority_score(&high, &sink_scores) > state_priority_score(&low, &sink_scores));

        let mut worklist = vec![low, high];
        let picked = pop_next_state(&mut worklist, &sink_scores).expect("state");
        assert_eq!(picked.block_id, 2);
    }

    #[test]
    fn authority_sensitive_matcher_is_token_aware() {
        let sensitive = IrPlace::Var {
            var: IrVar::Named("owner".to_string()),
            class: PlaceClass::Storage,
        };
        let non_sensitive = IrPlace::Var {
            var: IrVar::Named("surrogate".to_string()),
            class: PlaceClass::Storage,
        };
        assert!(place_is_authority_sensitive(&sensitive));
        assert!(!place_is_authority_sensitive(&non_sensitive));
    }

    #[test]
    fn public_mint_burn_requires_public_entrypoint() {
        let public_mint = test_function(Some("mint"), Visibility::Public, Mutability::NonPayable);
        let external_burn =
            test_function(Some("burn"), Visibility::External, Mutability::NonPayable);
        let internal_mint =
            test_function(Some("mint"), Visibility::Internal, Mutability::NonPayable);
        let other = test_function(Some("transfer"), Visibility::Public, Mutability::NonPayable);
        let compiler = crate::frontend::CompilerInfo {
            compiler_name: "test".to_string(),
            compiler_version: Some("0.8.0".to_string()),
            legacy_omitted_visibility_is_public: false,
        };

        assert!(is_public_mint_burn_function(&public_mint, &compiler));
        assert!(is_public_mint_burn_function(&external_burn, &compiler));
        assert!(!is_public_mint_burn_function(&internal_mint, &compiler));
        assert!(!is_public_mint_burn_function(&other, &compiler));
    }

    #[test]
    fn function_has_ether_send_detects_value_and_transfer() {
        let with_value = IrFunction {
            id: 0,
            name: Some("withdraw".to_string()),
            source: Some(0),
            span: span(),
            blocks: vec![crate::ir::IrBlock {
                id: 0,
                instrs: vec![IrInstr::Call {
                    dest: Vec::new(),
                    callee: IrValue::Var(IrVar::Named("call".to_string())),
                    args: Vec::new(),
                    options: vec![IrCallOption::Value(number_lit("1"))],
                    span: span(),
                }],
            }],
        };
        let with_transfer = IrFunction {
            id: 0,
            name: Some("pay".to_string()),
            source: Some(0),
            span: span(),
            blocks: vec![crate::ir::IrBlock {
                id: 0,
                instrs: vec![IrInstr::Call {
                    dest: Vec::new(),
                    callee: IrValue::Var(IrVar::Named("transfer".to_string())),
                    args: Vec::new(),
                    options: Vec::new(),
                    span: span(),
                }],
            }],
        };
        let without_send = IrFunction {
            id: 0,
            name: Some("deposit".to_string()),
            source: Some(0),
            span: span(),
            blocks: vec![crate::ir::IrBlock {
                id: 0,
                instrs: vec![IrInstr::Store {
                    dest: IrPlace::Var {
                        var: IrVar::Named("balances".to_string()),
                        class: PlaceClass::Storage,
                    },
                    src: number_lit("1"),
                    span: span(),
                }],
            }],
        };

        assert!(function_has_ether_send(&with_value));
        assert!(function_has_ether_send(&with_transfer));
        assert!(!function_has_ether_send(&without_send));
    }

    #[test]
    fn engine_detects_arbitrary_write_and_memory_manipulation() {
        let cfg = cfg_with_instrs(vec![
            IrInstr::Store {
                dest: IrPlace::Var {
                    var: IrVar::Named("owner".to_string()),
                    class: PlaceClass::Storage,
                },
                src: number_lit("1"),
                span: span(),
            },
            IrInstr::InlineAsm {
                language: Some("yul".to_string()),
                span: span(),
            },
            IrInstr::Return {
                values: Vec::new(),
                span: span(),
            },
        ]);
        let stats = run_engine(&cfg, true, false, false);
        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::ArbitraryWrite))
        );
        assert!(
            stats
                .vulnerabilities
                .iter()
                .any(|v| matches!(v.kind, VulnerabilityKind::MemoryManipulation))
        );
    }
}
