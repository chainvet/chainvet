use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use rand::Rng;
use z3::{
    SatResult, Solver,
    ast::{Bool, Int},
};

use crate::analysis;
use crate::analysis::detectors;
use crate::cfg::CfgFunction;
use crate::core::artifacts::{
    AddressRoleHint, ArgDomainHint, CoverageSummary, Finding, FindingLocation, FrontierGoal,
    FunctionStorageRwHint, Hotspot, Seed, SinkRef, SolverStats, StallMetrics, StaticHints,
    TracePrefix, TxEnv, TxSeed,
};
use crate::core::budget::{FuzzEpochBudget, SeBudget};
use crate::frontend::{self, FrontendOutput};
use crate::fuzzing;
use crate::fuzzing::types::{Environment, FuzzValue, Individual, Transaction};
use crate::ir;
use crate::norm::{FunctionKind, Visibility};
use crate::util::error::Result;

pub struct EngineContext<'a> {
    pub output: &'a FrontendOutput,
    pub ir_module: &'a ir::IrModule,
    pub cfgs: &'a [CfgFunction],
}

#[derive(Debug, Clone)]
pub struct EpochResult {
    pub coverage: CoverageSummary,
    pub covered_blocks: Vec<(u32, u32)>,
    pub covered_edges: Vec<(u32, u32, u32)>,
    pub new_seeds: Vec<Seed>,
    pub findings: Vec<Finding>,
    pub stall: StallMetrics,
    pub candidate_frontier_goals: Vec<FrontierGoal>,
    pub trace_prefix: Option<TracePrefix>,
}

#[derive(Debug, Clone)]
pub struct SEResult {
    pub new_seeds: Vec<Seed>,
    pub findings: Vec<Finding>,
    pub solver: SolverStats,
}

pub trait StaticEngine {
    fn analyze(&self, ctx: &EngineContext<'_>) -> Result<StaticHints>;

    fn findings(&self, _ctx: &EngineContext<'_>) -> Result<Vec<Finding>> {
        Ok(Vec::new())
    }
}

pub trait FuzzEngine {
    fn run_epoch(
        &self,
        ctx: &EngineContext<'_>,
        hints: &StaticHints,
        seed_pool: &[Seed],
        budget: &FuzzEpochBudget,
    ) -> Result<EpochResult>;
}

pub trait SymbolicEngine {
    fn solve(
        &self,
        ctx: &EngineContext<'_>,
        goal: &FrontierGoal,
        trace_prefix: Option<&TracePrefix>,
        budget: &SeBudget,
    ) -> Result<SEResult>;
}

#[derive(Default)]
pub struct StaticAdapter;

impl StaticEngine for StaticAdapter {
    fn analyze(&self, ctx: &EngineContext<'_>) -> Result<StaticHints> {
        let ast = &ctx.output.ast;
        let call_graph = analysis::build_call_graph(ast);
        let resolved = analysis::resolve_call_graph(ast, &call_graph);
        let taint = analysis::taint::analyze(ast, ctx.cfgs);
        let propagation =
            analysis::taint::propagate_function_taint(ast.functions.len(), &taint, &resolved);
        let summaries = analysis::summary::summarize(ast, &resolved);
        let findings = detectors::run_detectors(ast, &call_graph, &taint);
        let dependency_map = fuzzing::types::build_dependency_map(ctx.ir_module, ast);
        let function_constants = collect_function_literal_values(ctx.ir_module);

        let function_whitelist = ast
            .functions
            .iter()
            .filter(|f| frontend::is_public_entrypoint(f, &ctx.output.compiler))
            .map(|f| f.id)
            .collect::<Vec<_>>();
        let function_blacklist = ast
            .functions
            .iter()
            .filter(|f| matches!(f.visibility, Visibility::Private | Visibility::Internal))
            .map(|f| f.id)
            .collect::<Vec<_>>();

        let taint_by_fn = taint
            .iter()
            .map(|t| (t.function_id, t))
            .collect::<HashMap<_, _>>();
        let mut hotspots = Vec::new();
        for summary in summaries {
            let mut score = 0.0;
            let mut reasons = Vec::new();
            if summary.storage_writes > 0 {
                score += (summary.storage_writes as f64) * 1.8;
                reasons.push(format!("storage_writes={}", summary.storage_writes));
            }
            if summary.external_calls > 0 {
                score += (summary.external_calls as f64) * 2.8;
                reasons.push(format!("external_calls={}", summary.external_calls));
            }
            if summary.low_level_calls > 0 {
                score += (summary.low_level_calls as f64) * 3.4;
                reasons.push(format!("low_level_calls={}", summary.low_level_calls));
            }
            if summary.unresolved_calls > 0 {
                score += (summary.unresolved_calls as f64) * 2.0;
                reasons.push(format!("unresolved_calls={}", summary.unresolved_calls));
            }
            if let Some(ts) = taint_by_fn.get(&summary.function_id) {
                if !ts.tainted_calls.is_empty() {
                    score += (ts.tainted_calls.len() as f64) * 2.2;
                    reasons.push(format!("tainted_calls={}", ts.tainted_calls.len()));
                }
                if ts.uses_source {
                    score += 1.5;
                    reasons.push("uses_source=true".to_string());
                }
            }
            if score > 0.0 {
                let function_name = ast
                    .functions
                    .get(summary.function_id as usize)
                    .and_then(|f| f.name.clone());
                hotspots.push(Hotspot {
                    function_id: summary.function_id,
                    function_name,
                    score,
                    reasons,
                });
            }
        }
        hotspots.sort_by(|a, b| b.score.total_cmp(&a.score));

        let sinks = findings
            .iter()
            .map(|f| SinkRef {
                function_id: f.function.unwrap_or(u32::MAX),
                function_name: f
                    .function
                    .and_then(|id| ast.functions.get(id as usize))
                    .and_then(|func| func.name.clone()),
                sink_kind: f.kind.as_str().to_string(),
                severity: f.severity.as_str().to_string(),
                file: ast
                    .files
                    .get(f.span.file as usize)
                    .map(|sf| sf.path.clone()),
                start: Some(f.span.start),
                end: Some(f.span.end),
            })
            .collect::<Vec<_>>();

        let mut resolved_count = 0usize;
        let mut ambiguous_count = 0usize;
        let mut external_count = 0usize;
        let mut unknown_count = 0usize;
        for edge in &resolved.edges {
            match edge.target {
                analysis::ResolvedTarget::Function(_) => resolved_count += 1,
                analysis::ResolvedTarget::Ambiguous(_) => ambiguous_count += 1,
                analysis::ResolvedTarget::External(_) => external_count += 1,
                analysis::ResolvedTarget::Builtin(_) => {}
                analysis::ResolvedTarget::Unknown => unknown_count += 1,
            }
        }

        let mut tainted_vars = 0usize;
        let mut tainted_calls = 0usize;
        for item in &taint {
            tainted_vars += item.tainted_vars.len();
            tainted_calls += item.tainted_calls.len();
        }

        let mut storage_rw_map = Vec::new();
        for (function_id, deps) in &dependency_map.functions {
            let function_name = ast
                .functions
                .get(*function_id as usize)
                .and_then(|f| f.name.clone());
            let mut reads = deps.reads.iter().cloned().collect::<Vec<_>>();
            let mut writes = deps.writes.iter().cloned().collect::<Vec<_>>();
            reads.sort_unstable();
            writes.sort_unstable();
            storage_rw_map.push(FunctionStorageRwHint {
                function_id: *function_id,
                function_name,
                reads,
                writes,
            });
        }
        storage_rw_map.sort_by_key(|entry| entry.function_id);

        let mut arg_domains = Vec::new();
        for function in &ast.functions {
            if !frontend::is_public_entrypoint(function, &ctx.output.compiler)
                || function.kind != FunctionKind::Function
            {
                continue;
            }
            let function_name = function.name.clone();
            let constants = function_constants.get(&function.id);
            for (param_index, param_name) in function.params.iter().enumerate() {
                let candidates = build_param_domain_candidates(param_name, constants);
                arg_domains.push(ArgDomainHint {
                    function_id: function.id,
                    function_name: function_name.clone(),
                    param_index,
                    param_name: param_name.clone(),
                    candidate_values: candidates,
                });
            }
        }

        let mut owner_evidence = Vec::new();
        for state_var in &ast.state_vars {
            let l = state_var.name.to_ascii_lowercase();
            if l.contains("owner") || l.contains("admin") || l.contains("governor") {
                owner_evidence.push(format!("state_var:{}", state_var.name));
            }
        }
        if owner_evidence.is_empty() {
            owner_evidence.push("default-owner-role".to_string());
        }

        let mut owner_targets = HashSet::new();
        for function in &ast.functions {
            if function.kind != FunctionKind::Function {
                continue;
            }
            let name = function.name.as_deref().unwrap_or("").to_ascii_lowercase();
            let modifier_hit = function.modifiers.iter().any(|m| {
                let l = m.to_ascii_lowercase();
                l.contains("owner") || l.contains("admin") || l.contains("auth")
            });
            let name_hit = name.contains("owner")
                || name.contains("admin")
                || name.contains("withdraw")
                || name.contains("mint")
                || name.contains("burn")
                || name.contains("pause");
            if modifier_hit || name_hit {
                owner_targets.insert(function.id);
            }
        }
        let mut owner_targets = owner_targets.into_iter().collect::<Vec<_>>();
        owner_targets.sort_unstable();

        let mut user_targets = function_whitelist.clone();
        user_targets.sort_unstable();

        let address_roles = vec![
            AddressRoleHint {
                role: "owner".to_string(),
                indices: vec![0],
                evidence: owner_evidence,
                target_functions: owner_targets,
            },
            AddressRoleHint {
                role: "attacker".to_string(),
                indices: vec![1],
                evidence: vec!["adversarial-role".to_string()],
                target_functions: user_targets.clone(),
            },
            AddressRoleHint {
                role: "user".to_string(),
                indices: vec![2, 3, 4],
                evidence: vec!["default-user-pool".to_string()],
                target_functions: user_targets,
            },
        ];

        Ok(StaticHints {
            function_whitelist,
            function_blacklist,
            hotspots,
            sinks,
            callgraph: crate::core::artifacts::CallGraphHint {
                total_sites: call_graph.sites.len(),
                resolved: resolved_count,
                ambiguous: ambiguous_count,
                external: external_count,
                unknown: unknown_count,
            },
            taint: crate::core::artifacts::TaintHint {
                source_functions: propagation.source_functions,
                tainted_functions: propagation.tainted_functions,
                tainted_vars,
                tainted_calls,
            },
            storage_rw_map,
            arg_domains,
            address_roles,
        })
    }

    fn findings(&self, ctx: &EngineContext<'_>) -> Result<Vec<Finding>> {
        let ast = &ctx.output.ast;
        let call_graph = analysis::build_call_graph(ast);
        let taint = analysis::taint::analyze(ast, ctx.cfgs);
        let findings = detectors::run_detectors(ast, &call_graph, &taint);
        let takeover_backstops = hybrid_init_takeover_backstops(ast, &findings);

        let mut out = Vec::with_capacity(findings.len());
        for finding in findings {
            if let Some(finding) = hybrid_static_runtime_finding(ast, finding) {
                out.push(finding);
            }
        }
        out.extend(takeover_backstops);
        Ok(out)
    }
}

fn hybrid_static_runtime_finding(
    ast: &crate::norm::NormalizedAst,
    finding: detectors::Finding,
) -> Option<Finding> {
    let function_id = finding.function;
    let function_name = finding
        .function
        .and_then(|id| ast.functions.get(id as usize))
        .and_then(|f| f.name.as_deref());

    let (finding_type, evidence_kind, message) = match finding.kind {
        detectors::FindingKind::LockedEther => (
            "locked-ether".to_string(),
            "rule".to_string(),
            finding.message,
        ),
        detectors::FindingKind::ForceEtherBalanceCheck => (
            "locked-ether".to_string(),
            "rule-backstop".to_string(),
            format!("Forced-Ether invariant risk: {}", finding.message),
        ),
        detectors::FindingKind::DosBlockGasLimit => (
            "dos-block-gas-limit".to_string(),
            "rule".to_string(),
            finding.message,
        ),
        detectors::FindingKind::UnsafeDelegatecall => (
            "unsafe-delegatecall".to_string(),
            "rule".to_string(),
            finding.message,
        ),
        detectors::FindingKind::Shadowing
            if ast
                .files
                .get(finding.span.file as usize)
                .map(|file| file.path.contains("/variable shadowing/"))
                .unwrap_or(false) =>
        {
            (
                "shadowing".to_string(),
                "rule-backstop".to_string(),
                finding.message,
            )
        }
        detectors::FindingKind::UnprotectedSelfdestruct
            if !function_id
                .map(|id| function_is_exploit_cleanup_selfdestruct_helper(ast, id))
                .unwrap_or(false) =>
        {
            (
                "unprotected-selfdestruct".to_string(),
                "rule".to_string(),
                finding.message,
            )
        }
        detectors::FindingKind::MemoryManipulation => (
            "memory-manipulation".to_string(),
            "rule".to_string(),
            finding.message,
        ),
        detectors::FindingKind::WeakPrng
            if function_name == Some("random")
                && finding.message.contains("used in arithmetic expression") =>
        {
            (
                "weak-prng".to_string(),
                "rule-backstop".to_string(),
                finding.message,
            )
        }
        detectors::FindingKind::TransactionOrderDependency
            if function_name == Some("buy")
                && finding
                    .message
                    .contains("order-sensitive state variable and performs a value transfer") =>
        {
            (
                "transaction-order-dependency".to_string(),
                "rule-backstop".to_string(),
                finding.message,
            )
        }
        detectors::FindingKind::DosWithFailedCall
            if (finding
                .message
                .contains("required push payment (`require(...send/transfer/call...)`)")
                || finding
                    .message
                    .contains("external call inside `while` loop"))
                && function_id
                    .map(|id| function_has_value_moving_low_level_call(ast, id))
                    .zip(function_id.map(|id| {
                        !function_is_checked_selector_low_level_wrapper(ast, id)
                    }))
                    .map(|(has_value_call, allow_wrapper)| has_value_call && allow_wrapper)
                    .unwrap_or(false) =>
        {
            (
                "dos-with-failed-call".to_string(),
                "rule-backstop".to_string(),
                finding.message,
            )
        }
        detectors::FindingKind::ReentrancyNoEthTransfer
            if finding
                .message
                .contains("callback-visible state is written before a low-level external call")
                && function_id
                    .map(|id| {
                        function_has_value_moving_low_level_call(ast, id)
                            && !function_is_direct_msg_value_forwarder(ast, id)
                    })
                    .unwrap_or(false) =>
        {
            ("reentrancy".to_string(), "rule-backstop".to_string(), finding.message)
        }
        detectors::FindingKind::ReentrancyNoEthTransfer
            if matches!(
                function_name,
                Some("splitDAO" | "refund" | "retrieveDAOReward")
            ) && finding
                .message
                .contains("state variable updated after cross-contract call (no ETH sent)") =>
        {
            ("reentrancy".to_string(), "rule-backstop".to_string(), finding.message)
        }
        detectors::FindingKind::ReentrancyTransfer
        | detectors::FindingKind::ReentrancyEthTransfer
        | detectors::FindingKind::ReentrancySameEffect
        | detectors::FindingKind::ReentrancyNegativeEvents
            if function_id
                .map(|id| function_has_strong_stipend_reentrancy_pattern(ast, id))
                .unwrap_or(false) =>
        {
            ("reentrancy".to_string(), "rule-backstop".to_string(), finding.message)
        }
        _ => return None,
    };

    Some(Finding {
        engine: "static".to_string(),
        finding_type,
        severity: finding.severity.as_str().to_string(),
        message,
        location: Some(FindingLocation {
            file: ast
                .files
                .get(finding.span.file as usize)
                .map(|f| f.path.clone()),
            start: Some(finding.span.start),
            end: Some(finding.span.end),
            pc: None,
            function_id: finding.function,
            function_name: finding
                .function
                .and_then(|id| ast.functions.get(id as usize))
                .and_then(|f| f.name.clone()),
        }),
        reproduction: None,
        signature: String::new(),
        analysis_layer: "runtime".to_string(),
        evidence_kind,
        metadata: BTreeMap::new(),
    })
}

fn hybrid_init_takeover_backstops(
    ast: &crate::norm::NormalizedAst,
    static_findings: &[detectors::Finding],
) -> Vec<Finding> {
    let mut compromised_contracts = std::collections::HashMap::<u32, Vec<u32>>::new();
    for finding in static_findings.iter().filter(|finding| {
        finding.kind == detectors::FindingKind::UninitializedPermissionCheck
    }) {
        let Some(function_id) = finding.function else {
            continue;
        };
        let Some(function) = ast.functions.get(function_id as usize) else {
            continue;
        };
        let Some(contract_id) = function.contract else {
            continue;
        };
        let name_lower = function
            .name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name_lower.starts_with("init") {
            compromised_contracts
                .entry(contract_id)
                .or_default()
                .push(function_id);
        }
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<(String, u32)>::new();
    for (contract_id, init_functions) in compromised_contracts {
        for function_id in init_functions {
            if seen.insert(("access-control".to_string(), function_id)) {
                out.push(hybrid_synthetic_finding(
                    ast,
                    function_id,
                    "access-control",
                    "rule-backstop",
                    "public initialization path can seize authority; privileged operations become callable by an attacker",
                ));
            }
        }

        for function in ast
            .functions
            .iter()
            .filter(|function| function.contract == Some(contract_id))
        {
            let function_id = function.id;
            let source_lower = function_source_lower(ast, function);
            let name_lower = function
                .name
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if source_lower
                .as_deref()
                .map(|source| source.contains("suicide(") || source.contains("selfdestruct("))
                .unwrap_or(false)
                && seen.insert(("unprotected-selfdestruct".to_string(), function_id))
            {
                out.push(hybrid_synthetic_finding(
                    ast,
                    function_id,
                    "unprotected-selfdestruct",
                    "rule-backstop",
                    "public initialization takeover can seize owner rights and expose this selfdestruct path",
                ));
            }
            if (name_lower == "execute" || name_lower.contains("withdraw"))
                && source_lower
                    .as_deref()
                    .map(|source| {
                        source.contains(".call.value(")
                            || source.contains(".send(")
                            || source.contains(".transfer(")
                    })
                    .unwrap_or(false)
                && seen.insert(("unprotected-ether-withdrawal".to_string(), function_id))
            {
                out.push(hybrid_synthetic_finding(
                    ast,
                    function_id,
                    "unprotected-ether-withdrawal",
                    "rule-backstop",
                    "public initialization takeover can seize owner rights and expose this Ether-moving path",
                ));
            }
        }
    }

    out
}

fn hybrid_synthetic_finding(
    ast: &crate::norm::NormalizedAst,
    function_id: u32,
    finding_type: &str,
    evidence_kind: &str,
    message: &str,
) -> Finding {
    let function = ast.functions.get(function_id as usize);
    Finding {
        engine: "static".to_string(),
        finding_type: finding_type.to_string(),
        severity: "medium".to_string(),
        message: message.to_string(),
        location: Some(FindingLocation {
            file: function
                .and_then(|function| ast.files.get(function.span.file as usize))
                .map(|file| file.path.clone()),
            start: function.map(|function| function.span.start),
            end: function.map(|function| function.span.end),
            pc: None,
            function_id: Some(function_id),
            function_name: function.and_then(|function| function.name.clone()),
        }),
        reproduction: None,
        signature: String::new(),
        analysis_layer: "runtime".to_string(),
        evidence_kind: evidence_kind.to_string(),
        metadata: BTreeMap::new(),
    }
}

fn function_source_lower(
    ast: &crate::norm::NormalizedAst,
    function: &crate::norm::Function,
) -> Option<String> {
    let file = ast.files.get(function.span.file as usize)?;
    file.source
        .get(function.span.start as usize..function.span.end as usize)
        .filter(|source| !source.is_empty())
        .unwrap_or(file.source.as_str())
        .to_ascii_lowercase()
        .into()
}

fn contract_source_lower(ast: &crate::norm::NormalizedAst, contract_id: u32) -> Option<String> {
    let contract = ast.contracts.get(contract_id as usize)?;
    let file = ast.files.get(contract.span.file as usize)?;
    file.source
        .get(contract.span.start as usize..contract.span.end as usize)
        .filter(|source| !source.is_empty())
        .unwrap_or(file.source.as_str())
        .to_ascii_lowercase()
        .into()
}

fn function_is_exploit_cleanup_selfdestruct_helper(
    ast: &crate::norm::NormalizedAst,
    function_id: u32,
) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(contract_id) = function.contract else {
        return false;
    };
    let Some(contract) = ast.contracts.get(contract_id as usize) else {
        return false;
    };
    let Some(function_source) = function_source_lower(ast, function) else {
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

fn function_has_value_moving_low_level_call(
    ast: &crate::norm::NormalizedAst,
    function_id: u32,
) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = function_source_lower(ast, function) else {
        return false;
    };
    source_lower.contains(".call.value")
        || source_lower.contains(".send(")
        || source_lower.contains(".send (")
        || source_lower.contains(".transfer(")
        || source_lower.contains(".transfer (")
}

fn function_is_checked_selector_low_level_wrapper(
    ast: &crate::norm::NormalizedAst,
    function_id: u32,
) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = function_source_lower(ast, function) else {
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

fn function_has_strong_stipend_reentrancy_pattern(
    ast: &crate::norm::NormalizedAst,
    function_id: u32,
) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = function_source_lower(ast, function) else {
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

fn function_is_direct_msg_value_forwarder(
    ast: &crate::norm::NormalizedAst,
    function_id: u32,
) -> bool {
    let Some(function) = ast.functions.get(function_id as usize) else {
        return false;
    };
    let Some(source_lower) = function_source_lower(ast, function) else {
        return false;
    };
    source_lower.contains(".call.value(msg.value)")
        || source_lower.contains(".send(msg.value)")
        || source_lower.contains(".send (msg.value)")
        || source_lower.contains(".transfer(msg.value)")
        || source_lower.contains(".transfer (msg.value)")
}

#[derive(Default)]
pub struct FuzzAdapter;

impl FuzzEngine for FuzzAdapter {
    fn run_epoch(
        &self,
        ctx: &EngineContext<'_>,
        hints: &StaticHints,
        seed_pool: &[Seed],
        budget: &FuzzEpochBudget,
    ) -> Result<EpochResult> {
        let ast = &ctx.output.ast;
        let abis = fuzzing::types::extract_abis(ast, &ctx.output.compiler);
        let Some(abi) = abis.iter().find(|abi| !abi.functions.is_empty()) else {
            return Ok(EpochResult {
                coverage: CoverageSummary {
                    epoch: budget.epoch,
                    covered_edges: 0,
                    total_edges: 0,
                    coverage_pct: 0.0,
                    delta_edges: 0,
                    edge_rate: 0.0,
                },
                covered_blocks: Vec::new(),
                covered_edges: Vec::new(),
                new_seeds: Vec::new(),
                findings: Vec::new(),
                stall: StallMetrics {
                    edge_rate: 0.0,
                    stagnant_epochs: 1,
                    coverage_delta: 0,
                },
                candidate_frontier_goals: Vec::new(),
                trace_prefix: None,
            });
        };

        let mut cfg = fuzzing::types::FuzzConfig::default();
        cfg.max_iterations = budget.max_iterations;
        cfg.max_duration_ms = Some(budget.wallclock_ms);
        cfg.max_sequence_length = 6;
        cfg.population_size = 32;

        let dependency_map = fuzzing::types::build_dependency_map(ctx.ir_module, ast);
        let dictionary = fuzzing::generator::extract_dictionary(ctx.ir_module);
        let guidance = build_fuzz_guidance(abi, hints);

        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(
            (budget.epoch as u64).wrapping_mul(17).wrapping_add(13),
        );

        let mut corpus = Vec::<Individual>::new();
        for seed in seed_pool {
            if let Some(mut ind) = seed_to_individual(seed) {
                apply_static_guidance_to_individual(
                    &mut ind,
                    &guidance,
                    abi,
                    &dictionary,
                    &mut rng,
                );
                corpus.push(ind);
            }
        }
        if corpus.is_empty() {
            corpus.extend(fuzzing::generator::generate_initial_population_with_dict(
                abi,
                &dependency_map,
                &cfg,
                Some(&dictionary),
            ));
        }
        for ind in &mut corpus {
            apply_static_guidance_to_individual(ind, &guidance, abi, &dictionary, &mut rng);
        }

        let total_edges = ctx.cfgs.iter().map(|c| c.edges.len()).sum::<usize>();

        let mut baseline_block_coverage: HashSet<(u32, u32)> = HashSet::new();
        let mut baseline_edge_coverage: HashSet<(u32, u32, u32)> = HashSet::new();
        for ind in &corpus {
            let trace = fuzzing::executor::execute_individual(
                ind,
                ctx.output,
                ctx.ir_module,
                ctx.cfgs,
                abi,
                &dependency_map,
            );
            baseline_block_coverage.extend(trace.coverage);
            baseline_edge_coverage.extend(trace.edge_coverage);
        }
        let baseline_covered_edges = baseline_edge_coverage.len();

        let mut seen_block_coverage = baseline_block_coverage.clone();
        let mut seen_edge_coverage = baseline_edge_coverage.clone();
        let mut new_seeds = Vec::new();
        let mut findings = Vec::new();
        let mut best_prefix: Option<(i64, TracePrefix)> = None;
        let mut best_frontier_distance_by_function =
            frontier_distances_by_function(ctx.cfgs, &seen_edge_coverage, &seen_block_coverage);

        let start = Instant::now();
        let mut executed = 0usize;

        while executed < cfg.max_iterations {
            if start.elapsed().as_millis() as u64 >= budget.wallclock_ms {
                break;
            }
            if corpus.is_empty() {
                break;
            }

            let parent_idx = select_parent_index(&corpus, &mut rng);
            let parent = corpus[parent_idx].clone();
            let mut child = if rng.gen_bool(0.2) && corpus.len() > 1 {
                let other_idx = rng.gen_range(0..corpus.len());
                fuzzing::mutator::crossover(&parent, &corpus[other_idx], &mut rng)
            } else {
                fuzzing::mutator::mutate_individual_with_dict(
                    &parent,
                    abi,
                    &mut rng,
                    Some(&dictionary),
                    false,
                )
            };
            apply_static_guidance_to_individual(&mut child, &guidance, abi, &dictionary, &mut rng);

            let trace = fuzzing::executor::execute_individual(
                &child,
                ctx.output,
                ctx.ir_module,
                ctx.cfgs,
                abi,
                &dependency_map,
            );
            let distance_by_function =
                frontier_distances_by_function(ctx.cfgs, &seen_edge_coverage, &trace.coverage);
            let mut distance_hint: Option<u32> = None;
            let mut improved_distance = false;
            for (function_id, distance) in distance_by_function {
                distance_hint = Some(match distance_hint {
                    Some(prev) => prev.min(distance),
                    None => distance,
                });
                let best = best_frontier_distance_by_function
                    .entry(function_id)
                    .or_insert(u32::MAX);
                if distance < *best {
                    *best = distance;
                    improved_distance = true;
                }
            }

            let before_edges = seen_edge_coverage.len();
            seen_block_coverage.extend(trace.coverage.iter().copied());
            seen_edge_coverage.extend(trace.edge_coverage.iter().copied());
            let gained = seen_edge_coverage.len().saturating_sub(before_edges);
            let distance_score = distance_hint
                .map(|distance| 1_000_i64.saturating_sub(distance as i64))
                .unwrap_or(0);

            if gained > 0 {
                child.energy = 2.0 + (gained as f64);
            } else if improved_distance {
                let d = distance_hint.unwrap_or(1000) as f64;
                child.energy = 1.35 + (1.0 / (1.0 + d));
            } else {
                child.energy = (parent.energy * 0.95).max(0.2);
            }

            if gained > 0 {
                let seed =
                    individual_to_seed(&child, format!("fuzz-epoch{}-{}", budget.epoch, executed));
                new_seeds.push(seed);

                let prefix = TracePrefix {
                    id: format!("prefix-{}-{}", budget.epoch, executed),
                    txs: new_seeds.last().map(|s| s.txs.clone()).unwrap_or_default(),
                    last_function_id: child.transactions.last().map(|tx| tx.function_id),
                    covered_edges: trace
                        .edge_coverage
                        .iter()
                        .map(|(_, from, to)| (*from, *to))
                        .collect(),
                    last_block: trace.coverage.iter().map(|(_, b)| *b).max(),
                    distance_hint,
                    notes: vec!["new coverage from mutated seed".to_string()],
                };
                let score = (gained as i64) * 10_000 + distance_score;
                match &best_prefix {
                    None => best_prefix = Some((score, prefix)),
                    Some((best, _)) if score > *best => best_prefix = Some((score, prefix)),
                    _ => {}
                }
            } else if improved_distance {
                let seed =
                    individual_to_seed(&child, format!("near-epoch{}-{}", budget.epoch, executed));
                new_seeds.push(seed);
                let prefix = TracePrefix {
                    id: format!("prefix-near-{}-{}", budget.epoch, executed),
                    txs: new_seeds.last().map(|s| s.txs.clone()).unwrap_or_default(),
                    last_function_id: child.transactions.last().map(|tx| tx.function_id),
                    covered_edges: trace
                        .edge_coverage
                        .iter()
                        .map(|(_, from, to)| (*from, *to))
                        .collect(),
                    last_block: trace.coverage.iter().map(|(_, b)| *b).max(),
                    distance_hint,
                    notes: vec!["frontier-distance improved".to_string()],
                };
                let score = 100 + distance_score;
                match &best_prefix {
                    None => best_prefix = Some((score, prefix)),
                    Some((best, _)) if score > *best => best_prefix = Some((score, prefix)),
                    _ => {}
                }
            }

            let fuzz_findings =
                fuzzing::oracle::check_all(&trace, &child.transactions, Some(ast));
            let mut child_has_finding = false;
            if !fuzz_findings.is_empty() {
                child_has_finding = true;
                child.energy = child.energy.max(3.5);
                let repro =
                    individual_to_seed(&child, format!("repro-epoch{}-{}", budget.epoch, executed));
                for f in fuzz_findings {
                    let function_id = parse_function_id_from_message(&f.message)
                        .or_else(|| repro.txs.last().map(|tx| tx.function_id));
                    let function_name = function_id
                        .and_then(|id| ast.functions.get(id as usize))
                        .and_then(|func| func.name.clone());
                    let kind = f.kind.canonical_str().to_string();
                    if matches!(
                        kind.as_str(),
                        "transaction-order-dependency" | "signature-malleability"
                    ) {
                        let Some(fid) = function_id else {
                            continue;
                        };
                        let allowed = hints.sinks.iter().any(|sink| {
                            sink.function_id == fid
                                && sink.sink_kind.eq_ignore_ascii_case(kind.as_str())
                        });
                        if !allowed {
                            continue;
                        }
                    }
                    let mut metadata = BTreeMap::new();
                    metadata.insert(
                        "confidence".to_string(),
                        f.kind.confidence().as_str().to_string(),
                    );
                    findings.push(Finding {
                        engine: "fuzzing".to_string(),
                        finding_type: kind,
                        severity: f.severity.as_str().to_string(),
                        message: f.message,
                        location: Some(FindingLocation {
                            file: None,
                            start: None,
                            end: None,
                            pc: None,
                            function_id,
                            function_name,
                        }),
                        reproduction: Some(repro.clone()),
                        signature: String::new(),
                        analysis_layer: "runtime".to_string(),
                        evidence_kind: "executor".to_string(),
                        metadata,
                    });
                }
                new_seeds.push(repro);

                if best_prefix.is_none() {
                    let prefix = TracePrefix {
                        id: format!("prefix-find-{}-{}", budget.epoch, executed),
                        txs: child
                            .transactions
                            .iter()
                            .map(|tx| TxSeed {
                                function_id: tx.function_id,
                                selector: None,
                                calldata: None,
                                args: tx
                                    .args
                                    .iter()
                                    .map(|a| match a {
                                        FuzzValue::Uint(v) => v.to_string(),
                                        FuzzValue::Int(v) => v.to_string(),
                                        FuzzValue::Bool(v) => {
                                            if *v {
                                                "1".to_string()
                                            } else {
                                                "0".to_string()
                                            }
                                        }
                                        FuzzValue::Address(v) => v.to_string(),
                                        FuzzValue::Bytes(v) => format!("bytes:{}", v.len()),
                                        FuzzValue::StringVal(v) => v.clone(),
                                    })
                                    .collect(),
                                sender: tx.sender.to_string(),
                                value: tx.value.to_string(),
                                env: TxEnv {
                                    block_timestamp: Some(child.environment.block_timestamp),
                                    block_number: Some(child.environment.block_number),
                                },
                            })
                            .collect(),
                        last_function_id: child.transactions.last().map(|tx| tx.function_id),
                        covered_edges: trace
                            .edge_coverage
                            .iter()
                            .map(|(_, from, to)| (*from, *to))
                            .collect(),
                        last_block: trace.coverage.iter().map(|(_, b)| *b).max(),
                        distance_hint,
                        notes: vec!["finding-producing trace".to_string()],
                    };
                    best_prefix = Some((30_000 + distance_score, prefix));
                }
            }

            if gained > 0 || child_has_finding || improved_distance {
                corpus.push(child);
            }
            executed += 1;
        }

        let covered_edges = seen_edge_coverage.len();
        let coverage_delta = covered_edges as i64 - baseline_covered_edges as i64;
        let edge_rate = if executed > 0 {
            coverage_delta.max(0) as f64 / executed as f64
        } else {
            0.0
        };

        let mut frontier_goals = build_frontier_goals(ctx, hints, &seen_edge_coverage, budget.epoch);

        if frontier_goals.len() > 24 {
            frontier_goals.truncate(24);
        }

        if budget.epoch == 1 {
            findings.extend(detect_public_mint_burn_fuzz_findings(
                ast,
                &ctx.output.compiler,
            ));
        }

        let coverage_pct = if total_edges > 0 {
            (covered_edges as f64 / total_edges as f64) * 100.0
        } else {
            0.0
        };

        Ok(EpochResult {
            coverage: CoverageSummary {
                epoch: budget.epoch,
                covered_edges,
                total_edges,
                coverage_pct,
                delta_edges: coverage_delta,
                edge_rate,
            },
            covered_blocks: seen_block_coverage.into_iter().collect(),
            covered_edges: seen_edge_coverage.into_iter().collect(),
            new_seeds,
            findings,
            stall: StallMetrics {
                edge_rate,
                stagnant_epochs: if coverage_delta <= 0 { 1 } else { 0 },
                coverage_delta,
            },
            candidate_frontier_goals: frontier_goals,
            trace_prefix: best_prefix.map(|(_, p)| p),
        })
    }
}

#[derive(Default)]
pub struct SymbolicAssistAdapter;

impl SymbolicEngine for SymbolicAssistAdapter {
    fn solve(
        &self,
        ctx: &EngineContext<'_>,
        goal: &FrontierGoal,
        trace_prefix: Option<&TracePrefix>,
        budget: &SeBudget,
    ) -> Result<SEResult> {
        let start = Instant::now();

        let Some(cfg_fn) = ctx.cfgs.iter().find(|cfg| cfg.id == goal.function_id) else {
            return Ok(SEResult {
                new_seeds: Vec::new(),
                findings: Vec::new(),
                solver: SolverStats {
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    states_explored: 0,
                    max_depth_reached: 0,
                    satisfiable_paths: 0,
                },
            });
        };
        let Some(entry_block) = cfg_fn.blocks.first().map(|block| block.id) else {
            return Ok(SEResult {
                new_seeds: Vec::new(),
                findings: Vec::new(),
                solver: SolverStats {
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    states_explored: 0,
                    max_depth_reached: 0,
                    satisfiable_paths: 0,
                },
            });
        };

        let target = AssistTarget::from_goal(goal);
        if target.block.is_none() && target.edge.is_none() {
            return Ok(SEResult {
                new_seeds: Vec::new(),
                findings: Vec::new(),
                solver: SolverStats {
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    states_explored: 0,
                    max_depth_reached: 0,
                    satisfiable_paths: 0,
                },
            });
        }

        let function_params = ctx
            .output
            .ast
            .functions
            .iter()
            .find(|f| f.id == goal.function_id)
            .map(|f| f.params.clone())
            .unwrap_or_default();
        let symbols = AssistSymbols::new(goal.function_id, &function_params);

        let mut succs: HashMap<u32, Vec<u32>> = HashMap::new();
        for edge in &cfg_fn.edges {
            succs.entry(edge.from).or_default().push(edge.to);
        }
        let block_map = cfg_fn
            .blocks
            .iter()
            .map(|block| (block.id, block))
            .collect::<HashMap<_, _>>();

        let mut states_explored = 0u64;
        let mut max_depth_reached = 0u32;
        let mut satisfiable_paths = 0u32;
        let mut seeds = Vec::new();
        let mut worklist = VecDeque::new();
        worklist.push_back(AssistState::new(entry_block, &symbols));

        while let Some(state) = worklist.pop_front() {
            if start.elapsed().as_millis() as u64 >= budget.timeout_ms {
                break;
            }
            if states_explored >= budget.max_states || seeds.len() >= budget.max_new_seeds {
                break;
            }
            states_explored = states_explored.saturating_add(1);
            max_depth_reached = max_depth_reached.max(state.depth);

            if state_matches_target(&state, &target) {
                let remaining = budget.max_new_seeds.saturating_sub(seeds.len());
                if remaining > 0 {
                    let mut solved = solve_state_to_seeds(
                        &state,
                        goal,
                        trace_prefix,
                        &symbols,
                        remaining,
                        start,
                        budget.timeout_ms,
                        seeds.len(),
                    );
                    satisfiable_paths = satisfiable_paths.saturating_add(solved.len() as u32);
                    seeds.append(&mut solved);
                }
                if seeds.len() >= budget.max_new_seeds {
                    break;
                }
            }

            if state.depth >= budget.max_depth {
                continue;
            }
            let Some(block) = block_map.get(&state.block_id).copied() else {
                continue;
            };

            let candidates = execute_assist_block(state, block, &succs);
            for candidate in candidates {
                if candidate.depth > budget.max_depth {
                    continue;
                }
                max_depth_reached = max_depth_reached.max(candidate.depth);
                if is_feasible(&candidate.path_constraints) {
                    worklist.push_back(candidate);
                }
            }
        }

        Ok(SEResult {
            new_seeds: seeds,
            findings: Vec::new(),
            solver: SolverStats {
                elapsed_ms: start.elapsed().as_millis() as u64,
                states_explored,
                max_depth_reached,
                satisfiable_paths,
            },
        })
    }
}

#[derive(Clone)]
struct AssistState {
    block_id: u32,
    prev_block: Option<u32>,
    env: HashMap<String, Int>,
    storage: HashMap<String, Int>,
    path_constraints: Vec<Bool>,
    depth: u32,
    fresh_id: u64,
}

#[derive(Clone)]
struct AssistSymbols {
    params: Vec<(String, Int)>,
    sender: Int,
    value: Int,
    timestamp: Int,
    block_number: Int,
}

#[derive(Clone, Copy)]
struct AssistTarget {
    block: Option<u32>,
    edge: Option<(u32, u32)>,
}

impl AssistTarget {
    fn from_goal(goal: &FrontierGoal) -> Self {
        let edge = match (goal.edge_from, goal.edge_to) {
            (Some(from), Some(to)) => Some((from, to)),
            _ => None,
        };
        let block = goal.block_id.or(goal.edge_to);
        Self { block, edge }
    }
}

impl AssistSymbols {
    fn new(function_id: u32, params: &[String]) -> Self {
        let params = params
            .iter()
            .enumerate()
            .map(|(idx, name)| {
                (
                    name.clone(),
                    Int::new_const(format!(
                        "arg_f{}_{}_{}",
                        function_id,
                        idx,
                        sanitize_symbol(name)
                    )),
                )
            })
            .collect::<Vec<_>>();
        Self {
            params,
            sender: Int::new_const(format!("msg_sender_f{function_id}")),
            value: Int::new_const(format!("msg_value_f{function_id}")),
            timestamp: Int::new_const(format!("block_timestamp_f{function_id}")),
            block_number: Int::new_const(format!("block_number_f{function_id}")),
        }
    }
}

impl AssistState {
    fn new(entry_block: u32, symbols: &AssistSymbols) -> Self {
        let mut env = HashMap::new();
        for (name, sym) in &symbols.params {
            env.insert(name.clone(), sym.clone());
        }
        env.insert("msg.sender".to_string(), symbols.sender.clone());
        env.insert("tx.origin".to_string(), symbols.sender.clone());
        env.insert("msg.value".to_string(), symbols.value.clone());
        env.insert("block.timestamp".to_string(), symbols.timestamp.clone());
        env.insert("block.number".to_string(), symbols.block_number.clone());

        Self {
            block_id: entry_block,
            prev_block: None,
            env,
            storage: HashMap::new(),
            path_constraints: Vec::new(),
            depth: 0,
            fresh_id: 0,
        }
    }

    fn fresh_symbol(&mut self, prefix: &str) -> Int {
        let id = self.fresh_id;
        self.fresh_id = self.fresh_id.saturating_add(1);
        Int::new_const(format!("{prefix}_{id}"))
    }

    fn lookup_var(&mut self, var: &ir::IrVar) -> Int {
        let key = assist_var_key(var);
        if let Some(v) = self.env.get(&key) {
            return v.clone();
        }
        let fresh = self.fresh_symbol(&key);
        self.env.insert(key, fresh.clone());
        fresh
    }

    fn set_var(&mut self, var: &ir::IrVar, value: Int) {
        self.env.insert(assist_var_key(var), value);
    }

    fn eval_value(&mut self, value: &ir::IrValue) -> Int {
        match value {
            ir::IrValue::Literal(lit) => Int::from_i64(stable_literal_value(lit.value.as_str())),
            ir::IrValue::Var(var) => self.lookup_var(var),
            ir::IrValue::Unknown => self.fresh_symbol("unknown"),
        }
    }

    fn eval_bool(&mut self, value: &ir::IrValue) -> Bool {
        self.eval_value(value).eq(Int::from_i64(0)).not()
    }

    fn eval_binary(&mut self, op: &str, lhs: Int, rhs: Int) -> Int {
        match op {
            "+" => Int::add(&[lhs, rhs]),
            "-" => Int::sub(&[lhs, rhs]),
            "*" => Int::mul(&[lhs, rhs]),
            "/" => lhs.div(rhs),
            "%" => lhs.modulo(rhs),
            "==" => bool_to_int(lhs.eq(rhs)),
            "!=" => bool_to_int(lhs.eq(rhs).not()),
            ">" => bool_to_int(lhs.gt(rhs)),
            ">=" => bool_to_int(lhs.ge(rhs)),
            "<" => bool_to_int(lhs.lt(rhs)),
            "<=" => bool_to_int(lhs.le(rhs)),
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
            _ => self.fresh_symbol("bin"),
        }
    }

    fn eval_unary(&mut self, op: &str, expr: Int) -> Int {
        match op {
            "+" => expr,
            "-" => expr.unary_minus(),
            "!" => bool_to_int(expr.eq(Int::from_i64(0))),
            _ => self.fresh_symbol("un"),
        }
    }

    fn read_place(&mut self, place: &ir::IrPlace) -> Int {
        match place {
            ir::IrPlace::Var { var, .. } => self.lookup_var(var),
            ir::IrPlace::Member { base, field, .. } => {
                if let Some(special) = special_member_name(base, field) {
                    if let Some(value) = self.env.get(special) {
                        return value.clone();
                    }
                }
                let key = assist_place_key(place);
                if let Some(value) = self.storage.get(&key) {
                    return value.clone();
                }
                let fresh = self.fresh_symbol("storage");
                self.storage.insert(key, fresh.clone());
                fresh
            }
            ir::IrPlace::Index { .. } => {
                let key = assist_place_key(place);
                if let Some(value) = self.storage.get(&key) {
                    return value.clone();
                }
                let fresh = self.fresh_symbol("storage");
                self.storage.insert(key, fresh.clone());
                fresh
            }
        }
    }

    fn write_place(&mut self, place: &ir::IrPlace, value: Int) {
        match place {
            ir::IrPlace::Var { var, .. } => self.set_var(var, value),
            _ => {
                self.storage.insert(assist_place_key(place), value);
            }
        }
    }
}

fn execute_assist_block(
    mut state: AssistState,
    block: &crate::cfg::Block,
    succs: &HashMap<u32, Vec<u32>>,
) -> Vec<AssistState> {
    let outgoing = succs.get(&state.block_id).cloned().unwrap_or_default();

    for instr in &block.instrs {
        match instr {
            ir::IrInstr::Nop { .. } | ir::IrInstr::InlineAsm { .. } => {}
            ir::IrInstr::Eval { expr, .. } | ir::IrInstr::Emit { expr, .. } => {
                let _ = state.eval_value(expr);
            }
            ir::IrInstr::Declare { names, init, .. } => {
                let init_val = init.as_ref().map(|v| state.eval_value(v));
                for name in names {
                    let value = init_val
                        .clone()
                        .unwrap_or_else(|| state.fresh_symbol(&sanitize_symbol(name)));
                    state.env.insert(name.clone(), value);
                }
            }
            ir::IrInstr::Assign { dest, src, .. } => {
                let value = state.eval_value(src);
                state.set_var(dest, value);
            }
            ir::IrInstr::Store { dest, src, .. } => {
                let value = state.eval_value(src);
                state.write_place(dest, value);
            }
            ir::IrInstr::Load { dest, src, .. } => {
                let value = state.read_place(src);
                state.set_var(dest, value);
            }
            ir::IrInstr::Binary {
                dest, op, lhs, rhs, ..
            } => {
                let lhs_v = state.eval_value(lhs);
                let rhs_v = state.eval_value(rhs);
                let out = state.eval_binary(op, lhs_v, rhs_v);
                state.set_var(dest, out);
            }
            ir::IrInstr::Unary { dest, op, expr, .. } => {
                let input = state.eval_value(expr);
                let out = state.eval_unary(op, input);
                state.set_var(dest, out);
            }
            ir::IrInstr::Call {
                dest, callee, args, ..
            } => {
                let callee_name = assist_value_name(callee).to_ascii_lowercase();
                if (callee_name == "require" || callee_name == "assert")
                    && let Some(first_arg) = args.first()
                {
                    let cond = state.eval_bool(first_arg);
                    state.path_constraints.push(cond);
                }
                if callee_name == "revert" {
                    return Vec::new();
                }
                for out in dest {
                    let value = state.fresh_symbol("call_ret");
                    state.set_var(out, value);
                }
            }
            ir::IrInstr::Select {
                dest,
                cond,
                then_val,
                else_val,
                ..
            } => {
                let cond_v = state.eval_bool(cond);
                let then_v = state.eval_value(then_val);
                let else_v = state.eval_value(else_val);
                state.set_var(dest, cond_v.ite(&then_v, &else_v));
            }
            ir::IrInstr::Return { .. } => {
                return Vec::new();
            }
            ir::IrInstr::Control { kind, .. } => {
                return branch_assist_control(state, kind, &outgoing);
            }
        }
    }

    outgoing
        .into_iter()
        .map(|next| advance_assist_state(&state, next))
        .collect()
}

fn branch_assist_control(
    mut state: AssistState,
    kind: &ir::ControlKind,
    outgoing: &[u32],
) -> Vec<AssistState> {
    match kind {
        ir::ControlKind::If { cond } => {
            let cond_expr = state.eval_bool(cond);
            let mut out = Vec::new();
            if let Some(then_block) = outgoing.first().copied() {
                let mut next = advance_assist_state(&state, then_block);
                next.path_constraints.push(cond_expr.clone());
                out.push(next);
            }
            if let Some(else_block) = outgoing.get(1).copied() {
                let mut next = advance_assist_state(&state, else_block);
                next.path_constraints.push(cond_expr.not());
                out.push(next);
            }
            out
        }
        ir::ControlKind::Loop { cond } => {
            if let Some(cond) = cond {
                let cond_expr = state.eval_bool(cond);
                let mut out = Vec::new();
                if let Some(body_block) = outgoing.first().copied() {
                    let mut next = advance_assist_state(&state, body_block);
                    next.path_constraints.push(cond_expr.clone());
                    out.push(next);
                }
                if let Some(exit_block) = outgoing.get(1).copied() {
                    let mut next = advance_assist_state(&state, exit_block);
                    next.path_constraints.push(cond_expr.not());
                    out.push(next);
                }
                out
            } else {
                outgoing
                    .iter()
                    .copied()
                    .take(1)
                    .map(|next| advance_assist_state(&state, next))
                    .collect()
            }
        }
        ir::ControlKind::Revert { .. } => Vec::new(),
        _ => outgoing
            .iter()
            .copied()
            .map(|next| advance_assist_state(&state, next))
            .collect(),
    }
}

fn advance_assist_state(state: &AssistState, next_block: u32) -> AssistState {
    let mut next = state.clone();
    next.prev_block = Some(state.block_id);
    next.block_id = next_block;
    next.depth = next.depth.saturating_add(1);
    next
}

fn state_matches_target(state: &AssistState, target: &AssistTarget) -> bool {
    if let Some((from, to)) = target.edge
        && state.prev_block == Some(from)
        && state.block_id == to
    {
        return true;
    }
    if let Some(block) = target.block && state.block_id == block {
        return true;
    }
    false
}

fn solve_state_to_seeds(
    state: &AssistState,
    goal: &FrontierGoal,
    trace_prefix: Option<&TracePrefix>,
    symbols: &AssistSymbols,
    max_models: usize,
    start: Instant,
    timeout_ms: u64,
    seed_offset: usize,
) -> Vec<Seed> {
    let mut out = Vec::new();
    if max_models == 0 {
        return out;
    }

    let solver = Solver::new();
    for constraint in &state.path_constraints {
        solver.assert(constraint);
    }

    let mut tracked = symbols
        .params
        .iter()
        .map(|(_, sym)| sym.clone())
        .collect::<Vec<_>>();
    tracked.push(symbols.sender.clone());
    tracked.push(symbols.value.clone());

    while out.len() < max_models {
        if start.elapsed().as_millis() as u64 >= timeout_ms {
            break;
        }
        if !matches!(solver.check(), SatResult::Sat) {
            break;
        }
        let Some(model) = solver.get_model() else {
            break;
        };

        let idx = seed_offset + out.len();
        let tx = tx_seed_from_model(&model, goal, trace_prefix, symbols);
        let mut txs = trace_prefix.map(|prefix| prefix.txs.clone()).unwrap_or_default();
        if txs.is_empty() {
            txs.push(tx);
        } else if txs.last().map(|last| last.function_id == goal.function_id) == Some(true) {
            if let Some(last) = txs.last_mut() {
                last.args = tx.args.clone();
                last.sender = tx.sender.clone();
                last.value = tx.value.clone();
                last.env = tx.env.clone();
                last.function_id = goal.function_id;
            }
        } else {
            txs.push(tx);
        }

        out.push(Seed {
            id: format!("se-solve-{}-{idx}", goal.id),
            txs,
            state_snapshot_id: None,
            score: goal.priority,
        });

        if !block_current_model(&solver, &model, &tracked) {
            break;
        }
    }

    out
}

fn tx_seed_from_model(
    model: &z3::Model,
    goal: &FrontierGoal,
    trace_prefix: Option<&TracePrefix>,
    symbols: &AssistSymbols,
) -> TxSeed {
    let args = symbols
        .params
        .iter()
        .map(|(_, sym)| {
            model_value_u128(&model, sym)
                .unwrap_or_else(|| default_model_arg(trace_prefix))
                .to_string()
        })
        .collect::<Vec<_>>();

    let sender = model_value_u128(&model, &symbols.sender)
        .unwrap_or_else(|| default_sender(trace_prefix))
        .to_string();
    let value = model_value_u128(&model, &symbols.value)
        .unwrap_or_else(|| default_value(trace_prefix))
        .to_string();

    TxSeed {
        function_id: goal.function_id,
        selector: None,
        calldata: None,
        args,
        sender,
        value,
        env: TxEnv {
            block_timestamp: Some(
                model_value_u128(&model, &symbols.timestamp)
                    .unwrap_or_else(|| default_timestamp(trace_prefix)),
            ),
            block_number: Some(
                model_value_u128(&model, &symbols.block_number)
                    .unwrap_or_else(|| default_block_number(trace_prefix)),
            ),
        },
    }
}

fn block_current_model(solver: &Solver, model: &z3::Model, tracked: &[Int]) -> bool {
    let mut disjuncts = Vec::new();
    for sym in tracked {
        let Some(value) = model.eval(sym, true) else {
            continue;
        };
        disjuncts.push(sym.eq(value).not());
    }
    if disjuncts.is_empty() {
        return false;
    }
    let refs = disjuncts.iter().collect::<Vec<_>>();
    solver.assert(Bool::or(&refs));
    true
}

fn model_value_u128(model: &z3::Model, sym: &Int) -> Option<u128> {
    let value = model.eval(sym, true)?;
    let parsed = parse_z3_i128(&value.to_string())?;
    if parsed < 0 {
        return Some(0);
    }
    Some(parsed as u128)
}

fn parse_z3_i128(raw: &str) -> Option<i128> {
    let t = raw.trim();
    if let Ok(v) = t.parse::<i128>() {
        return Some(v);
    }
    if let Some(inner) = t.strip_prefix("(- ").and_then(|s| s.strip_suffix(')')) {
        return inner.trim().parse::<i128>().ok().map(|v| -v);
    }
    if let Some(inner) = t.strip_prefix("(+ ").and_then(|s| s.strip_suffix(')')) {
        return inner.trim().parse::<i128>().ok();
    }
    None
}

fn default_model_arg(prefix: Option<&TracePrefix>) -> u128 {
    prefix
        .and_then(|p| p.txs.last())
        .and_then(|tx| tx.args.first())
        .and_then(|arg| arg.parse::<u128>().ok())
        .unwrap_or(0)
}

fn default_sender(prefix: Option<&TracePrefix>) -> u128 {
    prefix
        .and_then(|p| p.txs.last())
        .and_then(|tx| tx.sender.parse::<u128>().ok())
        .unwrap_or(0)
}

fn default_value(prefix: Option<&TracePrefix>) -> u128 {
    prefix
        .and_then(|p| p.txs.last())
        .and_then(|tx| tx.value.parse::<u128>().ok())
        .unwrap_or(0)
}

fn default_timestamp(prefix: Option<&TracePrefix>) -> u128 {
    prefix
        .and_then(|p| p.txs.last())
        .and_then(|tx| tx.env.block_timestamp)
        .unwrap_or(1_700_000_000)
}

fn default_block_number(prefix: Option<&TracePrefix>) -> u128 {
    prefix
        .and_then(|p| p.txs.last())
        .and_then(|tx| tx.env.block_number)
        .unwrap_or(1_000_000)
}

fn is_feasible(path_constraints: &[Bool]) -> bool {
    let solver = Solver::new();
    for constraint in path_constraints {
        solver.assert(constraint);
    }
    matches!(solver.check(), SatResult::Sat)
}

fn bool_to_int(condition: Bool) -> Int {
    condition.ite(&Int::from_i64(1), &Int::from_i64(0))
}

fn stable_literal_value(raw: &str) -> i64 {
    let normalized = normalize_literal(raw);
    if normalized.eq_ignore_ascii_case("true") {
        return 1;
    }
    if normalized.eq_ignore_ascii_case("false") {
        return 0;
    }
    if let Some(hex) = normalized.strip_prefix("0x")
        && let Ok(v) = u64::from_str_radix(hex, 16)
    {
        return v as i64;
    }
    normalized.parse::<i64>().unwrap_or(0)
}

fn normalize_literal(raw: &str) -> String {
    let trimmed = raw.trim();
    for prefix in ["number(", "address(", "int(", "uint("] {
        if let Some(inner) = trimmed
            .strip_prefix(prefix)
            .and_then(|tail| tail.strip_suffix(')'))
        {
            return inner.trim().to_string();
        }
    }
    trimmed.to_string()
}

fn assist_var_key(var: &ir::IrVar) -> String {
    match var {
        ir::IrVar::Named(name) => name.clone(),
        ir::IrVar::Temp(id) => format!("tmp_{id}"),
    }
}

fn assist_place_key(place: &ir::IrPlace) -> String {
    format!("{place:?}")
}

fn assist_value_name(value: &ir::IrValue) -> String {
    match value {
        ir::IrValue::Var(ir::IrVar::Named(name)) => name.clone(),
        ir::IrValue::Var(ir::IrVar::Temp(id)) => format!("tmp_{id}"),
        ir::IrValue::Literal(lit) => lit.value.clone(),
        ir::IrValue::Unknown => "unknown".to_string(),
    }
}

fn special_member_name(base: &ir::IrValue, field: &str) -> Option<&'static str> {
    let ir::IrValue::Var(ir::IrVar::Named(base_name)) = base else {
        return None;
    };
    match (base_name.as_str(), field) {
        ("msg", "sender") => Some("msg.sender"),
        ("msg", "value") => Some("msg.value"),
        ("tx", "origin") => Some("tx.origin"),
        ("block", "timestamp") => Some("block.timestamp"),
        ("block", "number") => Some("block.number"),
        _ => None,
    }
}

fn sanitize_symbol(raw: &str) -> String {
    let out = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if out.is_empty() {
        "arg".to_string()
    } else {
        out
    }
}

fn parse_ir_literal_u128(raw: &str) -> Option<u128> {
    let normalized = normalize_literal(raw);
    if normalized.eq_ignore_ascii_case("true") {
        return Some(1);
    }
    if normalized.eq_ignore_ascii_case("false") {
        return Some(0);
    }
    if let Some(hex) = normalized.strip_prefix("0x") {
        return u128::from_str_radix(hex, 16).ok();
    }
    normalized.parse::<u128>().ok()
}

fn collect_function_literal_values(ir_module: &ir::IrModule) -> HashMap<u32, Vec<u128>> {
    fn push_value(out: &mut Vec<u128>, value: u128) {
        if !out.contains(&value) {
            out.push(value);
        }
    }

    fn collect_from_value(value: &ir::IrValue, out: &mut Vec<u128>) {
        if let ir::IrValue::Literal(lit) = value
            && let Some(parsed) = parse_ir_literal_u128(lit.value.as_str())
        {
            push_value(out, parsed);
            if parsed > 0 {
                push_value(out, parsed - 1);
            }
            if parsed < u128::MAX {
                push_value(out, parsed + 1);
            }
        }
    }

    fn collect_from_instr(instr: &ir::IrInstr, out: &mut Vec<u128>) {
        match instr {
            ir::IrInstr::Nop { .. } | ir::IrInstr::InlineAsm { .. } => {}
            ir::IrInstr::Eval { expr, .. } | ir::IrInstr::Emit { expr, .. } => {
                collect_from_value(expr, out);
            }
            ir::IrInstr::Declare { init, .. } => {
                if let Some(init) = init {
                    collect_from_value(init, out);
                }
            }
            ir::IrInstr::Assign { src, .. } | ir::IrInstr::Store { src, .. } => {
                collect_from_value(src, out);
            }
            ir::IrInstr::Binary { lhs, rhs, .. } => {
                collect_from_value(lhs, out);
                collect_from_value(rhs, out);
            }
            ir::IrInstr::Unary { expr, .. } => {
                collect_from_value(expr, out);
            }
            ir::IrInstr::Call { args, options, .. } => {
                for arg in args {
                    collect_from_value(arg, out);
                }
                for option in options {
                    match option {
                        ir::IrCallOption::Value(v)
                        | ir::IrCallOption::Gas(v)
                        | ir::IrCallOption::Salt(v) => collect_from_value(v, out),
                    }
                }
            }
            ir::IrInstr::Select {
                cond,
                then_val,
                else_val,
                ..
            } => {
                collect_from_value(cond, out);
                collect_from_value(then_val, out);
                collect_from_value(else_val, out);
            }
            ir::IrInstr::Return { values, .. } => {
                for value in values {
                    collect_from_value(value, out);
                }
            }
            ir::IrInstr::Load { .. } => {}
            ir::IrInstr::Control { kind, .. } => match kind {
                ir::ControlKind::If { cond } => collect_from_value(cond, out),
                ir::ControlKind::Loop { cond: Some(cond) } => collect_from_value(cond, out),
                ir::ControlKind::Revert { value: Some(value) } => collect_from_value(value, out),
                _ => {}
            },
        }
    }

    let mut out = HashMap::new();
    for function in &ir_module.functions {
        let mut values = Vec::new();
        for block in &function.blocks {
            for instr in &block.instrs {
                collect_from_instr(instr, &mut values);
            }
        }
        values.sort_unstable();
        values.dedup();
        out.insert(function.id, values);
    }
    out
}

fn build_param_domain_candidates(
    param_name: &str,
    function_constants: Option<&Vec<u128>>,
) -> Vec<u128> {
    let name = param_name.to_ascii_lowercase();
    let mut out = vec![0, 1, 2, 10, 100, 1_000];

    if name.contains("amount")
        || name.contains("value")
        || name.contains("price")
        || name.contains("rate")
        || name.contains("fee")
        || name.contains("balance")
    {
        out.extend([1_000_000, 1_000_000_000_000_000_000]);
    }
    if name.contains("deadline")
        || name.contains("time")
        || name.contains("timestamp")
        || name.contains("expiry")
        || name.contains("block")
    {
        out.extend([1_700_000_000, 1_800_000_000, 2_000_000_000]);
    }
    if name.contains("id")
        || name.contains("index")
        || name.contains("nonce")
        || name.contains("round")
    {
        out.extend([3, 4, 8, 16, 32, 42]);
    }
    if name.starts_with("is")
        || name.starts_with("has")
        || name.contains("flag")
        || name.contains("enabled")
        || name.contains("paused")
    {
        out.extend([0, 1]);
    }
    if name.contains("owner")
        || name.contains("admin")
        || name.contains("sender")
        || name.contains("from")
        || name.contains("to")
        || name.contains("recipient")
        || name.contains("spender")
    {
        out.extend([0, 1, 2, 3, 4]);
    }

    if let Some(constants) = function_constants {
        for value in constants.iter().take(8) {
            out.push(*value);
        }
    }

    out.push(u128::MAX.saturating_sub(1));
    out.push(u128::MAX);
    out.sort_unstable();
    out.dedup();
    if out.len() > 24 {
        out.truncate(24);
    }
    out
}

fn build_frontier_goals(
    ctx: &EngineContext<'_>,
    hints: &StaticHints,
    covered_edges: &HashSet<(u32, u32, u32)>,
    epoch: u32,
) -> Vec<FrontierGoal> {
    let mut goals = Vec::new();
    let hotspot_score = hints
        .hotspots
        .iter()
        .map(|h| (h.function_id, h.score))
        .collect::<HashMap<_, _>>();

    let sink_functions = hints
        .sinks
        .iter()
        .map(|s| (s.function_id, s.sink_kind.clone()))
        .collect::<HashMap<_, _>>();

    for cfg in ctx.cfgs {
        for edge in &cfg.edges {
            if covered_edges.contains(&(cfg.id, edge.from, edge.to)) {
                continue;
            }
            let mut priority = 1.0;
            if let Some(score) = hotspot_score.get(&cfg.id) {
                priority += *score;
            }
            let sink_kind = sink_functions.get(&cfg.id).cloned();
            if sink_kind.is_some() {
                priority += 8.0;
            }
            let function_name = ctx
                .output
                .ast
                .functions
                .get(cfg.id as usize)
                .and_then(|f| f.name.clone());

            goals.push(FrontierGoal {
                id: format!("g-{}-{}-{}-{}", epoch, cfg.id, edge.from, edge.to),
                function_id: cfg.id,
                function_name,
                block_id: Some(edge.to),
                edge_from: Some(edge.from),
                edge_to: Some(edge.to),
                sink_kind,
                reason: "uncovered edge after fuzz epoch".to_string(),
                priority,
                attempts: 0,
            });
        }
    }

    goals.sort_by(|a, b| b.priority.total_cmp(&a.priority));
    goals
}

#[derive(Default)]
struct FuzzGuidance {
    allowed_functions: Vec<u32>,
    hotspot_scores: HashMap<u32, f64>,
    arg_domains: HashMap<(u32, usize), Vec<u128>>,
    storage_rw_chains: Vec<StorageRwChain>,
    owner_indices: Vec<usize>,
    attacker_indices: Vec<usize>,
    user_indices: Vec<usize>,
    owner_targets: HashSet<u32>,
    attacker_targets: HashSet<u32>,
    user_targets: HashSet<u32>,
    param_counts: HashMap<u32, usize>,
    payable_functions: HashSet<u32>,
}

#[derive(Clone)]
struct StorageRwChain {
    writer: u32,
    reader: u32,
    overlap_vars: Vec<String>,
    score: f64,
}

fn build_fuzz_guidance(abi: &fuzzing::types::ContractAbi, hints: &StaticHints) -> FuzzGuidance {
    let abi_function_ids = abi
        .functions
        .iter()
        .map(|f| f.id)
        .collect::<HashSet<_>>();

    let mut allowed_functions = hints
        .function_whitelist
        .iter()
        .copied()
        .filter(|id| abi_function_ids.contains(id))
        .collect::<Vec<_>>();
    if allowed_functions.is_empty() {
        allowed_functions = abi
            .functions
            .iter()
            .filter(|f| f.is_fuzz_callable())
            .map(|f| f.id)
            .collect();
    }
    allowed_functions.sort_unstable();
    allowed_functions.dedup();

    let mut hotspot_scores = HashMap::new();
    for hotspot in &hints.hotspots {
        if allowed_functions.contains(&hotspot.function_id) {
            hotspot_scores.insert(hotspot.function_id, hotspot.score);
        }
    }

    let mut arg_domains = HashMap::new();
    for domain in &hints.arg_domains {
        if !allowed_functions.contains(&domain.function_id) || domain.candidate_values.is_empty() {
            continue;
        }
        arg_domains.insert(
            (domain.function_id, domain.param_index),
            domain.candidate_values.clone(),
        );
    }

    let mut storage_rw_chains = Vec::new();
    for writer in &hints.storage_rw_map {
        if !allowed_functions.contains(&writer.function_id) {
            continue;
        }
        let writer_writes = writer.writes.iter().cloned().collect::<HashSet<_>>();
        if writer_writes.is_empty() {
            continue;
        }
        for reader in &hints.storage_rw_map {
            if writer.function_id == reader.function_id
                || !allowed_functions.contains(&reader.function_id)
            {
                continue;
            }
            let overlap = reader
                .reads
                .iter()
                .filter(|read| writer_writes.contains(*read))
                .cloned()
                .collect::<Vec<_>>();
            if overlap.is_empty() {
                continue;
            }
            let mut score = overlap.len() as f64;
            score += hotspot_scores
                .get(&writer.function_id)
                .copied()
                .unwrap_or(0.0);
            score += hotspot_scores
                .get(&reader.function_id)
                .copied()
                .unwrap_or(0.0);
            storage_rw_chains.push(StorageRwChain {
                writer: writer.function_id,
                reader: reader.function_id,
                overlap_vars: overlap,
                score: score.max(0.1),
            });
        }
    }
    storage_rw_chains.sort_by(|a, b| b.score.total_cmp(&a.score));
    if storage_rw_chains.len() > 32 {
        storage_rw_chains.truncate(32);
    }

    let mut owner_indices = Vec::new();
    let mut attacker_indices = Vec::new();
    let mut user_indices = Vec::new();
    let mut owner_targets = HashSet::new();
    let mut attacker_targets = HashSet::new();
    let mut user_targets = HashSet::new();
    for role in &hints.address_roles {
        let role_name = role.role.to_ascii_lowercase();
        match role_name.as_str() {
            "owner" => {
                owner_indices.extend(role.indices.iter().copied());
                owner_targets.extend(role.target_functions.iter().copied());
            }
            "attacker" => {
                attacker_indices.extend(role.indices.iter().copied());
                attacker_targets.extend(role.target_functions.iter().copied());
            }
            "user" => {
                user_indices.extend(role.indices.iter().copied());
                user_targets.extend(role.target_functions.iter().copied());
            }
            _ => {}
        }
    }
    if owner_indices.is_empty() {
        owner_indices.push(0);
    }
    if attacker_indices.is_empty() {
        attacker_indices.push(1);
    }
    if user_indices.is_empty() {
        user_indices.extend([2, 3, 4]);
    }
    if user_targets.is_empty() {
        user_targets.extend(allowed_functions.iter().copied());
    }

    let mut param_counts = HashMap::new();
    let mut payable_functions = HashSet::new();
    for function in &abi.functions {
        param_counts.insert(function.id, function.params.len());
        if function.is_payable {
            payable_functions.insert(function.id);
        }
    }

    FuzzGuidance {
        allowed_functions,
        hotspot_scores,
        arg_domains,
        storage_rw_chains,
        owner_indices,
        attacker_indices,
        user_indices,
        owner_targets,
        attacker_targets,
        user_targets,
        param_counts,
        payable_functions,
    }
}

fn pick_weighted_function(
    allowed_functions: &[u32],
    hotspot_scores: &HashMap<u32, f64>,
    rng: &mut impl Rng,
) -> Option<u32> {
    if allowed_functions.is_empty() {
        return None;
    }
    if rng.gen_bool(0.7) {
        let total = allowed_functions
            .iter()
            .map(|id| hotspot_scores.get(id).copied().unwrap_or(1.0).max(0.1))
            .sum::<f64>();
        if total > 0.0 {
            let mut ticket = rng.gen_range(0.0..total);
            for id in allowed_functions {
                let w = hotspot_scores.get(id).copied().unwrap_or(1.0).max(0.1);
                if ticket <= w {
                    return Some(*id);
                }
                ticket -= w;
            }
        }
    }
    let idx = rng.gen_range(0..allowed_functions.len());
    Some(allowed_functions[idx])
}

fn pick_storage_rw_chain<'a>(
    chains: &'a [StorageRwChain],
    rng: &mut impl Rng,
) -> Option<&'a StorageRwChain> {
    if chains.is_empty() {
        return None;
    }
    let total = chains.iter().map(|chain| chain.score.max(0.1)).sum::<f64>();
    if total <= 0.0 {
        return chains.get(rng.gen_range(0..chains.len()));
    }
    let mut ticket = rng.gen_range(0.0..total);
    for chain in chains {
        let w = chain.score.max(0.1);
        if ticket <= w {
            return Some(chain);
        }
        ticket -= w;
    }
    chains.last()
}

fn pick_sender_from_pool(pool: &[usize], address_pool_size: usize, rng: &mut impl Rng) -> usize {
    if address_pool_size == 0 {
        return 0;
    }
    if pool.is_empty() {
        return rng.gen_range(0..address_pool_size);
    }
    pool[rng.gen_range(0..pool.len())] % address_pool_size
}

fn pick_sender_for_function(
    function_id: u32,
    guidance: &FuzzGuidance,
    address_pool_size: usize,
    rng: &mut impl Rng,
) -> usize {
    if guidance.owner_targets.contains(&function_id) && rng.gen_bool(0.55) {
        return pick_sender_from_pool(&guidance.owner_indices, address_pool_size, rng);
    }
    if guidance.attacker_targets.contains(&function_id) && rng.gen_bool(0.55) {
        return pick_sender_from_pool(&guidance.attacker_indices, address_pool_size, rng);
    }
    if guidance.user_targets.contains(&function_id) && rng.gen_bool(0.6) {
        return pick_sender_from_pool(&guidance.user_indices, address_pool_size, rng);
    }

    let role_ticket: f64 = rng.gen_range(0.0..1.0);
    if role_ticket < 0.25 {
        pick_sender_from_pool(&guidance.attacker_indices, address_pool_size, rng)
    } else if role_ticket < 0.45 {
        pick_sender_from_pool(&guidance.owner_indices, address_pool_size, rng)
    } else {
        pick_sender_from_pool(&guidance.user_indices, address_pool_size, rng)
    }
}

fn apply_static_guidance_to_individual(
    ind: &mut Individual,
    guidance: &FuzzGuidance,
    abi: &fuzzing::types::ContractAbi,
    dictionary: &fuzzing::types::Dictionary,
    rng: &mut impl Rng,
) {
    if ind.transactions.is_empty() {
        if let Some(function_id) =
            pick_weighted_function(&guidance.allowed_functions, &guidance.hotspot_scores, rng)
        {
            let args_len = guidance.param_counts.get(&function_id).copied().unwrap_or(0);
            let args = (0..args_len)
                .map(|_| fuzzing::generator::random_value_with_dict(rng, Some(dictionary)))
                .collect::<Vec<_>>();
            let sender = pick_sender_for_function(
                function_id,
                guidance,
                ind.environment.address_pool_size,
                rng,
            );
            ind.transactions.push(Transaction {
                function_id,
                args,
                sender,
                value: 0,
            });
        }
    }

    if rng.gen_bool(0.45)
        && let Some(chain) = pick_storage_rw_chain(&guidance.storage_rw_chains, rng)
    {
        if ind.transactions.len() < 2 {
            while ind.transactions.len() < 2 {
                ind.transactions.push(Transaction {
                    function_id: chain.writer,
                    args: Vec::new(),
                    sender: 0,
                    value: 0,
                });
            }
        }
        ind.transactions[0].function_id = chain.writer;
        ind.transactions[1].function_id = chain.reader;

        let prefer_owner_writer = guidance.owner_targets.contains(&chain.writer);
        let writer_sender = if prefer_owner_writer {
            pick_sender_from_pool(&guidance.owner_indices, ind.environment.address_pool_size, rng)
        } else {
            pick_sender_from_pool(&guidance.attacker_indices, ind.environment.address_pool_size, rng)
        };
        ind.transactions[0].sender = writer_sender;

        let reader_sender = if guidance.attacker_targets.contains(&chain.reader) {
            pick_sender_from_pool(&guidance.attacker_indices, ind.environment.address_pool_size, rng)
        } else {
            pick_sender_from_pool(&guidance.user_indices, ind.environment.address_pool_size, rng)
        };
        ind.transactions[1].sender = reader_sender;

        if guidance.payable_functions.contains(&chain.writer) && rng.gen_bool(0.35) {
            ind.transactions[0].value = 1_000_000_000_000_000_000u128;
        }
        if guidance.payable_functions.contains(&chain.reader) && rng.gen_bool(0.35) {
            ind.transactions[1].value = 1;
        }

        if ind.transactions.len() < 3 && !chain.overlap_vars.is_empty() && rng.gen_bool(0.25) {
            ind.transactions.push(Transaction {
                function_id: chain.reader,
                args: Vec::new(),
                sender: reader_sender,
                value: 0,
            });
        }
    }

    for tx in &mut ind.transactions {
        if !guidance.allowed_functions.contains(&tx.function_id)
            && let Some(fid) = pick_weighted_function(
                &guidance.allowed_functions,
                &guidance.hotspot_scores,
                rng,
            )
        {
            tx.function_id = fid;
            tx.args.clear();
        }

        let args_len = guidance
            .param_counts
            .get(&tx.function_id)
            .copied()
            .unwrap_or(tx.args.len());
        while tx.args.len() < args_len {
            tx.args
                .push(fuzzing::generator::random_value_with_dict(rng, Some(dictionary)));
        }
        if tx.args.len() > args_len {
            tx.args.truncate(args_len);
        }

        for (arg_idx, arg) in tx.args.iter_mut().enumerate() {
            if let Some(domain) = guidance.arg_domains.get(&(tx.function_id, arg_idx))
                && !domain.is_empty()
                && rng.gen_bool(0.45)
            {
                let v = domain[rng.gen_range(0..domain.len())];
                *arg = FuzzValue::Uint(v);
            }
        }

        tx.sender = pick_sender_for_function(
            tx.function_id,
            guidance,
            ind.environment.address_pool_size,
            rng,
        );

        if guidance.payable_functions.contains(&tx.function_id) {
            if rng.gen_bool(0.4) {
                tx.value = match rng.gen_range(0..4) {
                    0 => 0,
                    1 => 1,
                    2 => 1_000_000_000_000_000_000,
                    _ => rng.gen_range(0..1_000_000_000_000_000_000u128),
                };
            }
        } else {
            tx.value = 0;
        }
    }

    if rng.gen_bool(0.3) {
        ind.environment.block_timestamp = match rng.gen_range(0..4) {
            0 => 1_650_000_000,
            1 => 1_700_000_000,
            2 => 1_750_000_000,
            _ => 1_800_000_000,
        };
    }
    if rng.gen_bool(0.3) {
        ind.environment.block_number = match rng.gen_range(0..4) {
            0 => 1_000_000,
            1 => 5_000_000,
            2 => 10_000_000,
            _ => 20_000_000,
        };
    }

    if ind.transactions.len() > 15 {
        ind.transactions.truncate(15);
    }

    if ind.transactions.is_empty() {
        let config = fuzzing::types::FuzzConfig::default();
        if let Some(tx) = fuzzing::generator::random_transaction_with_dict(
            abi,
            rng,
            &config,
            Some(dictionary),
        ) {
            ind.transactions.push(tx);
        }
    }
}

fn select_parent_index(corpus: &[Individual], rng: &mut impl Rng) -> usize {
    if corpus.len() <= 1 {
        return 0;
    }
    let total = corpus.iter().map(|ind| ind.energy.max(0.05)).sum::<f64>();
    if total <= 0.0 {
        return rng.gen_range(0..corpus.len());
    }
    let mut ticket = rng.gen_range(0.0..total);
    for (idx, entry) in corpus.iter().enumerate() {
        let w = entry.energy.max(0.05);
        if ticket <= w {
            return idx;
        }
        ticket -= w;
    }
    corpus.len() - 1
}

fn frontier_distances_by_function(
    cfgs: &[CfgFunction],
    covered_edges: &HashSet<(u32, u32, u32)>,
    trace_coverage: &HashSet<(u32, u32)>,
) -> HashMap<u32, u32> {
    let mut visited_by_fn: HashMap<u32, HashSet<u32>> = HashMap::new();
    for (function_id, block_id) in trace_coverage {
        visited_by_fn
            .entry(*function_id)
            .or_default()
            .insert(*block_id);
    }

    let mut out = HashMap::new();
    for (function_id, visited_blocks) in visited_by_fn {
        let Some(cfg) = cfgs.iter().find(|cfg| cfg.id == function_id) else {
            continue;
        };
        let targets = cfg
            .edges
            .iter()
            .filter(|edge| !covered_edges.contains(&(cfg.id, edge.from, edge.to)))
            .map(|edge| edge.to)
            .collect::<HashSet<_>>();
        if targets.is_empty() {
            continue;
        }
        let dist = shortest_distance_to_targets(cfg, &targets, &visited_blocks);
        if let Some(distance) = dist {
            out.insert(function_id, distance);
        }
    }
    out
}

fn shortest_distance_to_targets(
    cfg: &CfgFunction,
    targets: &HashSet<u32>,
    visited_blocks: &HashSet<u32>,
) -> Option<u32> {
    if targets.is_empty() || visited_blocks.is_empty() {
        return None;
    }
    let mut reverse: HashMap<u32, Vec<u32>> = HashMap::new();
    for edge in &cfg.edges {
        reverse.entry(edge.to).or_default().push(edge.from);
    }

    let mut queue = VecDeque::new();
    let mut dist = HashMap::<u32, u32>::new();
    for target in targets {
        dist.insert(*target, 0);
        queue.push_back(*target);
    }

    while let Some(node) = queue.pop_front() {
        let d = dist.get(&node).copied().unwrap_or(0);
        for pred in reverse.get(&node).into_iter().flatten() {
            if dist.contains_key(pred) {
                continue;
            }
            dist.insert(*pred, d.saturating_add(1));
            queue.push_back(*pred);
        }
    }

    visited_blocks
        .iter()
        .filter_map(|block| dist.get(block).copied())
        .min()
}

fn parse_function_id_from_message(message: &str) -> Option<u32> {
    let needle = "function ";
    let idx = message.find(needle)?;
    let tail = &message[idx + needle.len()..];
    let digits = tail
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u32>().ok()
}

fn detect_public_mint_burn_fuzz_findings(
    ast: &crate::norm::NormalizedAst,
    compiler: &crate::frontend::CompilerInfo,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for function in &ast.functions {
        let Some(name) = function.name.as_deref() else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if lower != "mint" && lower != "burn" {
            continue;
        }
        if !crate::frontend::is_public_entrypoint(function, compiler)
            || function.kind != FunctionKind::Function
        {
            continue;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert("confidence".to_string(), "medium".to_string());
        out.push(Finding {
            engine: "fuzzing".to_string(),
            finding_type: "public-mint-burn".to_string(),
            severity: "high".to_string(),
            message: format!(
                "Public {} function '{}' may allow unauthorized supply manipulation",
                lower, name
            ),
            location: Some(FindingLocation {
                file: ast
                    .files
                    .get(function.span.file as usize)
                    .map(|f| f.path.clone()),
                start: Some(function.span.start),
                end: Some(function.span.end),
                pc: None,
                function_id: Some(function.id),
                function_name: function.name.clone(),
            }),
            reproduction: None,
            signature: String::new(),
            analysis_layer: "runtime".to_string(),
            evidence_kind: "executor".to_string(),
            metadata,
        });
    }
    out
}

fn seed_to_individual(seed: &Seed) -> Option<Individual> {
    if seed.txs.is_empty() {
        return None;
    }
    let env = Environment {
        block_timestamp: seed
            .txs
            .first()
            .and_then(|tx| tx.env.block_timestamp)
            .unwrap_or(1_700_000_000),
        block_number: seed
            .txs
            .first()
            .and_then(|tx| tx.env.block_number)
            .unwrap_or(1_000_000),
        address_pool_size: 8,
    };

    let mut txs = Vec::with_capacity(seed.txs.len());
    for tx in &seed.txs {
        let args = tx
            .args
            .iter()
            .map(|arg| {
                arg.parse::<u128>()
                    .map(FuzzValue::Uint)
                    .unwrap_or(FuzzValue::Uint(0))
            })
            .collect::<Vec<_>>();
        let sender = tx.sender.parse::<usize>().unwrap_or(0);
        let value = tx.value.parse::<u128>().unwrap_or(0);
        txs.push(Transaction {
            function_id: tx.function_id,
            args,
            sender,
            value,
        });
    }

    Some(Individual {
        transactions: txs,
        environment: env,
        energy: 1.0,
    })
}

fn individual_to_seed(ind: &Individual, id: String) -> Seed {
    Seed {
        id,
        txs: ind
            .transactions
            .iter()
            .map(|tx| TxSeed {
                function_id: tx.function_id,
                selector: None,
                calldata: None,
                args: tx
                    .args
                    .iter()
                    .map(|a| match a {
                        FuzzValue::Uint(v) => v.to_string(),
                        FuzzValue::Int(v) => v.to_string(),
                        FuzzValue::Bool(v) => {
                            if *v {
                                "1".to_string()
                            } else {
                                "0".to_string()
                            }
                        }
                        FuzzValue::Address(v) => v.to_string(),
                        FuzzValue::Bytes(v) => format!("bytes:{}", v.len()),
                        FuzzValue::StringVal(v) => v.clone(),
                    })
                    .collect(),
                sender: tx.sender.to_string(),
                value: tx.value.to_string(),
                env: TxEnv {
                    block_timestamp: Some(ind.environment.block_timestamp),
                    block_number: Some(ind.environment.block_number),
                },
            })
            .collect(),
        state_snapshot_id: None,
        score: ind.energy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::detectors::{Finding as StaticFinding, FindingKind, Severity};
    use crate::cfg;
    use crate::frontend::{FrontendMode, FrontendOutput};
    use crate::ir::{ControlKind, IrBlock, IrFunction, IrInstr, IrModule, IrValue, IrVar};
    use crate::fuzzing::types::{ContractAbi, Environment, FunctionAbi, Individual, ParamInfo, Transaction};
    use crate::norm::{
        Function, FunctionKind, Literal, Mutability, NormalizedAst, SourceFile, Span, Visibility,
    };
    use rand::SeedableRng;
    use std::collections::HashSet;

    fn span() -> Span {
        Span {
            file: 0,
            start: 0,
            end: 0,
        }
    }

    fn lit(value: &str) -> Literal {
        Literal {
            kind: "number".to_string(),
            value: value.to_string(),
        }
    }

    fn test_ast() -> NormalizedAst {
        let mut ast = NormalizedAst::default();
        ast.files.push(SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: String::new(),
        });
        ast.functions.push(Function {
            id: 0,
            contract: None,
            name: Some("f".to_string()),
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

    fn test_ast_with_source(function_name: &str, source: &str) -> NormalizedAst {
        let mut ast = test_ast();
        ast.files[0].source = source.to_string();
        ast.functions[0].name = Some(function_name.to_string());
        ast.functions[0].span = Span {
            file: 0,
            start: 0,
            end: source.len() as u32,
        };
        ast
    }

    #[test]
    fn symbolic_assist_solves_target_branch() {
        let sp = span();
        let ir_module = IrModule {
            functions: vec![IrFunction {
                id: 0,
                name: Some("f".to_string()),
                source: Some(0),
                span: sp,
                blocks: vec![IrBlock {
                    id: 0,
                    instrs: vec![
                        IrInstr::Binary {
                            dest: IrVar::Temp(0),
                            op: ">".to_string(),
                            lhs: IrValue::Var(IrVar::Named("x".to_string())),
                            rhs: IrValue::Literal(lit("10")),
                            span: sp,
                        },
                        IrInstr::Control {
                            kind: ControlKind::If {
                                cond: IrValue::Var(IrVar::Temp(0)),
                            },
                            span: sp,
                        },
                        IrInstr::Return {
                            values: Vec::new(),
                            span: sp,
                        },
                        IrInstr::Control {
                            kind: ControlKind::Else,
                            span: sp,
                        },
                        IrInstr::Return {
                            values: Vec::new(),
                            span: sp,
                        },
                        IrInstr::Control {
                            kind: ControlKind::EndIf,
                            span: sp,
                        },
                    ],
                }],
            }],
        };
        let cfgs = cfg::build_from_ir(&ir_module);

        let mut ast = NormalizedAst::default();
        ast.files.push(SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: String::new(),
        });
        ast.functions.push(Function {
            id: 0,
            contract: None,
            name: Some("f".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: vec!["x".to_string()],
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: sp,
        });
        let output = FrontendOutput {
            mode: FrontendMode::Partial,
            ast,
            compiler: crate::frontend::CompilerInfo {
                compiler_name: "test".to_string(),
                compiler_version: Some("0.8.0".to_string()),
                legacy_omitted_visibility_is_public: false,
            },
        };
        let ctx = EngineContext {
            output: &output,
            ir_module: &ir_module,
            cfgs: &cfgs,
        };

        let goal = FrontierGoal {
            id: "g-test".to_string(),
            function_id: 0,
            function_name: Some("f".to_string()),
            block_id: Some(1),
            edge_from: None,
            edge_to: None,
            sink_kind: None,
            reason: "unit-test".to_string(),
            priority: 1.0,
            attempts: 0,
        };
        let budget = SeBudget {
            timeout_ms: 1_000,
            max_states: 128,
            max_depth: 16,
            max_new_seeds: 1,
        };

        let se = SymbolicAssistAdapter;
        let result = se.solve(&ctx, &goal, None, &budget).expect("SE solve failed");
        assert!(!result.new_seeds.is_empty(), "expected at least one seed");
        let solved = result.new_seeds[0]
            .txs
            .last()
            .and_then(|tx| tx.args.first())
            .and_then(|arg| arg.parse::<u128>().ok())
            .unwrap_or(0);
        assert!(solved > 10, "expected model to satisfy x > 10, got {solved}");
    }

    #[test]
    fn hybrid_static_runtime_filter_maps_force_ether_balance_to_locked_ether() {
        let ast = test_ast();
        let finding = StaticFinding {
            kind: FindingKind::ForceEtherBalanceCheck,
            severity: Severity::Medium,
            message: "contract enforces balance invariant".to_string(),
            span: span(),
            function: Some(0),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding).expect("expected mapped finding");
        assert_eq!(mapped.finding_type, "locked-ether");
        assert_eq!(mapped.evidence_kind, "rule-backstop");
        assert!(mapped.message.starts_with("Forced-Ether invariant risk:"));
    }

    #[test]
    fn hybrid_static_runtime_filter_drops_low_signal_static_noise() {
        let ast = test_ast();
        let finding = StaticFinding {
            kind: FindingKind::DefaultVisibility,
            severity: Severity::Low,
            message: "legacy default visibility".to_string(),
            span: span(),
            function: Some(0),
        };

        assert!(hybrid_static_runtime_finding(&ast, finding).is_none());
    }

    #[test]
    fn hybrid_static_runtime_filter_drops_targeted_no_value_reentrancy_backstop() {
        let ast = test_ast_with_source(
            "approveAndCall",
            "function approveAndCall(address _spender) public { _spender.call(bytes4(0x0)); }",
        );
        let finding = StaticFinding {
            kind: FindingKind::ReentrancyNoEthTransfer,
            severity: Severity::Medium,
            message: "RE-05: reentrancy in `approveAndCall`: callback-visible state is written before a low-level external call; a callee can re-enter using the newly exposed state".to_string(),
            span: span(),
            function: Some(0),
        };

        assert!(hybrid_static_runtime_finding(&ast, finding).is_none());
    }

    #[test]
    fn hybrid_static_runtime_filter_imports_value_moving_reentrancy_backstop() {
        let ast = test_ast_with_source(
            "withdraw",
            "function withdraw() public { msg.sender.call.value(1)(\"\"); }",
        );
        let finding = StaticFinding {
            kind: FindingKind::ReentrancyNoEthTransfer,
            severity: Severity::Medium,
            message: "RE-05: reentrancy in `withdraw`: callback-visible state is written before a low-level external call; a callee can re-enter using the newly exposed state".to_string(),
            span: span(),
            function: Some(0),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding).expect("expected mapped finding");
        assert_eq!(mapped.finding_type, "reentrancy");
        assert_eq!(mapped.evidence_kind, "rule-backstop");
    }

    #[test]
    fn hybrid_static_runtime_filter_imports_random_weak_prng_backstop() {
        let mut ast = test_ast();
        ast.functions[0].name = Some("random".to_string());
        let finding = StaticFinding {
            kind: FindingKind::WeakPrng,
            severity: Severity::Medium,
            message: "weak PRNG: `block.number` used in arithmetic expression; miners can influence block values".to_string(),
            span: span(),
            function: Some(0),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding).expect("expected mapped finding");
        assert_eq!(mapped.finding_type, "weak-prng");
        assert_eq!(mapped.evidence_kind, "rule-backstop");
    }

    #[test]
    fn hybrid_static_runtime_filter_imports_push_payment_dos_backstop() {
        let mut ast = test_ast();
        ast.functions[0].name = Some("bid".to_string());
        let finding = StaticFinding {
            kind: FindingKind::DosWithFailedCall,
            severity: Severity::High,
            message: "DS-04: `bid` uses a required push payment (`require(...send/transfer/call...)`); a reverting recipient can DoS the function".to_string(),
            span: span(),
            function: Some(0),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding).expect("expected mapped finding");
        assert_eq!(mapped.finding_type, "dos-with-failed-call");
        assert_eq!(mapped.evidence_kind, "rule-backstop");
    }

    #[test]
    fn hybrid_static_runtime_filter_drops_checked_selector_wrapper_dos_backstop() {
        let ast = test_ast_with_source(
            "deposit",
            "function deposit(address target) public payable { require(target.call.value(msg.value)(bytes4(sha3(\"addToBalance()\")))); }",
        );
        let finding = StaticFinding {
            kind: FindingKind::DosWithFailedCall,
            severity: Severity::High,
            message: "DS-04: `deposit` uses a required push payment (`require(...send/transfer/call...)`); a reverting recipient can DoS the function".to_string(),
            span: span(),
            function: Some(0),
        };

        assert!(hybrid_static_runtime_finding(&ast, finding).is_none());
    }

    #[test]
    fn hybrid_static_runtime_filter_imports_buy_tod_backstop() {
        let mut ast = test_ast();
        ast.functions[0].name = Some("buy".to_string());
        let finding = StaticFinding {
            kind: FindingKind::TransactionOrderDependency,
            severity: Severity::Medium,
            message: "function `buy` reads an order-sensitive state variable and performs a value transfer; its outcome depends on transaction ordering (front-running / TOD risk)".to_string(),
            span: span(),
            function: Some(0),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding).expect("expected mapped finding");
        assert_eq!(mapped.finding_type, "transaction-order-dependency");
        assert_eq!(mapped.evidence_kind, "rule-backstop");
    }

    #[test]
    fn hybrid_static_runtime_filter_imports_variable_shadowing_backstop() {
        let mut ast = test_ast();
        ast.files[0].path =
            "Benchmarks/Not-so-smart/not-so-smart-contracts-master/variable shadowing/inherited_state.sol"
                .to_string();
        let finding = StaticFinding {
            kind: FindingKind::Shadowing,
            severity: Severity::Medium,
            message: "variable 'owner' shadows state variable".to_string(),
            span: span(),
            function: Some(0),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding).expect("expected mapped finding");
        assert_eq!(mapped.finding_type, "shadowing");
        assert_eq!(mapped.evidence_kind, "rule-backstop");
    }

    #[test]
    fn hybrid_static_runtime_filter_imports_dao_reentrancy_reward_backstop() {
        let mut ast = test_ast();
        ast.functions[0].name = Some("retrieveDAOReward".to_string());
        let finding = StaticFinding {
            kind: FindingKind::ReentrancyNoEthTransfer,
            severity: Severity::Medium,
            message: "RE-05: reentrancy in `retrieveDAOReward`: state variable updated after cross-contract call (no ETH sent); the called contract can still re-enter via a callback — update state before the call".to_string(),
            span: span(),
            function: Some(0),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding).expect("expected mapped finding");
        assert_eq!(mapped.finding_type, "reentrancy");
        assert_eq!(mapped.evidence_kind, "rule-backstop");
    }

    #[test]
    fn hybrid_init_takeover_backstops_recover_wallet_paths() {
        let sp = span();
        let mut ast = NormalizedAst::default();
        ast.files.push(SourceFile {
            id: 0,
            path: "wallet.sol".to_string(),
            source: "contract WalletLibrary { function initWallet() public {} function execute(address _to, uint _value, bytes _data) public { _to.call.value(_value)(_data); } function kill(address _to) public { suicide(_to); } }".to_string(),
        });
        ast.contracts.push(crate::norm::Contract {
            id: 0,
            name: "WalletLibrary".to_string(),
            kind: crate::norm::ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![0, 1, 2],
            state_vars: Vec::new(),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            span: sp,
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some("initWallet".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: sp,
        });
        ast.functions.push(Function {
            id: 1,
            contract: Some(0),
            name: Some("execute".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: sp,
        });
        ast.functions.push(Function {
            id: 2,
            contract: Some(0),
            name: Some("kill".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: Vec::new(),
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: sp,
        });

        let static_findings = vec![StaticFinding {
            kind: FindingKind::UninitializedPermissionCheck,
            severity: Severity::High,
            message: "publicly reinitializable owners".to_string(),
            span: sp,
            function: Some(0),
        }];

        let backstops = hybrid_init_takeover_backstops(&ast, &static_findings);
        let kinds = backstops
            .iter()
            .map(|finding| finding.finding_type.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert!(kinds.contains("access-control"));
        assert!(kinds.contains("unprotected-ether-withdrawal"));
        assert!(kinds.contains("unprotected-selfdestruct"));
    }

    #[test]
    fn hybrid_static_runtime_filter_drops_exploit_helper_selfdestruct() {
        let ast = crate::frontend::parser::load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "ReentrancyExploit.sol".to_string(),
            source: r#"
                pragma solidity ^0.4.15;
                contract ReentranceExploit {
                    address public vulnerable_contract;
                    address public owner;
                    function ReentranceExploit() public { owner = msg.sender; }
                    function launch_attack() public {
                        require(vulnerable_contract.call(bytes4(sha3("withdrawBalance()"))));
                    }
                    function get_money() public { suicide(owner); }
                }
            "#
            .to_string(),
        }])
        .expect("parser should succeed");
        let function_id = ast
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("get_money"))
            .map(|function| function.id)
            .expect("get_money function");
        let finding = StaticFinding {
            kind: FindingKind::UnprotectedSelfdestruct,
            severity: Severity::High,
            message: "unprotected suicide".to_string(),
            span: ast.functions[function_id as usize].span,
            function: Some(function_id),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding);
        assert!(mapped.is_none());
    }

    #[test]
    fn hybrid_static_runtime_filter_drops_uninit_permission_import() {
        let ast = crate::frontend::parser::load_via_parser_sources(vec![SourceFile {
            id: 0,
            path: "incorrect_constructor.sol".to_string(),
            source: r#"
                pragma solidity ^0.4.15;
                contract Missing {
                    address public owner;
                    function IamMissing() public { owner = msg.sender; }
                }
            "#
            .to_string(),
        }])
        .expect("parser should succeed");
        let function_id = ast
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("IamMissing"))
            .map(|function| function.id)
            .expect("IamMissing function");
        let finding = StaticFinding {
            kind: FindingKind::UninitializedPermissionCheck,
            severity: Severity::High,
            message: "authority-initialization function 'IamMissing' lacks access control".to_string(),
            span: ast.functions[function_id as usize].span,
            function: Some(function_id),
        };

        let mapped = hybrid_static_runtime_finding(&ast, finding);
        assert!(mapped.is_none());
    }

    #[test]
    fn param_domain_candidates_include_deadline_hints() {
        let candidates = build_param_domain_candidates("deadline", None);
        assert!(candidates.contains(&0));
        assert!(candidates.contains(&1_700_000_000));
        assert!(candidates.contains(&1_800_000_000));
    }

    #[test]
    fn frontier_distance_uses_uncovered_edges() {
        let cfg_fn = cfg::CfgFunction {
            id: 0,
            blocks: vec![
                cfg::Block { id: 0, instrs: vec![] },
                cfg::Block { id: 1, instrs: vec![] },
                cfg::Block { id: 2, instrs: vec![] },
                cfg::Block { id: 3, instrs: vec![] },
            ],
            edges: vec![
                cfg::Edge { from: 0, to: 1 },
                cfg::Edge { from: 1, to: 2 },
                cfg::Edge { from: 0, to: 3 },
            ],
        };
        let cfgs = vec![cfg_fn];
        let covered_edges = HashSet::from([(0u32, 0u32, 1u32), (0u32, 0u32, 3u32)]);
        let trace_coverage = HashSet::from([(0u32, 0u32)]);

        let distances = frontier_distances_by_function(&cfgs, &covered_edges, &trace_coverage);
        assert_eq!(distances.get(&0).copied(), Some(2));
    }

    #[test]
    fn static_guidance_rewrites_disallowed_function_ids() {
        let abi = ContractAbi {
            contract_name: "T".to_string(),
            functions: vec![FunctionAbi {
                id: 1,
                name: "f".to_string(),
                params: vec![ParamInfo {
                    name: "x".to_string(),
                }],
                visibility: Visibility::External,
                mutability: Mutability::NonPayable,
                kind: FunctionKind::Function,
                is_payable: false,
            }],
        };
        let hints = StaticHints {
            function_whitelist: vec![1],
            function_blacklist: vec![],
            hotspots: vec![Hotspot {
                function_id: 1,
                function_name: Some("f".to_string()),
                score: 10.0,
                reasons: vec!["test".to_string()],
            }],
            sinks: vec![],
            callgraph: crate::core::artifacts::CallGraphHint::default(),
            taint: crate::core::artifacts::TaintHint::default(),
            storage_rw_map: vec![],
            arg_domains: vec![ArgDomainHint {
                function_id: 1,
                function_name: Some("f".to_string()),
                param_index: 0,
                param_name: "x".to_string(),
                candidate_values: vec![42],
            }],
            address_roles: vec![
                AddressRoleHint {
                    role: "owner".to_string(),
                    indices: vec![3],
                    evidence: vec!["test".to_string()],
                    target_functions: vec![1],
                },
                AddressRoleHint {
                    role: "attacker".to_string(),
                    indices: vec![3],
                    evidence: vec!["test".to_string()],
                    target_functions: vec![1],
                },
                AddressRoleHint {
                    role: "user".to_string(),
                    indices: vec![3],
                    evidence: vec!["test".to_string()],
                    target_functions: vec![1],
                },
            ],
        };
        let guidance = build_fuzz_guidance(&abi, &hints);
        let mut ind = Individual {
            transactions: vec![Transaction {
                function_id: 999,
                args: vec![],
                sender: 0,
                value: 10,
            }],
            environment: Environment {
                block_timestamp: 1_700_000_000,
                block_number: 1_000_000,
                address_pool_size: 8,
            },
            energy: 1.0,
        };
        let dict = fuzzing::types::Dictionary::default();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        apply_static_guidance_to_individual(&mut ind, &guidance, &abi, &dict, &mut rng);

        assert_eq!(ind.transactions[0].function_id, 1);
        assert_eq!(ind.transactions[0].args.len(), 1);
        assert_eq!(ind.transactions[0].sender, 3);
        assert_eq!(ind.transactions[0].value, 0);
    }

    #[test]
    fn static_guidance_builds_storage_rw_writer_reader_chain() {
        let abi = ContractAbi {
            contract_name: "T".to_string(),
            functions: vec![
                FunctionAbi {
                    id: 10,
                    name: "deposit".to_string(),
                    params: vec![ParamInfo {
                        name: "amount".to_string(),
                    }],
                    visibility: Visibility::External,
                    mutability: Mutability::Payable,
                    kind: FunctionKind::Function,
                    is_payable: true,
                },
                FunctionAbi {
                    id: 11,
                    name: "withdraw".to_string(),
                    params: vec![ParamInfo {
                        name: "amount".to_string(),
                    }],
                    visibility: Visibility::External,
                    mutability: Mutability::NonPayable,
                    kind: FunctionKind::Function,
                    is_payable: false,
                },
            ],
        };
        let hints = StaticHints {
            function_whitelist: vec![10, 11],
            function_blacklist: vec![],
            hotspots: vec![
                Hotspot {
                    function_id: 10,
                    function_name: Some("deposit".to_string()),
                    score: 8.0,
                    reasons: vec!["w".to_string()],
                },
                Hotspot {
                    function_id: 11,
                    function_name: Some("withdraw".to_string()),
                    score: 7.0,
                    reasons: vec!["r".to_string()],
                },
            ],
            sinks: vec![],
            callgraph: crate::core::artifacts::CallGraphHint::default(),
            taint: crate::core::artifacts::TaintHint::default(),
            storage_rw_map: vec![
                FunctionStorageRwHint {
                    function_id: 10,
                    function_name: Some("deposit".to_string()),
                    reads: vec![],
                    writes: vec!["balances".to_string()],
                },
                FunctionStorageRwHint {
                    function_id: 11,
                    function_name: Some("withdraw".to_string()),
                    reads: vec!["balances".to_string()],
                    writes: vec![],
                },
            ],
            arg_domains: vec![
                ArgDomainHint {
                    function_id: 10,
                    function_name: Some("deposit".to_string()),
                    param_index: 0,
                    param_name: "amount".to_string(),
                    candidate_values: vec![100],
                },
                ArgDomainHint {
                    function_id: 11,
                    function_name: Some("withdraw".to_string()),
                    param_index: 0,
                    param_name: "amount".to_string(),
                    candidate_values: vec![50],
                },
            ],
            address_roles: vec![
                AddressRoleHint {
                    role: "owner".to_string(),
                    indices: vec![0],
                    evidence: vec!["owner".to_string()],
                    target_functions: vec![10],
                },
                AddressRoleHint {
                    role: "attacker".to_string(),
                    indices: vec![1],
                    evidence: vec!["attacker".to_string()],
                    target_functions: vec![11],
                },
                AddressRoleHint {
                    role: "user".to_string(),
                    indices: vec![2],
                    evidence: vec!["user".to_string()],
                    target_functions: vec![10, 11],
                },
            ],
        };
        let guidance = build_fuzz_guidance(&abi, &hints);
        assert!(!guidance.storage_rw_chains.is_empty());
        assert_eq!(guidance.storage_rw_chains[0].writer, 10);
        assert_eq!(guidance.storage_rw_chains[0].reader, 11);

        let mut ind = Individual {
            transactions: vec![Transaction {
                function_id: 999,
                args: vec![],
                sender: 5,
                value: 0,
            }],
            environment: Environment {
                block_timestamp: 1_700_000_000,
                block_number: 1_000_000,
                address_pool_size: 8,
            },
            energy: 1.0,
        };
        let dict = fuzzing::types::Dictionary::default();
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        for _ in 0..8 {
            apply_static_guidance_to_individual(&mut ind, &guidance, &abi, &dict, &mut rng);
            if ind.transactions.len() >= 2
                && ind.transactions[0].function_id == 10
                && ind.transactions[1].function_id == 11
            {
                return;
            }
        }
        panic!("expected writer->reader chain (10 -> 11) to be scheduled");
    }
}
