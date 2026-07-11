use chainvet_core::artifacts::{Seed, TxEnv, TxSeed};
use chainvet_core::norm::NormalizedAst;
use chainvet_fuzzing::fuzzing::types::{
    ContractAbi, DependencyMap, Environment, FuzzValue, Individual, Transaction, WriteValue,
};
use std::collections::{HashMap, HashSet};
use chainvet_se::symbolic::results::{CoverageWitness, SeFinding, Witness};

#[derive(Debug, Clone, serde::Serialize)]
pub struct HybridSeed {
    pub id: String,
    pub source_kind: String,
    pub confidence: String,
    pub function_id: u32,
    pub path_constraints: Vec<String>,
    pub tx_count: usize,
    pub artifact: Seed,
    #[serde(skip_serializing)]
    pub individual: Individual,
}

pub fn build_hybrid_seeds(
    ast: &NormalizedAst,
    abis: &[ContractAbi],
    findings: &[SeFinding],
) -> Vec<HybridSeed> {
    findings
        .iter()
        .enumerate()
        .filter_map(|(index, finding)| to_seed(ast, abis, finding, index))
        .collect()
}

/// Max total setup transactions prepended to one multi-transaction seed. Bounds
/// the transitive read-after-write walk so a densely-coupled contract can't
/// produce an unboundedly long sequence.
const MAX_SETUP_TXS: usize = 6;

/// Turn SE coverage witnesses into fuzzer seeds. Unlike [`build_hybrid_seeds`]
/// (which only seeds from *findings*), this seeds from every block SE reached.
///
/// For each witnessed block the target function is seeded two ways:
/// 1. **Single transaction** — replays SE's exact args. For an arg-gated block
///    (no storage precondition) this reaches the block deterministically.
/// 2. **Multi transaction** — if the target *reads* storage that other functions
///    *write*, the *transitive* read-after-write setup chain is prepended, so
///    the fuzzer replays a full setup→…→trigger sequence. Blocks gated behind a
///    chain of stateful preconditions (`register()` → `activate()` →
///    `withdraw()`, where each setter has its own precondition) need exactly
///    this. SE explores single functions over symbolic storage, so it never
///    produces the sequence itself — the dependency map supplies it. Setter args
///    are a scaffold the fuzzer mutates; parameterless setters unlock the block
///    immediately.
pub fn build_coverage_seeds(
    abis: &[ContractAbi],
    deps: &DependencyMap,
    coverage_witnesses: &[CoverageWitness],
) -> Vec<Individual> {
    let mut seeds = Vec::new();
    for cw in coverage_witnesses {
        let Some(target_tx) = transaction_for(abis, cw.function_id, &cw.witness) else {
            continue;
        };
        let environment = environment_from_witness(&cw.witness);

        // (1) Single-transaction seed.
        seeds.push(Individual {
            transactions: vec![target_tx.clone()],
            environment: environment.clone(),
            energy: 2.0,
        });

        // (2) Multi-transaction seed: the transitive read-after-write setup
        // chain, ordered so each function's storage reads are satisfied by an
        // earlier transaction, with setup args chosen to satisfy the guards.
        let setup_steps = resolve_setup_path(deps, cw.function_id);
        if setup_steps.is_empty() {
            continue;
        }
        let mut transactions: Vec<Transaction> = setup_steps
            .iter()
            .filter_map(|step| setup_transaction_for(abis, step, &cw.witness))
            .collect();
        if transactions.is_empty() {
            continue;
        }
        transactions.push(target_tx);
        seeds.push(Individual {
            transactions,
            environment,
            // Above the single-tx seed so the setup→trigger sequence is
            // explored preferentially.
            energy: 2.5,
        });
    }
    seeds
}

/// One setup transaction in a resolved chain: the function to call plus any
/// argument overrides chosen so the write it performs satisfies a downstream
/// guard (e.g. call `setMode` with arg 0 = 2 so a later `if (mode == 2)` holds).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupStep {
    function_id: u32,
    /// `(param_index, value)` overrides applied on top of the witness args.
    arg_overrides: Vec<(usize, u128)>,
}

/// The storage value a reader needs a variable to hold to pass its guard.
#[derive(Debug, Clone, Copy)]
enum Desired {
    /// No specific constant known — the variable just needs to be "set"
    /// (non-default). Covers boolean flags and `if (x)` truthiness guards.
    Nonzero,
    /// An `== c` guard demands exactly this value.
    Eq(u128),
}

impl Desired {
    /// The concrete value to write for this desire (1 stands in for "nonzero").
    fn value(self) -> u128 {
        match self {
            Desired::Nonzero => 1,
            Desired::Eq(v) => v,
        }
    }
}

/// Resolve the transitive read-after-write setup chain for `target`: an ordered
/// list of [`SetupStep`]s to run *before* the target so that, for every storage
/// variable read along the chain, an earlier transaction writes it with a value
/// that satisfies the reader's guard.
///
/// Post-order DFS over the dependency graph (edge: reader → a chosen writer of a
/// storage var it reads). Post-order emission guarantees a writer's own
/// prerequisites precede it, and every writer precedes the target. Writer choice
/// is **value-aware** (see [`SetupResolver::choose_writer`]) and falls back to
/// lowest-id when no writer is clearly better, so the result is never worse than
/// a neutral pick. Termination: a recursion-stack guard breaks cycles, the
/// emitted set avoids re-adds, and the length is capped at `MAX_SETUP_TXS`.
fn resolve_setup_path(deps: &DependencyMap, target: u32) -> Vec<SetupStep> {
    let mut resolver = SetupResolver {
        deps,
        ordered: Vec::new(),
        emitted: HashSet::new(),
        on_path: HashSet::new(),
        overrides: HashMap::new(),
    };
    resolver.visit(target, true);
    resolver
        .ordered
        .iter()
        .map(|id| SetupStep {
            function_id: *id,
            arg_overrides: resolver.overrides.get(id).cloned().unwrap_or_default(),
        })
        .collect()
}

struct SetupResolver<'a> {
    deps: &'a DependencyMap,
    ordered: Vec<u32>,
    emitted: HashSet<u32>,
    on_path: HashSet<u32>,
    /// writer id → chosen `(param_index, value)` argument overrides.
    overrides: HashMap<u32, Vec<(usize, u128)>>,
}

impl SetupResolver<'_> {
    /// The value `func_id` needs `var` to hold: the `== c` guard constant if it
    /// has one, otherwise "nonzero" (the variable must simply be set).
    fn desired_for(&self, func_id: u32, var: &str) -> Desired {
        self.deps
            .functions
            .get(&func_id)
            .and_then(|d| d.eq_guards.iter().find(|g| g.var == var))
            .map(|g| Desired::Eq(g.value))
            .unwrap_or(Desired::Nonzero)
    }

    /// Choose the best writer of `var` for `desired` among `candidates`, ranked:
    /// a constant that already satisfies the desire, then a parameter passthrough
    /// (settable to the exact value), then a known-but-wrong constant, then any.
    /// Ties break to the lowest id for determinism.
    fn choose_writer(&self, var: &str, desired: Desired, candidates: &[u32]) -> Option<u32> {
        let rank = |wid: u32| -> u8 {
            let wv = self
                .deps
                .functions
                .get(&wid)
                .and_then(|d| d.write_values.get(var));
            match (wv, desired) {
                (Some(WriteValue::Const(c)), Desired::Eq(v)) if *c == v => 3,
                (Some(WriteValue::Const(c)), Desired::Nonzero) if *c != 0 => 3,
                (Some(WriteValue::Param(_)), _) => 2,
                (Some(WriteValue::Const(_)), _) => 1,
                (None, _) => 0,
            }
        };
        candidates
            .iter()
            .copied()
            .max_by(|a, b| rank(*a).cmp(&rank(*b)).then(b.cmp(a)))
    }

    fn visit(&mut self, func_id: u32, is_target: bool) {
        if self.on_path.contains(&func_id) || (!is_target && self.emitted.contains(&func_id)) {
            return;
        }
        if self.ordered.len() >= MAX_SETUP_TXS {
            return;
        }
        self.on_path.insert(func_id);

        // Storage vars this function reads, sorted for deterministic ordering.
        let reads: Vec<String> = self
            .deps
            .functions
            .get(&func_id)
            .map(|d| {
                let mut v: Vec<String> = d.reads.iter().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default();

        for var in &reads {
            let desired = self.desired_for(func_id, var);
            // Candidate writers of this var (excluding self, not on the current
            // path to avoid cycles), lowest id first for stable tie-breaks.
            let mut candidates: Vec<u32> = self
                .deps
                .functions
                .iter()
                .filter(|(wid, wd)| {
                    **wid != func_id && !self.on_path.contains(*wid) && wd.writes.contains(var)
                })
                .map(|(wid, _)| *wid)
                .collect();
            candidates.sort_unstable();
            // Already satisfied by an emitted writer — nothing to add.
            if candidates.iter().any(|w| self.emitted.contains(w)) {
                continue;
            }
            let Some(writer) = self.choose_writer(var, desired, &candidates) else {
                continue;
            };
            // If the writer sets the var from a parameter, override that arg with
            // the value the guard wants.
            if let Some(WriteValue::Param(idx)) = self
                .deps
                .functions
                .get(&writer)
                .and_then(|d| d.write_values.get(var))
            {
                let entry = self.overrides.entry(writer).or_default();
                if !entry.iter().any(|(i, _)| i == idx) {
                    entry.push((*idx, desired.value()));
                }
            }
            self.visit(writer, false);
        }

        self.on_path.remove(&func_id);

        if !is_target && !self.emitted.contains(&func_id) && self.ordered.len() < MAX_SETUP_TXS {
            self.ordered.push(func_id);
            self.emitted.insert(func_id);
        }
    }
}

/// Build a setup transaction: the witness-derived base transaction with the
/// chosen argument overrides applied.
fn setup_transaction_for(
    abis: &[ContractAbi],
    step: &SetupStep,
    witness: &Witness,
) -> Option<Transaction> {
    let mut tx = transaction_for(abis, step.function_id, witness)?;
    for (idx, value) in &step.arg_overrides {
        if let Some(slot) = tx.args.get_mut(*idx) {
            *slot = FuzzValue::Uint(*value);
        }
    }
    Some(tx)
}

/// Build one transaction replaying `witness` against `function_id`, mapping
/// witnessed variable values onto matching parameter names (else `Uint(0)`).
/// `None` if the function isn't callable in the ABI (e.g. an internal function
/// SE reached via a cross-function call).
fn transaction_for(
    abis: &[ContractAbi],
    function_id: u32,
    witness: &Witness,
) -> Option<Transaction> {
    let function = abis
        .iter()
        .flat_map(|abi| abi.functions.iter())
        .find(|function| function.id == function_id)?;
    let args = function
        .params
        .iter()
        .map(|param| witness_var_to_fuzz_value(witness, &param.name).unwrap_or(FuzzValue::Uint(0)))
        .collect::<Vec<_>>();
    Some(Transaction {
        function_id,
        args,
        sender: address_index_from_witness(witness),
        value: u128_from_be_bytes(&witness.msg_value),
    })
}

fn environment_from_witness(witness: &Witness) -> Environment {
    Environment {
        block_timestamp: witness.block_timestamp as u128,
        block_number: witness.block_number as u128,
        address_pool_size: 5,
    }
}

fn to_seed(
    ast: &NormalizedAst,
    abis: &[ContractAbi],
    finding: &SeFinding,
    index: usize,
) -> Option<HybridSeed> {
    let function_id = finding
        .function_id
        .or_else(|| infer_function_id(ast, finding))?;
    let witness = finding.witness.as_ref();
    let function = abis
        .iter()
        .flat_map(|abi| abi.functions.iter())
        .find(|function| function.id == function_id)?;

    let args = function
        .params
        .iter()
        .map(|param| {
            witness
                .and_then(|w| witness_var_to_fuzz_value(w, &param.name))
                .unwrap_or(FuzzValue::Uint(0))
        })
        .collect::<Vec<_>>();
    let sender = witness.map(address_index_from_witness).unwrap_or(1);
    let value = witness
        .map(|witness| u128_from_be_bytes(&witness.msg_value))
        .unwrap_or(0);
    let environment = Environment {
        block_timestamp: witness
            .map(|witness| witness.block_timestamp as u128)
            .unwrap_or(Environment::default().block_timestamp),
        block_number: witness
            .map(|witness| witness.block_number as u128)
            .unwrap_or(Environment::default().block_number),
        address_pool_size: 5,
    };
    let tx = Transaction {
        function_id,
        args: args.clone(),
        sender,
        value,
    };
    let individual = Individual {
        transactions: vec![tx.clone()],
        environment: environment.clone(),
        energy: 2.0,
    };
    let id = format!("se-seed-{}-{index}", finding.kind.as_str());

    Some(HybridSeed {
        id: id.clone(),
        source_kind: finding.kind.as_str().to_string(),
        confidence: finding.confidence.as_str().to_string(),
        function_id,
        path_constraints: finding.path_constraints.clone(),
        tx_count: 1,
        artifact: Seed {
            id,
            txs: vec![TxSeed {
                function_id,
                selector: None,
                calldata: None,
                args: args.iter().map(format_fuzz_value).collect(),
                sender: format!("0x{:040x}", sender),
                value: value.to_string(),
                env: TxEnv {
                    block_timestamp: Some(environment.block_timestamp),
                    block_number: Some(environment.block_number),
                },
            }],
            state_snapshot_id: None,
            score: 1.0,
        },
        individual,
    })
}

fn format_fuzz_value(value: &FuzzValue) -> String {
    match value {
        FuzzValue::Uint(value) => value.to_string(),
        FuzzValue::Int(value) => value.to_string(),
        FuzzValue::Bool(value) => value.to_string(),
        FuzzValue::Address(value) => value.to_string(),
        FuzzValue::Bytes(value) => format!("0x{}", bytes_to_hex(value)),
        FuzzValue::StringVal(value) => value.clone(),
    }
}

/// Look up a function parameter name in the witness variables and convert
/// the concrete bytes to a FuzzValue.  Falls back to None when the witness
/// does not contain a matching variable (the caller defaults to Uint(0)).
fn witness_var_to_fuzz_value(witness: &Witness, param_name: &str) -> Option<FuzzValue> {
    let (_, bytes) = witness
        .variables
        .iter()
        .find(|(name, _)| name == param_name)?;
    // Convert big-endian bytes to u128. Pad/truncate to 16 bytes.
    let mut buf = [0u8; 16];
    let len = bytes.len().min(16);
    buf[16 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
    Some(FuzzValue::Uint(u128::from_be_bytes(buf)))
}

fn address_index_from_witness(witness: &Witness) -> usize {
    witness.msg_sender[19] as usize % 5
}

fn u128_from_be_bytes(bytes: &[u8; 32]) -> u128 {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[16..]);
    u128::from_be_bytes(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn infer_function_id(ast: &NormalizedAst, finding: &SeFinding) -> Option<u32> {
    ast.functions.iter().find_map(|function| {
        (function.span.file == finding.span.file
            && function.span.start <= finding.span.start
            && function.span.end >= finding.span.end)
            .then_some(function.id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainvet_core::norm::{FunctionKind, Mutability, Span, Visibility};
    use chainvet_fuzzing::fuzzing::types::{FunctionAbi, ParamInfo};
    use chainvet_sa::analysis::detectors::Severity;
    use chainvet_se::symbolic::results::finding::{Confidence, SeFinding, SeVulnKind};

    fn sample_ast() -> NormalizedAst {
        let mut ast = NormalizedAst::from_sources(vec![chainvet_core::norm::SourceFile {
            id: 0,
            path: "seed.sol".to_string(),
            source: String::new(),
        }]);
        ast.functions.push(chainvet_core::norm::Function {
            id: 7,
            contract: None,
            name: Some("withdraw".to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::External,
            mutability: Mutability::NonPayable,
            params: vec!["amount".to_string()],
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: 0,
                end: 100,
            },
        });
        ast
    }

    fn sample_abi() -> Vec<ContractAbi> {
        vec![ContractAbi {
            contract_name: "Seeded".to_string(),
            functions: vec![FunctionAbi {
                id: 7,
                name: "withdraw".to_string(),
                params: vec![ParamInfo {
                    name: "amount".to_string(),
                }],
                visibility: Visibility::External,
                mutability: Mutability::NonPayable,
                kind: FunctionKind::Function,
                is_payable: false,
            }],
        }]
    }

    fn sample_witness() -> Witness {
        Witness {
            msg_sender: [0u8; 20],
            msg_value: [0u8; 32],
            tx_origin: [0u8; 20],
            block_timestamp: 123,
            block_number: 456,
            this_balance: [0u8; 32],
            variables: Vec::new(),
        }
    }

    #[test]
    fn witness_becomes_seed_without_panicking() {
        let finding = SeFinding {
            kind: SeVulnKind::Reentrancy,
            severity: Severity::High,
            confidence: Confidence::High,
            message: "seed me".to_string(),
            span: Span {
                file: 0,
                start: 0,
                end: 0,
            },
            function_id: Some(7),
            path_constraints: vec!["balance > 0".to_string()],
            witness: Some(sample_witness()),
            state_id: 1,
            path_depth: 1,
        };
        let seeds = build_hybrid_seeds(&sample_ast(), &sample_abi(), &[finding]);
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].individual.transactions.len(), 1);
    }

    #[test]
    fn coverage_seed_prepends_writer_for_storage_reading_target() {
        use chainvet_fuzzing::fuzzing::types::FunctionDeps;
        use chainvet_se::symbolic::results::CoverageWitness;
        use std::collections::{HashMap, HashSet};

        fn func(id: u32, name: &str, params: Vec<&str>) -> FunctionAbi {
            FunctionAbi {
                id,
                name: name.to_string(),
                params: params
                    .into_iter()
                    .map(|p| ParamInfo { name: p.to_string() })
                    .collect(),
                visibility: Visibility::External,
                mutability: Mutability::NonPayable,
                kind: FunctionKind::Function,
                is_payable: false,
            }
        }

        // Writer (id 1) writes storage "flag"; target (id 2) reads it.
        let abis = vec![ContractAbi {
            contract_name: "S".to_string(),
            functions: vec![func(1, "setFlag", vec![]), func(2, "useFlag", vec!["v"])],
        }];
        let mut functions = HashMap::new();
        functions.insert(
            1u32,
            FunctionDeps {
                reads: HashSet::new(),
                writes: HashSet::from(["flag".to_string()]),
                ..Default::default()
            },
        );
        functions.insert(
            2u32,
            FunctionDeps {
                reads: HashSet::from(["flag".to_string()]),
                writes: HashSet::new(),
                ..Default::default()
            },
        );
        let deps = DependencyMap { functions };

        let cw = CoverageWitness {
            function_id: 2,
            block_id: 3,
            witness: sample_witness(),
        };
        let seeds = build_coverage_seeds(&abis, &deps, &[cw]);

        // A single-tx seed (target alone) and a multi-tx seed (writer → target).
        assert_eq!(seeds.len(), 2, "expected single-tx and multi-tx seeds");
        assert_eq!(seeds[0].transactions.len(), 1);
        assert_eq!(seeds[0].transactions[0].function_id, 2);
        assert_eq!(seeds[1].transactions.len(), 2);
        assert_eq!(seeds[1].transactions[0].function_id, 1, "writer must run first");
        assert_eq!(seeds[1].transactions[1].function_id, 2, "target must run last");
    }

    #[test]
    fn resolve_setup_path_walks_transitive_chain() {
        use chainvet_fuzzing::fuzzing::types::FunctionDeps;
        use std::collections::{HashMap, HashSet};

        // Chain: f1 writes "a" (no reads); f2 reads "a", writes "b";
        // f3 (target) reads "b". Reaching f3's gated block needs f1 → f2 → f3.
        let dep = |reads: &[&str], writes: &[&str]| FunctionDeps {
            reads: reads.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
            writes: writes.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
            ..Default::default()
        };
        let mut functions = HashMap::new();
        functions.insert(1u32, dep(&[], &["a"]));
        functions.insert(2u32, dep(&["a"], &["b"]));
        functions.insert(3u32, dep(&["b"], &[]));
        let deps = DependencyMap { functions };

        let ids = |steps: Vec<SetupStep>| steps.iter().map(|s| s.function_id).collect::<Vec<_>>();
        // Full transitive chain, correctly ordered, target excluded.
        assert_eq!(ids(resolve_setup_path(&deps, 3)), vec![1, 2]);
        // f2's own prerequisite resolves when it is the target.
        assert_eq!(ids(resolve_setup_path(&deps, 2)), vec![1]);
        // A leaf writer needs no setup.
        assert!(resolve_setup_path(&deps, 1).is_empty());
    }

    #[test]
    fn resolve_setup_path_terminates_on_cycle() {
        use chainvet_fuzzing::fuzzing::types::FunctionDeps;
        use std::collections::{HashMap, HashSet};

        // Mutual read-after-write cycle: f1 reads "b"/writes "a";
        // f2 reads "a"/writes "b". The recursion-stack guard must break it.
        let dep = |reads: &[&str], writes: &[&str]| FunctionDeps {
            reads: reads.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
            writes: writes.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
            ..Default::default()
        };
        let mut functions = HashMap::new();
        functions.insert(1u32, dep(&["b"], &["a"]));
        functions.insert(2u32, dep(&["a"], &["b"]));
        let deps = DependencyMap { functions };

        // Must terminate and place the reachable writer without duplication.
        let path = resolve_setup_path(&deps, 1);
        let ids: Vec<u32> = path.iter().map(|s| s.function_id).collect();
        assert_eq!(ids, vec![2], "cycle broken; the other writer is placed once");
    }

    #[test]
    fn value_aware_selection_overrides_param_writer_to_guard_value() {
        use chainvet_fuzzing::fuzzing::types::{EqGuard, FunctionDeps, WriteValue};
        use std::collections::{HashMap, HashSet};

        // setMode(id 1) writes "mode" from param 0; disable(id 2) writes mode=0.
        // Target useMode(id 3) is gated on `mode == 2`. Value-aware selection
        // must prefer setMode and override its arg to 2 — not disable, and not
        // setMode with a neutral 0 arg.
        let mut functions = HashMap::new();
        functions.insert(
            1u32,
            FunctionDeps {
                writes: HashSet::from(["mode".to_string()]),
                write_values: HashMap::from([("mode".to_string(), WriteValue::Param(0))]),
                ..Default::default()
            },
        );
        functions.insert(
            2u32,
            FunctionDeps {
                writes: HashSet::from(["mode".to_string()]),
                write_values: HashMap::from([("mode".to_string(), WriteValue::Const(0))]),
                ..Default::default()
            },
        );
        functions.insert(
            3u32,
            FunctionDeps {
                reads: HashSet::from(["mode".to_string()]),
                eq_guards: vec![EqGuard {
                    var: "mode".to_string(),
                    value: 2,
                }],
                ..Default::default()
            },
        );
        let deps = DependencyMap { functions };

        let steps = resolve_setup_path(&deps, 3);
        assert_eq!(steps.len(), 1, "one setup writer for the target");
        assert_eq!(steps[0].function_id, 1, "must pick the param writer, not disable");
        assert_eq!(
            steps[0].arg_overrides,
            vec![(0usize, 2u128)],
            "arg 0 overridden to the guard's required value (2)"
        );
    }
}
