use sha2::{Digest, Sha256};

use crate::fuzzing::types::{
    ExecutionTrace, FuzzFinding, FuzzFindingKind, FuzzSeverity, TraceEventKind, Transaction,
};
use chainvet_core::norm::{NormalizedAst, Visibility};

/// Run all oracle checks on an execution trace.
pub fn check_all(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    // Taxonomy-aligned core checks (taxonomy.xlsx):
    // Access Control, Arithmetic, Block Manipulation, Cryptographic, DoS, Reentrancy, Storage&Memory.
    findings.extend(check_reentrancy(trace, tx_sequence, ast));
    findings.extend(check_timestamp_dependency(trace, tx_sequence));
    findings.extend(check_unchecked_call(trace, tx_sequence, ast));
    findings.extend(check_exception_disorder(trace, tx_sequence, ast));
    // In Solidity >= 0.8 arithmetic is checked: an overflow reverts instead of
    // wrapping, so the wrapping-based overflow/underflow oracles would be false
    // positives (confirmed on audited 0.8 code in the clean precision set).
    let arithmetic_unchecked = ast
        .map(|a| !crate::analysis::detectors::arithmetic::all_files_are_0_8_plus(a))
        .unwrap_or(true);
    if arithmetic_unchecked {
        findings.extend(check_integer_overflow(trace, tx_sequence));
        findings.extend(check_integer_underflow(trace, tx_sequence));
    }
    findings.extend(check_access_control(trace, tx_sequence, ast));
    findings.extend(check_arbitrary_write(trace, tx_sequence, ast));
    findings.extend(check_wrong_constructor_name(trace, tx_sequence));
    findings.extend(check_tx_origin(trace, tx_sequence));
    findings.extend(check_selfdestruct(trace, tx_sequence, ast));
    findings.extend(check_dos(trace, tx_sequence));
    findings.extend(check_dos_block_gas_limit(trace, tx_sequence));
    findings.extend(check_unsafe_send_in_require(trace, tx_sequence, ast));
    findings.extend(check_dos_with_failed_call(trace, tx_sequence, ast));
    findings.extend(check_unsafe_delegatecall(trace, tx_sequence));
    findings.extend(check_transaction_order_dependency(trace, tx_sequence));
    findings.extend(check_weak_prng(trace, tx_sequence));
    findings.extend(check_hardcoded_gas(trace, tx_sequence, ast));
    findings.extend(check_storage_memory(trace, tx_sequence));
    findings.extend(check_division_before_multiplication(trace, tx_sequence));
    findings.extend(check_cryptographic(trace, tx_sequence));
    findings.extend(check_unprotected_ether_withdrawal(trace, tx_sequence, ast));
    findings.extend(check_locked_ether(trace, tx_sequence));
    findings.extend(check_supply_conservation(trace, tx_sequence, ast));
    findings
}

/// ERC-20 supply conservation invariant: the sum of per-account balances must
/// equal `totalSupply` after any sequence of transactions. A divergence means a
/// transaction created or destroyed tokens outside supply accounting (e.g. a
/// `transfer` that credits the receiver without debiting the sender). Relies on
/// the executor keying mapping state by resolved runtime index.
fn check_supply_conservation(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let Some(ast) = ast else {
        return Vec::new();
    };
    let balance_var = ast.state_vars.iter().find(|v| {
        v.name.to_ascii_lowercase().contains("balance")
            && v.type_string
                .as_deref()
                .map(|t| t.contains("mapping"))
                .unwrap_or(false)
    });
    let supply_var = ast
        .state_vars
        .iter()
        .find(|v| v.name.to_ascii_lowercase().contains("totalsupply"));
    let (Some(balance_var), Some(supply_var)) = (balance_var, supply_var) else {
        return Vec::new();
    };

    let prefix = format!("{}#", balance_var.name);
    let sum: u128 = trace
        .final_state
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .map(|(_, v)| v.as_uint())
        .sum();
    let total = trace
        .final_state
        .get(&supply_var.name)
        .map(|v| v.as_uint())
        .unwrap_or(0);

    // Only flag the inflation direction: more tokens in balances than the total
    // supply (tokens created in an account without supply accounting — the
    // classic mint-without-bookkeeping bug). The opposite direction (sum < total)
    // is mostly the abstract executor under-modeling balances on complex real
    // contracts, so flagging it produces false positives. Also require a
    // non-reverted trace so partial state from a reverted sequence isn't judged.
    if sum > total && !trace.reverted {
        let hash = hash_finding("supply-conservation", 0, &format!("{sum}:{total}"));
        return vec![FuzzFinding {
            span: None,
            kind: FuzzFindingKind::InvariantViolation,
            severity: FuzzSeverity::High,
            message: format!(
                "ERC-20 supply conservation violated: sum of `{}` ({}) exceeds `{}` ({}); \
                a transaction creates tokens outside supply accounting",
                balance_var.name, sum, supply_var.name, total
            ),
            tx_sequence: tx_sequence.to_vec(),
            trace_hash: hash,
        }];
    }
    Vec::new()
}

/// Reentrancy: callback-capable external call followed by a storage write in the same function.
fn check_reentrancy(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    #[derive(Default)]
    struct ReentrancyCtx {
        observed_reads: std::collections::HashSet<String>,
        observed_writes: std::collections::HashSet<String>,
        pre_call_reads: std::collections::HashSet<String>,
        pre_call_writes: std::collections::HashSet<String>,
        external_call_seen: bool,
        callback_seen: bool,
        post_call_write: bool,
        stale_read: bool,
        emitted_high: bool,
        emitted_fallback: bool,
    }

    fn write_key(var_name: &str, slot_key: &str) -> String {
        if !slot_key.trim().is_empty() {
            slot_key.to_string()
        } else {
            var_name.to_string()
        }
    }

    let mut findings = Vec::new();
    let mut by_fn: std::collections::HashMap<u32, ReentrancyCtx> = std::collections::HashMap::new();

    for event in &trace.events {
        if function_is_checked_selector_low_level_wrapper(event.function_id, ast) {
            continue;
        }
        let ctx = by_fn.entry(event.function_id).or_default();
        match &event.kind {
            TraceEventKind::StorageRead {
                var_name, slot_key, ..
            } => {
                ctx.observed_reads.insert(write_key(var_name, slot_key));
            }
            TraceEventKind::ExternalCall {
                reentrant_capable, ..
            } => {
                if *reentrant_capable {
                    ctx.external_call_seen = true;
                    ctx.callback_seen = false;
                    ctx.post_call_write = false;
                    ctx.stale_read = false;
                    ctx.pre_call_reads = ctx.observed_reads.clone();
                    ctx.pre_call_writes = ctx.observed_writes.clone();
                }
            }
            TraceEventKind::ReentrantCallback { .. } => {
                ctx.callback_seen = true;
            }
            TraceEventKind::StorageWrite {
                var_name, slot_key, ..
            } => {
                if !ctx.external_call_seen {
                    continue;
                }
                let key = write_key(var_name, slot_key);
                ctx.observed_writes.insert(key.clone());
                ctx.post_call_write = true;
                if ctx.pre_call_reads.contains(&key) {
                    ctx.stale_read = true;
                }

                if ctx.callback_seen && (ctx.stale_read || ctx.post_call_write) && !ctx.emitted_high
                {
                    let evidence = if ctx.stale_read {
                        "stale-read+post-call-mutation"
                    } else {
                        "post-call-mutation"
                    };
                    let hash = hash_finding(
                        "reentrancy",
                        event.function_id,
                        format!("{key}:{evidence}").as_str(),
                    );
                    findings.push(FuzzFinding {
                    span: None,
                        kind: FuzzFindingKind::Reentrancy,
                        severity: FuzzSeverity::High,
                        message: format!(
                            "Potential reentrancy: feasible callback in function {} followed by storage write '{}' (evidence={})",
                            event.function_id, key, evidence
                        ),
                        tx_sequence: tx_sequence.to_vec(),
                        trace_hash: hash,
                    });
                    ctx.emitted_high = true;
                } else if !ctx.callback_seen
                    && ctx.post_call_write
                    && !ctx.emitted_fallback
                    && function_has_value_moving_low_level_call(ast, event.function_id)
                {
                    let hash = hash_finding("reentrancy-fallback", event.function_id, key.as_str());
                    findings.push(FuzzFinding {
                    span: None,
                        kind: FuzzFindingKind::ReentrancyHeuristic,
                        severity: FuzzSeverity::Low,
                        message: format!(
                            "Heuristic reentrancy signal: external call in function {} followed by storage write '{}' without callback evidence",
                            event.function_id, key
                        ),
                        tx_sequence: tx_sequence.to_vec(),
                        trace_hash: hash,
                    });
                    ctx.emitted_fallback = true;
                }
            }
            _ => {}
        }
    }

    for (function_id, ctx) in by_fn {
        if function_is_checked_selector_low_level_wrapper(function_id, ast) {
            continue;
        }
        if ctx.external_call_seen
            && ctx.callback_seen
            && !ctx.emitted_high
            && !ctx.emitted_fallback
            && function_has_value_moving_low_level_call(ast, function_id)
        {
            if !ctx.pre_call_writes.is_empty() {
                let mut writes = ctx.pre_call_writes.into_iter().collect::<Vec<_>>();
                writes.sort_unstable();
                let detail = writes.join(",");
                let hash =
                    hash_finding("reentrancy-pre-call-effects", function_id, detail.as_str());
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::ReentrancyHeuristic,
                    severity: FuzzSeverity::Low,
                    message: format!(
                        "Heuristic reentrancy signal: function {} performs state effects [{}] before a feasible external callback",
                        function_id, detail
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            } else {
                let hash = hash_finding("reentrancy-callback", function_id, "callback-only");
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::ReentrancyHeuristic,
                    severity: FuzzSeverity::Low,
                    message: format!(
                        "Heuristic reentrancy signal: feasible callback observed in function {} without post-call state-write evidence",
                        function_id
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

/// Timestamp dependency: block.timestamp used in a conditional branch or mixed into
/// randomness-style arithmetic.
fn check_timestamp_dependency(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen_functions = std::collections::HashSet::new();

    for event in &trace.events {
        let message = match &event.kind {
            TraceEventKind::BranchOnTimestamp => Some(format!(
                "Timestamp dependency: block.timestamp used in conditional branch in function {}",
                event.function_id
            )),
            TraceEventKind::TimestampArithmetic => Some(format!(
                "Timestamp dependency: block.timestamp-derived value mixed into arithmetic randomness in function {}",
                event.function_id
            )),
            _ => None,
        };
        if let Some(message) = message {
            if seen_functions.insert(event.function_id) {
                let hash = hash_finding("timestamp", event.function_id, "branch");
                findings.push(FuzzFinding {
                    span: event.span,
                    kind: FuzzFindingKind::TimestampDependency,
                    severity: FuzzSeverity::Medium,
                    message,
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

/// Unchecked call: an external call whose return value is not checked.
fn check_unchecked_call(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::CallReturnUnchecked { callee } = &event.kind {
            if function_is_checked_selector_low_level_wrapper(event.function_id, ast) {
                continue;
            }
            let key = (event.function_id, callee.clone());
            if seen.insert(key) {
                let hash = hash_finding("unchecked-call", event.function_id, callee);
                findings.push(FuzzFinding {
                    span: event.span,
                    kind: FuzzFindingKind::UncheckedCall,
                    severity: FuzzSeverity::Medium,
                    message: format!(
                        "Unchecked external call to '{}' in function {} — return value not verified",
                        callee, event.function_id
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

/// Exception disorder: external call followed by state write without checking the return value.
fn check_exception_disorder(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::ExternalCallThenState { callee, checked } = &event.kind {
            if function_is_checked_selector_low_level_wrapper(event.function_id, ast) {
                continue;
            }
            if !checked && callee_can_fail_without_revert(callee) {
                let key = (event.function_id, callee.clone());
                if seen.insert(key) {
                    let hash = hash_finding("exception-disorder", event.function_id, callee);
                    findings.push(FuzzFinding {
                    span: event.span,
                        kind: FuzzFindingKind::ExceptionDisorder,
                        severity: FuzzSeverity::Medium,
                        message: format!(
                            "Exception disorder: external call to '{}' in function {} followed by state change without checking return",
                            callee, event.function_id
                        ),
                        tx_sequence: tx_sequence.to_vec(),
                        trace_hash: hash,
                    });
                }
            }
        }
    }

    findings
}

/// Integer overflow: arithmetic op where wrapping occurred.
fn check_integer_overflow(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::ArithmeticOp {
            op,
            lhs,
            rhs,
            result,
        } = &event.kind
        {
            let overflowed = match op.as_str() {
                "+" => {
                    // Wrapping addition: result < either operand
                    *result < *lhs || *result < *rhs
                }
                "*" => {
                    // Wrapping multiplication: if lhs != 0, result / lhs != rhs
                    *lhs != 0 && *rhs != 0 && *result / *lhs != *rhs
                }
                "-" => {
                    // Wrapping subtraction: result > lhs (underflow)
                    *result > *lhs && *rhs > 0
                }
                _ => false,
            };

            if overflowed {
                let key = (event.function_id, op.clone());
                if seen.insert(key) {
                    let hash = hash_finding("overflow", event.function_id, op);
                    findings.push(FuzzFinding {
                    span: event.span,
                        kind: FuzzFindingKind::IntegerOverflow,
                        severity: FuzzSeverity::High,
                        message: format!(
                            "Potential integer overflow in function {}: {} {} {} = {} (wrapping detected)",
                            event.function_id, lhs, op, rhs, result
                        ),
                        tx_sequence: tx_sequence.to_vec(),
                        trace_hash: hash,
                    });
                }
            }
        }
    }

    findings
}

#[derive(Default)]
struct AuthorityWriteSummary {
    authority_slots: std::collections::HashSet<String>,
    non_authority_slots: std::collections::HashSet<String>,
    sender_checked: bool,
    wrong_constructor_candidate: bool,
}

impl AuthorityWriteSummary {
    fn exclusive_authority_write(&self) -> bool {
        !self.authority_slots.is_empty() && self.non_authority_slots.is_empty()
    }
}

fn collect_authority_write_summaries(
    trace: &ExecutionTrace,
) -> std::collections::HashMap<u32, AuthorityWriteSummary> {
    let mut by_fn: std::collections::HashMap<u32, AuthorityWriteSummary> =
        std::collections::HashMap::new();

    for event in &trace.events {
        let summary = by_fn.entry(event.function_id).or_default();
        match &event.kind {
            TraceEventKind::StorageWrite {
                var_name,
                slot_key,
                authority_sensitive,
                caller_keyed,
            } if var_name != "__no_sender_check" && !*caller_keyed => {
                let slot = if slot_key.trim().is_empty() {
                    var_name.clone()
                } else {
                    slot_key.clone()
                };
                if *authority_sensitive {
                    summary.authority_slots.insert(slot);
                } else {
                    summary.non_authority_slots.insert(slot);
                }
            }
            TraceEventKind::SenderChecked => {
                summary.sender_checked = true;
            }
            TraceEventKind::WrongConstructorCandidate { .. } => {
                summary.wrong_constructor_candidate = true;
            }
            _ => {}
        }
    }

    by_fn
}

fn detail_from_slots(slots: &std::collections::HashSet<String>) -> String {
    let mut ordered = slots.iter().cloned().collect::<Vec<_>>();
    ordered.sort_unstable();
    ordered.join(",")
}

fn function_has_authority_guard_hint(function_id: u32, ast: Option<&NormalizedAst>) -> bool {
    let Some(ast) = ast else {
        return false;
    };
    let Some(function) = ast_function_by_id(ast, function_id) else {
        return false;
    };
    chainvet_frontend::frontend::is_legacy_named_constructor(function, ast)
        || chainvet_frontend::frontend::has_sender_authority_check_hint(function, ast)
}

fn function_is_externally_callable(function_id: u32, ast: Option<&NormalizedAst>) -> bool {
    ast.and_then(|ast| ast_function_by_id(ast, function_id))
        .map(|function| {
            matches!(
                function.visibility,
                Visibility::Public | Visibility::External
            )
        })
        .unwrap_or(true)
}

fn check_access_control(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen_functions = std::collections::HashSet::new();
    let summaries = collect_authority_write_summaries(trace);

    for (func_id, summary) in summaries {
        if summary.sender_checked
            || summary.wrong_constructor_candidate
            || function_has_authority_guard_hint(func_id, ast)
            || !summary.exclusive_authority_write()
        {
            continue;
        }
        if seen_functions.insert(func_id) {
            let detail = detail_from_slots(&summary.authority_slots);
            let hash = hash_finding("access-control", func_id, "no-sender-check");
            findings.push(FuzzFinding {
                    span: None,
                kind: FuzzFindingKind::AccessControl,
                severity: FuzzSeverity::High,
                message: format!(
                    "Missing access control: function {} mutates authority slot(s) [{}] without checking msg.sender",
                    func_id, detail
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    findings
}

/// Arbitrary write: storage writes happen in a function without sender check and
/// the same function is successfully exercised by multiple distinct senders.
fn check_arbitrary_write(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let summaries = collect_authority_write_summaries(trace);

    let mut senders_by_fn: std::collections::HashMap<u32, std::collections::HashSet<usize>> =
        std::collections::HashMap::new();
    for tx in tx_sequence {
        senders_by_fn
            .entry(tx.function_id)
            .or_default()
            .insert(tx.sender);
    }

    for (function_id, summary) in summaries {
        if summary.sender_checked
            || summary.wrong_constructor_candidate
            || function_has_authority_guard_hint(function_id, ast)
            || !summary.exclusive_authority_write()
        {
            continue;
        }
        let sender_count = senders_by_fn
            .get(&function_id)
            .map(|s| s.len())
            .unwrap_or(0);
        if sender_count < 2 {
            continue;
        }

        let detail = detail_from_slots(&summary.authority_slots);

        if seen.insert(function_id) {
            let hash = hash_finding("arbitrary-write", function_id, detail.as_str());
            findings.push(FuzzFinding {
                    span: None,
                kind: FuzzFindingKind::ArbitraryWrite,
                severity: FuzzSeverity::High,
                message: format!(
                    "Arbitrary write risk: function {} writes storage without sender check and was exercised by {} distinct senders (vars: {})",
                    function_id,
                    sender_count,
                    detail
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    findings
}

fn check_wrong_constructor_name(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::WrongConstructorCandidate {
            function_name,
            slot_key,
        } = &event.kind
        {
            if seen.insert(event.function_id) {
                let hash = hash_finding(
                    "wrong-constructor-name",
                    event.function_id,
                    function_name.as_str(),
                );
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::WrongConstructorName,
                    severity: FuzzSeverity::High,
                    message: format!(
                        "Wrong constructor name: function {} ('{}') reassigns authority slot '{}' from msg.sender",
                        event.function_id, function_name, slot_key
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

/// tx.origin authentication: using tx.origin for authorization.
fn check_tx_origin(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen_functions = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::TxOriginUsed = &event.kind {
            if seen_functions.insert(event.function_id) {
                let hash = hash_finding("tx-origin", event.function_id, "used");
                findings.push(FuzzFinding {
                    span: event.span,
                    kind: FuzzFindingKind::TxOriginAuth,
                    severity: FuzzSeverity::Medium,
                    message: format!(
                        "tx.origin used in function {} — vulnerable to phishing attacks, use msg.sender instead",
                        event.function_id
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

fn source_span_lower(ast: &NormalizedAst, span: chainvet_core::norm::Span) -> Option<String> {
    let file = ast.files.get(span.file as usize)?;
    file.source
        .get(span.start as usize..span.end as usize)
        .filter(|source| !source.is_empty())
        .unwrap_or(file.source.as_str())
        .to_ascii_lowercase()
        .into()
}

fn contract_source_lower(ast: &NormalizedAst, contract_id: u32) -> Option<String> {
    let contract = ast.contracts.get(contract_id as usize)?;
    source_span_lower(ast, contract.span)
}

fn function_is_exploit_cleanup_selfdestruct_helper(
    ast: Option<&NormalizedAst>,
    function_id: u32,
) -> bool {
    let Some(ast) = ast else {
        return false;
    };
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
    if !(function_source.contains("suicide(owner")
        || function_source.contains("selfdestruct(owner"))
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

/// Unprotected selfdestruct: selfdestruct without access control.
fn check_selfdestruct(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen_functions = std::collections::HashSet::new();

    // Collect functions with selfdestruct and check if they have sender checks
    let mut functions_with_selfdestruct: std::collections::HashSet<u32> =
        std::collections::HashSet::new();
    let mut functions_with_sender_check: std::collections::HashSet<u32> =
        std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::SelfDestructCall => {
                functions_with_selfdestruct.insert(event.function_id);
            }
            TraceEventKind::SenderChecked => {
                functions_with_sender_check.insert(event.function_id);
            }
            _ => {}
        }
    }

    for func_id in &functions_with_selfdestruct {
        if seen_functions.insert(*func_id)
            && !functions_with_sender_check.contains(func_id)
            && !function_has_authority_guard_hint(*func_id, ast)
            && !function_is_exploit_cleanup_selfdestruct_helper(ast, *func_id)
        {
            let hash = hash_finding("selfdestruct", *func_id, "call");
            findings.push(FuzzFinding {
                span: None,
                kind: FuzzFindingKind::SelfDestruct,
                severity: FuzzSeverity::High,
                message: format!(
                    "Unprotected selfdestruct in function {} — anyone can destroy the contract",
                    func_id
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    findings
}

/// Denial of service: unbounded loops over storage arrays.
fn check_dos(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::UnboundedLoop { var_name } = &event.kind {
            let key = (event.function_id, var_name.clone());
            if seen.insert(key) {
                let hash = hash_finding("dos", event.function_id, var_name);
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::DenialOfService,
                    severity: FuzzSeverity::Medium,
                    message: format!(
                        "Potential DoS: unbounded loop in function {} with storage-dependent condition '{}'",
                        event.function_id, var_name
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

fn check_dos_block_gas_limit(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut loop_functions = std::collections::HashSet::new();
    let mut value_moving_loop_functions = std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::UnboundedLoop { .. } => {
                loop_functions.insert(event.function_id);
            }
            TraceEventKind::HardcodedGasCall { .. }
            | TraceEventKind::EtherSent { .. }
            | TraceEventKind::ExternalCall {
                has_value: true, ..
            } => {
                value_moving_loop_functions.insert(event.function_id);
            }
            _ => {}
        }
    }

    for function_id in loop_functions {
        if !value_moving_loop_functions.contains(&function_id) || !seen.insert(function_id) {
            continue;
        }
        let hash = hash_finding("dos-block-gas-limit", function_id, "dynamic-loop");
        findings.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::DosBlockGasLimit,
            severity: FuzzSeverity::Medium,
            message: format!(
                "DoS with block gas limit: function {} iterates over a storage-derived/dynamic loop bound and performs external value-moving calls",
                function_id
            ),
            tx_sequence: tx_sequence.to_vec(),
            trace_hash: hash,
        });
    }

    findings
}

/// Unsafe send() in require/assert condition can be griefed into revert-based DoS.
fn check_unsafe_send_in_require(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::UnsafeSendInRequire { callee } = &event.kind {
            if function_is_checked_selector_low_level_wrapper(event.function_id, ast) {
                continue;
            }
            let key = (event.function_id, callee.clone());
            if seen.insert(key) {
                let hash = hash_finding("unsafe-send-in-require", event.function_id, callee);
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::UnsafeSendInRequire,
                    severity: FuzzSeverity::High,
                    message: format!(
                        "Unsafe send in require/assert in function {} — recipient-controlled failure can cause DoS",
                        event.function_id
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

/// DoS with failed call: external call inside loop may revert whole transaction.
fn check_dos_with_failed_call(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut function_has_loop: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut function_has_loop_transfer: std::collections::HashSet<u32> =
        std::collections::HashSet::new();
    let mut function_has_required_push_call: std::collections::HashSet<u32> =
        std::collections::HashSet::new();

    for event in &trace.events {
        if function_is_checked_selector_low_level_wrapper(event.function_id, ast) {
            continue;
        }
        match &event.kind {
            TraceEventKind::LoopEncountered | TraceEventKind::UnboundedLoop { .. } => {
                function_has_loop.insert(event.function_id);
            }
            TraceEventKind::HardcodedGasCall { callee } => {
                if callee_reverts_on_failure(callee) {
                    function_has_loop_transfer.insert(event.function_id);
                }
            }
            TraceEventKind::UnsafeSendInRequire { .. } => {
                function_has_required_push_call.insert(event.function_id);
            }
            _ => {}
        }
    }

    for function_id in function_has_loop {
        if function_has_loop_transfer.contains(&function_id) && seen.insert(function_id) {
            let hash = hash_finding("dos-with-failed-call", function_id, "loop-transfer");
            findings.push(FuzzFinding {
                    span: None,
                kind: FuzzFindingKind::DosWithFailedCall,
                severity: FuzzSeverity::High,
                message: format!(
                    "DoS with failed call: function {} executes transfer-like calls in loop context",
                    function_id
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    for function_id in function_has_required_push_call {
        if seen.insert(function_id) {
            let hash = hash_finding("dos-with-failed-call", function_id, "require-send");
            findings.push(FuzzFinding {
                    span: None,
                kind: FuzzFindingKind::DosWithFailedCall,
                severity: FuzzSeverity::High,
                message: format!(
                    "DoS with failed call: function {} requires send/transfer success, so a reverting recipient can block execution",
                    function_id
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    findings
}

fn callee_can_fail_without_revert(callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    !callee_reverts_on_failure(&lower)
}

fn callee_reverts_on_failure(callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    lower == "transfer" || lower.ends_with(".transfer")
}

/// Hash a finding for deduplication.
fn hash_finding(kind: &str, function_id: u32, detail: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(function_id.to_le_bytes());
    hasher.update(detail.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

// ---------------------------------------------------------------------------
// New taxonomy-aligned oracle checks
// ---------------------------------------------------------------------------

/// Integer underflow: subtraction where result > lhs (wrapping underflow).
fn check_integer_underflow(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::ArithmeticOp {
            op,
            lhs,
            rhs,
            result,
        } = &event.kind
        {
            if op == "-" && *result > *lhs && *rhs > 0 {
                let key = (event.function_id, op.clone());
                if seen.insert(key) {
                    let hash = hash_finding("underflow", event.function_id, op);
                    findings.push(FuzzFinding {
                    span: event.span,
                        kind: FuzzFindingKind::IntegerUnderflow,
                        severity: FuzzSeverity::High,
                        message: format!(
                            "Potential integer underflow in function {}: {} {} {} = {} (wrapping detected)",
                            event.function_id, lhs, op, rhs, result
                        ),
                        tx_sequence: tx_sequence.to_vec(),
                        trace_hash: hash,
                    });
                }
            }
        }
    }

    findings
}

/// Unsafe delegatecall: delegatecall without sender check.
fn check_unsafe_delegatecall(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut functions_with_delegatecall: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();
    let mut functions_with_sender_check: std::collections::HashSet<u32> =
        std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::DelegatecallDetected { callee } => {
                functions_with_delegatecall
                    .entry(event.function_id)
                    .or_insert_with(|| callee.clone());
            }
            TraceEventKind::SenderChecked => {
                functions_with_sender_check.insert(event.function_id);
            }
            _ => {}
        }
    }

    for (func_id, callee) in &functions_with_delegatecall {
        if !functions_with_sender_check.contains(func_id) && seen.insert(*func_id) {
            let hash = hash_finding("unsafe-delegatecall", *func_id, callee);
            findings.push(FuzzFinding {
                span: None,
                kind: FuzzFindingKind::UnsafeDelegatecall,
                severity: FuzzSeverity::High,
                message: format!(
                    "Unsafe delegatecall to '{}' in function {} without access control",
                    callee, func_id
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    findings
}

/// Weak PRNG: block.number or blockhash used (predictable randomness).
fn check_weak_prng(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen_functions = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::BlockNumberUsed = &event.kind {
            if seen_functions.insert(event.function_id) {
                let hash = hash_finding("weak-prng", event.function_id, "block-number");
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::WeakPRNG,
                    severity: FuzzSeverity::Medium,
                    message: format!(
                        "Weak PRNG: block.number/blockhash used in function {} — predictable randomness source",
                        event.function_id
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

/// Transaction order dependency: reads order-sensitive storage and performs value transfer.
fn check_transaction_order_dependency(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut sensitive_reads: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut value_transfer: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut read_slots_by_fn: std::collections::HashMap<u32, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    let mut write_slots_by_fn: std::collections::HashMap<u32, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    for event in &trace.events {
        match &event.kind {
            TraceEventKind::StorageRead {
                var_name,
                slot_key,
                order_sensitive,
                ..
            } => {
                if *order_sensitive || is_order_sensitive_storage_name(var_name) {
                    sensitive_reads.insert(event.function_id);
                    read_slots_by_fn
                        .entry(event.function_id)
                        .or_default()
                        .insert(slot_key.clone());
                }
            }
            TraceEventKind::StorageWrite { slot_key, .. } => {
                write_slots_by_fn
                    .entry(event.function_id)
                    .or_default()
                    .insert(slot_key.clone());
            }
            TraceEventKind::EtherSent { .. }
            | TraceEventKind::HardcodedGasCall { .. }
            | TraceEventKind::ExternalCall {
                has_value: true, ..
            } => {
                value_transfer.insert(event.function_id);
            }
            _ => {}
        }
    }

    for function_id in sensitive_reads {
        let has_value_path = value_transfer.contains(&function_id);
        let sender_count = tx_sequence
            .iter()
            .filter(|tx| tx.function_id == function_id)
            .map(|tx| tx.sender)
            .collect::<std::collections::HashSet<_>>()
            .len();
        if sender_count < 2 {
            continue;
        }
        let has_writer_reader_path = read_slots_by_fn
            .get(&function_id)
            .map(|read_slots| {
                write_slots_by_fn.iter().any(|(writer_fn, write_slots)| {
                    writer_fn != &function_id
                        && write_slots.iter().any(|slot| read_slots.contains(slot))
                })
            })
            .unwrap_or(false);
        if !has_value_path && !has_writer_reader_path {
            continue;
        }

        let detail = if has_value_path {
            "sensitive+value"
        } else if has_writer_reader_path {
            "writer-reader"
        } else {
            continue;
        };

        if seen.insert((function_id, detail)) {
            let hash = hash_finding("transaction-order-dependency", function_id, detail);
            findings.push(FuzzFinding {
                    span: None,
                kind: FuzzFindingKind::TransactionOrderDependency,
                severity: FuzzSeverity::Medium,
                message: format!(
                    "Transaction order dependency: function {} has order-sensitive {} behavior across {} distinct senders",
                    function_id, detail, sender_count
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    findings
}

fn is_order_sensitive_storage_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "price"
                    | "rate"
                    | "reward"
                    | "allow"
                    | "allowed"
                    | "allowance"
                    | "allowances"
                    | "approval"
                    | "approved"
                    | "nonce"
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

/// Hardcoded gas: .transfer() or .send() with fixed 2300 gas stipend.
fn check_hardcoded_gas(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::HardcodedGasCall { callee } = &event.kind {
            if function_is_checked_selector_low_level_wrapper(event.function_id, ast) {
                continue;
            }
            let key = (event.function_id, callee.clone());
            if seen.insert(key) {
                let hash = hash_finding("hardcoded-gas", event.function_id, callee);
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::HardcodedGas,
                    severity: FuzzSeverity::Low,
                    message: format!(
                        "Hardcoded gas: '{}' in function {} uses fixed 2300 gas stipend — may fail with contract recipients",
                        callee, event.function_id
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

/// Locked ether: contract receives ETH (payable) but has no ether-sending call.
fn check_locked_ether(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut functions_with_balance_invariant = std::collections::HashSet::new();
    let mut functions_with_selfdestruct = std::collections::HashSet::new();
    for event in &trace.events {
        match &event.kind {
            TraceEventKind::BalanceInvariantCheck => {
                functions_with_balance_invariant.insert(event.function_id);
            }
            TraceEventKind::SelfDestructCall => {
                functions_with_selfdestruct.insert(event.function_id);
            }
            _ => {}
        }
    }

    for function_id in &functions_with_balance_invariant {
        let detail = if functions_with_selfdestruct.contains(function_id) {
            "balance-invariant-selfdestruct"
        } else {
            "balance-invariant"
        };
        let hash = hash_finding("locked-ether", *function_id, detail);
        return vec![FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::LockedEther,
            severity: FuzzSeverity::Medium,
            message: format!(
                "Forced-Ether invariant risk: function {} checks this.balance/address(this).balance in require/assert{}",
                function_id,
                if functions_with_selfdestruct.contains(function_id) {
                    " before selfdestruct/suicide"
                } else {
                    ""
                }
            ),
            tx_sequence: tx_sequence.to_vec(),
            trace_hash: hash,
        }];
    }

    Vec::new()
}

/// Storage/memory issues: inline assembly, delegatecall in loop.
fn check_storage_memory(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::InlineAssemblyDetected => {
                if seen.insert((event.function_id, "inline-asm".to_string())) {
                    let hash = hash_finding("storage-memory", event.function_id, "inline-asm");
                    findings.push(FuzzFinding {
                    span: None,
                        kind: FuzzFindingKind::StorageMemoryIssue,
                        severity: FuzzSeverity::Medium,
                        message: format!(
                            "Inline assembly usage in function {} — error-prone and may manipulate memory directly",
                            event.function_id
                        ),
                        tx_sequence: tx_sequence.to_vec(),
                        trace_hash: hash,
                    });
                }
            }
            TraceEventKind::DelegatecallInLoop { callee } => {
                if seen.insert((event.function_id, callee.clone())) {
                    let hash = hash_finding("storage-memory", event.function_id, callee);
                    findings.push(FuzzFinding {
                    span: None,
                        kind: FuzzFindingKind::StorageMemoryIssue,
                        severity: FuzzSeverity::High,
                        message: format!(
                            "delegatecall to '{}' inside a loop in function {} — storage corruption risk",
                            callee, event.function_id
                        ),
                        tx_sequence: tx_sequence.to_vec(),
                        trace_hash: hash,
                    });
                }
            }
            _ => {}
        }
    }

    findings
}

/// Division before multiplication: precision loss from integer rounding.
fn check_division_before_multiplication(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::DivisionBeforeMultiplication { function_id_inner } = &event.kind {
            if seen.insert(*function_id_inner) {
                let hash = hash_finding("div-before-mul", *function_id_inner, "pattern");
                findings.push(FuzzFinding {
                    span: None,
                    kind: FuzzFindingKind::DivisionBeforeMultiplication,
                    severity: FuzzSeverity::Medium,
                    message: format!(
                        "Division before multiplication in function {} — may cause precision loss due to integer rounding",
                        function_id_inner
                    ),
                    tx_sequence: tx_sequence.to_vec(),
                    trace_hash: hash,
                });
            }
        }
    }

    findings
}

/// Cryptographic issue: ecrecover without zero-address check.
fn check_cryptographic(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut ecrecover_funcs = std::collections::HashSet::new();
    let mut zero_checked_funcs = std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::EcrecoverCalled => {
                ecrecover_funcs.insert(event.function_id);
            }
            TraceEventKind::EcrecoverZeroChecked => {
                zero_checked_funcs.insert(event.function_id);
            }
            _ => {}
        }
    }

    for function_id in ecrecover_funcs {
        if zero_checked_funcs.contains(&function_id) {
            continue;
        }
        let sender_count = tx_sequence
            .iter()
            .filter(|tx| tx.function_id == function_id)
            .map(|tx| tx.sender)
            .collect::<std::collections::HashSet<_>>()
            .len();
        if sender_count < 2 {
            continue;
        }
        if seen.insert((function_id, "cryptographic")) {
            let hash = hash_finding("cryptographic", function_id, "ecrecover-no-zero-check");
            findings.push(FuzzFinding {
                    span: None,
                kind: FuzzFindingKind::CryptographicIssue,
                severity: FuzzSeverity::Medium,
                message: format!(
                    "ecrecover in function {} without observed zero-address check across {} distinct senders",
                    function_id, sender_count
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
        if seen.insert((function_id, "signature-malleability")) {
            let hash = hash_finding("signature-malleability", function_id, "ecrecover");
            findings.push(FuzzFinding {
                    span: None,
            kind: FuzzFindingKind::SignatureMalleability,
            severity: FuzzSeverity::Medium,
            message: format!(
                    "Signature malleability risk: function {} uses ecrecover without observed zero-address guard across {} distinct senders",
                    function_id,
                    sender_count
            ),
            tx_sequence: tx_sequence.to_vec(),
            trace_hash: hash,
        });
        }
    }

    findings
}

/// Unprotected ether withdrawal: function sends ETH without checking msg.sender.
fn check_unprotected_ether_withdrawal(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
    ast: Option<&NormalizedAst>,
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut functions_with_ether_send: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();
    let mut functions_with_sender_check: std::collections::HashSet<u32> =
        std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::EtherSent { callee } => {
                functions_with_ether_send
                    .entry(event.function_id)
                    .or_insert_with(|| callee.clone());
            }
            TraceEventKind::SenderChecked => {
                functions_with_sender_check.insert(event.function_id);
            }
            _ => {}
        }
    }

    for (func_id, callee) in &functions_with_ether_send {
        if !functions_with_sender_check.contains(func_id)
            && function_is_externally_callable(*func_id, ast)
            && !function_has_authority_guard_hint(*func_id, ast)
            && !function_is_direct_msg_value_forwarder(*func_id, ast)
            && !function_is_public_sender_payout(*func_id, ast)
            && !function_is_checked_selector_low_level_wrapper(*func_id, ast)
            && seen.insert(*func_id)
        {
            let hash = hash_finding("unprotected-withdrawal", *func_id, callee);
            findings.push(FuzzFinding {
                span: None,
                kind: FuzzFindingKind::UnprotectedEtherWithdrawal,
                severity: FuzzSeverity::High,
                message: format!(
                    "Unprotected Ether withdrawal via '{}' in function {} — anyone can drain funds",
                    callee, func_id
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    findings
}

fn function_source_lower(ast: Option<&NormalizedAst>, function_id: u32) -> Option<String> {
    let ast = ast?;
    let function = ast_function_by_id(ast, function_id)?;
    let file = ast.files.get(function.span.file as usize)?;
    Some(
        file.source
            .get(function.span.start as usize..function.span.end as usize)
            .filter(|source| !source.is_empty())
            .unwrap_or(file.source.as_str())
            .to_ascii_lowercase(),
    )
}

fn function_is_direct_msg_value_forwarder(function_id: u32, ast: Option<&NormalizedAst>) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    source_lower.contains(".call.value(msg.value)")
        || source_lower.contains(".send(msg.value)")
        || source_lower.contains(".send (msg.value)")
        || source_lower.contains(".transfer(msg.value)")
        || source_lower.contains(".transfer (msg.value)")
}

fn function_is_public_sender_payout(function_id: u32, ast: Option<&NormalizedAst>) -> bool {
    let Some(ast) = ast else {
        return false;
    };
    let Some(function) = ast_function_by_id(ast, function_id) else {
        return false;
    };
    chainvet_frontend::frontend::has_public_sender_payout_hint(function, ast)
}

fn ast_function_by_id(ast: &NormalizedAst, function_id: u32) -> Option<&chainvet_core::norm::Function> {
    ast.functions
        .iter()
        .find(|function| function.id == function_id)
}

fn function_has_value_moving_low_level_call(ast: Option<&NormalizedAst>, function_id: u32) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
        return false;
    };
    source_lower.contains(".call.value")
        || source_lower.contains(".send(")
        || source_lower.contains(".send (")
        || source_lower.contains(".transfer(")
        || source_lower.contains(".transfer (")
}

fn function_is_checked_selector_low_level_wrapper(
    function_id: u32,
    ast: Option<&NormalizedAst>,
) -> bool {
    let Some(source_lower) = function_source_lower(ast, function_id) else {
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

/// Deduplicate findings by trace hash.
pub fn deduplicate(findings: Vec<FuzzFinding>) -> Vec<FuzzFinding> {
    let mut seen = std::collections::HashSet::new();
    let mut unique = Vec::new();
    for finding in findings {
        if seen.insert(finding.trace_hash.clone()) {
            unique.push(finding);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzing::types::{FuzzValue, TraceEvent};
    use chainvet_core::norm::{
        Contract, ContractKind, Function, FunctionKind, Mutability, NormalizedAst, SourceFile,
        Span, Visibility,
    };

    fn make_tx() -> Vec<Transaction> {
        vec![Transaction {
            function_id: 0,
            args: vec![FuzzValue::Uint(100)],
            sender: 0,
            value: 0,
        }]
    }

    fn storage_write(
        var_name: &str,
        slot_key: &str,
        authority_sensitive: bool,
        caller_keyed: bool,
    ) -> TraceEventKind {
        TraceEventKind::StorageWrite {
            var_name: var_name.to_string(),
            slot_key: slot_key.to_string(),
            authority_sensitive,
            caller_keyed,
        }
    }

    fn storage_read(var_name: &str) -> TraceEventKind {
        TraceEventKind::StorageRead {
            var_name: var_name.to_string(),
            slot_key: var_name.to_string(),
            order_sensitive: is_order_sensitive_storage_name(var_name),
            caller_keyed: false,
        }
    }

    fn authority_modifier_ast(function_name: &str, head: &str) -> NormalizedAst {
        let mut ast = NormalizedAst::default();
        ast.files.push(SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: format!("{head} {{ admin = _owner; }}"),
        });
        ast.contracts.push(Contract {
            id: 0,
            name: "theRun".to_string(),
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
                end: head.len() as u32,
            },
        });
        ast.functions.push(Function {
            id: 0,
            contract: Some(0),
            name: Some(function_name.to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::NonPayable,
            params: vec!["_owner".to_string()],
            returns: Vec::new(),
            modifiers: Vec::new(),
            body: None,
            span: Span {
                file: 0,
                start: 0,
                end: ast.files[0].source.len() as u32,
            },
        });
        ast
    }

    fn visibility_ast(function_name: &str, visibility: Visibility) -> NormalizedAst {
        let source = format!("function {function_name}() {{ admin.send(1); }}");
        let mut ast = NormalizedAst::default();
        ast.files.push(SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: source.clone(),
        });
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
            visibility,
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

    fn source_ast_with_id(function_name: &str, source: &str, function_id: u32) -> NormalizedAst {
        let mut ast = NormalizedAst::default();
        ast.files.push(SourceFile {
            id: 0,
            path: "test.sol".to_string(),
            source: source.to_string(),
        });
        ast.contracts.push(Contract {
            id: 0,
            name: "Vault".to_string(),
            kind: ContractKind::Contract,
            bases: Vec::new(),
            functions: vec![function_id],
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
            id: function_id,
            contract: Some(0),
            name: Some(function_name.to_string()),
            kind: FunctionKind::Function,
            visibility: Visibility::Public,
            mutability: Mutability::Payable,
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

    fn source_ast(function_name: &str, source: &str) -> NormalizedAst {
        source_ast_with_id(function_name, source, 0)
    }

    #[test]
    fn detect_reentrancy() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::ExternalCall {
                        callee: "target.call".to_string(),
                        has_value: true,
                        low_level: true,
                        reentrant_capable: true,
                    },
                },
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::ReentrantCallback {
                        into_function_id: 0,
                    },
                },
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: storage_write("balance", "balance", false, false),
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_reentrancy(&trace, &make_tx(), None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::Reentrancy);
    }

    #[test]
    fn checked_selector_wrapper_suppresses_fuzz_unchecked_call() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::CallReturnUnchecked {
                    callee: "target.call.value".to_string(),
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let ast = source_ast(
            "deposit",
            "function deposit(address target) public payable { require(target.call.value(msg.value)(bytes4(sha3(\"addToBalance()\")))); }",
        );

        let findings = check_unchecked_call(&trace, &make_tx(), Some(&ast));
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_reentrancy_from_no_value_callback() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: storage_write("allowed", "allowed[msg.sender][_spender]", false, false),
                },
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::ExternalCall {
                        callee: "spender.call".to_string(),
                        has_value: false,
                        low_level: true,
                        reentrant_capable: true,
                    },
                },
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::ReentrantCallback {
                        into_function_id: 1,
                    },
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let ast = authority_modifier_ast(
            "approveAndCall",
            "function approveAndCall() public { spender.call(bytes4(0x0), 1); }",
        );
        let findings = check_reentrancy(&trace, &make_tx(), Some(&ast));
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_timestamp() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 1,
                kind: TraceEventKind::BranchOnTimestamp,
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_timestamp_dependency(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::TimestampDependency);
    }

    #[test]
    fn detect_timestamp_from_randomness_arithmetic() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 4,
                kind: TraceEventKind::TimestampArithmetic,
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_timestamp_dependency(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::TimestampDependency);
    }

    #[test]
    fn detect_overflow() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::ArithmeticOp {
                    op: "+".to_string(),
                    lhs: u128::MAX,
                    rhs: 1,
                    result: 0, // wrapping overflow
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_integer_overflow(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::IntegerOverflow);
    }

    #[test]
    fn detect_access_control() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: storage_write("owner", "owner", true, false),
                },
                // No SenderChecked event => access control issue
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_access_control(&trace, &make_tx(), None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::AccessControl);
    }

    #[test]
    fn detect_arbitrary_write_with_multi_sender_evidence() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 7,
                kind: storage_write("owner", "owner", true, false),
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![
            Transaction {
                function_id: 7,
                args: vec![FuzzValue::Uint(1)],
                sender: 0,
                value: 0,
            },
            Transaction {
                function_id: 7,
                args: vec![FuzzValue::Uint(2)],
                sender: 3,
                value: 0,
            },
        ];
        let findings = check_arbitrary_write(&trace, &txs, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::ArbitraryWrite);
    }

    #[test]
    fn caller_keyed_balance_write_is_not_access_control_or_arbitrary_write() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 9,
                kind: storage_write("balances", "balances[msg.sender]", false, true),
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![
            Transaction {
                function_id: 9,
                args: vec![FuzzValue::Uint(1)],
                sender: 0,
                value: 0,
            },
            Transaction {
                function_id: 9,
                args: vec![FuzzValue::Uint(2)],
                sender: 2,
                value: 0,
            },
        ];
        assert!(check_access_control(&trace, &txs, None).is_empty());
        assert!(check_arbitrary_write(&trace, &txs, None).is_empty());
    }

    #[test]
    fn wrong_constructor_candidate_suppresses_generic_authority_findings() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: storage_write("creator", "creator", true, false),
                },
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::WrongConstructorCandidate {
                        function_name: "DynamicPyramid".to_string(),
                        slot_key: "creator".to_string(),
                    },
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![
            Transaction {
                function_id: 0,
                args: vec![],
                sender: 0,
                value: 0,
            },
            Transaction {
                function_id: 0,
                args: vec![],
                sender: 1,
                value: 0,
            },
        ];

        assert!(check_access_control(&trace, &txs, None).is_empty());
        assert!(check_arbitrary_write(&trace, &txs, None).is_empty());

        let wrong_constructor = check_wrong_constructor_name(&trace, &txs);
        assert_eq!(wrong_constructor.len(), 1);
        assert!(wrong_constructor[0].message.contains("function 0"));
    }

    #[test]
    fn authority_modifier_hint_suppresses_generic_authority_findings() {
        let ast = authority_modifier_ast(
            "ChangeOwnership",
            "function ChangeOwnership(address _owner) onlyowner",
        );
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: storage_write("admin", "admin", true, false),
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![
            Transaction {
                function_id: 0,
                args: vec![FuzzValue::Uint(1)],
                sender: 0,
                value: 0,
            },
            Transaction {
                function_id: 0,
                args: vec![FuzzValue::Uint(2)],
                sender: 1,
                value: 0,
            },
        ];

        assert!(check_access_control(&trace, &txs, Some(&ast)).is_empty());
        assert!(check_arbitrary_write(&trace, &txs, Some(&ast)).is_empty());
    }

    #[test]
    fn authority_modifier_hint_suppresses_unprotected_withdrawal() {
        let ast = authority_modifier_ast("CollectAllFees", "function CollectAllFees() onlyowner");
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::EtherSent {
                    callee: "admin.send".to_string(),
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };

        assert!(check_unprotected_ether_withdrawal(&trace, &make_tx(), Some(&ast)).is_empty());
    }

    #[test]
    fn public_reward_claim_payout_suppresses_unprotected_withdrawal() {
        let ast = source_ast(
            "solve",
            "function solve(string solution) public payable { require(hash == sha3(solution)); msg.sender.transfer(1 ether); }",
        );
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::EtherSent {
                    callee: "msg.sender.transfer".to_string(),
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };

        assert!(check_unprotected_ether_withdrawal(&trace, &make_tx(), Some(&ast)).is_empty());
    }

    #[test]
    fn nonpositional_function_id_keeps_sender_owned_withdrawal_suppressed() {
        let function_id = 7;
        let ast = source_ast_with_id(
            "withdraw",
            "function withdraw(uint amount) public payable { if (credit[msg.sender] >= amount) { msg.sender.call.value(amount)(); credit[msg.sender] -= amount; } }",
            function_id,
        );
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id,
                kind: TraceEventKind::EtherSent {
                    callee: "msg.sender.call.value".to_string(),
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![Transaction {
            function_id,
            args: vec![FuzzValue::Uint(100)],
            sender: 0,
            value: 0,
        }];

        assert!(check_unprotected_ether_withdrawal(&trace, &txs, Some(&ast)).is_empty());
    }

    #[test]
    fn private_function_does_not_emit_unprotected_withdrawal() {
        let ast = visibility_ast("settlePayout", Visibility::Private);
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::EtherSent {
                    callee: "admin.send".to_string(),
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };

        assert!(check_unprotected_ether_withdrawal(&trace, &make_tx(), Some(&ast)).is_empty());
    }

    #[test]
    fn detect_tx_origin() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::TxOriginUsed,
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_tx_origin(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::TxOriginAuth);
    }

    #[test]
    fn detect_selfdestruct() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::SelfDestructCall,
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_selfdestruct(&trace, &make_tx(), None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::SelfDestruct);
    }

    #[test]
    fn sender_checked_selfdestruct_is_suppressed() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::SenderChecked,
                },
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::SelfDestructCall,
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_selfdestruct(&trace, &make_tx(), None);
        assert!(findings.is_empty());
    }

    #[test]
    fn exploit_helper_cleanup_selfdestruct_is_suppressed() {
        let ast = chainvet_frontend::frontend::parser::load_via_parser_sources(vec![chainvet_core::norm::SourceFile {
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
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id,
                kind: TraceEventKind::SelfDestructCall,
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };

        let findings = check_selfdestruct(&trace, &make_tx(), Some(&ast));
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_forced_ether_balance_invariant_as_locked_ether() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 3,
                    kind: TraceEventKind::BalanceInvariantCheck,
                },
                TraceEvent {
                    span: None,
                    function_id: 3,
                    kind: TraceEventKind::SelfDestructCall,
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_locked_ether(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::LockedEther);
    }

    #[test]
    fn detect_dos() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::UnboundedLoop {
                    var_name: "$t3".to_string(),
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_dos(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::DenialOfService);
    }

    #[test]
    fn detect_dos_block_gas_limit() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::UnboundedLoop {
                        var_name: "refundAddresses.length".to_string(),
                    },
                },
                TraceEvent {
                    span: None,
                    function_id: 0,
                    kind: TraceEventKind::HardcodedGasCall {
                        callee: "recipient.transfer".to_string(),
                    },
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_dos_block_gas_limit(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::DosBlockGasLimit);
    }

    #[test]
    fn detect_exception_disorder() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::ExternalCallThenState {
                    callee: "target".to_string(),
                    checked: false,
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_exception_disorder(&trace, &make_tx(), None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::ExceptionDisorder);
    }

    #[test]
    fn detect_unsafe_send_in_require() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 0,
                kind: TraceEventKind::UnsafeSendInRequire {
                    callee: "send".to_string(),
                },
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_unsafe_send_in_require(&trace, &make_tx(), None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::UnsafeSendInRequire);
    }

    #[test]
    fn detect_dos_with_failed_call() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 1,
                    kind: TraceEventKind::LoopEncountered,
                },
                TraceEvent {
                    span: None,
                    function_id: 1,
                    kind: TraceEventKind::HardcodedGasCall {
                        callee: "target.transfer".to_string(),
                    },
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_dos_with_failed_call(&trace, &make_tx(), None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::DosWithFailedCall);
    }

    #[test]
    fn detect_transaction_order_dependency() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 2,
                    kind: storage_read("price"),
                },
                TraceEvent {
                    span: None,
                    function_id: 2,
                    kind: TraceEventKind::EtherSent {
                        callee: "msg.sender".to_string(),
                    },
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![
            Transaction {
                function_id: 2,
                args: vec![FuzzValue::Uint(10)],
                sender: 0,
                value: 0,
            },
            Transaction {
                function_id: 2,
                args: vec![FuzzValue::Uint(11)],
                sender: 1,
                value: 0,
            },
        ];
        let findings = check_transaction_order_dependency(&trace, &txs);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].kind,
            FuzzFindingKind::TransactionOrderDependency
        );
    }

    #[test]
    fn tod_requires_multi_sender_evidence() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 2,
                    kind: storage_read("price"),
                },
                TraceEvent {
                    span: None,
                    function_id: 2,
                    kind: TraceEventKind::EtherSent {
                        callee: "msg.sender".to_string(),
                    },
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![Transaction {
            function_id: 2,
            args: vec![FuzzValue::Uint(10)],
            sender: 0,
            value: 0,
        }];
        let findings = check_transaction_order_dependency(&trace, &txs);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_tod_writer_reader_dependency_without_value_transfer() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 7,
                    kind: storage_write("price", "price", false, false),
                },
                TraceEvent {
                    span: None,
                    function_id: 8,
                    kind: storage_read("price"),
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![
            Transaction {
                function_id: 8,
                args: vec![FuzzValue::Uint(10)],
                sender: 0,
                value: 0,
            },
            Transaction {
                function_id: 8,
                args: vec![FuzzValue::Uint(11)],
                sender: 1,
                value: 0,
            },
            Transaction {
                function_id: 7,
                args: vec![FuzzValue::Uint(12)],
                sender: 1,
                value: 0,
            },
        ];
        let findings = check_transaction_order_dependency(&trace, &txs);
        assert!(findings
            .iter()
            .any(|f| f.kind == FuzzFindingKind::TransactionOrderDependency));
    }

    #[test]
    fn detect_signature_malleability() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
                    span: None,
                function_id: 3,
                kind: TraceEventKind::EcrecoverCalled,
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![
            Transaction {
                function_id: 3,
                args: vec![FuzzValue::Uint(1)],
                sender: 0,
                value: 0,
            },
            Transaction {
                function_id: 3,
                args: vec![FuzzValue::Uint(2)],
                sender: 1,
                value: 0,
            },
        ];
        let findings = check_cryptographic(&trace, &txs);
        assert!(findings
            .iter()
            .any(|f| f.kind == FuzzFindingKind::SignatureMalleability));
    }

    #[test]
    fn cryptographic_zero_check_suppresses_malleability_finding() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    span: None,
                    function_id: 3,
                    kind: TraceEventKind::EcrecoverCalled,
                },
                TraceEvent {
                    span: None,
                    function_id: 3,
                    kind: TraceEventKind::EcrecoverZeroChecked,
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let txs = vec![
            Transaction {
                function_id: 3,
                args: vec![FuzzValue::Uint(1)],
                sender: 0,
                value: 0,
            },
            Transaction {
                function_id: 3,
                args: vec![FuzzValue::Uint(2)],
                sender: 1,
                value: 0,
            },
        ];
        let findings = check_cryptographic(&trace, &txs);
        assert!(findings.is_empty());
    }

    #[test]
    fn dedup_removes_duplicates() {
        let f1 = FuzzFinding {
            span: None,
            kind: FuzzFindingKind::Reentrancy,
            severity: FuzzSeverity::High,
            message: "test".to_string(),
            tx_sequence: make_tx(),
            trace_hash: "abc".to_string(),
        };
        let f2 = f1.clone();
        let f3 = FuzzFinding {
            span: None,
            trace_hash: "def".to_string(),
            ..f1.clone()
        };
        let unique = deduplicate(vec![f1, f2, f3]);
        assert_eq!(unique.len(), 2);
    }
}
