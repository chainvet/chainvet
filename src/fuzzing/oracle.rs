use sha2::{Digest, Sha256};

use crate::fuzzing::types::{
    ExecutionTrace, FuzzFinding, FuzzFindingKind, FuzzSeverity, TraceEventKind, Transaction,
};

/// Run all oracle checks on an execution trace.
pub fn check_all(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    // Taxonomy-aligned core checks (taxonomy.xlsx):
    // Access Control, Arithmetic, Block Manipulation, Cryptographic, DoS, Reentrancy, Storage&Memory.
    findings.extend(check_reentrancy(trace, tx_sequence));
    findings.extend(check_timestamp_dependency(trace, tx_sequence));
    findings.extend(check_unchecked_call(trace, tx_sequence));
    findings.extend(check_exception_disorder(trace, tx_sequence));
    findings.extend(check_integer_overflow(trace, tx_sequence));
    findings.extend(check_integer_underflow(trace, tx_sequence));
    findings.extend(check_access_control(trace, tx_sequence));
    findings.extend(check_arbitrary_write(trace, tx_sequence));
    findings.extend(check_tx_origin(trace, tx_sequence));
    findings.extend(check_selfdestruct(trace, tx_sequence));
    findings.extend(check_dos(trace, tx_sequence));
    findings.extend(check_unsafe_send_in_require(trace, tx_sequence));
    findings.extend(check_dos_with_failed_call(trace, tx_sequence));
    findings.extend(check_unsafe_delegatecall(trace, tx_sequence));
    findings.extend(check_transaction_order_dependency(trace, tx_sequence));
    findings.extend(check_weak_prng(trace, tx_sequence));
    findings.extend(check_hardcoded_gas(trace, tx_sequence));
    findings.extend(check_storage_memory(trace, tx_sequence));
    findings.extend(check_division_before_multiplication(trace, tx_sequence));
    findings.extend(check_cryptographic(trace, tx_sequence));
    findings.extend(check_unprotected_ether_withdrawal(trace, tx_sequence));
    findings.extend(check_locked_ether(trace, tx_sequence));
    findings
}

/// Reentrancy: callback-capable external call followed by a storage write in the same function.
fn check_reentrancy(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut external_call_seen: std::collections::HashMap<u32, bool> =
        std::collections::HashMap::new();
    let mut callback_seen: std::collections::HashMap<u32, bool> = std::collections::HashMap::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::ExternalCall {
                has_value,
                reentrant_capable,
                ..
            } => {
                if *has_value && *reentrant_capable {
                    external_call_seen.insert(event.function_id, true);
                }
            }
            TraceEventKind::ReentrantCallback { .. } => {
                callback_seen.insert(event.function_id, true);
            }
            TraceEventKind::StorageWrite { var_name, .. } => {
                if external_call_seen
                    .get(&event.function_id)
                    .copied()
                    .unwrap_or(false)
                    && callback_seen
                        .get(&event.function_id)
                        .copied()
                        .unwrap_or(false)
                {
                    let hash = hash_finding("reentrancy", event.function_id, var_name);
                    findings.push(FuzzFinding {
                        kind: FuzzFindingKind::Reentrancy,
                        severity: FuzzSeverity::High,
                        message: format!(
                            "Potential reentrancy: callback-capable external call with value in function {} followed by storage write to '{}'",
                            event.function_id, var_name
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

/// Timestamp dependency: block.timestamp used in a conditional branch.
fn check_timestamp_dependency(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen_functions = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::BranchOnTimestamp = &event.kind {
            if seen_functions.insert(event.function_id) {
                let hash = hash_finding("timestamp", event.function_id, "branch");
                findings.push(FuzzFinding {
                    kind: FuzzFindingKind::TimestampDependency,
                    severity: FuzzSeverity::Medium,
                    message: format!(
                        "Timestamp dependency: block.timestamp used in conditional branch in function {}",
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

/// Unchecked call: an external call whose return value is not checked.
fn check_unchecked_call(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::CallReturnUnchecked { callee } = &event.kind {
            let key = (event.function_id, callee.clone());
            if seen.insert(key) {
                let hash = hash_finding("unchecked-call", event.function_id, callee);
                findings.push(FuzzFinding {
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
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::ExternalCallThenState { callee, checked } = &event.kind {
            if !checked {
                let key = (event.function_id, callee.clone());
                if seen.insert(key) {
                    let hash = hash_finding("exception-disorder", event.function_id, callee);
                    findings.push(FuzzFinding {
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
fn check_access_control(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen_functions = std::collections::HashSet::new();

    // Find functions that write to storage but never check msg.sender
    let mut functions_with_writes: std::collections::HashSet<u32> =
        std::collections::HashSet::new();
    let mut functions_with_sender_check: std::collections::HashSet<u32> =
        std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::StorageWrite {
                var_name,
                authority_sensitive,
                caller_keyed,
                ..
            } => {
                if var_name != "__no_sender_check" && *authority_sensitive && !*caller_keyed {
                    functions_with_writes.insert(event.function_id);
                }
            }
            TraceEventKind::SenderChecked => {
                functions_with_sender_check.insert(event.function_id);
            }
            _ => {}
        }
    }

    for func_id in &functions_with_writes {
        if !functions_with_sender_check.contains(func_id) && seen_functions.insert(*func_id) {
            let hash = hash_finding("access-control", *func_id, "no-sender-check");
            findings.push(FuzzFinding {
                kind: FuzzFindingKind::AccessControl,
                severity: FuzzSeverity::High,
                message: format!(
                    "Missing access control: function {} writes to storage without checking msg.sender",
                    func_id
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
fn check_arbitrary_write(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut writes_by_fn: std::collections::HashMap<u32, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    let mut sender_checked: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::StorageWrite {
                var_name,
                slot_key,
                authority_sensitive,
                caller_keyed,
            } if var_name != "__no_sender_check" && *authority_sensitive && !*caller_keyed => {
                writes_by_fn
                    .entry(event.function_id)
                    .or_default()
                    .insert(slot_key.clone());
            }
            TraceEventKind::SenderChecked => {
                sender_checked.insert(event.function_id);
            }
            _ => {}
        }
    }

    let mut senders_by_fn: std::collections::HashMap<u32, std::collections::HashSet<usize>> =
        std::collections::HashMap::new();
    for tx in tx_sequence {
        senders_by_fn
            .entry(tx.function_id)
            .or_default()
            .insert(tx.sender);
    }

    for (function_id, writes) in writes_by_fn {
        if sender_checked.contains(&function_id) {
            continue;
        }
        let sender_count = senders_by_fn.get(&function_id).map(|s| s.len()).unwrap_or(0);
        if sender_count < 2 {
            continue;
        }

        let mut interesting_vars = writes
            .iter()
            .filter(|name| {
                let lower = name.to_ascii_lowercase();
                lower.contains("owner")
                    || lower.contains("admin")
                    || lower.contains("operator")
                    || lower.contains("minter")
                    || lower.contains("pauser")
                    || lower.contains("implementation")
                    || lower.contains("governance")
            })
            .cloned()
            .collect::<Vec<_>>();
        interesting_vars.sort_unstable();
        let detail = if !interesting_vars.is_empty() {
            interesting_vars.join(",")
        } else {
            let mut all = writes.into_iter().collect::<Vec<_>>();
            all.sort_unstable();
            all.join(",")
        };

        if seen.insert(function_id) {
            let hash = hash_finding("arbitrary-write", function_id, detail.as_str());
            findings.push(FuzzFinding {
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

/// tx.origin authentication: using tx.origin for authorization.
fn check_tx_origin(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen_functions = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::TxOriginUsed = &event.kind {
            if seen_functions.insert(event.function_id) {
                let hash = hash_finding("tx-origin", event.function_id, "used");
                findings.push(FuzzFinding {
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

/// Unprotected selfdestruct: selfdestruct without access control.
fn check_selfdestruct(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
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
        if seen_functions.insert(*func_id) {
            let severity = if functions_with_sender_check.contains(func_id) {
                FuzzSeverity::Low
            } else {
                FuzzSeverity::High
            };
            let msg = if functions_with_sender_check.contains(func_id) {
                format!("selfdestruct in function {} (has sender check)", func_id)
            } else {
                format!(
                    "Unprotected selfdestruct in function {} — anyone can destroy the contract",
                    func_id
                )
            };
            let hash = hash_finding("selfdestruct", *func_id, "call");
            findings.push(FuzzFinding {
                kind: FuzzFindingKind::SelfDestruct,
                severity,
                message: msg,
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

/// Unsafe send() in require/assert condition can be griefed into revert-based DoS.
fn check_unsafe_send_in_require(
    trace: &ExecutionTrace,
    tx_sequence: &[Transaction],
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::UnsafeSendInRequire { callee } = &event.kind {
            let key = (event.function_id, callee.clone());
            if seen.insert(key) {
                let hash = hash_finding("unsafe-send-in-require", event.function_id, callee);
                findings.push(FuzzFinding {
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
) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut function_has_loop: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut function_has_external_call: std::collections::HashSet<u32> =
        std::collections::HashSet::new();

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::LoopEncountered | TraceEventKind::UnboundedLoop { .. } => {
                function_has_loop.insert(event.function_id);
            }
            TraceEventKind::ExternalCall { .. } | TraceEventKind::HardcodedGasCall { .. } => {
                function_has_external_call.insert(event.function_id);
            }
            _ => {}
        }
    }

    for function_id in function_has_loop {
        if !function_has_external_call.contains(&function_id) {
            continue;
        }
        if seen.insert(function_id) {
            let hash = hash_finding("dos-with-failed-call", function_id, "loop-external-call");
            findings.push(FuzzFinding {
                kind: FuzzFindingKind::DosWithFailedCall,
                severity: FuzzSeverity::High,
                message: format!(
                    "DoS with failed call: function {} executes external call in loop context",
                    function_id
                ),
                tx_sequence: tx_sequence.to_vec(),
                trace_hash: hash,
            });
        }
    }

    findings
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

    for event in &trace.events {
        match &event.kind {
            TraceEventKind::StorageRead {
                var_name,
                order_sensitive,
                ..
            } => {
                if *order_sensitive || is_order_sensitive_storage_name(var_name) {
                    sensitive_reads.insert(event.function_id);
                }
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
        if !value_transfer.contains(&function_id) {
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
        if seen.insert(function_id) {
            let hash = hash_finding("transaction-order-dependency", function_id, "sensitive+value");
            findings.push(FuzzFinding {
                kind: FuzzFindingKind::TransactionOrderDependency,
                severity: FuzzSeverity::Medium,
                message: format!(
                    "Transaction order dependency: function {} reads order-sensitive storage and transfers value across {} distinct senders",
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
fn check_hardcoded_gas(trace: &ExecutionTrace, tx_sequence: &[Transaction]) -> Vec<FuzzFinding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &trace.events {
        if let TraceEventKind::HardcodedGasCall { callee } = &event.kind {
            let key = (event.function_id, callee.clone());
            if seen.insert(key) {
                let hash = hash_finding("hardcoded-gas", event.function_id, callee);
                findings.push(FuzzFinding {
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
    // Check if any transaction sent value (payable function)
    let has_payable = tx_sequence.iter().any(|tx| tx.value > 0);
    // Check if any ether was sent out
    let has_ether_out = trace.events.iter().any(|e| {
        matches!(&e.kind, TraceEventKind::EtherSent { .. })
            || matches!(&e.kind, TraceEventKind::HardcodedGasCall { .. })
    });

    if has_payable && !has_ether_out {
        let hash = hash_finding("locked-ether", 0, "contract");
        return vec![FuzzFinding {
            kind: FuzzFindingKind::LockedEther,
            severity: FuzzSeverity::Medium,
            message: "Contract accepts Ether but has no withdrawal mechanism — Ether may be permanently locked".to_string(),
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
        if !functions_with_sender_check.contains(func_id) && seen.insert(*func_id) {
            let hash = hash_finding("unprotected-withdrawal", *func_id, callee);
            findings.push(FuzzFinding {
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

    #[test]
    fn detect_reentrancy() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    function_id: 0,
                    kind: TraceEventKind::ExternalCall {
                        callee: "target.call".to_string(),
                        has_value: true,
                        reentrant_capable: true,
                    },
                },
                TraceEvent {
                    function_id: 0,
                    kind: TraceEventKind::ReentrantCallback {
                        into_function_id: 0,
                    },
                },
                TraceEvent {
                    function_id: 0,
                    kind: storage_write("balance", "balance", false, false),
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_reentrancy(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::Reentrancy);
    }

    #[test]
    fn detect_timestamp() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
    fn detect_overflow() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
        let findings = check_access_control(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::AccessControl);
    }

    #[test]
    fn detect_arbitrary_write_with_multi_sender_evidence() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
        let findings = check_arbitrary_write(&trace, &txs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::ArbitraryWrite);
    }

    #[test]
    fn caller_keyed_balance_write_is_not_access_control_or_arbitrary_write() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
        assert!(check_access_control(&trace, &txs).is_empty());
        assert!(check_arbitrary_write(&trace, &txs).is_empty());
    }

    #[test]
    fn detect_tx_origin() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
                function_id: 0,
                kind: TraceEventKind::SelfDestructCall,
            }],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_selfdestruct(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::SelfDestruct);
    }

    #[test]
    fn detect_dos() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
    fn detect_exception_disorder() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
        let findings = check_exception_disorder(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::ExceptionDisorder);
    }

    #[test]
    fn detect_unsafe_send_in_require() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
        let findings = check_unsafe_send_in_require(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::UnsafeSendInRequire);
    }

    #[test]
    fn detect_dos_with_failed_call() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    function_id: 1,
                    kind: TraceEventKind::LoopEncountered,
                },
                TraceEvent {
                    function_id: 1,
                    kind: TraceEventKind::ExternalCall {
                        callee: "target.call".to_string(),
                        has_value: false,
                        reentrant_capable: false,
                    },
                },
            ],
            coverage: Default::default(),
            edge_coverage: Default::default(),
            reverted: false,
            final_state: Default::default(),
        };
        let findings = check_dos_with_failed_call(&trace, &make_tx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FuzzFindingKind::DosWithFailedCall);
    }

    #[test]
    fn detect_transaction_order_dependency() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    function_id: 2,
                    kind: storage_read("price"),
                },
                TraceEvent {
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
        assert_eq!(findings[0].kind, FuzzFindingKind::TransactionOrderDependency);
    }

    #[test]
    fn tod_requires_multi_sender_evidence() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    function_id: 2,
                    kind: storage_read("price"),
                },
                TraceEvent {
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
    fn detect_signature_malleability() {
        let trace = ExecutionTrace {
            events: vec![TraceEvent {
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
        assert!(
            findings
                .iter()
                .any(|f| f.kind == FuzzFindingKind::SignatureMalleability)
        );
    }

    #[test]
    fn cryptographic_zero_check_suppresses_malleability_finding() {
        let trace = ExecutionTrace {
            events: vec![
                TraceEvent {
                    function_id: 3,
                    kind: TraceEventKind::EcrecoverCalled,
                },
                TraceEvent {
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
            kind: FuzzFindingKind::Reentrancy,
            severity: FuzzSeverity::High,
            message: "test".to_string(),
            tx_sequence: make_tx(),
            trace_hash: "abc".to_string(),
        };
        let f2 = f1.clone();
        let f3 = FuzzFinding {
            trace_hash: "def".to_string(),
            ..f1.clone()
        };
        let unique = deduplicate(vec![f1, f2, f3]);
        assert_eq!(unique.len(), 2);
    }
}
