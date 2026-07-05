//! Audit-report rendering shared by the CLI and the server (Markdown / HTML / PDF).
//!
//! A single [`AuditReport`] model is built from the orchestrator's typed
//! [`ScanResult`] and rendered to each format off the same data. The structure
//! follows a Cyfrin-style audit report (protocol summary → disclaimer → risk
//! classification → scope → executive summary → findings by severity, each with
//! impact, a proof-of-concept, and a recommended mitigation). The per-finding
//! guidance/remediation content is a deterministic, curated library keyed by
//! detector kind — no AI required.

mod html;
mod markdown;
mod pdf;

use std::collections::HashMap;

use chainvet_core::norm::NormalizedAst;
use chainvet_orchestrator::{ScanFinding, ScanMode, ScanResult};

pub use html::render_html;
pub use markdown::render_markdown;
pub use pdf::{render_pdf_bytes, write_pdf};

/// The full audit report, decoupled from the engines — built once, rendered many.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub project_name: String,
    pub target: String,
    pub analysis_mode: String,
    pub raw_findings: usize,
    pub metrics: Vec<AuditMetric>,
    pub findings: Vec<AuditFinding>,
}

#[derive(Debug, Clone)]
pub struct AuditMetric {
    pub label: String,
    pub value: String,
}

impl AuditMetric {
    fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub category: String,
    pub kind: String,
    pub severity: String,
    /// Confidence tier (`confirmed`/`candidate`).
    pub tier: String,
    /// Raw per-detector engine confidence; absent for symbolic/fuzz findings.
    pub confidence: Option<String>,
    pub message: String,
    pub file: Option<String>,
    /// 1-based start line (resolved from the byte span).
    pub start: Option<u32>,
    /// 1-based end line.
    pub end: Option<u32>,
    pub function_name: Option<String>,
    /// Which engine surfaced it (`static`/`symbolic`/`fuzz`/`hybrid-confirmed`).
    pub analysis_layer: String,
}

/// Running aggregate of hybrid telemetry across one or more scans, so a report
/// covering several files (the server analyzes a project file-by-file) still
/// surfaces one coherent metrics block.
#[derive(Default)]
struct HybridAgg {
    static_selected: usize,
    static_total: usize,
    se_findings: usize,
    corpus: usize,
    coverage_sum: f64,
    coverage_n: usize,
}

impl AuditReport {
    /// Build the report from a single completed scan. The AST is used only to
    /// resolve `function_id`s to real names so proofs-of-concept name the right
    /// function.
    pub fn from_scan(result: &ScanResult, ast: &NormalizedAst, target: &str) -> Self {
        Self::from_scans([(result, ast)], target)
    }

    /// Build one report from several `(scan, ast)` pairs — used when a target is
    /// a project analyzed file-by-file. Findings are accumulated across all
    /// pairs (each pair resolves its own function names) and hybrid telemetry is
    /// aggregated. For a single pair this is identical to [`Self::from_scan`].
    pub fn from_scans<'a>(
        scans: impl IntoIterator<Item = (&'a ScanResult, &'a NormalizedAst)>,
        target: &str,
    ) -> Self {
        let mut findings = Vec::new();
        let mut raw_findings = 0usize;
        let mut mode: Option<ScanMode> = None;
        let mut agg: Option<HybridAgg> = None;

        for (result, ast) in scans {
            mode.get_or_insert(result.mode);
            raw_findings += result.findings.len();
            append_findings(result, ast, &mut findings);
            if let Some(hybrid) = &result.hybrid {
                let a = agg.get_or_insert_with(HybridAgg::default);
                a.static_selected += hybrid.summary.static_targets_selected;
                a.static_total += hybrid.summary.static_targets_total;
                a.se_findings += hybrid.summary.se_findings_total;
                a.corpus += hybrid.summary.fuzz_corpus_size;
                a.coverage_sum += hybrid.fuzz_coverage_pct;
                a.coverage_n += 1;
            }
        }

        let metrics = agg
            .map(|a| {
                let coverage = if a.coverage_n == 0 {
                    0.0
                } else {
                    a.coverage_sum / a.coverage_n as f64
                };
                vec![
                    AuditMetric::new(
                        "Static targets",
                        format!("{}/{}", a.static_selected, a.static_total),
                    ),
                    AuditMetric::new("Symbolic findings", a.se_findings.to_string()),
                    AuditMetric::new("Fuzz coverage", format!("{coverage:.1}%")),
                    AuditMetric::new("Fuzz corpus", a.corpus.to_string()),
                ]
            })
            .unwrap_or_default();

        Self {
            project_name: project_name_from_path(target),
            target: target.to_string(),
            analysis_mode: mode.map(mode_label).unwrap_or("hybrid").to_string(),
            raw_findings,
            metrics,
            findings,
        }
    }
}

/// Resolve one scan's findings into [`AuditFinding`]s and append them to `out`.
fn append_findings(result: &ScanResult, ast: &NormalizedAst, out: &mut Vec<AuditFinding>) {
    let names: HashMap<u32, String> = ast
        .functions
        .iter()
        .filter_map(|f| f.name.clone().map(|name| (f.id, name)))
        .collect();

    // Read each referenced source once so byte spans resolve to line numbers.
    let mut sources: HashMap<String, String> = HashMap::new();
    for row in &result.findings {
        if let Some(file) = &row.file {
            sources
                .entry(file.clone())
                .or_insert_with(|| std::fs::read_to_string(file).unwrap_or_default());
        }
    }

    out.extend(
        result
            .findings
            .iter()
            .map(|row| AuditFinding::from_row(row, &names, &sources)),
    );
}

impl AuditFinding {
    fn from_row(
        row: &ScanFinding,
        names: &HashMap<u32, String>,
        sources: &HashMap<String, String>,
    ) -> Self {
        let kind = row.kind.clone();
        let category = row
            .category
            .clone()
            .filter(|c| !c.trim().is_empty())
            .unwrap_or_else(|| default_category_for_kind(&kind).to_string());
        // Resolve byte offsets to 1-based line numbers against the source.
        let source = row.file.as_ref().and_then(|f| sources.get(f));
        let to_line = |offset: Option<u32>| offset.map(|o| line_of(source, o));
        Self {
            category,
            kind,
            severity: row
                .severity
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "informational".to_string()),
            tier: row.tier.clone(),
            confidence: row.confidence.clone(),
            message: row.message.clone(),
            file: row.file.clone(),
            start: to_line(row.start),
            end: to_line(row.end),
            function_name: row.function_id.and_then(|id| names.get(&id).cloned()),
            analysis_layer: row.provenance.clone(),
        }
    }
}

/// 1-based line number of a byte offset within `source` (1 if unavailable).
fn line_of(source: Option<&String>, offset: u32) -> u32 {
    match source {
        Some(text) => {
            let end = (offset as usize).min(text.len());
            1 + text[..end].bytes().filter(|&b| b == b'\n').count() as u32
        }
        None => 0,
    }
}

fn mode_label(mode: ScanMode) -> &'static str {
    match mode {
        ScanMode::Static => "static",
        ScanMode::Symbolic => "symbolic",
        ScanMode::Fuzzing => "fuzzing",
        ScanMode::Hybrid => "hybrid",
    }
}

fn project_name_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("Smart Contract Project")
        .to_string()
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

#[derive(Default, Clone, Copy)]
pub(crate) struct SeverityCounts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

pub(crate) fn severity_counts(findings: &[AuditFinding]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for finding in findings {
        match severity_bucket(&finding.severity) {
            "high" => counts.high += 1,
            "medium" => counts.medium += 1,
            "low" => counts.low += 1,
            _ => counts.informational += 1,
        }
    }
    counts
}

pub(crate) fn severity_bucket(severity: &str) -> &'static str {
    let value = severity.trim().to_ascii_lowercase();
    if value.contains("critical") || value.contains("high") {
        "high"
    } else if value.contains("medium") || value.contains("moderate") {
        "medium"
    } else if value.contains("low") {
        "low"
    } else {
        "informational"
    }
}

pub(crate) fn severity_sort_rank(severity: &str) -> u8 {
    match severity_bucket(severity) {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

pub(crate) fn severity_label(severity: &str) -> &'static str {
    match severity_bucket(severity) {
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Informational",
    }
}

pub(crate) fn finding_id(idx: usize, severity: &str) -> String {
    let prefix = match severity_bucket(severity) {
        "high" => "H",
        "medium" => "M",
        "low" => "L",
        _ => "I",
    };
    format!("{prefix}-{idx:02}")
}

pub(crate) fn finding_title(finding: &AuditFinding) -> String {
    let mut title = title_case_kind(&finding.kind);
    if let Some(function) = finding
        .function_name
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        title.push_str(" in ");
        title.push_str(function);
    }
    title
}

pub(crate) fn location_summary(finding: &AuditFinding) -> String {
    // Reference the file by name — the full path is stated once under Scope, and
    // repeating an absolute path per finding bloats tables (and overflows in PDF).
    let file = finding
        .file
        .as_deref()
        .map(|path| {
            std::path::Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(path)
        })
        .unwrap_or("<unknown>");
    let mut location = String::from(file);
    if let Some(function) = finding
        .function_name
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        location.push_str("::");
        location.push_str(function);
    }
    match (finding.start, finding.end) {
        (Some(start), Some(end)) if start != 0 && end != 0 && start != end => {
            location.push_str(&format!(":{start}-{end}"));
        }
        (Some(start), _) if start != 0 => {
            location.push_str(&format!(":{start}"));
        }
        _ => {}
    }
    location
}

fn title_case_kind(kind: &str) -> String {
    kind.split(['-', '_', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Detector-kind canonicalization + category (harvested from `surfaced`)
// ---------------------------------------------------------------------------

pub(crate) fn canonicalize_kind(kind: &str) -> String {
    let normalized = kind.trim();
    if normalized.is_empty() {
        return String::new();
    }
    if normalized.starts_with("reentrancy") {
        return "reentrancy".to_string();
    }
    match normalized {
        "hardcoded-gas" => "hardcoded-gas-transfer".to_string(),
        "storage-memory-issue" => "memory-manipulation".to_string(),
        "unused-return-value" => "unchecked-call".to_string(),
        "dangerous-block-timestamp" => "timestamp-dependency".to_string(),
        "underflow" => "integer-underflow".to_string(),
        "force-ether-balance-check" => "locked-ether".to_string(),
        other => other.to_string(),
    }
}

fn default_category_for_kind(kind: &str) -> &'static str {
    match canonicalize_kind(kind).as_str() {
        "access-control"
        | "arbitrary-write"
        | "arbitrary-storage-write"
        | "unchecked-call"
        | "exception-disorder"
        | "tx-origin"
        | "unprotected-selfdestruct"
        | "unsafe-delegatecall"
        | "wrong-constructor-name"
        | "uninit-permission-check"
        | "unprotected-ether-withdrawal"
        | "public-mint-burn" => "Access Control",
        "integer-overflow" | "integer-underflow" | "division-before-multiplication" => "Arithmetic",
        "weak-prng" | "timestamp-dependency" | "transaction-order-dependency" => {
            "Block Manipulation"
        }
        "dos-block-gas-limit"
        | "dos-with-failed-call"
        | "hardcoded-gas-transfer"
        | "locked-ether" => "Denial of Service",
        "memory-manipulation" | "shadowing" => "Storage and Memory",
        "reentrancy" => "Reentrancy",
        "cryptographic-issue" | "signature-malleability" => "Cryptographic",
        _ => "Miscellaneous",
    }
}

// ---------------------------------------------------------------------------
// Curated guidance library: per-detector abuse / PoC / remediation.
// Deterministic and AI-independent.
// ---------------------------------------------------------------------------

pub(crate) struct FindingGuidance {
    pub abuse: String,
    pub poc_code: Option<String>,
    pub remediation: String,
    pub remediation_code: Option<String>,
}

pub(crate) fn impact_for_finding(finding: &AuditFinding) -> &'static str {
    match canonicalize_kind(&finding.kind).as_str() {
        "reentrancy" => {
            "A vulnerable external-call flow may allow an attacker-controlled contract to re-enter before state is finalized, potentially draining funds or corrupting accounting."
        }
        "access-control"
        | "tx-origin"
        | "unprotected-selfdestruct"
        | "unsafe-delegatecall"
        | "unprotected-ether-withdrawal"
        | "public-mint-burn"
        | "arbitrary-storage-write" => {
            "Missing or weak authorization can allow unauthorized users to execute privileged actions or change sensitive protocol state."
        }
        "integer-overflow" | "integer-underflow" => {
            "Arithmetic edge cases can produce incorrect balances, limits, or accounting values when unchecked math is reachable."
        }
        "weak-prng" | "timestamp-dependency" | "transaction-order-dependency" => {
            "Block-derived or ordering-sensitive logic can be influenced by miners, validators, or transaction ordering, causing unfair or unexpected outcomes."
        }
        "dos-block-gas-limit" | "dos-with-failed-call" | "locked-ether" => {
            "The affected flow may become unavailable, fail for legitimate users, or permanently trap funds under realistic execution conditions."
        }
        "unchecked-call" | "hardcoded-gas-transfer" => {
            "External call failures may be missed or forced by gas constraints, causing state to continue under incorrect assumptions."
        }
        "memory-manipulation" | "shadowing" => {
            "Ambiguous storage or variable behavior can cause developers and users to reason incorrectly about the contract state."
        }
        _ => {
            "The finding indicates behavior that may weaken contract safety, correctness, or maintainability depending on the surrounding business logic."
        }
    }
}

fn recommendation_for_kind(kind: &str, category: &str) -> &'static str {
    match canonicalize_kind(kind).as_str() {
        "reentrancy" => {
            "Apply checks-effects-interactions, update state before external calls, and consider a reentrancy guard on externally callable payout paths."
        }
        "access-control"
        | "unprotected-ether-withdrawal"
        | "public-mint-burn"
        | "arbitrary-storage-write" => {
            "Add explicit authorization checks for privileged functions and cover them with tests for unauthorized callers."
        }
        "tx-origin" => {
            "Use `msg.sender` for authorization instead of `tx.origin`, and validate the intended caller model in tests."
        }
        "unprotected-selfdestruct" => {
            "Remove `selfdestruct` where possible, or restrict it to a tightly controlled administrative path."
        }
        "unsafe-delegatecall" => {
            "Avoid delegatecall to user-controlled addresses. If delegatecall is required, restrict targets to trusted implementations."
        }
        "integer-overflow" | "integer-underflow" => {
            "Use Solidity 0.8+ checked arithmetic or a reviewed SafeMath-style library for older compiler versions."
        }
        "weak-prng" | "timestamp-dependency" => {
            "Avoid block variables for randomness. Use a commit-reveal design or a verifiable randomness oracle for value-bearing outcomes."
        }
        "transaction-order-dependency" => {
            "Design state transitions so transaction ordering cannot give another participant a profitable advantage."
        }
        "dos-block-gas-limit" => {
            "Avoid unbounded loops over dynamic storage. Prefer pull-based accounting, pagination, or bounded batch processing."
        }
        "dos-with-failed-call" | "unchecked-call" => {
            "Check external call return values and isolate user-specific failures with pull payments or retryable accounting."
        }
        "hardcoded-gas-transfer" => {
            "Avoid relying on fixed gas stipends for critical transfers. Prefer explicit call handling with checked success."
        }
        "locked-ether" => {
            "Add a reviewed withdrawal or recovery path and test forced-Ether and accounting edge cases."
        }
        "shadowing" => {
            "Rename shadowed variables and avoid local or parameter names that hide state variables."
        }
        _ if category.eq_ignore_ascii_case("gas") => {
            "Review the affected code path for unnecessary storage access, repeated computation, or unbounded iteration."
        }
        _ => {
            "Review the affected code path manually, add a focused regression test, and apply the smallest code change that removes the unsafe behavior."
        }
    }
}

pub(crate) fn guidance_for_finding(finding: &AuditFinding) -> FindingGuidance {
    let kind = canonicalize_kind(&finding.kind);
    let function = finding
        .function_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("vulnerableFunction");
    let location = location_summary(finding);

    match kind.as_str() {
        "reentrancy" => FindingGuidance {
            abuse: format!(
                "An attacker can call `{function}` from a contract whose fallback re-enters the same function before the vulnerable contract finalizes its accounting. If the balance or entitlement is reduced after the external call, the attacker can withdraw more than their legitimate balance. A minimal abuse flow is: deposit or obtain credit, call `{function}`, re-enter from `receive()`, and repeat until the contract balance or gas is exhausted. Location: {location}."
            ),
            poc_code: Some(format!(
                r#"interface IVictim {{
    function addToBalance() external payable;
    function {function}() external;
}}

contract ReentrancyPoC {{
    IVictim public victim;
    uint256 public reentered;

    constructor(address victim_) {{
        victim = IVictim(victim_);
    }}

    function attack() external payable {{
        victim.addToBalance{{value: msg.value}}();
        victim.{function}();
    }}

    receive() external payable {{
        if (reentered < 3 && address(victim).balance > 0) {{
            reentered++;
            victim.{function}();
        }}
    }}
}}"#
            )),
            remediation: "Apply checks-effects-interactions on the affected withdrawal path: validate the caller, calculate the amount, update all internal accounting before the external transfer, then perform the external call. Add a reentrancy guard on externally callable payout functions and prefer pull-based withdrawals for user funds.".to_string(),
            remediation_code: Some(format!(
                r#"bool private locked;
mapping(address => uint256) private balances;

modifier nonReentrant() {{
    require(!locked, "reentrant");
    locked = true;
    _;
    locked = false;
}}

function {function}() external nonReentrant {{
    uint256 amount = balances[msg.sender];
    require(amount != 0, "nothing to withdraw");

    balances[msg.sender] = 0; // effects before interaction

    (bool ok, ) = msg.sender.call{{value: amount}}("");
    require(ok, "transfer failed");
}}"#
            )),
        },
        "access-control" | "unprotected-ether-withdrawal" | "public-mint-burn"
        | "arbitrary-storage-write" => FindingGuidance {
            abuse: format!(
                "The function `{function}` appears to perform a privileged action without a reliable authorization gate. Any externally owned account or contract can call it directly, so an attacker can execute the privileged path without owning the protocol role. Depending on the function, this may drain ETH, mint/burn assets, or change security-critical state. Location: {location}."
            ),
            poc_code: Some(format!(
                r#"interface IVictim {{
    function {function}() external;
}}

contract UnauthorizedCallerPoC {{
    function exploit(address victim) external {{
        // Succeeds if {function} has no onlyOwner/role check.
        IVictim(victim).{function}();
    }}
}}"#
            )),
            remediation: "Restrict the function to the exact role that is supposed to execute it. Use `onlyOwner`, role-based access control, or a protocol-specific permission check, and add negative tests that prove arbitrary callers revert.".to_string(),
            remediation_code: Some(format!(
                r#"address private owner;

modifier onlyOwner() {{
    require(msg.sender == owner, "not authorized");
    _;
}}

function {function}() external onlyOwner {{
    // privileged logic
}}"#
            )),
        },
        "tx-origin" => FindingGuidance {
            abuse: format!(
                "Authorization based on `tx.origin` can be phished. An attacker deploys a contract that calls `{function}` and convinces the legitimate owner to trigger the attacker contract. During the nested call, `tx.origin` is still the owner, so the victim incorrectly authorizes the attacker's contract. Location: {location}."
            ),
            poc_code: Some(format!(
                r#"interface IVictim {{
    function {function}() external;
}}

contract TxOriginPhishingPoC {{
    IVictim private immutable victim;

    constructor(address victim_) {{
        victim = IVictim(victim_);
    }}

    function claimReward() external {{
        // If victim checks tx.origin == owner, this call can pass
        // when the owner is tricked into calling claimReward().
        victim.{function}();
    }}
}}"#
            )),
            remediation: "Never use `tx.origin` for authorization. Authorize the immediate caller with `msg.sender`, or use explicit signatures/meta-transaction validation when calls are intentionally relayed.".to_string(),
            remediation_code: Some(format!(
                r#"address private owner;

function {function}() external {{
    require(msg.sender == owner, "not owner");
    // privileged logic
}}"#
            )),
        },
        "weak-prng" | "timestamp-dependency" => FindingGuidance {
            abuse: format!(
                "The outcome can be influenced because it depends on block data such as timestamp, block number, block hash, or caller-controlled inputs. A validator or searcher can choose whether to include a transaction, reorder it, or slightly influence timestamp-dependent execution to bias the result. Location: {location}."
            ),
            poc_code: Some(
                r#"contract RandomnessBiasPoC {
    function attackerStrategy(address game, bytes calldata playTx) external {
        // The attacker simulates the outcome off-chain for the current block.
        // If the computed value is unfavorable, they do not submit/bundle playTx.
        // If favorable, they submit it or ask a block builder to include it.
        game.call(playTx);
    }
}"#
                .to_string(),
            ),
            remediation: "Do not derive value-bearing randomness from block variables or public transaction inputs. Use a commit-reveal scheme for low-value flows, or a verifiable randomness oracle such as Chainlink VRF for lotteries, games, winner selection, and asset distribution.".to_string(),
            remediation_code: Some(
                r#"// Commit-reveal sketch:
mapping(address => bytes32) public commits;

function commit(bytes32 commitment) external {
    commits[msg.sender] = commitment;
}

function reveal(uint256 secret) external {
    require(commits[msg.sender] == keccak256(abi.encode(secret, msg.sender)), "bad reveal");
    // Combine committed secret with a future source, or prefer VRF for high-value randomness.
}"#
                .to_string(),
            ),
        },
        "unchecked-call" => FindingGuidance {
            abuse: format!(
                "The contract appears to continue execution after an external call without requiring success. An attacker-controlled callee can revert or return `false`, while the victim still updates state as if the transfer or action succeeded. This can create incorrect accounting, unpaid withdrawals, or inconsistent protocol state. Location: {location}."
            ),
            poc_code: Some(
                r#"contract RejectsEther {
    receive() external payable {
        revert("reject payment");
    }
}

// If the victim ignores the return value:
// (bool ok, ) = user.call{value: amount}("");
// balances[user] = 0; // state changes even when ok == false"#
                .to_string(),
            ),
            remediation: "Check the returned success flag for every low-level call. Only update accounting after the call succeeds, or use a pull-payment design where failed recipients can retry without blocking other users.".to_string(),
            remediation_code: Some(
                r#"(bool ok, ) = recipient.call{value: amount}("");
require(ok, "external call failed");"#
                    .to_string(),
            ),
        },
        "hardcoded-gas-transfer" => FindingGuidance {
            abuse: format!(
                "`transfer`/`send` forwards a fixed 2300 gas stipend. A recipient contract with a non-trivial `receive()` function can fail the transfer, causing withdrawals or payout loops to revert and creating a denial of service. Location: {location}."
            ),
            poc_code: Some(
                r#"contract GasHeavyReceiver {
    uint256 public writes;

    receive() external payable {
        writes += 1; // costs more than the 2300 gas stipend
    }
}"#
                .to_string(),
            ),
            remediation: "Avoid relying on `transfer`/`send` for critical payouts. Use `call` with checked success, update state before the call, and prefer pull payments so one receiver cannot block the entire payout flow.".to_string(),
            remediation_code: Some(
                r#"uint256 amount = pending[msg.sender];
pending[msg.sender] = 0;

(bool ok, ) = msg.sender.call{value: amount}("");
require(ok, "ETH transfer failed");"#
                    .to_string(),
            ),
        },
        "integer-overflow" | "integer-underflow" => FindingGuidance {
            abuse: format!(
                "Unchecked arithmetic can wrap around and produce values that are much larger or smaller than intended. An attacker can choose inputs near integer boundaries to bypass balance, supply, or limit checks. Location: {location}."
            ),
            poc_code: Some(
                r#"contract OverflowPoC {
    function overflow(uint256 balance, uint256 amount) external pure returns (uint256) {
        unchecked {
            return balance + amount; // wraps if balance + amount > type(uint256).max
        }
    }
}"#
                .to_string(),
            ),
            remediation: "Compile with Solidity 0.8 or newer and do not use `unchecked` around security-critical accounting. If the project must use an older compiler, use a reviewed SafeMath library for every arithmetic operation that affects balances, supply, limits, or authorization.".to_string(),
            remediation_code: Some(
                r#"pragma solidity ^0.8.20;

function addBalance(uint256 balance, uint256 amount) internal pure returns (uint256) {
    return balance + amount; // reverts automatically on overflow in Solidity 0.8+
}"#
                .to_string(),
            ),
        },
        "locked-ether" => FindingGuidance {
            abuse: format!(
                "ETH can enter the contract, but the analyzer did not find a reliable recovery or withdrawal path for the affected balance. Funds may become permanently inaccessible after direct transfers, forced ETH via selfdestruct, or normal payable flows. Location: {location}."
            ),
            poc_code: Some(
                r#"contract ForceEther {
    constructor() payable {}

    function forceSend(address target) external {
        selfdestruct(payable(target));
    }
}"#
                .to_string(),
            ),
            remediation: "Add an explicit, access-controlled recovery or withdrawal function for ETH that is not part of normal accounting. If ETH should never be accepted, make receive/fallback revert and document how forced ETH is handled.".to_string(),
            remediation_code: Some(
                r#"function recoverEther(address payable to, uint256 amount) external onlyOwner {
    require(to != address(0), "bad recipient");
    (bool ok, ) = to.call{value: amount}("");
    require(ok, "recovery failed");
}"#
                .to_string(),
            ),
        },
        "unsafe-delegatecall" => FindingGuidance {
            abuse: format!(
                "Delegatecall executes code from another address in the storage context of the caller. If an attacker can influence the delegatecall target or calldata, they can overwrite storage, seize ownership, or drain funds. Location: {location}."
            ),
            poc_code: Some(
                r#"contract MaliciousImplementation {
    // Storage slot layout chosen to match the victim.
    address public owner;

    function seizeOwnership() external {
        owner = msg.sender;
    }
}"#
                .to_string(),
            ),
            remediation: "Only delegatecall to trusted, immutable or allowlisted implementations. Validate calldata, preserve storage layout intentionally, and use a reviewed proxy pattern when upgradeability is required.".to_string(),
            remediation_code: Some(
                r#"mapping(address => bool) public approvedImplementation;

function execute(address implementation, bytes calldata data) external onlyOwner {
    require(approvedImplementation[implementation], "implementation not approved");
    (bool ok, ) = implementation.delegatecall(data);
    require(ok, "delegatecall failed");
}"#
                .to_string(),
            ),
        },
        "unprotected-selfdestruct" => FindingGuidance {
            abuse: format!(
                "If an attacker can reach a selfdestruct path, they can permanently remove contract code or force remaining ETH to an arbitrary beneficiary. This can break integrations and destroy protocol availability. Location: {location}."
            ),
            poc_code: Some(format!(
                r#"interface IVictim {{
    function {function}() external;
}}

contract KillPoC {{
    function exploit(address victim) external {{
        IVictim(victim).{function}();
    }}
}}"#
            )),
            remediation: "Remove selfdestruct unless it is strictly required. If it must remain, restrict it to a timelocked governance or owner-only emergency path and emit an event before execution.".to_string(),
            remediation_code: Some(format!(
                r#"function {function}() external onlyOwner {{
    // Prefer removing this entirely.
    selfdestruct(payable(owner));
}}"#
            )),
        },
        "shadowing" => FindingGuidance {
            abuse: format!(
                "A local variable, parameter, or inherited declaration shadows another state item. This can cause reviewers and developers to believe a security-critical state variable is being read or updated when the code is actually using a different value. Location: {location}."
            ),
            poc_code: Some(
                r#"contract ShadowingExample {
    address public owner;

    function setOwner(address owner) external {
        // This assigns the parameter to itself, not the state variable.
        owner = owner;
    }
}"#
                .to_string(),
            ),
            remediation: "Rename shadowing variables and use explicit naming conventions for parameters and storage variables. For example, use `newOwner` for parameters and assign it to `owner` directly.".to_string(),
            remediation_code: Some(
                r#"function setOwner(address newOwner) external onlyOwner {
    require(newOwner != address(0), "zero owner");
    owner = newOwner;
}"#
                .to_string(),
            ),
        },
        _ => FindingGuidance {
            abuse: format!(
                "The finding points to behavior that may be exploitable depending on surrounding business logic. Review the path at {location}, identify who can call it, which state variables change, and whether an attacker can control the inputs or external call target."
            ),
            poc_code: None,
            remediation: recommendation_for_kind(&finding.kind, &finding.category).to_string(),
            remediation_code: None,
        },
    }
}
