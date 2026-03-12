use std::collections::HashMap;

use crate::core::artifacts::Finding;

#[derive(Debug, Default)]
pub struct FindingTriage {
    unique: HashMap<String, Finding>,
    total_seen: usize,
    total_seen_by_layer: HashMap<String, usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct TriageResult {
    pub inserted: usize,
    pub duplicates: usize,
}

impl FindingTriage {
    pub fn ingest(&mut self, findings: Vec<Finding>) -> TriageResult {
        let mut inserted = 0;
        let mut duplicates = 0;

        for mut finding in findings {
            self.total_seen += 1;
            *self
                .total_seen_by_layer
                .entry(finding.analysis_layer.clone())
                .or_insert(0) += 1;
            if finding.signature.is_empty() {
                finding.signature = signature_for(&finding);
            }

            match self.unique.get_mut(&finding.signature) {
                None => {
                    self.unique.insert(finding.signature.clone(), finding);
                    inserted += 1;
                }
                Some(existing) => {
                    duplicates += 1;
                    if reproducer_len(&finding) < reproducer_len(existing) {
                        *existing = finding;
                    }
                }
            }
        }

        TriageResult {
            inserted,
            duplicates,
        }
    }

    pub fn unique_findings(&self) -> Vec<Finding> {
        let mut out: Vec<Finding> = self.unique.values().cloned().collect();
        out.sort_by(|a, b| a.signature.cmp(&b.signature));
        out
    }

    pub fn total_seen(&self) -> usize {
        self.total_seen
    }

    pub fn unique_count(&self) -> usize {
        self.unique.len()
    }

    pub fn total_seen_by_layer(&self, layer: &str) -> usize {
        self.total_seen_by_layer
            .get(layer)
            .copied()
            .unwrap_or(0)
    }

    pub fn unique_count_by_layer(&self, layer: &str) -> usize {
        self.unique
            .values()
            .filter(|finding| finding.analysis_layer == layer)
            .count()
    }
}

fn reproducer_len(f: &Finding) -> usize {
    f.reproduction
        .as_ref()
        .map(|seed| seed.tx_len())
        .unwrap_or(0)
}

fn signature_for(f: &Finding) -> String {
    let loc = f.location.as_ref();
    let file = loc
        .and_then(|l| l.file.as_deref())
        .unwrap_or("none")
        .to_string();
    let start = loc
        .and_then(|l| l.start)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string());
    let end = loc
        .and_then(|l| l.end)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string());
    let pc = loc
        .and_then(|l| l.pc)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string());
    let function_id = loc
        .and_then(|l| l.function_id)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string());
    let revert_hash = f
        .metadata
        .get("revert_reason_hash")
        .or_else(|| f.metadata.get("revert_hash"))
        .cloned()
        .unwrap_or_else(|| "none".to_string());

    // Keep engine in signature for now to avoid cross-engine collapsing of distinct evidence.
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        f.engine,
        f.analysis_layer,
        f.evidence_kind,
        f.finding_type,
        file,
        start,
        end,
        pc,
        function_id,
        revert_hash
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::artifacts::{FindingLocation, Seed, TxEnv, TxSeed};

    fn finding(sig: &str, tx_len: usize) -> Finding {
        Finding {
            engine: "fuzzing".to_string(),
            finding_type: "reentrancy".to_string(),
            severity: "high".to_string(),
            message: "x".to_string(),
            location: Some(FindingLocation {
                file: None,
                start: None,
                end: None,
                pc: None,
                function_id: Some(1),
                function_name: None,
            }),
            reproduction: Some(Seed {
                id: format!("seed-{tx_len}"),
                txs: (0..tx_len)
                    .map(|_| TxSeed {
                        function_id: 1,
                        selector: None,
                        calldata: None,
                        args: vec!["0".to_string()],
                        sender: "0".to_string(),
                        value: "0".to_string(),
                        env: TxEnv::default(),
                    })
                    .collect(),
                state_snapshot_id: None,
                score: 1.0,
            }),
            signature: sig.to_string(),
            analysis_layer: "runtime".to_string(),
            evidence_kind: "executor".to_string(),
            metadata: Default::default(),
        }
    }

    #[test]
    fn triage_keeps_shortest_reproducer() {
        let mut triage = FindingTriage::default();
        triage.ingest(vec![finding("sig", 4)]);
        triage.ingest(vec![finding("sig", 2)]);

        let unique = triage.unique_findings();
        assert_eq!(unique.len(), 1);
        assert_eq!(unique[0].reproduction.as_ref().unwrap().tx_len(), 2);
    }
}
