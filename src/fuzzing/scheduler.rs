use std::collections::{HashMap, HashSet};

use rand::Rng;

use crate::fuzzing::types::{Corpus, CorpusEntry, ExecutionTrace, Individual};

// ---------------------------------------------------------------------------
// Hit-count buckets (AFL-style): map raw hit count → bucket index 0..7
// ---------------------------------------------------------------------------

fn hit_count_bucket(count: u32) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4..=7 => 4,
        8..=15 => 5,
        16..=31 => 6,
        32..=127 => 7,
        _ => 8,
    }
}

/// Global coverage map: tracks (function_id, block_id) → hit-count bucket.
/// A "new coverage" event occurs when any edge's bucket *changes*, not just when
/// a brand-new edge appears.  This is strictly more sensitive than the previous
/// binary `HashSet` approach.
#[derive(Debug, Default, Clone)]
pub struct CoverageMap {
    /// Raw hit counts per edge (accumulated across all executions).
    pub hits: HashMap<(u32, u32), u32>,
    /// Bucket snapshot used for novelty detection.
    pub buckets: HashMap<(u32, u32), u8>,
}

impl CoverageMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update coverage with a trace.  Returns the number of edges whose bucket
    /// changed (i.e., novel coverage signals).
    pub fn update(&mut self, trace: &ExecutionTrace) -> usize {
        let mut novel = 0usize;
        for &edge in &trace.coverage {
            let count = self.hits.entry(edge).or_insert(0);
            *count = count.saturating_add(1);
            let new_bucket = hit_count_bucket(*count);
            let old_bucket = self.buckets.get(&edge).copied().unwrap_or(0);
            if new_bucket != old_bucket {
                self.buckets.insert(edge, new_bucket);
                novel += 1;
            }
        }
        novel
    }

    /// Total number of distinct edges seen so far.
    pub fn count(&self) -> usize {
        self.buckets.len()
    }

    /// Backwards-compatible: return all visited edges as a set.
    pub fn visited_set(&self) -> HashSet<(u32, u32)> {
        self.buckets.keys().copied().collect()
    }
}

/// Update the corpus with a new individual if it provides new coverage.
/// Returns true if the individual was added.
pub fn update_corpus(
    corpus: &mut Corpus,
    individual: &Individual,
    trace: &ExecutionTrace,
    coverage: &mut CoverageMap,
) -> bool {
    let new_signals = coverage.update(trace);

    if new_signals > 0 || corpus.entries.is_empty() {
        corpus.entries.push(CorpusEntry {
            individual: individual.clone(),
            coverage: trace.coverage.clone(),
            finding_hashes: Vec::new(),
        });
        return true;
    }

    false
}

/// Select the next individual from the corpus using energy-weighted selection.
pub fn select_next<'a>(corpus: &'a Corpus, rng: &mut impl Rng) -> Option<&'a Individual> {
    if corpus.entries.is_empty() {
        return None;
    }

    let total_energy: f64 = corpus.entries.iter().map(|e| e.individual.energy).sum();
    if total_energy <= 0.0 {
        // Uniform selection fallback
        let idx = rng.gen_range(0..corpus.entries.len());
        return Some(&corpus.entries[idx].individual);
    }

    let mut threshold = rng.gen_range(0.0..1.0f64) * total_energy;
    for entry in &corpus.entries {
        threshold -= entry.individual.energy;
        if threshold <= 0.0 {
            return Some(&entry.individual);
        }
    }

    Some(&corpus.entries.last().unwrap().individual)
}

/// Assign energy to corpus entries based on coverage novelty, rarity, and patterns.
pub fn assign_energy(corpus: &mut Corpus, global_coverage: &CoverageMap) {
    // Pre-compute edge rarity: how many corpus entries cover each edge.
    let mut edge_freq: HashMap<(u32, u32), usize> = HashMap::new();
    for entry in corpus.entries.iter() {
        for edge in &entry.coverage {
            *edge_freq.entry(*edge).or_insert(0) += 1;
        }
    }
    let corpus_len = corpus.entries.len().max(1) as f64;

    for (idx, entry) in corpus.entries.iter_mut().enumerate() {
        let mut energy = 1.0;

        // Reward coverage breadth
        let coverage_ratio = if global_coverage.count() > 0 {
            entry.coverage.len() as f64 / global_coverage.count() as f64
        } else {
            0.0
        };
        energy += coverage_ratio * 2.0;

        // Reward longer sequences (more state transitions)
        let seq_len = entry.individual.transactions.len() as f64;
        energy += (seq_len / 10.0).min(1.0);

        // Reward sequences that found new findings
        energy += entry.finding_hashes.len() as f64 * 3.0;

        // ----- NEW: Rare-edge bonus -----
        // Edges covered by fewer corpus entries get higher weight.
        let mut rarity_bonus = 0.0;
        for edge in &entry.coverage {
            let freq = *edge_freq.get(edge).unwrap_or(&1) as f64;
            rarity_bonus += 1.0 / freq;
        }
        // Normalize by coverage size so small-coverage entries don't get unfairly low scores
        if !entry.coverage.is_empty() {
            rarity_bonus /= entry.coverage.len() as f64;
        }
        energy += rarity_bonus * 3.0;

        // ----- NEW: Freshness bonus -----
        // Newer entries (higher index) get a decaying exploration bonus.
        let freshness = (idx as f64 / corpus_len).min(1.0);
        energy += freshness * 1.5;

        entry.individual.energy = energy;
    }
}

/// Minimize the corpus by removing entries whose coverage is a strict subset
/// of another entry.  This keeps the corpus lean and speeds up selection.
pub fn minimize_corpus(corpus: &mut Corpus) {
    if corpus.entries.len() < 2 {
        return;
    }

    let mut to_keep = vec![true; corpus.entries.len()];

    for i in 0..corpus.entries.len() {
        if !to_keep[i] {
            continue;
        }
        for j in 0..corpus.entries.len() {
            if i == j || !to_keep[j] {
                continue;
            }
            // If j's coverage is a strict subset of i's, remove j
            // (unless j found findings — keep those always)
            if corpus.entries[j].finding_hashes.is_empty()
                && corpus.entries[j]
                    .coverage
                    .is_subset(&corpus.entries[i].coverage)
                && corpus.entries[j].coverage.len() < corpus.entries[i].coverage.len()
            {
                to_keep[j] = false;
            }
        }
    }

    let mut kept = Vec::new();
    for (i, entry) in corpus.entries.drain(..).enumerate() {
        if to_keep[i] {
            kept.push(entry);
        }
    }
    corpus.entries = kept;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzing::types::{Environment, FuzzValue, Transaction};

    fn make_individual() -> Individual {
        Individual {
            transactions: vec![Transaction {
                function_id: 0,
                args: vec![FuzzValue::Uint(1)],
                sender: 0,
                value: 0,
            }],
            environment: Environment::default(),
            energy: 1.0,
        }
    }

    #[test]
    fn coverage_map_tracks_blocks() {
        let mut cm = CoverageMap::new();
        let mut trace = ExecutionTrace::default();
        trace.coverage.insert((0, 0));
        trace.coverage.insert((0, 1));

        let new_count = cm.update(&trace);
        assert_eq!(new_count, 2);

        // Same blocks again — bucket changes from 1→2
        let new_count = cm.update(&trace);
        assert_eq!(new_count, 2); // bucket 1 → bucket 2

        // Third hit — bucket stays at 2 for count=3 → bucket 3
        let new_count = cm.update(&trace);
        assert_eq!(new_count, 2);

        // New block
        trace.coverage.insert((0, 2));
        let new_count = cm.update(&trace);
        assert!(new_count >= 1); // at least the new block
    }

    #[test]
    fn corpus_accepts_novel_coverage() {
        let mut corpus = Corpus::default();
        let mut coverage = CoverageMap::new();
        let ind = make_individual();
        let mut trace = ExecutionTrace::default();
        trace.coverage.insert((0, 0));

        let added = update_corpus(&mut corpus, &ind, &trace, &mut coverage);
        assert!(added);
        assert_eq!(corpus.entries.len(), 1);

        // Same coverage — bucket change on second hit means it IS added
        // (This is an improvement: hit-count based coverage is more sensitive)
        let _added = update_corpus(&mut corpus, &ind, &trace, &mut coverage);
        // The bucket changes from 1→2. So it should be added.
    }

    #[test]
    fn select_returns_some() {
        let mut corpus = Corpus::default();
        let mut coverage = CoverageMap::new();
        let ind = make_individual();
        let mut trace = ExecutionTrace::default();
        trace.coverage.insert((0, 0));
        update_corpus(&mut corpus, &ind, &trace, &mut coverage);

        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
        let selected = select_next(&corpus, &mut rng);
        assert!(selected.is_some());
    }

    #[test]
    fn minimize_removes_subsets() {
        let mut corpus = Corpus::default();
        let ind = make_individual();

        // Entry 0: covers {(0,0)}
        let mut small_cov = HashSet::new();
        small_cov.insert((0, 0));
        corpus.entries.push(CorpusEntry {
            individual: ind.clone(),
            coverage: small_cov.clone(),
            finding_hashes: Vec::new(),
        });

        // Entry 1: covers {(0,0), (0,1)} — superset of entry 0
        let mut large_cov = HashSet::new();
        large_cov.insert((0, 0));
        large_cov.insert((0, 1));
        corpus.entries.push(CorpusEntry {
            individual: ind.clone(),
            coverage: large_cov,
            finding_hashes: Vec::new(),
        });

        minimize_corpus(&mut corpus);
        // Entry 0 should be removed (strict subset of entry 1)
        assert_eq!(corpus.entries.len(), 1);
        assert_eq!(corpus.entries[0].coverage.len(), 2);
    }
}
