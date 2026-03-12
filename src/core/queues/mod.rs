use std::collections::{HashSet, VecDeque};

use crate::core::artifacts::{Finding, FrontierGoal, Seed};

pub mod redis;
pub mod sqlite;

pub trait SeedQueue {
    fn push(&mut self, seed: Seed) -> bool;
    fn push_many(&mut self, seeds: Vec<Seed>) -> usize;
    fn snapshot(&self) -> Vec<Seed>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait FrontierQueue {
    fn push(&mut self, goal: FrontierGoal);
    fn push_many(&mut self, goals: Vec<FrontierGoal>);
    fn pop_highest_priority(&mut self) -> Option<FrontierGoal>;
    fn len(&self) -> usize;
}

pub trait FindingQueue {
    fn push_many(&mut self, findings: Vec<Finding>);
    fn drain_all(&mut self) -> Vec<Finding>;
    fn len(&self) -> usize;
}

#[derive(Debug, Default)]
pub struct InMemorySeedQueue {
    queue: VecDeque<Seed>,
    seen: HashSet<String>,
}

impl SeedQueue for InMemorySeedQueue {
    fn push(&mut self, seed: Seed) -> bool {
        let key = seed.key();
        if !self.seen.insert(key) {
            return false;
        }
        self.queue.push_back(seed);
        true
    }

    fn push_many(&mut self, seeds: Vec<Seed>) -> usize {
        let mut added = 0;
        for seed in seeds {
            if self.push(seed) {
                added += 1;
            }
        }
        added
    }

    fn snapshot(&self) -> Vec<Seed> {
        self.queue.iter().cloned().collect()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

#[derive(Debug, Default)]
pub struct InMemoryFrontierQueue {
    queue: Vec<FrontierGoal>,
    seen: HashSet<String>,
}

impl InMemoryFrontierQueue {
    fn key(goal: &FrontierGoal) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            goal.function_id,
            goal.block_id
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string()),
            goal.edge_from
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string()),
            goal.edge_to
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string()),
            goal.sink_kind.as_deref().unwrap_or("none")
        )
    }
}

impl FrontierQueue for InMemoryFrontierQueue {
    fn push(&mut self, goal: FrontierGoal) {
        let key = Self::key(&goal);
        if !self.seen.insert(key) {
            return;
        }
        self.queue.push(goal);
    }

    fn push_many(&mut self, goals: Vec<FrontierGoal>) {
        for goal in goals {
            self.push(goal);
        }
    }

    fn pop_highest_priority(&mut self) -> Option<FrontierGoal> {
        if self.queue.is_empty() {
            return None;
        }
        let mut best_idx = 0usize;
        let mut best_score = self.queue[0].priority;
        for (idx, goal) in self.queue.iter().enumerate().skip(1) {
            if goal.priority > best_score {
                best_score = goal.priority;
                best_idx = idx;
            }
        }
        let goal = self.queue.swap_remove(best_idx);
        self.seen.remove(&Self::key(&goal));
        Some(goal)
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

#[derive(Debug, Default)]
pub struct InMemoryFindingQueue {
    queue: VecDeque<Finding>,
}

impl FindingQueue for InMemoryFindingQueue {
    fn push_many(&mut self, findings: Vec<Finding>) {
        self.queue.extend(findings);
    }

    fn drain_all(&mut self) -> Vec<Finding> {
        self.queue.drain(..).collect()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::artifacts::{TxEnv, TxSeed};

    fn seed(function_id: u32) -> Seed {
        Seed {
            id: format!("s-{function_id}"),
            txs: vec![TxSeed {
                function_id,
                selector: None,
                calldata: None,
                args: vec!["1".to_string()],
                sender: "0".to_string(),
                value: "0".to_string(),
                env: TxEnv::default(),
            }],
            state_snapshot_id: None,
            score: 1.0,
        }
    }

    #[test]
    fn seed_queue_dedups_by_key() {
        let mut q = InMemorySeedQueue::default();
        assert!(q.push(seed(1)));
        assert!(!q.push(seed(1)));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn frontier_queue_pops_highest() {
        let mut q = InMemoryFrontierQueue::default();
        q.push(FrontierGoal {
            id: "a".to_string(),
            function_id: 0,
            function_name: None,
            block_id: None,
            edge_from: None,
            edge_to: None,
            sink_kind: None,
            reason: "x".to_string(),
            priority: 1.0,
            attempts: 0,
        });
        q.push(FrontierGoal {
            id: "b".to_string(),
            function_id: 1,
            function_name: None,
            block_id: None,
            edge_from: None,
            edge_to: None,
            sink_kind: None,
            reason: "y".to_string(),
            priority: 5.0,
            attempts: 0,
        });

        let popped = q.pop_highest_priority().expect("goal");
        assert_eq!(popped.id, "b");
    }

    #[test]
    fn frontier_queue_dedups_same_goal_key() {
        let mut q = InMemoryFrontierQueue::default();
        let mk = |id: &str, p: f64| FrontierGoal {
            id: id.to_string(),
            function_id: 7,
            function_name: None,
            block_id: Some(3),
            edge_from: None,
            edge_to: None,
            sink_kind: Some("reentrancy".to_string()),
            reason: "x".to_string(),
            priority: p,
            attempts: 0,
        };

        q.push(mk("g1", 1.0));
        q.push(mk("g2", 9.0)); // same key, should be ignored
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn sqlite_backend_seed_queue_uses_same_contract() {
        let backend = sqlite::SqliteQueueBackend::new("/tmp/hybrid-queues.sqlite3");
        let mut q = backend.seed_queue();
        assert!(q.push(seed(1)));
        assert!(!q.push(seed(1)));
        assert_eq!(q.len(), 1);
        assert_eq!(q.db_path().to_string_lossy(), "/tmp/hybrid-queues.sqlite3");
    }

    #[test]
    fn redis_backend_frontier_queue_uses_same_contract() {
        let backend = redis::RedisQueueBackend::new("redis://127.0.0.1:6379/0");
        let mut q = backend.frontier_queue();
        q.push(FrontierGoal {
            id: "a".to_string(),
            function_id: 0,
            function_name: None,
            block_id: None,
            edge_from: Some(1),
            edge_to: Some(2),
            sink_kind: Some("call".to_string()),
            reason: "x".to_string(),
            priority: 1.0,
            attempts: 0,
        });
        q.push(FrontierGoal {
            id: "b".to_string(),
            function_id: 0,
            function_name: None,
            block_id: None,
            edge_from: Some(1),
            edge_to: Some(2),
            sink_kind: Some("call".to_string()),
            reason: "dup".to_string(),
            priority: 99.0,
            attempts: 0,
        });
        assert_eq!(q.len(), 1);
        assert_eq!(
            backend.url(),
            q.url()
        );
    }
}
