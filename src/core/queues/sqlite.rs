use std::path::{Path, PathBuf};

use crate::core::artifacts::{Finding, FrontierGoal, Seed};

use super::{
    FindingQueue, FrontierQueue, InMemoryFindingQueue, InMemoryFrontierQueue, InMemorySeedQueue,
    SeedQueue,
};

#[derive(Debug, Clone)]
pub struct SqliteQueueBackend {
    db_path: PathBuf,
}

impl SqliteQueueBackend {
    pub fn new<P: Into<PathBuf>>(db_path: P) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn seed_queue(&self) -> SqliteSeedQueue {
        SqliteSeedQueue {
            db_path: self.db_path.clone(),
            inner: InMemorySeedQueue::default(),
        }
    }

    pub fn frontier_queue(&self) -> SqliteFrontierQueue {
        SqliteFrontierQueue {
            db_path: self.db_path.clone(),
            inner: InMemoryFrontierQueue::default(),
        }
    }

    pub fn finding_queue(&self) -> SqliteFindingQueue {
        SqliteFindingQueue {
            db_path: self.db_path.clone(),
            inner: InMemoryFindingQueue::default(),
        }
    }
}

#[derive(Debug, Default)]
pub struct SqliteSeedQueue {
    db_path: PathBuf,
    inner: InMemorySeedQueue,
}

impl SqliteSeedQueue {
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

impl SeedQueue for SqliteSeedQueue {
    fn push(&mut self, seed: Seed) -> bool {
        self.inner.push(seed)
    }

    fn push_many(&mut self, seeds: Vec<Seed>) -> usize {
        self.inner.push_many(seeds)
    }

    fn snapshot(&self) -> Vec<Seed> {
        self.inner.snapshot()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[derive(Debug, Default)]
pub struct SqliteFrontierQueue {
    db_path: PathBuf,
    inner: InMemoryFrontierQueue,
}

impl SqliteFrontierQueue {
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

impl FrontierQueue for SqliteFrontierQueue {
    fn push(&mut self, goal: FrontierGoal) {
        self.inner.push(goal);
    }

    fn push_many(&mut self, goals: Vec<FrontierGoal>) {
        self.inner.push_many(goals);
    }

    fn pop_highest_priority(&mut self) -> Option<FrontierGoal> {
        self.inner.pop_highest_priority()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[derive(Debug, Default)]
pub struct SqliteFindingQueue {
    db_path: PathBuf,
    inner: InMemoryFindingQueue,
}

impl SqliteFindingQueue {
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

impl FindingQueue for SqliteFindingQueue {
    fn push_many(&mut self, findings: Vec<Finding>) {
        self.inner.push_many(findings);
    }

    fn drain_all(&mut self) -> Vec<Finding> {
        self.inner.drain_all()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}
