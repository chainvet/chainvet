use crate::core::artifacts::{Finding, FrontierGoal, Seed};

use super::{
    FindingQueue, FrontierQueue, InMemoryFindingQueue, InMemoryFrontierQueue, InMemorySeedQueue,
    SeedQueue,
};

#[derive(Debug, Clone)]
pub struct RedisQueueBackend {
    url: String,
}

impl RedisQueueBackend {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn seed_queue(&self) -> RedisSeedQueue {
        RedisSeedQueue {
            url: self.url.clone(),
            inner: InMemorySeedQueue::default(),
        }
    }

    pub fn frontier_queue(&self) -> RedisFrontierQueue {
        RedisFrontierQueue {
            url: self.url.clone(),
            inner: InMemoryFrontierQueue::default(),
        }
    }

    pub fn finding_queue(&self) -> RedisFindingQueue {
        RedisFindingQueue {
            url: self.url.clone(),
            inner: InMemoryFindingQueue::default(),
        }
    }
}

#[derive(Debug, Default)]
pub struct RedisSeedQueue {
    url: String,
    inner: InMemorySeedQueue,
}

impl RedisSeedQueue {
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl SeedQueue for RedisSeedQueue {
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
pub struct RedisFrontierQueue {
    url: String,
    inner: InMemoryFrontierQueue,
}

impl RedisFrontierQueue {
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl FrontierQueue for RedisFrontierQueue {
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
pub struct RedisFindingQueue {
    url: String,
    inner: InMemoryFindingQueue,
}

impl RedisFindingQueue {
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl FindingQueue for RedisFindingQueue {
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
