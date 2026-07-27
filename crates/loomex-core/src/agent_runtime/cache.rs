use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use loomex_protocol::{AgentExecutorCapability, ExecutorKind};

#[derive(Debug, Clone)]
struct CachedProbe {
    observed: Instant,
    executable: PathBuf,
    capability: AgentExecutorCapability,
}

/// In-memory TTL cache. Persistence and heartbeat scheduling belong to the
/// caller, which can explicitly invalidate entries after setup/auth changes.
#[derive(Debug, Default)]
pub struct ProbeCache {
    entries: BTreeMap<ExecutorKind, CachedProbe>,
}

impl ProbeCache {
    pub fn get(
        &self,
        executor: ExecutorKind,
        executable: &Path,
        ttl: Duration,
    ) -> Option<AgentExecutorCapability> {
        self.entries.get(&executor).and_then(|entry| {
            (entry.executable == executable && entry.observed.elapsed() < ttl)
                .then(|| entry.capability.clone())
        })
    }

    pub fn insert(
        &mut self,
        executor: ExecutorKind,
        executable: PathBuf,
        capability: AgentExecutorCapability,
    ) {
        self.entries.insert(
            executor,
            CachedProbe {
                observed: Instant::now(),
                executable,
                capability,
            },
        );
    }

    pub fn invalidate(&mut self, executor: ExecutorKind) {
        self.entries.remove(&executor);
    }

    pub fn invalidate_all(&mut self) {
        self.entries.clear();
    }
}
