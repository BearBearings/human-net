use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::Serialize;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::debug;

#[derive(Clone)]
pub struct PeerTable {
    inner: Arc<RwLock<HashMap<String, PeerRecord>>>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn update(&self, record: PeerRecord) {
        let mut table = self.inner.write();
        table.insert(record.did.clone(), record);
    }

    pub fn remove_by_service(&self, service_id: &str) -> bool {
        let mut table = self.inner.write();
        let before = table.len();
        table.retain(|_, record| record.service_id != service_id);
        before != table.len()
    }

    pub fn list(&self) -> Vec<PeerRecord> {
        self.inner.read().values().cloned().collect::<Vec<_>>()
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn purge_older_than(&self, cutoff: OffsetDateTime) -> usize {
        let mut table = self.inner.write();
        let before = table.len();
        table.retain(|_, record| record.last_seen >= cutoff);
        before.saturating_sub(table.len())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerRecord {
    pub did: String,
    pub alias: String,
    #[serde(skip_serializing)]
    pub service_id: String,
    pub addresses: Vec<String>,
    pub endpoints: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

pub fn spawn_purge_task(table: PeerTable, ttl: Duration) -> tokio::task::JoinHandle<()> {
    let interval_duration = if ttl > Duration::from_secs(30) {
        ttl / 2
    } else if ttl.is_zero() {
        Duration::from_secs(15)
    } else {
        ttl
    };

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);
        loop {
            interval.tick().await;
            let ttl_seconds = ttl.as_secs().max(1) as i64;
            let cutoff = OffsetDateTime::now_utc() - TimeDuration::seconds(ttl_seconds);
            let removed = table.purge_older_than(cutoff);
            if removed > 0 {
                debug!(removed, "purged stale peer entries");
            }
        }
    })
}
