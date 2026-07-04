use async_trait::async_trait;
use hickory_server::proto::rr::Record;
use std::{sync::Arc, time::Duration};

#[async_trait]
pub trait DnsRecordCache: Send + Sync {
    async fn get(&self, key: &str) -> Option<Arc<Vec<Record>>>;
    async fn insert(&self, key: String, records: Vec<Record>);
    async fn check_health(&self) -> bool {
        self.is_healthy()
    }
    fn is_required(&self) -> bool {
        false
    }
    fn is_healthy(&self) -> bool {
        true
    }
    fn error_count(&self) -> u64 {
        0
    }
}

pub fn minimum_ttl(records: &[Record]) -> Option<Duration> {
    records
        .iter()
        .map(|record| record.ttl())
        .min()
        .map(u64::from)
        .map(Duration::from_secs)
}
