use crate::caching::base::{DnsRecordCache, minimum_ttl};
use async_trait::async_trait;
use hickory_server::proto::rr::Record;
use moka::{Expiry, future::Cache};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct CachedRecords {
    records: Arc<Vec<Record>>,
    ttl: Duration,
}

struct RecordTtlExpiry;

impl Expiry<String, CachedRecords> for RecordTtlExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CachedRecords,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &CachedRecords,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

#[derive(Clone)]
pub struct MokaDnsRecordCache {
    inner: Cache<String, CachedRecords>,
}

impl MokaDnsRecordCache {
    pub fn new(max_entries: u64) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(max_entries)
                .expire_after(RecordTtlExpiry)
                .build(),
        }
    }
}

#[async_trait]
impl DnsRecordCache for MokaDnsRecordCache {
    async fn get(&self, key: &str) -> Option<Arc<Vec<Record>>> {
        self.inner.get(key).await.map(|entry| entry.records)
    }

    async fn insert(&self, key: String, records: Vec<Record>) {
        let ttl = match minimum_ttl(&records) {
            Some(ttl) if !ttl.is_zero() => ttl,
            _ => return,
        };

        self.inner
            .insert(
                key,
                CachedRecords {
                    records: Arc::new(records),
                    ttl,
                },
            )
            .await;
    }
}
