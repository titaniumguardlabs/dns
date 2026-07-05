use crate::caching::base::{DnsRecordCache, minimum_ttl};
use crate::dns::DnsRecord;
use async_trait::async_trait;
use redis::AsyncCommands;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tracing::error;

type CacheError = Box<dyn std::error::Error + Send + Sync>;
type CacheResult<T> = Result<T, CacheError>;

pub struct RedisDnsRecordCache {
    client: redis::Client,
    key_prefix: String,
    required: bool,
    timeout: Duration,
    failure_threshold: u32,
    consecutive_failures: AtomicU32,
    errors: AtomicU64,
    last_health_ok: AtomicBool,
    circuit_open: AtomicBool,
}

impl RedisDnsRecordCache {
    pub fn new(
        url: &str,
        key_prefix: &str,
        required: bool,
        timeout_ms: u64,
        failure_threshold: u32,
    ) -> CacheResult<Self> {
        let client = redis::Client::open(url).map_err(|err| {
            Box::<dyn std::error::Error + Send + Sync>::from(io::Error::other(format!(
                "failed to connect to redis: {err}",
            )))
        })?;

        Ok(Self {
            client,
            key_prefix: key_prefix.to_string(),
            required,
            timeout: Duration::from_millis(timeout_ms.max(1)),
            failure_threshold: failure_threshold.max(1),
            consecutive_failures: AtomicU32::new(0),
            errors: AtomicU64::new(0),
            last_health_ok: AtomicBool::new(false),
            circuit_open: AtomicBool::new(false),
        })
    }

    fn namespaced_key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }

    async fn with_connection(&self) -> Option<redis::aio::MultiplexedConnection> {
        match timeout(self.timeout, self.client.get_multiplexed_async_connection()).await {
            Ok(Ok(conn)) => {
                self.record_success();
                Some(conn)
            }
            Ok(Err(err)) => {
                self.record_failure();
                error!(error = %err, "failed to obtain redis connection");
                None
            }
            Err(_) => {
                self.record_failure();
                error!("timed out obtaining redis connection");
                None
            }
        }
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_health_ok.store(true, Ordering::Relaxed);
        self.circuit_open.store(false, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.last_health_ok.store(false, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.failure_threshold {
            self.circuit_open.store(true, Ordering::Relaxed);
        }
    }

    fn encode_records(records: &[DnsRecord]) -> CacheResult<Vec<u8>> {
        let mut out = Vec::new();
        for record in records {
            let encoded_record = record.to_wire()?;
            let len = u32::try_from(encoded_record.len())
                .map_err(|_| io::Error::other("record encoding too large"))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&encoded_record);
        }
        Ok(out)
    }

    fn decode_records(blob: &[u8]) -> CacheResult<Vec<DnsRecord>> {
        let mut records = Vec::new();
        let mut cursor = 0usize;

        while cursor < blob.len() {
            if blob.len() - cursor < 4 {
                return Err(io::Error::other("invalid cached record length prefix").into());
            }

            let len = u32::from_be_bytes([
                blob[cursor],
                blob[cursor + 1],
                blob[cursor + 2],
                blob[cursor + 3],
            ]) as usize;
            cursor += 4;

            if blob.len() - cursor < len {
                return Err(io::Error::other("truncated cached record blob").into());
            }

            let encoded_record = &blob[cursor..cursor + len];
            cursor += len;

            records.push(DnsRecord::from_wire(encoded_record)?);
        }

        Ok(records)
    }
}

#[async_trait]
impl DnsRecordCache for RedisDnsRecordCache {
    async fn get(&self, key: &str) -> Option<Arc<Vec<DnsRecord>>> {
        let mut conn = self.with_connection().await?;
        let redis_key = self.namespaced_key(key);
        let blob: Option<Vec<u8>> = match timeout(self.timeout, conn.get(&redis_key)).await {
            Ok(Ok(value)) => {
                self.record_success();
                value
            }
            Ok(Err(err)) => {
                self.record_failure();
                error!(error = %err, "redis get failed");
                return None;
            }
            Err(_) => {
                self.record_failure();
                error!("redis get timed out");
                return None;
            }
        };

        let blob = blob?;
        match Self::decode_records(&blob) {
            Ok(records) => Some(Arc::new(records)),
            Err(err) => {
                self.record_failure();
                error!(error = %err, "failed to decode cached dns records");
                None
            }
        }
    }

    async fn insert(&self, key: String, records: Vec<DnsRecord>) {
        let ttl = match minimum_ttl(&records) {
            Some(ttl) if !ttl.is_zero() => ttl.as_secs().max(1),
            _ => return,
        };
        let blob = match Self::encode_records(&records) {
            Ok(blob) => blob,
            Err(err) => {
                error!(error = %err, "failed to encode dns records for cache");
                return;
            }
        };

        if let Some(mut conn) = self.with_connection().await {
            let redis_key = self.namespaced_key(&key);
            match timeout(self.timeout, conn.set_ex::<_, _, ()>(&redis_key, blob, ttl)).await {
                Ok(Ok(())) => self.record_success(),
                Ok(Err(err)) => {
                    self.record_failure();
                    error!(error = %err, "redis set_ex failed");
                }
                Err(_) => {
                    self.record_failure();
                    error!("redis set_ex timed out");
                }
            }
        }
    }

    async fn check_health(&self) -> bool {
        self.with_connection().await.is_some()
    }

    fn is_required(&self) -> bool {
        self.required
    }

    fn is_healthy(&self) -> bool {
        self.last_health_ok.load(Ordering::Relaxed) && !self.circuit_open.load(Ordering::Relaxed)
    }

    fn error_count(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
}
