use crate::logging::cidr::IpCidr;
use crate::logging::config::{LoggingConfig, is_safe_tenant_path_segment};
use crate::logging::hasher::{RotatingHasher, day_bucket};
use crate::logging::policy::policy_for_mode;
use crate::logging::types::{PolicyBinding, RawLogEvent, SanitizedLogEvent};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{os::unix::fs::MetadataExt, os::unix::fs::OpenOptionsExt};
use tokio::time;
use tracing::error;

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0x20000;
#[cfg(any(target_os = "macos", target_os = "ios"))]
const O_NOFOLLOW: i32 = 0x100;

#[derive(Clone)]
pub struct LoggingPipeline {
    enabled: bool,
    root: PathBuf,
    hasher: RotatingHasher,
    default_policy: PolicyBinding,
    tenant_policies: Vec<PolicyBinding>,
    purge_interval: Duration,
    write_errors: Arc<AtomicU64>,
    last_write_ok: Arc<AtomicBool>,
}

impl LoggingPipeline {
    pub fn from_config(config: &LoggingConfig) -> Self {
        let default_policy = PolicyBinding {
            tenant_id: "default".to_string(),
            mode: config.default_mode.clone(),
            retention_days: config.default_retention_days,
            cidrs: Vec::new(),
        };

        let tenant_policies = config
            .tenants
            .iter()
            .map(|tenant| PolicyBinding {
                tenant_id: tenant.tenant_id.clone(),
                mode: tenant.mode.clone(),
                retention_days: tenant
                    .retention_days
                    .unwrap_or(config.default_retention_days),
                cidrs: tenant
                    .client_cidrs
                    .iter()
                    .filter_map(|cidr| IpCidr::parse(cidr))
                    .collect(),
            })
            .collect();

        Self {
            enabled: config.enabled,
            root: PathBuf::from(&config.log_dir),
            hasher: RotatingHasher {
                secret: config.hmac_secret.as_bytes().to_vec(),
                rotation_minutes: config.key_rotation_minutes.max(1),
            },
            default_policy,
            tenant_policies,
            purge_interval: Duration::from_secs(config.purge_interval_seconds.max(60)),
            write_errors: Arc::new(AtomicU64::new(0)),
            last_write_ok: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn start_retention_task(self: Arc<Self>) {
        if !self.enabled {
            return;
        }

        tokio::spawn(async move {
            let mut ticker = time::interval(self.purge_interval);
            loop {
                ticker.tick().await;
                self.enforce_retention();
            }
        });
    }

    pub fn log_request(&self, event: RawLogEvent) {
        if !self.enabled {
            return;
        }

        let binding = self.select_policy(event.client_ip);
        let policy = policy_for_mode(&binding.mode);
        let sanitized = policy.sanitize(&event, &binding.tenant_id, &self.hasher);
        if let Err(err) = self.write_event(&binding.tenant_id, &sanitized) {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
            self.last_write_ok.store(false, Ordering::Relaxed);
            error!(error = %err, tenant_id = %binding.tenant_id, "failed to write dns audit log");
        } else {
            self.last_write_ok.store(true, Ordering::Relaxed);
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.last_write_ok.load(Ordering::Relaxed)
    }

    pub fn check_health(&self) -> io::Result<bool> {
        if !self.enabled {
            return Ok(true);
        }

        match self.write_health_probe() {
            Ok(()) => {
                self.last_write_ok.store(true, Ordering::Relaxed);
                Ok(true)
            }
            Err(err) => {
                self.write_errors.fetch_add(1, Ordering::Relaxed);
                self.last_write_ok.store(false, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    pub fn write_error_count(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    fn select_policy(&self, client_ip: IpAddr) -> &PolicyBinding {
        for policy in &self.tenant_policies {
            if policy.cidrs.iter().any(|cidr| cidr.contains(client_ip)) {
                return policy;
            }
        }

        &self.default_policy
    }

    fn write_event(&self, tenant_id: &str, event: &SanitizedLogEvent) -> std::io::Result<()> {
        if !is_safe_tenant_path_segment(tenant_id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("logging tenant_id is not a safe path segment: {tenant_id}"),
            ));
        }

        let tenant_dir = self.root.join(tenant_id);
        ensure_safe_tenant_dir(&self.root, &tenant_dir)?;

        let day = day_bucket(event.ts_ms);
        let log_file = tenant_dir.join(format!("{day}.jsonl"));
        let mut file = open_append_no_symlink(&log_file)?;
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn write_health_probe(&self) -> io::Result<()> {
        let tenant_dir = self.root.join(&self.default_policy.tenant_id);
        ensure_safe_tenant_dir(&self.root, &tenant_dir)?;
        let probe_file = tenant_dir.join(".healthcheck");
        let mut file = open_append_no_symlink(&probe_file)?;
        file.write_all(b"ok\n")?;
        file.flush()
    }

    fn enforce_retention(&self) {
        if !self.enabled {
            return;
        }

        let retention: HashMap<String, u16> = self
            .tenant_policies
            .iter()
            .map(|binding| (binding.tenant_id.clone(), binding.retention_days))
            .chain(std::iter::once((
                self.default_policy.tenant_id.clone(),
                self.default_policy.retention_days,
            )))
            .collect();

        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let tenant_dir = entry.path();
                if !tenant_dir.is_dir()
                    || fs::symlink_metadata(entry.path())
                        .map(|metadata| metadata.file_type().is_symlink())
                        .unwrap_or(true)
                {
                    continue;
                }

                let tenant_id = entry.file_name().to_string_lossy().to_string();
                let days = retention
                    .get(&tenant_id)
                    .copied()
                    .unwrap_or(self.default_policy.retention_days);
                purge_old_files(&tenant_dir, days);
            }
        }
    }
}

fn ensure_safe_tenant_dir(root: &Path, tenant_dir: &Path) -> std::io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(root) {
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("log root must not be a symlink: {}", root.display()),
            ));
        }
    }
    fs::create_dir_all(root)?;
    reject_group_or_world_writable_dir(root)?;
    let root = root.canonicalize()?;

    if fs::symlink_metadata(tenant_dir)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "tenant log directory must not be a symlink: {}",
                tenant_dir.display()
            ),
        ));
    }
    fs::create_dir_all(tenant_dir)?;
    if let Ok(metadata) = fs::symlink_metadata(tenant_dir) {
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "tenant log directory must not be a symlink: {}",
                    tenant_dir.display()
                ),
            ));
        }
        let tenant_canonical = tenant_dir.canonicalize()?;
        if !tenant_canonical.starts_with(&root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "tenant log directory escapes log root: {}",
                    tenant_dir.display()
                ),
            ));
        }
        reject_group_or_world_writable_dir(&tenant_canonical)?;
    }
    Ok(())
}

fn open_append_no_symlink(path: &Path) -> io::Result<fs::File> {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("log file must not be a symlink: {}", path.display()),
        ));
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    options.custom_flags(O_NOFOLLOW);
    options.open(path)
}

fn reject_group_or_world_writable_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let metadata = fs::metadata(path)?;
        if metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "log directory must not be group/world writable: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn purge_old_files(dir: &Path, retention_days: u16) {
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(
            u64::from(retention_days) * 24 * 60 * 60,
        ))
        .unwrap_or(UNIX_EPOCH);

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let should_delete = entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .map(|mtime| mtime < cutoff)
                .unwrap_or(false);
            if should_delete {
                let _ = fs::remove_file(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RecordType;
    use crate::logging::config::LoggingConfig;
    use crate::logging::types::RawLogEvent;
    use std::net::IpAddr;
    use std::path::PathBuf;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock before unix epoch")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("dns-logging-{name}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn log_request_rejects_symlinked_tenant_directory() {
        let root = TempDir::new("root");
        let outside = TempDir::new("outside");
        std::os::unix::fs::symlink(outside.path(), root.path().join("default")).expect("symlink");

        let mut config = LoggingConfig::default();
        config.log_dir = root.path().to_string_lossy().to_string();
        let pipeline = LoggingPipeline::from_config(&config);

        let event = RawLogEvent {
            started_at: SystemTime::now(),
            latency_ms: 1,
            client_ip: IpAddr::from([127, 0, 0, 1]),
            qname: "example.com.".to_string(),
            qtype: RecordType::A,
            response_code: "NoError".to_string(),
            device_hint: None,
        };

        let binding = pipeline.select_policy(event.client_ip);
        let policy = policy_for_mode(&binding.mode);
        let sanitized = policy.sanitize(&event, &binding.tenant_id, &pipeline.hasher);
        let err = pipeline
            .write_event(&binding.tenant_id, &sanitized)
            .expect_err("symlink should be rejected");
        assert!(err.to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn log_request_rejects_symlinked_log_file() {
        let root = TempDir::new("root-file");
        let outside = TempDir::new("outside-file");

        let mut config = LoggingConfig::default();
        config.log_dir = root.path().to_string_lossy().to_string();
        let pipeline = LoggingPipeline::from_config(&config);
        let event = RawLogEvent {
            started_at: SystemTime::now(),
            latency_ms: 1,
            client_ip: IpAddr::from([127, 0, 0, 1]),
            qname: "example.com.".to_string(),
            qtype: RecordType::A,
            response_code: "NoError".to_string(),
            device_hint: None,
        };
        let binding = pipeline.select_policy(event.client_ip);
        let policy = policy_for_mode(&binding.mode);
        let sanitized = policy.sanitize(&event, &binding.tenant_id, &pipeline.hasher);
        let tenant_dir = root.path().join(&binding.tenant_id);
        fs::create_dir_all(&tenant_dir).expect("tenant dir");
        let day = day_bucket(sanitized.ts_ms);
        let outside_file = outside.path().join("audit.jsonl");
        fs::write(&outside_file, "").expect("outside file");
        std::os::unix::fs::symlink(outside_file, tenant_dir.join(format!("{day}.jsonl")))
            .expect("symlink");

        let err = pipeline
            .write_event(&binding.tenant_id, &sanitized)
            .expect_err("log file symlink should be rejected");
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn audit_health_recovers_after_successful_write() {
        let root = TempDir::new("recover-root");
        let blocked_path = root.path().join("audit-root");
        fs::write(&blocked_path, "not a directory").expect("write blocker");

        let mut config = LoggingConfig::default();
        config.log_dir = blocked_path.to_string_lossy().to_string();
        let pipeline = LoggingPipeline::from_config(&config);
        let event = RawLogEvent {
            started_at: SystemTime::now(),
            latency_ms: 1,
            client_ip: IpAddr::from([127, 0, 0, 1]),
            qname: "example.com.".to_string(),
            qtype: RecordType::A,
            response_code: "NoError".to_string(),
            device_hint: None,
        };

        pipeline.log_request(event.clone());
        assert!(!pipeline.is_healthy());
        assert_eq!(pipeline.write_error_count(), 1);

        fs::remove_file(&blocked_path).expect("remove blocker");
        fs::create_dir_all(&blocked_path).expect("create log root");
        pipeline.log_request(event);

        assert!(pipeline.is_healthy());
        assert_eq!(pipeline.write_error_count(), 1);
    }

    #[test]
    fn audit_health_probe_failure_updates_metrics_state() {
        let root = TempDir::new("probe-root");
        let blocked_path = root.path().join("audit-root");
        fs::write(&blocked_path, "not a directory").expect("write blocker");

        let mut config = LoggingConfig::default();
        config.log_dir = blocked_path.to_string_lossy().to_string();
        let pipeline = LoggingPipeline::from_config(&config);

        assert!(pipeline.check_health().is_err());
        assert!(!pipeline.is_healthy());
        assert_eq!(pipeline.write_error_count(), 1);
    }
}
