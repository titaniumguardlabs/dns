use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum LogMode {
    Strict,
    Standard,
    EnterpriseForensics,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantLoggingRule {
    pub tenant_id: String,
    pub mode: LogMode,
    #[serde(default)]
    pub retention_days: Option<u16>,
    #[serde(default)]
    pub client_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_logging_enabled")]
    pub enabled: bool,
    #[serde(default = "default_log_mode")]
    pub default_mode: LogMode,
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
    #[serde(default = "default_rotation_minutes")]
    pub key_rotation_minutes: u64,
    #[serde(default = "default_hmac_secret")]
    pub hmac_secret: String,
    #[serde(default = "default_retention_days")]
    pub default_retention_days: u16,
    #[serde(default = "default_purge_interval_seconds")]
    pub purge_interval_seconds: u64,
    #[serde(default)]
    pub tenants: Vec<TenantLoggingRule>,
}

pub(crate) fn is_safe_tenant_path_segment(tenant_id: &str) -> bool {
    !tenant_id.is_empty()
        && tenant_id != "."
        && tenant_id != ".."
        && tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: default_logging_enabled(),
            default_mode: default_log_mode(),
            log_dir: default_log_dir(),
            key_rotation_minutes: default_rotation_minutes(),
            hmac_secret: default_hmac_secret(),
            default_retention_days: default_retention_days(),
            purge_interval_seconds: default_purge_interval_seconds(),
            tenants: Vec::new(),
        }
    }
}

fn default_logging_enabled() -> bool {
    true
}

fn default_log_mode() -> LogMode {
    LogMode::Strict
}

fn default_log_dir() -> String {
    "var/log/dns".to_string()
}

fn default_rotation_minutes() -> u64 {
    60
}

fn default_hmac_secret() -> String {
    String::new()
}

fn default_retention_days() -> u16 {
    30
}

fn default_purge_interval_seconds() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::is_safe_tenant_path_segment;

    #[test]
    fn tenant_path_segment_rejects_path_traversal() {
        for tenant_id in ["", ".", "..", "../tenant", "tenant/name", "tenant\\name"] {
            assert!(
                !is_safe_tenant_path_segment(tenant_id),
                "{tenant_id} should be rejected"
            );
        }
    }

    #[test]
    fn tenant_path_segment_allows_simple_identifiers() {
        for tenant_id in ["default", "tenant-1", "tenant_1", "tenant.example"] {
            assert!(
                is_safe_tenant_path_segment(tenant_id),
                "{tenant_id} should be accepted"
            );
        }
    }
}
