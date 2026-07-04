#[cfg(feature = "audit-logging")]
mod cidr;
mod config;
mod edns;
#[cfg(feature = "audit-logging")]
mod hasher;
#[cfg(feature = "audit-logging")]
mod pipeline;
#[cfg(feature = "audit-logging")]
mod policy;
mod types;

#[cfg(test)]
pub use config::LogMode;
pub use config::LoggingConfig;
#[cfg(all(test, feature = "audit-logging"))]
pub use config::TenantLoggingRule;
pub use edns::extract_device_hint;
#[cfg(feature = "audit-logging")]
pub use pipeline::LoggingPipeline;
pub use types::RawLogEvent;

#[cfg(not(feature = "audit-logging"))]
#[derive(Clone)]
pub struct LoggingPipeline;

#[cfg(not(feature = "audit-logging"))]
impl LoggingPipeline {
    pub fn from_config(_config: &LoggingConfig) -> Self {
        Self
    }

    pub fn start_retention_task(self: std::sync::Arc<Self>) {}

    pub fn log_request(&self, _event: RawLogEvent) {}

    pub fn is_healthy(&self) -> bool {
        true
    }

    pub fn check_health(&self) -> std::io::Result<bool> {
        Ok(true)
    }

    pub fn write_error_count(&self) -> u64 {
        0
    }
}
