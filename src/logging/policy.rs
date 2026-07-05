use crate::logging::cidr::truncate_ip;
use crate::logging::config::LogMode;
use crate::logging::hasher::{RotatingHasher, unix_millis};
use crate::logging::types::{RawLogEvent, SanitizedLogEvent};

pub trait LogModePolicy: Send + Sync {
    fn sanitize(
        &self,
        raw: &RawLogEvent,
        tenant_id: &str,
        hasher: &RotatingHasher,
    ) -> SanitizedLogEvent;
}

pub struct StrictPolicy;
pub struct StandardPolicy;
pub struct EnterpriseForensicsPolicy;

impl LogModePolicy for StrictPolicy {
    fn sanitize(
        &self,
        raw: &RawLogEvent,
        tenant_id: &str,
        hasher: &RotatingHasher,
    ) -> SanitizedLogEvent {
        let (window, qname_hash) = hasher.hash("qname", raw.qname.as_bytes(), raw.started_at);
        SanitizedLogEvent {
            ts_ms: unix_millis(raw.started_at),
            tenant_id: tenant_id.to_string(),
            mode: "strict".to_string(),
            response_code: raw.response_code.clone(),
            qtype: raw.qtype.to_string(),
            latency_ms: raw.latency_ms,
            qname: None,
            qname_hash: Some(qname_hash),
            client_ip: None,
            device_id_hash: None,
            hash_window: window,
        }
    }
}

impl LogModePolicy for StandardPolicy {
    fn sanitize(
        &self,
        raw: &RawLogEvent,
        tenant_id: &str,
        hasher: &RotatingHasher,
    ) -> SanitizedLogEvent {
        let device_input = raw
            .device_hint
            .clone()
            .unwrap_or_else(|| raw.client_ip.to_string().into_bytes());
        let (window, device_id_hash) =
            hasher.hash("device", device_input.as_slice(), raw.started_at);
        let (_, qname_hash) = hasher.hash("qname", raw.qname.as_bytes(), raw.started_at);
        SanitizedLogEvent {
            ts_ms: unix_millis(raw.started_at),
            tenant_id: tenant_id.to_string(),
            mode: "standard".to_string(),
            response_code: raw.response_code.clone(),
            qtype: raw.qtype.to_string(),
            latency_ms: raw.latency_ms,
            qname: None,
            qname_hash: Some(qname_hash),
            client_ip: Some(truncate_ip(raw.client_ip)),
            device_id_hash: Some(device_id_hash),
            hash_window: window,
        }
    }
}

impl LogModePolicy for EnterpriseForensicsPolicy {
    fn sanitize(
        &self,
        raw: &RawLogEvent,
        tenant_id: &str,
        hasher: &RotatingHasher,
    ) -> SanitizedLogEvent {
        let (window, _) = hasher.hash("forensics", raw.qname.as_bytes(), raw.started_at);
        SanitizedLogEvent {
            ts_ms: unix_millis(raw.started_at),
            tenant_id: tenant_id.to_string(),
            mode: "enterprise_forensics".to_string(),
            response_code: raw.response_code.clone(),
            qtype: raw.qtype.to_string(),
            latency_ms: raw.latency_ms,
            qname: Some(raw.qname.clone()),
            qname_hash: None,
            client_ip: Some(raw.client_ip.to_string()),
            device_id_hash: raw
                .device_hint
                .as_ref()
                .map(|hint| hasher.hash("device", hint, raw.started_at).1),
            hash_window: window,
        }
    }
}

pub fn policy_for_mode(mode: &LogMode) -> Box<dyn LogModePolicy> {
    match mode {
        LogMode::Strict => Box::new(StrictPolicy),
        LogMode::Standard => Box::new(StandardPolicy),
        LogMode::EnterpriseForensics => Box::new(EnterpriseForensicsPolicy),
    }
}
