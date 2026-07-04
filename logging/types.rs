use hickory_server::proto::rr::RecordType;
use serde::Serialize;
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Clone)]
pub struct RawLogEvent {
    pub started_at: SystemTime,
    pub latency_ms: u128,
    pub client_ip: IpAddr,
    pub qname: String,
    pub qtype: RecordType,
    pub response_code: String,
    pub device_hint: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct SanitizedLogEvent {
    pub ts_ms: u128,
    pub tenant_id: String,
    pub mode: String,
    pub response_code: String,
    pub qtype: String,
    pub latency_ms: u128,
    pub qname: Option<String>,
    pub qname_hash: Option<String>,
    pub client_ip: Option<String>,
    pub device_id_hash: Option<String>,
    pub hash_window: u64,
}

#[derive(Clone)]
pub struct PolicyBinding {
    pub tenant_id: String,
    pub mode: crate::logging::config::LogMode,
    pub retention_days: u16,
    pub cidrs: Vec<crate::logging::cidr::IpCidr>,
}
