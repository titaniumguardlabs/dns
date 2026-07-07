use crate::caching::CachingConfig;
#[cfg(feature = "dnscrypt")]
use crate::dns::DnsName;
use crate::logging::LoggingConfig;
use crate::policy::RuleEngineConfig;
#[cfg(any(feature = "doh", feature = "dnscrypt"))]
use base64::Engine;
#[cfg(any(feature = "doh", feature = "dnscrypt"))]
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use std::io::ErrorKind;
use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};
use tracing::warn;

pub const DEFAULT_CONFIG_PATH: &str = "config.json";
pub const DEFAULT_LISTEN_PORT: u16 = 8080;
pub const DEFAULT_HEALTH_LISTEN_PORT: u16 = 8081;
pub const DEFAULT_MCP_LISTEN_PORT: u16 = 8082;
pub const DEFAULT_MAX_DOH_H2_CONNECTIONS: u32 = 1024;
pub const DEFAULT_MAX_DOH_H2_STREAMS_PER_CONNECTION: u32 = 100;
pub const DEFAULT_MAX_DOH_BODY_BYTES: usize = 4096;
pub const DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_SECONDS: u64 = 10;
#[cfg(feature = "dnscrypt")]
pub const DNSCRYPT_KEY_BYTES: usize = 32;
#[cfg(feature = "dnscrypt")]
pub const DNSCRYPT_CLIENT_MAGIC_BYTES: usize = 8;

mod hpke;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    #[serde(default)]
    pub policy_file_path: Option<String>,
    #[serde(default)]
    pub rule_engine: RuleEngineConfig,
    #[serde(default)]
    pub resolvers: Vec<IpAddr>,
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
    #[serde(default)]
    pub transports: TransportConfig,
    #[serde(default)]
    pub caching: CachingConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub recursion: RecursionConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    pub name: String,
    pub soa: ZoneSoaConfig,
    #[serde(default)]
    pub records: BTreeMap<String, BTreeMap<String, ZoneRecordSetConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneSoaConfig {
    #[serde(alias = "MNAME")]
    pub mname: String,
    #[serde(alias = "RNAME")]
    pub rname: String,
    #[serde(alias = "SERIAL")]
    pub serial: u32,
    #[serde(alias = "REFRESH")]
    pub refresh: u32,
    #[serde(alias = "RETRY")]
    pub retry: u32,
    #[serde(alias = "EXPIRE")]
    pub expire: u32,
    #[serde(alias = "MINIMUM")]
    pub minimum: u32,
    #[serde(default = "default_zone_soa_ttl")]
    pub ttl: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneRecordSetConfig {
    #[serde(default = "default_zone_record_ttl")]
    pub ttl: u32,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    #[serde(default = "default_health_listen_addr")]
    pub listen_addr: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    #[serde(default = "default_mcp_enabled")]
    pub enabled: bool,
    #[serde(default = "default_mcp_listen_addr")]
    pub listen_addr: SocketAddr,
    #[serde(default = "default_mcp_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_mcp_allowed_hosts")]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_mcp_resolve_client_ip")]
    pub resolve_client_ip: IpAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_client_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownConfig {
    #[serde(default = "default_shutdown_drain_timeout_seconds")]
    pub drain_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(not(feature = "dot"), allow(dead_code))]
#[serde(deny_unknown_fields)]
pub struct TlsTransportConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(not(feature = "doh"), allow(dead_code))]
#[serde(deny_unknown_fields)]
pub struct HttpsTransportConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub dns_hostname: Option<String>,
    #[serde(default = "default_https_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_max_doh_h2_connections")]
    pub max_doh_h2_connections: u32,
    #[serde(default = "default_max_doh_h2_streams_per_connection")]
    pub max_doh_h2_streams_per_connection: u32,
    #[serde(default = "default_max_doh_body_bytes")]
    pub max_doh_body_bytes: usize,
    #[serde(default)]
    pub odoh: Option<OdohConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(not(feature = "doh"), allow(dead_code))]
#[serde(deny_unknown_fields)]
pub struct OdohConfig {
    #[serde(deserialize_with = "hpke::deserialize_hpke_kem_id")]
    pub kem_id: u16,
    #[serde(deserialize_with = "hpke::deserialize_hpke_kdf_id")]
    pub kdf_id: u16,
    #[serde(deserialize_with = "hpke::deserialize_hpke_aead_id")]
    pub aead_id: u16,
    pub public_key_base64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(not(any(feature = "doq", feature = "doh3")), allow(dead_code))]
#[serde(deny_unknown_fields)]
pub struct QuicTransportConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub dns_hostname: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(not(feature = "dnscrypt"), allow(dead_code))]
#[serde(deny_unknown_fields)]
pub struct DnsCryptTransportConfig {
    pub listen_addr: SocketAddr,
    pub provider_name: String,
    pub provider_secret_key_path: String,
    pub resolver_secret_key_path: String,
    pub cert_serial: u32,
    pub cert_valid_from: u32,
    pub cert_valid_until: u32,
    #[serde(default)]
    pub client_magic: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(default)]
    pub dot: Option<TlsTransportConfig>,
    #[serde(default)]
    pub doh: Option<HttpsTransportConfig>,
    #[serde(default)]
    pub doq: Option<QuicTransportConfig>,
    #[serde(default)]
    pub doh3: Option<QuicTransportConfig>,
    #[serde(default)]
    pub dnscrypt: Option<DnsCryptTransportConfig>,
}

impl AppConfig {
    pub fn from_file(path: impl AsRef<Path>) -> DynResult<Self> {
        let data = fs::read_to_string(path)?;
        let config = serde_json::from_str(&data)?;
        Ok(config)
    }

    pub fn load_or_default(path: impl AsRef<Path>) -> DynResult<Self> {
        let path = path.as_ref();
        match Self::from_file(path) {
            Ok(config) => Ok(config),
            Err(err)
                if err
                    .downcast_ref::<std::io::Error>()
                    .map(|io_err| io_err.kind() == ErrorKind::NotFound)
                    .unwrap_or(false) =>
            {
                warn!("config file {} not found, using defaults", path.display());
                Ok(Self::default())
            }
            Err(err) => Err(err),
        }
    }

    pub fn load_required(path: impl AsRef<Path>) -> DynResult<Self> {
        Self::from_file(path)
    }

    pub fn root_hints(&self) -> Vec<IpAddr> {
        if self.resolvers.is_empty() {
            default_root_server_ips()
        } else {
            self.resolvers.clone()
        }
    }

    pub fn validate(&self, strict_mode: bool) -> DynResult<()> {
        if self.listen_addr.port() == 0 {
            return Err("listen_addr port must be greater than zero".into());
        }
        if self.health.listen_addr.port() == 0 {
            return Err("health.listen_addr port must be greater than zero".into());
        }
        if !self.health.listen_addr.ip().is_loopback() {
            return Err(
                "health.listen_addr must be loopback unless an authenticated ops listener is added"
                    .into(),
            );
        }
        if self.mcp.enabled {
            #[cfg(not(feature = "mcp"))]
            return Err("mcp.enabled=true requires the `mcp` feature".into());

            if self.mcp.listen_addr.port() == 0 {
                return Err("mcp.listen_addr port must be greater than zero".into());
            }
            if !self.mcp.listen_addr.ip().is_loopback() {
                return Err(
                    "mcp.listen_addr must be loopback unless an authenticated MCP listener is added"
                        .into(),
                );
            }
            if !self.mcp.endpoint.starts_with('/') {
                return Err("mcp.endpoint must start with '/'".into());
            }
        }
        if self.shutdown.drain_timeout_seconds == 0 {
            return Err("shutdown.drain_timeout_seconds must be greater than zero".into());
        }
        #[cfg(not(feature = "redis-cache"))]
        if matches!(self.caching, CachingConfig::Redis { .. }) {
            return Err("caching.type=redis requires the `redis-cache` feature".into());
        }

        #[cfg(feature = "redis-cache")]
        if let CachingConfig::Redis {
            timeout_ms,
            failure_threshold,
            ..
        } = &self.caching
        {
            if *timeout_ms == 0 {
                return Err("caching.timeout_ms must be greater than zero".into());
            }
            if *failure_threshold == 0 {
                return Err("caching.failure_threshold must be greater than zero".into());
            }
        }
        if self.recursion.enabled && self.recursion.allowed_client_cidrs.is_empty() {
            return Err(
                "recursion.allowed_client_cidrs must be non-empty when recursion is enabled".into(),
            );
        }
        for cidr in &self.recursion.allowed_client_cidrs {
            validate_ip_cidr(cidr)
                .map_err(|err| format!("invalid recursion CIDR {cidr}: {err}"))?;
        }

        #[cfg(not(feature = "dot"))]
        if self.transports.dot.is_some() {
            return Err("transports.dot requires the `dot` feature".into());
        }
        #[cfg(not(feature = "doh"))]
        if self.transports.doh.is_some() {
            return Err("transports.doh requires the `doh` feature".into());
        }
        #[cfg(not(feature = "doq"))]
        if self.transports.doq.is_some() {
            return Err("transports.doq requires the `doq` feature".into());
        }
        #[cfg(not(feature = "doh3"))]
        if self.transports.doh3.is_some() {
            return Err("transports.doh3 requires the `doh3` feature".into());
        }
        #[cfg(not(feature = "dnscrypt"))]
        if self.transports.dnscrypt.is_some() {
            return Err("transports.dnscrypt requires the `dnscrypt` feature".into());
        }

        validate_tls_paths(
            self.transports
                .dot
                .as_ref()
                .map(|cfg| (cfg.cert_path.as_str(), cfg.key_path.as_str())),
        )?;
        validate_tls_paths(
            self.transports
                .doh
                .as_ref()
                .map(|cfg| (cfg.cert_path.as_str(), cfg.key_path.as_str())),
        )?;
        validate_tls_paths(
            self.transports
                .doq
                .as_ref()
                .map(|cfg| (cfg.cert_path.as_str(), cfg.key_path.as_str())),
        )?;
        validate_tls_paths(
            self.transports
                .doh3
                .as_ref()
                .map(|cfg| (cfg.cert_path.as_str(), cfg.key_path.as_str())),
        )?;

        if let Some(doh) = self.transports.doh.as_ref() {
            if doh.max_doh_h2_connections == 0 {
                return Err(
                    "transports.doh.max_doh_h2_connections must be greater than zero".into(),
                );
            }
            if doh.max_doh_h2_streams_per_connection == 0 {
                return Err(
                    "transports.doh.max_doh_h2_streams_per_connection must be greater than zero"
                        .into(),
                );
            }
            if doh.max_doh_body_bytes == 0 {
                return Err("transports.doh.max_doh_body_bytes must be greater than zero".into());
            }
            #[cfg(feature = "doh")]
            if let Some(odoh) = doh.odoh.as_ref() {
                odoh.decode_public_key_bytes().map_err(|err| {
                    format!("invalid transports.doh.odoh.public_key_base64: {err}")
                })?;
            }
        }
        #[cfg(feature = "dnscrypt")]
        if let Some(dnscrypt) = self.transports.dnscrypt.as_ref() {
            validate_dnscrypt_config(dnscrypt)?;
        }

        #[cfg(not(feature = "audit-logging"))]
        if self.logging.enabled {
            return Err("logging.enabled=true requires the `audit-logging` feature".into());
        }

        if strict_mode && self.logging.enabled {
            let secret = self.logging.hmac_secret.trim();
            if secret.is_empty() {
                return Err("logging.hmac_secret must be non-empty when logging is enabled".into());
            }
            if secret.eq_ignore_ascii_case("change-me") {
                return Err("logging.hmac_secret must not use insecure sentinel values".into());
            }
        }

        if self.logging.enabled {
            for tenant in &self.logging.tenants {
                if !is_safe_tenant_path_segment(&tenant.tenant_id) {
                    return Err(format!(
                        "logging.tenants tenant_id must be a safe path segment: {}",
                        tenant.tenant_id
                    )
                    .into());
                }
            }
        }

        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_LISTEN_PORT)),
            policy_file_path: None,
            rule_engine: RuleEngineConfig::default(),
            resolvers: Vec::new(),
            zones: Vec::new(),
            transports: TransportConfig::default(),
            caching: CachingConfig::default(),
            logging: LoggingConfig::default(),
            health: HealthConfig::default(),
            mcp: McpConfig::default(),
            recursion: RecursionConfig::default(),
            shutdown: ShutdownConfig::default(),
        }
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_health_listen_addr(),
        }
    }
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: default_mcp_enabled(),
            listen_addr: default_mcp_listen_addr(),
            endpoint: default_mcp_endpoint(),
            allowed_hosts: default_mcp_allowed_hosts(),
            allowed_origins: Vec::new(),
            resolve_client_ip: default_mcp_resolve_client_ip(),
        }
    }
}

impl Default for RecursionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_client_cidrs: Vec::new(),
        }
    }
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout_seconds: default_shutdown_drain_timeout_seconds(),
        }
    }
}

fn default_health_listen_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], DEFAULT_HEALTH_LISTEN_PORT))
}

fn default_mcp_enabled() -> bool {
    cfg!(feature = "mcp")
}

fn default_mcp_listen_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], DEFAULT_MCP_LISTEN_PORT))
}

fn default_mcp_endpoint() -> String {
    "/mcp".to_string()
}

fn default_mcp_allowed_hosts() -> Vec<String> {
    vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ]
}

fn default_mcp_resolve_client_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn default_shutdown_drain_timeout_seconds() -> u64 {
    DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_SECONDS
}

fn default_https_endpoint() -> String {
    "/dns-query".to_string()
}

fn default_max_doh_h2_connections() -> u32 {
    DEFAULT_MAX_DOH_H2_CONNECTIONS
}

fn default_max_doh_h2_streams_per_connection() -> u32 {
    DEFAULT_MAX_DOH_H2_STREAMS_PER_CONNECTION
}

fn default_max_doh_body_bytes() -> usize {
    DEFAULT_MAX_DOH_BODY_BYTES
}

fn validate_tls_paths(paths: Option<(&str, &str)>) -> DynResult<()> {
    let Some((cert_path, key_path)) = paths else {
        return Ok(());
    };
    if !Path::new(cert_path).is_file() {
        return Err(
            format!("TLS certificate path does not exist or is not a file: {cert_path}").into(),
        );
    }
    if !Path::new(key_path).is_file() {
        return Err(
            format!("TLS private key path does not exist or is not a file: {key_path}").into(),
        );
    }
    Ok(())
}

#[cfg(feature = "dnscrypt")]
fn validate_dnscrypt_config(config: &DnsCryptTransportConfig) -> DynResult<()> {
    if config.listen_addr.port() == 0 {
        return Err("transports.dnscrypt.listen_addr port must be greater than zero".into());
    }
    if config.cert_valid_from > config.cert_valid_until {
        return Err(
            "transports.dnscrypt.cert_valid_from must be before or equal to cert_valid_until"
                .into(),
        );
    }
    let provider_name = DnsName::parse_ascii(&config.provider_name)
        .map_err(|err| format!("invalid transports.dnscrypt.provider_name: {err}"))?;
    if provider_name.to_ascii() == "." {
        return Err("transports.dnscrypt.provider_name must not be root".into());
    }
    decode_dnscrypt_key_file(
        &config.provider_secret_key_path,
        "transports.dnscrypt.provider_secret_key_path",
    )?;
    decode_dnscrypt_key_file(
        &config.resolver_secret_key_path,
        "transports.dnscrypt.resolver_secret_key_path",
    )?;
    if let Some(client_magic) = config.client_magic.as_deref() {
        let decoded = STANDARD
            .decode(client_magic.trim())
            .map_err(|err| format!("invalid transports.dnscrypt.client_magic base64: {err}"))?;
        if decoded.len() != DNSCRYPT_CLIENT_MAGIC_BYTES {
            return Err(format!(
                "transports.dnscrypt.client_magic must decode to {DNSCRYPT_CLIENT_MAGIC_BYTES} bytes"
            )
            .into());
        }
        if decoded[..7] == [0; 7] {
            return Err(
                "transports.dnscrypt.client_magic must not start with seven zero bytes".into(),
            );
        }
    }
    Ok(())
}

#[cfg(feature = "dnscrypt")]
pub(crate) fn decode_dnscrypt_key_file(
    path: &str,
    field: &str,
) -> DynResult<[u8; DNSCRYPT_KEY_BYTES]> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("{field} could not be read from {path}: {err}"))?;
    let decoded = STANDARD
        .decode(contents.trim())
        .map_err(|err| format!("{field} must contain base64 key bytes: {err}"))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "{field} must decode to {DNSCRYPT_KEY_BYTES} bytes, got {}",
            bytes.len()
        )
        .into()
    })
}

fn is_safe_tenant_path_segment(tenant_id: &str) -> bool {
    !tenant_id.is_empty()
        && tenant_id != "."
        && tenant_id != ".."
        && tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_ip_cidr(input: &str) -> Result<(), String> {
    let (addr, prefix) = input
        .split_once('/')
        .ok_or_else(|| "expected address/prefix".to_string())?;
    let addr: IpAddr = addr.parse().map_err(|_| "invalid IP address".to_string())?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| "invalid prefix length".to_string())?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("prefix length must be <= {max}"));
    }
    Ok(())
}

impl OdohConfig {
    #[cfg(feature = "doh")]
    pub fn decode_public_key_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = STANDARD
            .decode(self.public_key_base64.as_bytes())
            .map_err(|_| "public_key_base64 must be standard base64".to_string())?;
        let expected_len = match self.kem_id {
            0x0010 => 65usize,
            0x0011 => 97usize,
            0x0012 => 133usize,
            0x0020 => 32usize,
            0x0021 => 56usize,
            other => {
                return Err(format!(
                    "unsupported KEM for ODoH key validation: {other:#06x}"
                ));
            }
        };
        if bytes.len() != expected_len {
            return Err(format!(
                "public key length mismatch for kem_id={:#06x}: expected {}, got {}",
                self.kem_id,
                expected_len,
                bytes.len()
            ));
        }
        if matches!(self.kem_id, 0x0010 | 0x0011 | 0x0012) && bytes.first().copied() != Some(0x04) {
            return Err(
                "EC KEM public keys must be uncompressed points (first byte 0x04)".to_string(),
            );
        }
        Ok(bytes)
    }
}

fn default_zone_soa_ttl() -> u32 {
    3600
}

fn default_zone_record_ttl() -> u32 {
    300
}

fn default_root_server_ips() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(Ipv4Addr::from([198, 41, 0, 4])), // a.root-servers.net
        IpAddr::V4(Ipv4Addr::from([170, 247, 170, 2])), // b.root-servers.net
        IpAddr::V4(Ipv4Addr::from([192, 33, 4, 12])), // c.root-servers.net
        IpAddr::V4(Ipv4Addr::from([199, 7, 91, 13])), // d.root-servers.net
        IpAddr::V4(Ipv4Addr::from([192, 203, 230, 10])), // e.root-servers.net
        IpAddr::V4(Ipv4Addr::from([192, 5, 5, 241])), // f.root-servers.net
        IpAddr::V4(Ipv4Addr::from([192, 112, 36, 4])), // g.root-servers.net
        IpAddr::V4(Ipv4Addr::from([198, 97, 190, 53])), // h.root-servers.net
        IpAddr::V4(Ipv4Addr::from([192, 36, 148, 17])), // i.root-servers.net
        IpAddr::V4(Ipv4Addr::from([192, 58, 128, 30])), // j.root-servers.net
        IpAddr::V4(Ipv4Addr::from([193, 0, 14, 129])), // k.root-servers.net
        IpAddr::V4(Ipv4Addr::from([199, 7, 83, 42])), // l.root-servers.net
        IpAddr::V4(Ipv4Addr::from([202, 12, 27, 33])), // m.root-servers.net
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30])),
        IpAddr::V6(Ipv6Addr::from([0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42])),
        IpAddr::V6(Ipv6Addr::from([0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35])),
    ]
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
