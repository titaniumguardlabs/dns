use super::*;
use crate::logging::{LogMode, TenantLoggingRule};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_missing_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.json", std::process::id()))
}

fn sample_config() -> AppConfig {
    AppConfig {
        listen_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_LISTEN_PORT)),
        policy_file_path: None,
        rule_engine: RuleEngineConfig::default(),
        resolvers: vec![
            IpAddr::V4(Ipv4Addr::from([8, 8, 8, 8])),
            IpAddr::V4(Ipv4Addr::from([1, 1, 1, 1])),
            IpAddr::V6(Ipv6Addr::from([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111])),
            IpAddr::V6(Ipv6Addr::from([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001])),
        ],
        zones: Vec::new(),
        transports: TransportConfig::default(),
        caching: CachingConfig::default(),
        logging: LoggingConfig::default(),
        health: HealthConfig::default(),
        recursion: RecursionConfig::default(),
        shutdown: ShutdownConfig::default(),
    }
}

fn temp_file_with_contents(prefix: &str, contents: &[u8]) -> PathBuf {
    let path = unique_missing_path(prefix);
    fs::write(&path, contents).expect("temp file write should succeed");
    path
}

fn write_temp_config(prefix: &str, contents: &str) -> PathBuf {
    let path = unique_missing_path(prefix);
    fs::write(&path, contents).expect("temporary config write should succeed");
    path
}

#[test]
fn app_config_from_file_parses_config() {
    let path = write_temp_config(
        "dns-config-parse",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "resolvers": ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
}
"#,
    );
    let config = AppConfig::from_file(&path).expect("config should parse");
    let _ = fs::remove_file(&path);

    assert_eq!(config.listen_addr, SocketAddr::from(([0, 0, 0, 0], 8080)));
    assert_eq!(config.resolvers.len(), 4);
    assert!(config.zones.is_empty());
    assert!(config.transports.dot.is_none());
    assert!(matches!(config.caching, CachingConfig::Memory { .. }));
    assert_eq!(config.logging.default_mode, LogMode::Strict);
}

#[test]
fn app_config_load_or_default_uses_default_when_file_missing() {
    let missing = unique_missing_path("dns-config-missing");
    let config = AppConfig::load_or_default(&missing).expect("missing file should fallback");

    assert_eq!(config.listen_addr.port(), DEFAULT_LISTEN_PORT);
    assert!(config.resolvers.is_empty());
    assert!(config.zones.is_empty());
    assert!(config.transports.doh.is_none());
    assert!(matches!(config.caching, CachingConfig::Memory { .. }));
    assert_eq!(config.root_hints().len(), 26);
}

#[test]
fn app_config_load_required_fails_when_file_missing() {
    let missing = unique_missing_path("dns-config-missing-required");
    let err = AppConfig::load_required(&missing).expect_err("missing file should fail");
    assert!(
        err.to_string().contains("No such file") || err.to_string().contains("not found"),
        "unexpected error: {err}"
    );
}

#[test]
fn app_config_default_uses_root_server_hints() {
    let config = AppConfig::default();

    assert!(config.resolvers.is_empty());
    assert!(config.zones.is_empty());
    assert!(matches!(config.caching, CachingConfig::Memory { .. }));
    assert_eq!(config.root_hints().len(), 26);
    assert!(
        config
            .root_hints()
            .contains(&IpAddr::V4(Ipv4Addr::from([198, 41, 0, 4])))
    );
    assert!(config.root_hints().contains(&IpAddr::V6(Ipv6Addr::from([
        0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30
    ]))));
}

#[test]
fn app_config_root_hints_prefers_configured_resolvers() {
    let config = sample_config();

    assert_eq!(config.resolvers.len(), 4);
    assert_eq!(config.root_hints(), config.resolvers);
}

#[test]
fn app_config_parses_authoritative_zone_from_json_uppercase_soa_fields() {
    let path = write_temp_config(
        "dns-zone-parse-json-uppercased-soa",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "zones": [
    {
      "name": "corp.internal.",
      "soa": {
        "MNAME": "ns1.corp.internal.",
        "RNAME": "dns-admin.corp.internal.",
        "SERIAL": 2026022001,
        "REFRESH": 3600,
        "RETRY": 600,
        "EXPIRE": 1209600,
        "MINIMUM": 300
      },
      "records": {
        "@": {
          "NS": { "ttl": 3600, "values": ["ns1.corp.internal."] },
          "A": { "ttl": 300, "values": ["10.10.0.53"] }
        }
      }
    }
  ]
}
"#,
    );
    let config = AppConfig::from_file(&path).expect("config should parse");
    let _ = fs::remove_file(&path);

    assert_eq!(config.zones.len(), 1);
    let zone = &config.zones[0];
    assert_eq!(zone.name, "corp.internal.");
    assert_eq!(zone.soa.serial, 2026022001);
    assert!(zone.records.contains_key("@"));
}

#[test]
fn app_config_parses_authoritative_zone_from_json() {
    let path = write_temp_config(
        "dns-zone-parse-json",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "zones": [
    {
      "name": "corp.internal.",
      "soa": {
        "mname": "ns1.corp.internal.",
        "rname": "dns-admin.corp.internal.",
        "serial": 2026022001,
        "refresh": 3600,
        "retry": 600,
        "expire": 1209600,
        "minimum": 300
      },
      "records": {
        "@": {
          "A": { "ttl": 300, "values": ["10.10.0.53"] }
        }
      }
    }
  ]
}
"#,
    );
    let config = AppConfig::from_file(&path).expect("config should parse");
    let _ = fs::remove_file(&path);

    assert_eq!(config.zones.len(), 1);
    assert_eq!(config.zones[0].soa.minimum, 300);
}

#[test]
fn app_config_parses_doh_odoh_hpke_ids() {
    let path = write_temp_config(
        "dns-doh-odoh-ids",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "transports": {
    "doh": {
      "listen_addr": "0.0.0.0:8443",
      "cert_path": "/tmp/cert.pem",
      "key_path": "/tmp/key.pem",
      "odoh": {
        "kem_id": "0x0020",
        "kdf_id": "0x0001",
        "aead_id": "0x0001",
        "public_key_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      }
    }
  }
}
"#,
    );
    let config = AppConfig::from_file(&path).expect("config should parse");
    let _ = fs::remove_file(&path);

    let odoh = config
        .transports
        .doh
        .as_ref()
        .and_then(|doh| doh.odoh.as_ref())
        .expect("odoh config should be present");
    assert_eq!(odoh.kem_id, 0x0020);
    assert_eq!(odoh.kdf_id, 0x0001);
    assert_eq!(odoh.aead_id, 0x0001);
}

#[test]
fn app_config_parses_doh_odoh_rfc_string_ids() {
    let path = write_temp_config(
        "dns-doh-odoh-rfc-string-ids",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "transports": {
    "doh": {
      "listen_addr": "0.0.0.0:8443",
      "cert_path": "/tmp/cert.pem",
      "key_path": "/tmp/key.pem",
      "odoh": {
        "kem_id": "DHKEM(X25519, HKDF-SHA256)",
        "kdf_id": "HKDF-SHA256",
        "aead_id": "AES-128-GCM",
        "public_key_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      }
    }
  }
}
"#,
    );
    let config = AppConfig::from_file(&path).expect("config should parse");
    let _ = fs::remove_file(&path);

    let odoh = config
        .transports
        .doh
        .as_ref()
        .and_then(|doh| doh.odoh.as_ref())
        .expect("odoh config should be present");
    assert_eq!(odoh.kem_id, 0x0020);
    assert_eq!(odoh.kdf_id, 0x0001);
    assert_eq!(odoh.aead_id, 0x0001);
}

#[test]
fn app_config_rejects_unsupported_doh_odoh_kem_id() {
    let path = write_temp_config(
        "dns-doh-odoh-invalid-kem",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "transports": {
    "doh": {
      "listen_addr": "0.0.0.0:8443",
      "cert_path": "/tmp/cert.pem",
      "key_path": "/tmp/key.pem",
      "odoh": {
        "kem_id": "0x9999",
        "kdf_id": "0x0001",
        "aead_id": "0x0001",
        "public_key_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      }
    }
  }
}
"#,
    );
    let err = AppConfig::from_file(&path).expect_err("config should fail");
    let _ = fs::remove_file(&path);
    let text = err.to_string();
    assert!(
        text.contains("unsupported HPKE KEM ID"),
        "unexpected: {text}"
    );
}

#[test]
fn app_config_parses_memory_cache_config() {
    let path = write_temp_config(
        "dns-cache-memory",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "caching": {
    "type": "memory",
    "max_entries": 2048
  }
}
"#,
    );
    let config = AppConfig::from_file(&path).expect("config should parse");
    let _ = fs::remove_file(&path);

    match config.caching {
        CachingConfig::Memory { max_entries } => assert_eq!(max_entries, 2048),
        other => panic!("expected memory cache config, got: {other:?}"),
    }
}

#[test]
fn app_config_parses_redis_cache_config() {
    let path = write_temp_config(
        "dns-cache-redis",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "caching": {
    "type": "redis",
    "url": "redis://127.0.0.1/",
    "key_prefix": "dns:records:"
  }
}
"#,
    );
    let config = AppConfig::from_file(&path).expect("config should parse");
    let _ = fs::remove_file(&path);

    match config.caching {
        CachingConfig::Redis {
            url,
            key_prefix,
            required,
            timeout_ms,
            failure_threshold,
        } => {
            assert_eq!(url, "redis://127.0.0.1/");
            assert_eq!(key_prefix, "dns:records:");
            assert!(!required);
            assert_eq!(timeout_ms, 250);
            assert_eq!(failure_threshold, 3);
        }
        other => panic!("expected redis cache config, got: {other:?}"),
    }
}

#[test]
fn app_config_defaults_rule_engine_settings() {
    let config = AppConfig::default();
    assert_eq!(config.rule_engine.max_trace_facts, 64);
    assert!(config.rule_engine.enable_explain_logs);
    assert!(config.policy_file_path.is_none());
}

#[test]
fn app_config_parses_policy_file_and_rule_engine() {
    let path = write_temp_config(
        "dns-policy-settings",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "policy_file_path": "/etc/titaniumguard/dns-policy.json",
  "rule_engine": {
    "max_trace_facts": 12,
    "enable_explain_logs": false
  }
}
"#,
    );
    let config = AppConfig::from_file(&path).expect("config should parse");
    let _ = fs::remove_file(&path);

    assert_eq!(
        config.policy_file_path.as_deref(),
        Some("/etc/titaniumguard/dns-policy.json")
    );
    assert_eq!(config.rule_engine.max_trace_facts, 12);
    assert!(!config.rule_engine.enable_explain_logs);
}

#[test]
fn app_config_rejects_unknown_top_level_field() {
    let path = write_temp_config(
        "dns-config-unknown-top-level",
        r#"
{
  "listen_addr": "0.0.0.0:8080",
  "unexpected_field": true
}
"#,
    );
    let err = AppConfig::from_file(&path).expect_err("config should fail");
    let _ = fs::remove_file(&path);
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn validate_rejects_insecure_logging_secret_in_strict_mode() {
    let mut config = AppConfig::default();
    config.logging.enabled = true;
    config.logging.hmac_secret = "change-me".to_string();

    let err = config.validate(true).expect_err("validation should fail");
    assert!(err.to_string().contains("insecure sentinel"));
}

#[test]
fn validate_rejects_logging_tenant_id_path_traversal() {
    let mut config = AppConfig::default();
    config.logging.enabled = true;
    config.logging.tenants.push(TenantLoggingRule {
        tenant_id: "../tenant".to_string(),
        mode: LogMode::Standard,
        retention_days: None,
        client_cidrs: Vec::new(),
    });

    let err = config.validate(false).expect_err("validation should fail");
    assert!(err.to_string().contains("safe path segment"));
}

#[test]
fn validate_rejects_non_loopback_health_listener() {
    let mut config = AppConfig::default();
    config.health.listen_addr = "0.0.0.0:8081".parse().expect("addr");

    let err = config.validate(false).expect_err("validation should fail");
    assert!(err.to_string().contains("health.listen_addr"));
}

#[test]
fn validate_rejects_enabled_recursion_without_cidrs() {
    let mut config = AppConfig::default();
    config.recursion.enabled = true;

    let err = config.validate(false).expect_err("validation should fail");
    assert!(err.to_string().contains("recursion.allowed_client_cidrs"));
}

#[test]
fn validate_rejects_invalid_recursion_cidr() {
    let mut config = AppConfig::default();
    config.recursion.allowed_client_cidrs = vec!["127.0.0.1/99".to_string()];

    let err = config.validate(false).expect_err("validation should fail");
    assert!(err.to_string().contains("invalid recursion CIDR"));
}

#[test]
fn validate_rejects_missing_tls_files() {
    let mut config = AppConfig::default();
    config.transports.dot = Some(TlsTransportConfig {
        listen_addr: "0.0.0.0:853".parse().expect("addr"),
        cert_path: "/tmp/definitely-missing-cert.pem".to_string(),
        key_path: "/tmp/definitely-missing-key.pem".to_string(),
    });

    let err = config.validate(false).expect_err("validation should fail");
    assert!(err.to_string().contains("TLS certificate path"));
}

#[test]
fn validate_accepts_valid_odoh_public_key_for_kem() {
    let cert = temp_file_with_contents("dns-cert", b"cert");
    let key = temp_file_with_contents("dns-key", b"key");

    let mut config = AppConfig::default();
    config.transports.doh = Some(HttpsTransportConfig {
        listen_addr: "0.0.0.0:8443".parse().expect("addr"),
        cert_path: cert.to_string_lossy().to_string(),
        key_path: key.to_string_lossy().to_string(),
        dns_hostname: None,
        endpoint: "/dns-query".to_string(),
        max_doh_h2_connections: DEFAULT_MAX_DOH_H2_CONNECTIONS,
        max_doh_h2_streams_per_connection: DEFAULT_MAX_DOH_H2_STREAMS_PER_CONNECTION,
        max_doh_body_bytes: DEFAULT_MAX_DOH_BODY_BYTES,
        odoh: Some(OdohConfig {
            kem_id: 0x0020,
            kdf_id: 0x0001,
            aead_id: 0x0001,
            public_key_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        }),
    });

    let result = config.validate(false);
    let _ = fs::remove_file(cert);
    let _ = fs::remove_file(key);
    assert!(result.is_ok(), "unexpected error: {result:?}");
}

#[test]
fn validate_rejects_mismatched_odoh_public_key_length() {
    let cert = temp_file_with_contents("dns-cert-mismatch", b"cert");
    let key = temp_file_with_contents("dns-key-mismatch", b"key");

    let mut config = AppConfig::default();
    config.transports.doh = Some(HttpsTransportConfig {
        listen_addr: "0.0.0.0:8443".parse().expect("addr"),
        cert_path: cert.to_string_lossy().to_string(),
        key_path: key.to_string_lossy().to_string(),
        dns_hostname: None,
        endpoint: "/dns-query".to_string(),
        max_doh_h2_connections: DEFAULT_MAX_DOH_H2_CONNECTIONS,
        max_doh_h2_streams_per_connection: DEFAULT_MAX_DOH_H2_STREAMS_PER_CONNECTION,
        max_doh_body_bytes: DEFAULT_MAX_DOH_BODY_BYTES,
        odoh: Some(OdohConfig {
            kem_id: 0x0021,
            kdf_id: 0x0001,
            aead_id: 0x0001,
            public_key_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        }),
    });

    let result = config.validate(false);
    let _ = fs::remove_file(cert);
    let _ = fs::remove_file(key);
    assert!(result.is_err(), "expected validation failure");
}
