use super::Forwarder;
use crate::caching::MokaDnsRecordCache;
use crate::config::RecursionConfig;
use crate::config::{ZoneConfig, ZoneRecordSetConfig, ZoneSoaConfig};
use crate::dns::{
    DnsClass, DnsMessage, DnsName, DnsQuestion, DnsRequest, RecordType, ResponseCode,
    TransportProtocol,
};
use crate::dns::{DnsRecord, RData};
use crate::logging::{LoggingConfig, LoggingPipeline};
use crate::policy::{PolicyRuntime, RuleEngineConfig};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

async fn async_test_policy_runtime() -> Arc<PolicyRuntime> {
    Arc::new(
        PolicyRuntime::from_file_or_default(None, RuleEngineConfig::default())
            .await
            .expect("policy runtime"),
    )
}

fn test_policy_runtime() -> Arc<PolicyRuntime> {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    Arc::new(
        runtime
            .block_on(PolicyRuntime::from_file_or_default(
                None,
                RuleEngineConfig::default(),
            ))
            .expect("policy runtime"),
    )
}

fn write_temp_policy(contents: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("dns-policy-{}-{nanos}.json", std::process::id()));
    std::fs::write(&path, contents).expect("policy write");
    path
}

fn wire_request(name: &str, record_type: RecordType) -> DnsRequest {
    let mut message = DnsMessage::query(
        0,
        DnsQuestion {
            name: DnsName::parse_ascii(name).expect("valid name"),
            record_type,
            class: DnsClass::IN,
        },
    );
    message.header.recursion_desired = true;
    DnsRequest {
        client_ip: IpAddr::from([127, 0, 0, 1]),
        protocol: TransportProtocol::Udp,
        message,
    }
}

fn single_a_zone() -> ZoneConfig {
    let mut api_records = BTreeMap::new();
    api_records.insert(
        "A".to_string(),
        ZoneRecordSetConfig {
            ttl: 300,
            values: vec!["192.0.2.10".to_string()],
        },
    );
    let mut records = BTreeMap::new();
    records.insert("api".to_string(), api_records);

    ZoneConfig {
        name: "corp.internal.".to_string(),
        soa: ZoneSoaConfig {
            mname: "ns1.corp.internal.".to_string(),
            rname: "dns-admin.corp.internal.".to_string(),
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 1209600,
            minimum: 300,
            ttl: 3600,
        },
        records,
        dnssec: None,
    }
}

#[test]
fn forwarder_new_rejects_empty_resolvers() {
    let logger = Arc::new(LoggingPipeline::from_config(&LoggingConfig::default()));
    let result = Forwarder::with_cache(
        &[],
        &[],
        Arc::new(MokaDnsRecordCache::new(100_000)),
        logger,
        test_policy_runtime(),
        Default::default(),
    );
    assert!(result.is_err());
}

#[test]
fn cache_key_canonicalizes_query_name_case() {
    let lower = wire_request("www.example.com.", RecordType::A);
    let mixed = wire_request("WWW.Example.COM.", RecordType::A);

    let lower_key = Forwarder::cache_key(&lower).expect("cache key");
    let mixed_key = Forwarder::cache_key(&mixed).expect("cache key");

    assert_eq!(lower_key, mixed_key);
}

#[test]
fn cache_key_separates_dnssec_ok() {
    let plain_request = wire_request("www.example.com.", RecordType::A);
    let mut dnssec_request = wire_request("www.example.com.", RecordType::A);
    dnssec_request.message.additionals.push(DnsRecord {
        name: DnsName::root(),
        ttl: 0x0000_8000,
        class: DnsClass::Unknown(1232),
        data: RData::OPT(Vec::new()),
    });

    let plain_key = Forwarder::cache_key(&plain_request).expect("cache key");
    let dnssec_key = Forwarder::cache_key(&dnssec_request).expect("cache key");

    assert_ne!(plain_key, dnssec_key);
}

#[test]
fn authoritative_zone_matching_prefers_longest_owned_suffix() {
    let logger = Arc::new(LoggingPipeline::from_config(&LoggingConfig::default()));
    let zones = vec![
        ZoneConfig {
            name: "internal.".to_string(),
            soa: ZoneSoaConfig {
                mname: "ns1.internal.".to_string(),
                rname: "dns-admin.internal.".to_string(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 1209600,
                minimum: 300,
                ttl: 3600,
            },
            records: BTreeMap::new(),
            dnssec: None,
        },
        ZoneConfig {
            name: "corp.internal.".to_string(),
            soa: ZoneSoaConfig {
                mname: "ns1.corp.internal.".to_string(),
                rname: "dns-admin.corp.internal.".to_string(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 1209600,
                minimum: 300,
                ttl: 3600,
            },
            records: BTreeMap::new(),
            dnssec: None,
        },
    ];
    let forwarder = Forwarder::with_cache(
        &[IpAddr::from([198, 41, 0, 4])],
        &zones,
        Arc::new(MokaDnsRecordCache::new(100_000)),
        logger,
        test_policy_runtime(),
        Default::default(),
    )
    .expect("forwarder should build");

    let name = DnsName::parse_ascii("api.corp.internal.").expect("valid fqdn");
    let zone = forwarder
        .authoritative_zones
        .find_zone(&name)
        .expect("zone should match");
    assert_eq!(zone.apex_ascii, "corp.internal.");
}

#[tokio::test]
async fn repo_dns_request_deny_rule_returns_refused() {
    let policy_path = write_temp_policy(
        r#"{
  "version":"1.0.0",
  "defaults":{"action":"ALLOW","log_level":"info","fail_closed":false},
  "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
  "dimensions":{"dns.qname":{"type":"string","source_stage":"REQUEST","description":""}},
  "operators":{"EQ":{"applicable_types":["string"],"value_schema":{"type":"string"},"semantics":""}},
  "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
  "rule_sets":[{"id":"global","scope":"GLOBAL","enabled":true,"rules":[{"id":"deny_bad","enabled":true,"priority":100,"description":"","when":{"all":[{"field":"dns.qname","op":"EQ","value":"blocked.example."}]},"action":{"type":"DENY","deny":{"reason":"blocked","status_code":403,"body":"blocked"}},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","created_by":"test"}}]}]
}"#,
    );
    let policy_runtime = Arc::new(
        PolicyRuntime::from_file_or_default(
            Some(policy_path.to_string_lossy().as_ref()),
            RuleEngineConfig::default(),
        )
        .await
        .expect("policy runtime"),
    );
    let logger = Arc::new(LoggingPipeline::from_config(&LoggingConfig::default()));
    let forwarder = Forwarder::with_cache(
        &[IpAddr::from([198, 41, 0, 4])],
        &[],
        Arc::new(MokaDnsRecordCache::new(100_000)),
        logger,
        policy_runtime,
        Default::default(),
    )
    .expect("forwarder should build");

    let response = forwarder
        .handle_dns_request(wire_request("blocked.example.", RecordType::A))
        .await;
    let _ = std::fs::remove_file(policy_path);

    assert_eq!(response.header.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn repo_dns_request_returns_authoritative_answer() {
    let logger = Arc::new(LoggingPipeline::from_config(&LoggingConfig::default()));
    let forwarder = Forwarder::with_cache(
        &[IpAddr::from([198, 41, 0, 4])],
        &[single_a_zone()],
        Arc::new(MokaDnsRecordCache::new(100_000)),
        logger,
        async_test_policy_runtime().await,
        Default::default(),
    )
    .expect("forwarder should build");

    let response = forwarder
        .handle_dns_request(wire_request("api.corp.internal.", RecordType::A))
        .await;

    assert_eq!(response.header.response_code, ResponseCode::NoError);
    assert!(response.header.authoritative);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].name.to_ascii(), "api.corp.internal.");
    assert_eq!(response.answers[0].record_type(), RecordType::A);
}

#[tokio::test]
async fn repo_dns_request_denies_recursion_by_default() {
    let logger = Arc::new(LoggingPipeline::from_config(&LoggingConfig::default()));
    let forwarder = Forwarder::with_cache(
        &[IpAddr::from([198, 41, 0, 4])],
        &[],
        Arc::new(MokaDnsRecordCache::new(100_000)),
        logger,
        async_test_policy_runtime().await,
        Default::default(),
    )
    .expect("forwarder should build");

    let response = forwarder
        .handle_dns_request(wire_request("www.example.com.", RecordType::A))
        .await;

    assert_eq!(response.header.response_code, ResponseCode::Refused);
}

#[test]
fn recursion_authorizer_allows_configured_client_cidr() {
    let authorizer = super::RecursionAuthorizer::from_config(&RecursionConfig {
        enabled: true,
        allowed_client_cidrs: vec!["127.0.0.0/8".to_string()],
    })
    .expect("recursion config should parse");

    assert!(authorizer.allows(IpAddr::from([127, 0, 0, 1])));
    assert!(!authorizer.allows(IpAddr::from([192, 0, 2, 1])));
}
