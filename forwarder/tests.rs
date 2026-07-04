use super::Forwarder;
use crate::caching::MokaDnsRecordCache;
#[cfg(feature = "recursion")]
use crate::config::RecursionConfig;
use crate::config::{ZoneConfig, ZoneSoaConfig};
use crate::logging::{LoggingConfig, LoggingPipeline};
use crate::policy::{PolicyRuntime, RuleEngineConfig};
use hickory_server::authority::{MessageRequest, MessageResponse};
use hickory_server::proto::op::Edns;
use hickory_server::proto::op::{Message, Query, ResponseCode};
use hickory_server::proto::rr::{Name, Record, RecordType};
use hickory_server::proto::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder,
};
use hickory_server::proto::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Default)]
struct TestResponseHandler;

#[async_trait::async_trait]
impl ResponseHandler for TestResponseHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response
                .destructive_emit(&mut encoder)
                .map_err(|err| io::Error::other(format!("failed to encode response: {err}")))?
        };
        Ok(info)
    }
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

async fn async_test_policy_runtime() -> Arc<PolicyRuntime> {
    Arc::new(
        PolicyRuntime::from_file_or_default(None, RuleEngineConfig::default())
            .await
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

fn request_from_wire(name: &str, record_type: RecordType) -> Request {
    let mut message = Message::new();
    message
        .add_query(Query::query(
            Name::from_ascii(name).expect("valid name"),
            record_type,
        ))
        .set_recursion_desired(true);

    let mut encoded = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut encoded);
        message.emit(&mut encoder).expect("encode dns message");
    }

    let mut decoder = BinDecoder::new(&encoded);
    let request = MessageRequest::read(&mut decoder).expect("decode dns request");
    Request::new(
        request,
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 55321)),
        Protocol::Udp,
    )
}

#[test]
#[cfg(feature = "recursion")]
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
fn response_edns_is_sane_and_preserves_dnssec_and_options() {
    let mut request_edns = Edns::new();
    request_edns
        .set_version(0)
        .set_max_payload(4096)
        .set_dnssec_ok(true);

    let response_edns = Forwarder::response_edns_from_request(&request_edns);

    assert_eq!(response_edns.max_payload(), 1232);
    assert!(response_edns.flags().dnssec_ok);
    assert_eq!(response_edns.version(), 0);
}

#[test]
#[cfg(feature = "recursion")]
fn minimized_zone_chain_walks_suffixes() {
    let name = Name::from_ascii("www.example.com.").expect("valid fqdn");
    let chain = Forwarder::minimized_zone_chain(&name);

    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].to_ascii(), "com.");
    assert_eq!(chain[1].to_ascii(), "example.com.");
}

#[test]
#[cfg(feature = "recursion")]
fn cache_key_canonicalizes_query_name_case() {
    let lower = request_from_wire("www.example.com.", RecordType::A);
    let mixed = request_from_wire("WWW.Example.COM.", RecordType::A);

    let lower_key = Forwarder::cache_key(&lower, false).expect("cache key");
    let mixed_key = Forwarder::cache_key(&mixed, false).expect("cache key");

    assert_eq!(lower_key, mixed_key);
}

#[test]
#[cfg(feature = "recursion")]
fn cache_key_separates_dnssec_ok() {
    let request = request_from_wire("www.example.com.", RecordType::A);

    let plain_key = Forwarder::cache_key(&request, false).expect("cache key");
    let dnssec_key = Forwarder::cache_key(&request, true).expect("cache key");

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

    let name = Name::from_ascii("api.corp.internal.").expect("valid fqdn");
    let zone = forwarder
        .authoritative_zones
        .find_zone(&name)
        .expect("zone should match");
    assert_eq!(zone.apex_ascii, "corp.internal.");
}

#[tokio::test]
async fn deny_rule_returns_refused() {
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

    let request = request_from_wire("blocked.example.", RecordType::A);
    let response = forwarder
        .handle_request(&request, TestResponseHandler)
        .await;
    let _ = std::fs::remove_file(policy_path);

    assert_eq!(response.response_code(), ResponseCode::Refused);
}

#[tokio::test]
async fn recursion_is_denied_by_default() {
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

    let request = request_from_wire("www.example.com.", RecordType::A);
    let response = forwarder
        .handle_request(&request, TestResponseHandler)
        .await;

    assert_eq!(response.response_code(), ResponseCode::Refused);
}

#[test]
#[cfg(feature = "recursion")]
fn recursion_authorizer_allows_configured_client_cidr() {
    let authorizer = super::RecursionAuthorizer::from_config(&RecursionConfig {
        enabled: true,
        allowed_client_cidrs: vec!["127.0.0.0/8".to_string()],
    })
    .expect("recursion config should parse");

    assert!(authorizer.allows(IpAddr::from([127, 0, 0, 1])));
    assert!(!authorizer.allows(IpAddr::from([192, 0, 2, 1])));
}
