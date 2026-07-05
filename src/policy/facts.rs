use crate::dns::{DnsClass, DnsRequest};
use chrono::{Datelike, Local, Timelike};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct RuntimeFacts {
    pub fields: HashMap<String, Value>,
}

impl RuntimeFacts {
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.fields.get(field)
    }

    pub fn snapshot(&self, max_items: usize) -> Map<String, Value> {
        let mut map = Map::new();
        for (index, (k, v)) in self.fields.iter().enumerate() {
            if index >= max_items {
                break;
            }
            map.insert(k.clone(), v.clone());
        }
        map
    }
}

pub fn from_repo_dns_request(request: &DnsRequest) -> RuntimeFacts {
    let now = Local::now();
    let mut facts = RuntimeFacts::default();

    facts.fields.insert(
        "client.ip".to_string(),
        Value::String(request.client_ip.to_string()),
    );
    if let Some(query) = request.message.first_question() {
        facts.fields.insert(
            "dns.qname".to_string(),
            Value::String(query.name.to_ascii()),
        );
        facts.fields.insert(
            "dns.qtype".to_string(),
            Value::String(query.record_type.to_string()),
        );
        facts.fields.insert(
            "dns.qclass".to_string(),
            Value::String(match query.class {
                DnsClass::IN => "IN".to_string(),
                DnsClass::ANY => "ANY".to_string(),
                DnsClass::Unknown(code) => format!("CLASS{code}"),
            }),
        );
    }
    facts.fields.insert(
        "dns.dnssec_ok".to_string(),
        Value::Bool(request.dnssec_ok()),
    );
    facts.fields.insert(
        "dns.recursion_desired".to_string(),
        Value::Bool(request.recursion_desired()),
    );
    facts.fields.insert(
        "conn.protocol".to_string(),
        Value::String(request.protocol.as_policy_value().to_string()),
    );
    facts
        .fields
        .insert("time.local.hour".to_string(), json!(now.hour() as u64));
    facts.fields.insert(
        "time.local.dow".to_string(),
        Value::String(now.weekday().to_string().to_lowercase()),
    );

    facts
}

#[cfg(test)]
mod tests {
    use super::from_repo_dns_request;
    use crate::dns::{
        DnsClass as WireClass, DnsMessage as WireMessage, DnsName as WireName,
        DnsQuestion as WireQuestion, DnsRequest, RData, RecordType as WireRecordType,
        TransportProtocol,
    };
    use std::net::IpAddr;

    fn request_from_wire(name: &str, record_type: WireRecordType) -> DnsRequest {
        let mut message = WireMessage::query(
            0,
            WireQuestion {
                name: WireName::parse_ascii(name).expect("valid name"),
                record_type,
                class: WireClass::IN,
            },
        );
        message.header.recursion_desired = true;
        DnsRequest {
            client_ip: IpAddr::from([127, 0, 0, 1]),
            protocol: TransportProtocol::Udp,
            message,
        }
    }

    #[test]
    fn extracts_expected_dns_facts() {
        let request = request_from_wire("www.example.com.", WireRecordType::A);
        let facts = from_repo_dns_request(&request);

        assert_eq!(
            facts.get("dns.qname").and_then(|v| v.as_str()),
            Some("www.example.com.")
        );
        assert_eq!(facts.get("dns.qtype").and_then(|v| v.as_str()), Some("A"));
        assert_eq!(
            facts.get("client.ip").and_then(|v| v.as_str()),
            Some("127.0.0.1")
        );
        assert_eq!(
            facts.get("dns.recursion_desired").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            facts.get("conn.protocol").and_then(|v| v.as_str()),
            Some("dns")
        );
        assert!(facts.get("time.local.hour").is_some());
        assert!(facts.get("time.local.dow").is_some());
    }

    #[test]
    fn extracts_expected_dns_facts_from_repo_request() {
        let mut message = WireMessage::query(
            1,
            WireQuestion {
                name: WireName::parse_ascii("secure.example.").expect("valid name"),
                record_type: WireRecordType::AAAA,
                class: WireClass::IN,
            },
        );
        message.header.recursion_desired = true;
        message.additionals.push(crate::dns::DnsRecord {
            name: WireName::root(),
            ttl: 0x0000_8000,
            class: WireClass::Unknown(1232),
            data: RData::OPT(Vec::new()),
        });
        let request = crate::dns::DnsRequest {
            client_ip: IpAddr::from([192, 0, 2, 10]),
            protocol: crate::dns::TransportProtocol::Https,
            message,
        };

        let facts = from_repo_dns_request(&request);

        assert_eq!(
            facts.get("dns.qname").and_then(|v| v.as_str()),
            Some("secure.example.")
        );
        assert_eq!(
            facts.get("dns.qtype").and_then(|v| v.as_str()),
            Some("AAAA")
        );
        assert_eq!(
            facts.get("dns.dnssec_ok").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            facts.get("conn.protocol").and_then(|v| v.as_str()),
            Some("doh")
        );
    }
}
