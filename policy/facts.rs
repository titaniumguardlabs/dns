use chrono::{Datelike, Local, Timelike};
use hickory_server::server::Request;
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

pub fn from_dns_request(request: &Request) -> RuntimeFacts {
    let now = Local::now();
    let mut facts = RuntimeFacts::default();

    let client_ip = request.src().ip();

    facts.fields.insert(
        "client.ip".to_string(),
        Value::String(client_ip.to_string()),
    );
    if let Ok(request_info) = request.request_info() {
        let query = request_info.query.original();
        facts.fields.insert(
            "dns.qname".to_string(),
            Value::String(query.name().to_ascii().to_lowercase()),
        );
        facts.fields.insert(
            "dns.qtype".to_string(),
            Value::String(format!("{:?}", query.query_type()).to_uppercase()),
        );
        facts.fields.insert(
            "dns.qclass".to_string(),
            Value::String(format!("{:?}", query.query_class()).to_uppercase()),
        );
    }
    facts.fields.insert(
        "dns.dnssec_ok".to_string(),
        Value::Bool(
            request
                .edns()
                .map(|edns| edns.flags().dnssec_ok)
                .unwrap_or(false),
        ),
    );
    facts.fields.insert(
        "dns.recursion_desired".to_string(),
        Value::Bool(request.header().recursion_desired()),
    );

    // Hickory protocol metadata is not consistently exposed across all request wrappers.
    facts.fields.insert(
        "conn.protocol".to_string(),
        Value::String("dns".to_string()),
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
    use super::from_dns_request;
    use hickory_server::{
        authority::MessageRequest,
        proto::{
            op::Message,
            rr::{Name, RecordType},
            serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
            xfer::Protocol,
        },
        server::Request,
    };
    use std::net::{Ipv4Addr, SocketAddr};

    fn request_from_wire(name: &str, record_type: RecordType) -> Request {
        let mut message = Message::new();
        message
            .add_query(hickory_server::proto::op::Query::query(
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
    fn extracts_expected_dns_facts() {
        let request = request_from_wire("www.example.com.", RecordType::A);
        let facts = from_dns_request(&request);

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
}
