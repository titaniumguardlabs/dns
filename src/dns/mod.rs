mod error;
mod header;
mod message;
mod name;
mod question;
mod record;
mod request;
mod types;
pub(crate) mod wire;

pub use error::{DnsError, DnsResult};
pub use header::DnsHeader;
pub use message::DnsMessage;
pub use name::DnsName;
pub use question::DnsQuestion;
pub use record::{DnsRecord, RData};
pub use request::{DnsRequest, TransportProtocol};
pub use types::{DnsClass, RecordType, ResponseCode};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_and_emits_query_wire() {
        let wire = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let message = DnsMessage::from_wire(&wire).expect("query should parse");

        assert_eq!(message.header.id, 0x1234);
        assert!(!message.header.response);
        assert!(message.header.recursion_desired);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.questions[0].name.to_ascii(), "www.example.com.");
        assert_eq!(message.questions[0].record_type, RecordType::A);
        assert_eq!(message.questions[0].class, DnsClass::IN);
        assert_eq!(message.to_wire().expect("query should emit"), wire);
    }

    #[test]
    fn parses_compressed_a_response_wire() {
        let wire = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
            0x2c, 0x00, 0x04, 0xcb, 0x00, 0x71, 0x0a,
        ];

        let message = DnsMessage::from_wire(&wire).expect("response should parse");

        assert!(message.header.response);
        assert!(message.header.recursion_available);
        assert_eq!(message.header.response_code, ResponseCode::NoError);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].name.to_ascii(), "www.example.com.");
        assert_eq!(message.answers[0].ttl, 300);
        assert_eq!(
            message.answers[0].data,
            RData::A(Ipv4Addr::new(203, 0, 113, 10))
        );

        let emitted = DnsMessage::from_wire(&message.to_wire().expect("response should emit"))
            .expect("emitted response should parse");
        assert_eq!(emitted, message);
    }

    #[test]
    fn parses_authority_soa_and_txt_records() {
        let authority = DnsRecord {
            name: DnsName::parse_ascii("example.com.").expect("valid name"),
            ttl: 3600,
            class: DnsClass::IN,
            data: RData::SOA {
                mname: DnsName::parse_ascii("ns1.example.com.").expect("valid mname"),
                rname: DnsName::parse_ascii("admin.example.com.").expect("valid rname"),
                serial: 2026070401,
                refresh: 3600,
                retry: 600,
                expire: 1_209_600,
                minimum: 300,
            },
        };
        let answer = DnsRecord {
            name: DnsName::parse_ascii("example.com.").expect("valid name"),
            ttl: 300,
            class: DnsClass::IN,
            data: RData::TXT(vec![b"titaniumguard dns".to_vec()]),
        };
        let mut message = DnsMessage::query(
            7,
            DnsQuestion {
                name: DnsName::parse_ascii("example.com.").expect("valid name"),
                record_type: RecordType::TXT,
                class: DnsClass::IN,
            },
        );
        message.header.response = true;
        message.header.authoritative = true;
        message.answers.push(answer);
        message.authorities.push(authority);

        let reparsed =
            DnsMessage::from_wire(&message.to_wire().expect("message should emit")).expect("parse");

        assert_eq!(reparsed, message);
    }

    #[test]
    fn parses_and_emits_extended_authoritative_records() {
        let name = DnsName::parse_ascii("example.com.").expect("valid name");
        let records = vec![
            DnsRecord {
                name: name.clone(),
                ttl: 300,
                class: DnsClass::IN,
                data: RData::CAA {
                    flags: 0,
                    tag: "issue".to_string(),
                    value: b"ca.example".to_vec(),
                },
            },
            DnsRecord {
                name: name.clone(),
                ttl: 300,
                class: DnsClass::IN,
                data: RData::SVCB {
                    priority: 1,
                    target: DnsName::parse_ascii("svc.example.com.").expect("target"),
                    params: vec![
                        (1, vec![2, b'h', b'2']),
                        (3, 8443u16.to_be_bytes().to_vec()),
                    ],
                },
            },
            DnsRecord {
                name: name.clone(),
                ttl: 300,
                class: DnsClass::IN,
                data: RData::HTTPS {
                    priority: 1,
                    target: DnsName::root(),
                    params: vec![(2, Vec::new())],
                },
            },
            DnsRecord {
                name: name.clone(),
                ttl: 300,
                class: DnsClass::IN,
                data: RData::DS {
                    key_tag: 12345,
                    algorithm: 15,
                    digest_type: 2,
                    digest: vec![0xaa, 0xbb],
                },
            },
            DnsRecord {
                name: name.clone(),
                ttl: 300,
                class: DnsClass::IN,
                data: RData::DNSKEY {
                    flags: 256,
                    protocol: 3,
                    algorithm: 15,
                    public_key: vec![1; 32],
                },
            },
            DnsRecord {
                name: name.clone(),
                ttl: 300,
                class: DnsClass::IN,
                data: RData::RRSIG {
                    type_covered: RecordType::A,
                    algorithm: 15,
                    labels: 2,
                    original_ttl: 300,
                    expiration: 1_800_086_400,
                    inception: 1_800_000_000,
                    key_tag: 12345,
                    signer_name: name.clone(),
                    signature: vec![2; 64],
                },
            },
            DnsRecord {
                name: name.clone(),
                ttl: 300,
                class: DnsClass::IN,
                data: RData::NSEC {
                    next_domain: DnsName::parse_ascii("www.example.com.").expect("next"),
                    type_bit_maps: vec![0, 1, 0x40],
                },
            },
        ];
        let mut message = DnsMessage::query(
            11,
            DnsQuestion {
                name,
                record_type: RecordType::ANY,
                class: DnsClass::IN,
            },
        );
        message.header.response = true;
        message.answers = records;

        let reparsed =
            DnsMessage::from_wire(&message.to_wire().expect("message should emit")).expect("parse");

        assert_eq!(reparsed, message);
    }

    #[test]
    fn rejects_pointer_loop() {
        let wire = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01,
        ];

        let err = DnsMessage::from_wire(&wire).expect_err("pointer loop should fail");

        assert!(err.to_string().contains("pointer loop"));
    }

    #[test]
    fn rejects_oversized_label() {
        let label = "a".repeat(64);
        let err = DnsName::parse_ascii(&format!("{label}.example.")).expect_err("invalid label");

        assert!(err.to_string().contains("63 octets"));
    }
}
