use super::DynResult;
use crate::dns::{RData, RecordType};

mod a;
mod aaaa;
mod caa;
mod cname;
mod dnskey;
mod ds;
mod https;
mod mx;
mod ns;
mod nsec;
mod ptr;
mod rrsig;
mod soa;
mod srv;
mod svcb;
mod txt;

pub(super) fn parse(record_type: RecordType, value: &str) -> DynResult<RData> {
    match record_type {
        RecordType::A => a::parse(value),
        RecordType::AAAA => aaaa::parse(value),
        RecordType::TXT => txt::parse(value),
        RecordType::NS => ns::parse(value),
        RecordType::CNAME => cname::parse(value),
        RecordType::PTR => ptr::parse(value),
        RecordType::MX => mx::parse(value),
        RecordType::SRV => srv::parse(value),
        RecordType::CAA => caa::parse(value),
        RecordType::SVCB => svcb::parse(value),
        RecordType::HTTPS => https::parse(value),
        RecordType::DS => ds::parse(value),
        RecordType::SOA => soa::parse(value),
        RecordType::DNSKEY => dnskey::parse(value),
        RecordType::RRSIG => rrsig::parse(value),
        RecordType::NSEC => nsec::parse(value),
        other => Err(format!("unsupported record type in authoritative parser: {other}").into()),
    }
}

fn parse_dns_name(input: &str) -> DynResult<crate::dns::DnsName> {
    Ok(crate::dns::DnsName::parse_ascii(input)?)
}

fn decode_hex(input: &str) -> DynResult<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return Err("hex string must contain an even number of digits".into());
    }
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}
