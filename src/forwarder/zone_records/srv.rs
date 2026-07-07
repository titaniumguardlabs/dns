use super::{DynResult, parse_dns_name};
use crate::dns::RData;

pub(super) fn parse(value: &str) -> DynResult<RData> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(format!(
            "invalid SRV value '{value}', expected: '<priority> <weight> <port> <target>'"
        )
        .into());
    }
    Ok(RData::SRV {
        priority: parts[0].parse()?,
        weight: parts[1].parse()?,
        port: parts[2].parse()?,
        target: parse_dns_name(parts[3])?,
    })
}
