use super::{DynResult, parse_dns_name};
use crate::dns::RData;

pub(super) fn parse(value: &str) -> DynResult<RData> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(
            format!("invalid MX value '{value}', expected: '<preference> <exchange>'").into(),
        );
    }
    Ok(RData::MX {
        preference: parts[0].parse()?,
        exchange: parse_dns_name(parts[1])?,
    })
}
