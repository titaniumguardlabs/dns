use super::{DynResult, parse_dns_name};
use crate::dns::RData;

pub(super) fn parse(value: &str) -> DynResult<RData> {
    Ok(RData::NS(parse_dns_name(value)?))
}
