use super::DynResult;
use crate::dns::RData;

pub(super) fn parse(_value: &str) -> DynResult<RData> {
    Err("DNSKEY records are generated from zones[].dnssec".into())
}
