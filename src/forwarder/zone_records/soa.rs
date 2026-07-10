use super::DynResult;
use crate::dns::RData;

pub(super) fn parse(_value: &str) -> DynResult<RData> {
    Err("SOA records must be configured in zone.soa".into())
}
