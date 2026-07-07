use super::DynResult;
use crate::dns::RData;

pub(super) fn parse(value: &str) -> DynResult<RData> {
    Ok(RData::AAAA(value.parse()?))
}
