use super::DynResult;
use crate::dns::RData;

pub(super) fn parse(value: &str) -> DynResult<RData> {
    Ok(RData::TXT(vec![value.as_bytes().to_vec()]))
}
