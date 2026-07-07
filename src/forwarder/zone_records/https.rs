use super::DynResult;
use crate::dns::RData;

pub(super) fn parse(value: &str) -> DynResult<RData> {
    let (priority, target, params) = super::svcb::parse_svcb_fields("HTTPS", value)?;
    Ok(RData::HTTPS {
        priority,
        target,
        params,
    })
}
