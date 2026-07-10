use super::{DynResult, decode_hex};
use crate::dns::RData;

pub(super) fn parse(value: &str) -> DynResult<RData> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(format!(
            "invalid DS value '{value}', expected: '<key_tag> <algorithm> <digest_type> <hex_digest>'"
        )
        .into());
    }
    Ok(RData::DS {
        key_tag: parts[0].parse()?,
        algorithm: parts[1].parse()?,
        digest_type: parts[2].parse()?,
        digest: decode_hex(parts[3])?,
    })
}
