use super::DynResult;
use crate::dns::RData;

pub(super) fn parse(value: &str) -> DynResult<RData> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(
            format!("invalid CAA value '{value}', expected: '<flags> <tag> <value>'").into(),
        );
    }
    let flags = parts[0].parse()?;
    let tag = parts[1].to_string();
    if tag.is_empty() || !tag.is_ascii() {
        return Err("CAA tag must be non-empty ascii".into());
    }
    Ok(RData::CAA {
        flags,
        tag,
        value: parts[2..].join(" ").into_bytes(),
    })
}
