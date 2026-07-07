use crate::dns::wire::DnsDecoder;
use crate::dns::{DnsError, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaaData {
    pub(crate) flags: u8,
    pub(crate) tag: String,
    pub(crate) value: Vec<u8>,
}

pub(crate) fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<CaaData> {
    let flags = decoder.read_u8()?;
    let tag_len = usize::from(decoder.read_u8()?);
    let tag = std::str::from_utf8(decoder.read_exact(tag_len)?)
        .map_err(|_| DnsError::new("caa tag is not utf-8"))?
        .to_string();
    let consumed = 2 + tag_len;
    if consumed > rdlength {
        return Err(DnsError::new("truncated caa rdata"));
    }
    Ok(CaaData {
        flags,
        tag,
        value: decoder.read_exact(rdlength - consumed)?.to_vec(),
    })
}

pub(crate) fn emit(out: &mut Vec<u8>, data: &CaaData) -> DnsResult<()> {
    let tag_len =
        u8::try_from(data.tag.len()).map_err(|_| DnsError::new("caa tag exceeds 255 octets"))?;
    out.push(data.flags);
    out.push(tag_len);
    out.extend_from_slice(data.tag.as_bytes());
    out.extend_from_slice(&data.value);
    Ok(())
}
