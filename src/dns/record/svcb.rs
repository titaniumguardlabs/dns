use crate::dns::name::DnsName;
use crate::dns::wire::{DnsDecoder, emit_u16};
use crate::dns::{DnsError, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcbData {
    pub priority: u16,
    pub target: DnsName,
    pub params: Vec<(u16, Vec<u8>)>,
}

pub fn read(decoder: &mut DnsDecoder<'_>, rdata_end: usize) -> DnsResult<SvcbData> {
    let priority = decoder.read_u16()?;
    let target = DnsName::read(decoder)?;
    let mut params = Vec::new();
    while decoder.position() < rdata_end {
        let key = decoder.read_u16()?;
        let len = usize::from(decoder.read_u16()?);
        params.push((key, decoder.read_exact(len)?.to_vec()));
    }
    Ok(SvcbData {
        priority,
        target,
        params,
    })
}

pub fn emit(
    out: &mut Vec<u8>,
    priority: u16,
    target: &DnsName,
    params: &[(u16, Vec<u8>)],
) -> DnsResult<()> {
    emit_u16(out, priority);
    target.emit(out)?;
    for (key, value) in params {
        emit_u16(out, *key);
        let len = u16::try_from(value.len())
            .map_err(|_| DnsError::new("svcb parameter value too large"))?;
        emit_u16(out, len);
        out.extend_from_slice(value);
    }
    Ok(())
}
