use crate::dns::wire::{DnsDecoder, emit_u16};
use crate::dns::{DnsName, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SrvData {
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) port: u16,
    pub(crate) target: DnsName,
}

pub(crate) fn read(decoder: &mut DnsDecoder<'_>) -> DnsResult<SrvData> {
    Ok(SrvData {
        priority: decoder.read_u16()?,
        weight: decoder.read_u16()?,
        port: decoder.read_u16()?,
        target: DnsName::read(decoder)?,
    })
}

pub(crate) fn emit(out: &mut Vec<u8>, data: &SrvData) -> DnsResult<()> {
    emit_u16(out, data.priority);
    emit_u16(out, data.weight);
    emit_u16(out, data.port);
    data.target.emit(out)
}
