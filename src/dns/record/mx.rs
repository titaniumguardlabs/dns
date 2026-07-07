use crate::dns::wire::{DnsDecoder, emit_u16};
use crate::dns::{DnsName, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MxData {
    pub(crate) preference: u16,
    pub(crate) exchange: DnsName,
}

pub(crate) fn read(decoder: &mut DnsDecoder<'_>) -> DnsResult<MxData> {
    Ok(MxData {
        preference: decoder.read_u16()?,
        exchange: DnsName::read(decoder)?,
    })
}

pub(crate) fn emit(out: &mut Vec<u8>, data: &MxData) -> DnsResult<()> {
    emit_u16(out, data.preference);
    data.exchange.emit(out)
}
