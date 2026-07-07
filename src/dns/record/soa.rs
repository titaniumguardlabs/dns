use crate::dns::wire::{DnsDecoder, emit_u32};
use crate::dns::{DnsName, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SoaData {
    pub(crate) mname: DnsName,
    pub(crate) rname: DnsName,
    pub(crate) serial: u32,
    pub(crate) refresh: u32,
    pub(crate) retry: u32,
    pub(crate) expire: u32,
    pub(crate) minimum: u32,
}

pub(crate) fn read(decoder: &mut DnsDecoder<'_>) -> DnsResult<SoaData> {
    Ok(SoaData {
        mname: DnsName::read(decoder)?,
        rname: DnsName::read(decoder)?,
        serial: decoder.read_u32()?,
        refresh: decoder.read_u32()?,
        retry: decoder.read_u32()?,
        expire: decoder.read_u32()?,
        minimum: decoder.read_u32()?,
    })
}

pub(crate) fn emit(out: &mut Vec<u8>, data: &SoaData) -> DnsResult<()> {
    data.mname.emit(out)?;
    data.rname.emit(out)?;
    emit_u32(out, data.serial);
    emit_u32(out, data.refresh);
    emit_u32(out, data.retry);
    emit_u32(out, data.expire);
    emit_u32(out, data.minimum);
    Ok(())
}
