use crate::dns::DnsResult;
use crate::dns::name::DnsName;
use crate::dns::types::{DnsClass, RecordType};
use crate::dns::wire::{DnsDecoder, emit_u16};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: DnsName,
    pub record_type: RecordType,
    pub class: DnsClass,
}

impl DnsQuestion {
    pub(crate) fn read(decoder: &mut DnsDecoder<'_>) -> DnsResult<Self> {
        Ok(Self {
            name: DnsName::read(decoder)?,
            record_type: RecordType::from_code(decoder.read_u16()?),
            class: DnsClass::from_code(decoder.read_u16()?),
        })
    }

    pub(crate) fn emit(&self, out: &mut Vec<u8>) -> DnsResult<()> {
        self.name.emit(out)?;
        emit_u16(out, self.record_type.code());
        emit_u16(out, self.class.code());
        Ok(())
    }
}
