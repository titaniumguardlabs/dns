use crate::dns::wire::DnsDecoder;
use crate::dns::{DnsName, DnsResult};

pub(crate) fn read(decoder: &mut DnsDecoder<'_>) -> DnsResult<DnsName> {
    DnsName::read(decoder)
}

pub(crate) fn emit(out: &mut Vec<u8>, name: &DnsName) -> DnsResult<()> {
    name.emit(out)
}
