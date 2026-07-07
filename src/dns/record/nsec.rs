use crate::dns::name::DnsName;
use crate::dns::wire::DnsDecoder;
use crate::dns::{DnsError, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsecData {
    pub next_domain: DnsName,
    pub type_bit_maps: Vec<u8>,
}

pub fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<NsecData> {
    let start = decoder.position();
    let next_domain = DnsName::read(decoder)?;
    let consumed = decoder.position() - start;
    if consumed > rdlength {
        return Err(DnsError::new("truncated nsec next domain"));
    }
    Ok(NsecData {
        next_domain,
        type_bit_maps: decoder.read_exact(rdlength - consumed)?.to_vec(),
    })
}

pub fn emit(out: &mut Vec<u8>, next_domain: &DnsName, type_bit_maps: &[u8]) -> DnsResult<()> {
    next_domain.emit(out)?;
    out.extend_from_slice(type_bit_maps);
    Ok(())
}
