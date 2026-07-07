use crate::dns::wire::{DnsDecoder, emit_u16};
use crate::dns::{DnsError, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnskeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

pub fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<DnskeyData> {
    if rdlength < 4 {
        return Err(DnsError::new("truncated dnskey rdata"));
    }
    Ok(DnskeyData {
        flags: decoder.read_u16()?,
        protocol: decoder.read_u8()?,
        algorithm: decoder.read_u8()?,
        public_key: decoder.read_exact(rdlength - 4)?.to_vec(),
    })
}

pub fn emit(out: &mut Vec<u8>, flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) {
    emit_u16(out, flags);
    out.push(protocol);
    out.push(algorithm);
    out.extend_from_slice(public_key);
}
