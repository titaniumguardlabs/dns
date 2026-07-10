use crate::dns::wire::{DnsDecoder, emit_u16};
use crate::dns::{DnsError, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsData {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

pub fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<DsData> {
    if rdlength < 4 {
        return Err(DnsError::new("truncated ds rdata"));
    }
    Ok(DsData {
        key_tag: decoder.read_u16()?,
        algorithm: decoder.read_u8()?,
        digest_type: decoder.read_u8()?,
        digest: decoder.read_exact(rdlength - 4)?.to_vec(),
    })
}

pub fn emit(out: &mut Vec<u8>, key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) {
    emit_u16(out, key_tag);
    out.push(algorithm);
    out.push(digest_type);
    out.extend_from_slice(digest);
}
