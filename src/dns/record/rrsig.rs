use crate::dns::name::DnsName;
use crate::dns::types::RecordType;
use crate::dns::wire::{DnsDecoder, emit_u16, emit_u32};
use crate::dns::{DnsError, DnsResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsigData {
    pub type_covered: RecordType,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer_name: DnsName,
    pub signature: Vec<u8>,
}

pub fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<RrsigData> {
    if rdlength < 18 {
        return Err(DnsError::new("truncated rrsig rdata"));
    }
    let start = decoder.position();
    let type_covered = RecordType::from_code(decoder.read_u16()?);
    let algorithm = decoder.read_u8()?;
    let labels = decoder.read_u8()?;
    let original_ttl = decoder.read_u32()?;
    let expiration = decoder.read_u32()?;
    let inception = decoder.read_u32()?;
    let key_tag = decoder.read_u16()?;
    let signer_name = DnsName::read(decoder)?;
    let consumed = decoder.position() - start;
    if consumed > rdlength {
        return Err(DnsError::new("truncated rrsig signer name"));
    }
    Ok(RrsigData {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        signature: decoder.read_exact(rdlength - consumed)?.to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn emit(
    out: &mut Vec<u8>,
    type_covered: RecordType,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: &DnsName,
    signature: &[u8],
) -> DnsResult<()> {
    emit_u16(out, type_covered.code());
    out.push(algorithm);
    out.push(labels);
    emit_u32(out, original_ttl);
    emit_u32(out, expiration);
    emit_u32(out, inception);
    emit_u16(out, key_tag);
    signer_name.emit(out)?;
    out.extend_from_slice(signature);
    Ok(())
}
