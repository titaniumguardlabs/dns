use crate::dns::DnsResult;
use crate::dns::wire::DnsDecoder;

pub fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<Vec<u8>> {
    Ok(decoder.read_exact(rdlength)?.to_vec())
}

pub fn emit(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}
