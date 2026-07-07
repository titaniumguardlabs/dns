use crate::dns::wire::DnsDecoder;
use crate::dns::{DnsError, DnsResult};

pub(crate) fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<Vec<Vec<u8>>> {
    let end = decoder.position() + rdlength;
    let mut chunks = Vec::new();
    while decoder.position() < end {
        let len = usize::from(decoder.read_u8()?);
        chunks.push(decoder.read_exact(len)?.to_vec());
    }
    Ok(chunks)
}

pub(crate) fn emit(out: &mut Vec<u8>, chunks: &[Vec<u8>]) -> DnsResult<()> {
    for chunk in chunks {
        let len =
            u8::try_from(chunk.len()).map_err(|_| DnsError::new("txt chunk exceeds 255 octets"))?;
        out.push(len);
        out.extend_from_slice(chunk);
    }
    Ok(())
}
