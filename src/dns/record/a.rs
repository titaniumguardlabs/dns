use crate::dns::wire::DnsDecoder;
use crate::dns::{DnsError, DnsResult};
use std::net::Ipv4Addr;

pub(crate) fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<Ipv4Addr> {
    if rdlength != 4 {
        return Err(DnsError::new("invalid a rdata length"));
    }
    let octets = decoder.read_exact(4)?;
    Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

pub(crate) fn emit(out: &mut Vec<u8>, addr: &Ipv4Addr) {
    out.extend_from_slice(&addr.octets());
}
