use crate::dns::wire::DnsDecoder;
use crate::dns::{DnsError, DnsResult};
use std::net::Ipv6Addr;

pub(crate) fn read(decoder: &mut DnsDecoder<'_>, rdlength: usize) -> DnsResult<Ipv6Addr> {
    if rdlength != 16 {
        return Err(DnsError::new("invalid aaaa rdata length"));
    }
    let octets = decoder.read_exact(16)?;
    let mut addr = [0u8; 16];
    addr.copy_from_slice(octets);
    Ok(Ipv6Addr::from(addr))
}

pub(crate) fn emit(out: &mut Vec<u8>, addr: &Ipv6Addr) {
    out.extend_from_slice(&addr.octets());
}
