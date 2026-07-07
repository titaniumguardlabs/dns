use crate::dns::name::DnsName;
use crate::dns::types::{DnsClass, RecordType};
use crate::dns::wire::{DnsDecoder, emit_u16, emit_u32};
use crate::dns::{DnsError, DnsResult};
use std::net::{Ipv4Addr, Ipv6Addr};

mod a;
mod aaaa;
mod caa;
mod cname;
mod dnskey;
mod ds;
mod https;
mod mx;
mod ns;
mod nsec;
mod opt;
mod ptr;
mod rrsig;
mod soa;
mod srv;
mod svcb;
mod txt;
mod unknown;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: DnsName,
    pub ttl: u32,
    pub class: DnsClass,
    pub data: RData,
}

impl DnsRecord {
    pub fn from_wire(bytes: &[u8]) -> DnsResult<Self> {
        let mut decoder = DnsDecoder::new(bytes);
        let record = Self::read(&mut decoder)?;
        if decoder.position() != decoder.len() {
            return Err(DnsError::new("trailing bytes after dns record"));
        }
        Ok(record)
    }

    pub fn to_wire(&self) -> DnsResult<Vec<u8>> {
        let mut out = Vec::new();
        self.emit(&mut out)?;
        Ok(out)
    }

    pub fn record_type(&self) -> RecordType {
        self.data.record_type()
    }

    pub(crate) fn read(decoder: &mut DnsDecoder<'_>) -> DnsResult<Self> {
        let name = DnsName::read(decoder)?;
        let record_type = RecordType::from_code(decoder.read_u16()?);
        let class = DnsClass::from_code(decoder.read_u16()?);
        let ttl = decoder.read_u32()?;
        let rdlength = decoder.read_u16()? as usize;
        let data_end = decoder
            .position()
            .checked_add(rdlength)
            .ok_or_else(|| DnsError::new("record data length overflow"))?;
        if data_end > decoder.len() {
            return Err(DnsError::new("truncated record data"));
        }
        let data = RData::read(decoder, record_type, rdlength)?;
        if decoder.position() != data_end {
            decoder.set_position(data_end)?;
        }
        Ok(Self {
            name,
            ttl,
            class,
            data,
        })
    }

    pub(crate) fn emit(&self, out: &mut Vec<u8>) -> DnsResult<()> {
        self.name.emit(out)?;
        emit_u16(out, self.record_type().code());
        emit_u16(out, self.class.code());
        emit_u32(out, self.ttl);
        let len_offset = out.len();
        emit_u16(out, 0);
        let data_start = out.len();
        self.data.emit(out)?;
        let data_len = out.len() - data_start;
        let data_len =
            u16::try_from(data_len).map_err(|_| DnsError::new("record data too large"))?;
        out[len_offset..len_offset + 2].copy_from_slice(&data_len.to_be_bytes());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(DnsName),
    CNAME(DnsName),
    PTR(DnsName),
    SOA {
        mname: DnsName,
        rname: DnsName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    MX {
        preference: u16,
        exchange: DnsName,
    },
    TXT(Vec<Vec<u8>>),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },
    CAA {
        flags: u8,
        tag: String,
        value: Vec<u8>,
    },
    SVCB {
        priority: u16,
        target: DnsName,
        params: Vec<(u16, Vec<u8>)>,
    },
    HTTPS {
        priority: u16,
        target: DnsName,
        params: Vec<(u16, Vec<u8>)>,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    RRSIG {
        type_covered: RecordType,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer_name: DnsName,
        signature: Vec<u8>,
    },
    NSEC {
        next_domain: DnsName,
        type_bit_maps: Vec<u8>,
    },
    OPT(Vec<u8>),
    Unknown {
        record_type: RecordType,
        bytes: Vec<u8>,
    },
}

impl RData {
    pub fn record_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::AAAA(_) => RecordType::AAAA,
            Self::NS(_) => RecordType::NS,
            Self::CNAME(_) => RecordType::CNAME,
            Self::PTR(_) => RecordType::PTR,
            Self::SOA { .. } => RecordType::SOA,
            Self::MX { .. } => RecordType::MX,
            Self::TXT(_) => RecordType::TXT,
            Self::SRV { .. } => RecordType::SRV,
            Self::CAA { .. } => RecordType::CAA,
            Self::SVCB { .. } => RecordType::SVCB,
            Self::HTTPS { .. } => RecordType::HTTPS,
            Self::DS { .. } => RecordType::DS,
            Self::DNSKEY { .. } => RecordType::DNSKEY,
            Self::RRSIG { .. } => RecordType::RRSIG,
            Self::NSEC { .. } => RecordType::NSEC,
            Self::OPT(_) => RecordType::OPT,
            Self::Unknown { record_type, .. } => *record_type,
        }
    }

    pub(crate) fn read(
        decoder: &mut DnsDecoder<'_>,
        record_type: RecordType,
        rdlength: usize,
    ) -> DnsResult<Self> {
        let rdata_start = decoder.position();
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or_else(|| DnsError::new("record data length overflow"))?;
        match record_type {
            RecordType::A => Ok(Self::A(a::read(decoder, rdlength)?)),
            RecordType::AAAA => Ok(Self::AAAA(aaaa::read(decoder, rdlength)?)),
            RecordType::NS => Ok(Self::NS(ns::read(decoder)?)),
            RecordType::CNAME => Ok(Self::CNAME(cname::read(decoder)?)),
            RecordType::PTR => Ok(Self::PTR(ptr::read(decoder)?)),
            RecordType::SOA => {
                let data = soa::read(decoder)?;
                Ok(Self::SOA {
                    mname: data.mname,
                    rname: data.rname,
                    serial: data.serial,
                    refresh: data.refresh,
                    retry: data.retry,
                    expire: data.expire,
                    minimum: data.minimum,
                })
            }
            RecordType::MX => {
                let data = mx::read(decoder)?;
                Ok(Self::MX {
                    preference: data.preference,
                    exchange: data.exchange,
                })
            }
            RecordType::TXT => Ok(Self::TXT(txt::read(decoder, rdlength)?)),
            RecordType::SRV => {
                let data = srv::read(decoder)?;
                Ok(Self::SRV {
                    priority: data.priority,
                    weight: data.weight,
                    port: data.port,
                    target: data.target,
                })
            }
            RecordType::CAA => {
                let data = caa::read(decoder, rdlength)?;
                Ok(Self::CAA {
                    flags: data.flags,
                    tag: data.tag,
                    value: data.value,
                })
            }
            RecordType::SVCB => {
                let data = svcb::read(decoder, rdata_end)?;
                Ok(Self::SVCB {
                    priority: data.priority,
                    target: data.target,
                    params: data.params,
                })
            }
            RecordType::HTTPS => {
                let data = https::read(decoder, rdata_end)?;
                Ok(Self::HTTPS {
                    priority: data.priority,
                    target: data.target,
                    params: data.params,
                })
            }
            RecordType::DS => {
                let data = ds::read(decoder, rdlength)?;
                Ok(Self::DS {
                    key_tag: data.key_tag,
                    algorithm: data.algorithm,
                    digest_type: data.digest_type,
                    digest: data.digest,
                })
            }
            RecordType::DNSKEY => {
                let data = dnskey::read(decoder, rdlength)?;
                Ok(Self::DNSKEY {
                    flags: data.flags,
                    protocol: data.protocol,
                    algorithm: data.algorithm,
                    public_key: data.public_key,
                })
            }
            RecordType::RRSIG => {
                let data = rrsig::read(decoder, rdlength)?;
                Ok(Self::RRSIG {
                    type_covered: data.type_covered,
                    algorithm: data.algorithm,
                    labels: data.labels,
                    original_ttl: data.original_ttl,
                    expiration: data.expiration,
                    inception: data.inception,
                    key_tag: data.key_tag,
                    signer_name: data.signer_name,
                    signature: data.signature,
                })
            }
            RecordType::NSEC => {
                let data = nsec::read(decoder, rdlength)?;
                Ok(Self::NSEC {
                    next_domain: data.next_domain,
                    type_bit_maps: data.type_bit_maps,
                })
            }
            RecordType::OPT => Ok(Self::OPT(opt::read(decoder, rdlength)?)),
            other => Ok(Self::Unknown {
                record_type: other,
                bytes: unknown::read(decoder, rdlength)?,
            }),
        }
    }

    pub(crate) fn emit(&self, out: &mut Vec<u8>) -> DnsResult<()> {
        match self {
            Self::A(addr) => a::emit(out, addr),
            Self::AAAA(addr) => aaaa::emit(out, addr),
            Self::NS(name) => ns::emit(out, name)?,
            Self::CNAME(name) => cname::emit(out, name)?,
            Self::PTR(name) => ptr::emit(out, name)?,
            Self::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => soa::emit(
                out,
                &soa::SoaData {
                    mname: mname.clone(),
                    rname: rname.clone(),
                    serial: *serial,
                    refresh: *refresh,
                    retry: *retry,
                    expire: *expire,
                    minimum: *minimum,
                },
            )?,
            Self::MX {
                preference,
                exchange,
            } => mx::emit(
                out,
                &mx::MxData {
                    preference: *preference,
                    exchange: exchange.clone(),
                },
            )?,
            Self::TXT(chunks) => txt::emit(out, chunks)?,
            Self::SRV {
                priority,
                weight,
                port,
                target,
            } => srv::emit(
                out,
                &srv::SrvData {
                    priority: *priority,
                    weight: *weight,
                    port: *port,
                    target: target.clone(),
                },
            )?,
            Self::CAA { flags, tag, value } => caa::emit(
                out,
                &caa::CaaData {
                    flags: *flags,
                    tag: tag.clone(),
                    value: value.clone(),
                },
            )?,
            Self::SVCB {
                priority,
                target,
                params,
            } => svcb::emit(out, *priority, target, params)?,
            Self::HTTPS {
                priority,
                target,
                params,
            } => https::emit(out, *priority, target, params)?,
            Self::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => ds::emit(out, *key_tag, *algorithm, *digest_type, digest),
            Self::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => dnskey::emit(out, *flags, *protocol, *algorithm, public_key),
            Self::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
            } => rrsig::emit(
                out,
                *type_covered,
                *algorithm,
                *labels,
                *original_ttl,
                *expiration,
                *inception,
                *key_tag,
                signer_name,
                signature,
            )?,
            Self::NSEC {
                next_domain,
                type_bit_maps,
            } => nsec::emit(out, next_domain, type_bit_maps)?,
            Self::OPT(bytes) => opt::emit(out, bytes),
            Self::Unknown { bytes, .. } => unknown::emit(out, bytes),
        }
        Ok(())
    }
}
