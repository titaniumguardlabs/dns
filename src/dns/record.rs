use crate::dns::name::DnsName;
use crate::dns::types::{DnsClass, RecordType};
use crate::dns::wire::{DnsDecoder, emit_u16, emit_u32};
use crate::dns::{DnsError, DnsResult};
use std::net::{Ipv4Addr, Ipv6Addr};

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
            Self::OPT(_) => RecordType::OPT,
            Self::Unknown { record_type, .. } => *record_type,
        }
    }

    pub(crate) fn read(
        decoder: &mut DnsDecoder<'_>,
        record_type: RecordType,
        rdlength: usize,
    ) -> DnsResult<Self> {
        match record_type {
            RecordType::A if rdlength == 4 => {
                let octets = decoder.read_exact(4)?;
                Ok(Self::A(Ipv4Addr::new(
                    octets[0], octets[1], octets[2], octets[3],
                )))
            }
            RecordType::AAAA if rdlength == 16 => {
                let octets = decoder.read_exact(16)?;
                let mut addr = [0u8; 16];
                addr.copy_from_slice(octets);
                Ok(Self::AAAA(Ipv6Addr::from(addr)))
            }
            RecordType::NS => Ok(Self::NS(DnsName::read(decoder)?)),
            RecordType::CNAME => Ok(Self::CNAME(DnsName::read(decoder)?)),
            RecordType::PTR => Ok(Self::PTR(DnsName::read(decoder)?)),
            RecordType::SOA => Ok(Self::SOA {
                mname: DnsName::read(decoder)?,
                rname: DnsName::read(decoder)?,
                serial: decoder.read_u32()?,
                refresh: decoder.read_u32()?,
                retry: decoder.read_u32()?,
                expire: decoder.read_u32()?,
                minimum: decoder.read_u32()?,
            }),
            RecordType::MX => Ok(Self::MX {
                preference: decoder.read_u16()?,
                exchange: DnsName::read(decoder)?,
            }),
            RecordType::TXT => {
                let end = decoder.position() + rdlength;
                let mut chunks = Vec::new();
                while decoder.position() < end {
                    let len = usize::from(decoder.read_u8()?);
                    chunks.push(decoder.read_exact(len)?.to_vec());
                }
                Ok(Self::TXT(chunks))
            }
            RecordType::SRV => Ok(Self::SRV {
                priority: decoder.read_u16()?,
                weight: decoder.read_u16()?,
                port: decoder.read_u16()?,
                target: DnsName::read(decoder)?,
            }),
            RecordType::OPT => Ok(Self::OPT(decoder.read_exact(rdlength)?.to_vec())),
            other => Ok(Self::Unknown {
                record_type: other,
                bytes: decoder.read_exact(rdlength)?.to_vec(),
            }),
        }
    }

    pub(crate) fn emit(&self, out: &mut Vec<u8>) -> DnsResult<()> {
        match self {
            Self::A(addr) => out.extend_from_slice(&addr.octets()),
            Self::AAAA(addr) => out.extend_from_slice(&addr.octets()),
            Self::NS(name) | Self::CNAME(name) | Self::PTR(name) => name.emit(out)?,
            Self::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                mname.emit(out)?;
                rname.emit(out)?;
                emit_u32(out, *serial);
                emit_u32(out, *refresh);
                emit_u32(out, *retry);
                emit_u32(out, *expire);
                emit_u32(out, *minimum);
            }
            Self::MX {
                preference,
                exchange,
            } => {
                emit_u16(out, *preference);
                exchange.emit(out)?;
            }
            Self::TXT(chunks) => {
                for chunk in chunks {
                    let len = u8::try_from(chunk.len())
                        .map_err(|_| DnsError::new("txt chunk exceeds 255 octets"))?;
                    out.push(len);
                    out.extend_from_slice(chunk);
                }
            }
            Self::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                emit_u16(out, *priority);
                emit_u16(out, *weight);
                emit_u16(out, *port);
                target.emit(out)?;
            }
            Self::OPT(bytes) | Self::Unknown { bytes, .. } => out.extend_from_slice(bytes),
        }
        Ok(())
    }
}
