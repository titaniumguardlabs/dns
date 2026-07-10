use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    OPT,
    DS,
    RRSIG,
    NSEC,
    DNSKEY,
    SVCB,
    HTTPS,
    CAA,
    ANY,
    Unknown(u16),
}

impl RecordType {
    pub fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            41 => Self::OPT,
            43 => Self::DS,
            46 => Self::RRSIG,
            47 => Self::NSEC,
            48 => Self::DNSKEY,
            64 => Self::SVCB,
            65 => Self::HTTPS,
            257 => Self::CAA,
            255 => Self::ANY,
            other => Self::Unknown(other),
        }
    }

    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::PTR => 12,
            Self::MX => 15,
            Self::TXT => 16,
            Self::AAAA => 28,
            Self::SRV => 33,
            Self::OPT => 41,
            Self::DS => 43,
            Self::RRSIG => 46,
            Self::NSEC => 47,
            Self::DNSKEY => 48,
            Self::SVCB => 64,
            Self::HTTPS => 65,
            Self::CAA => 257,
            Self::ANY => 255,
            Self::Unknown(code) => code,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => f.write_str("A"),
            Self::NS => f.write_str("NS"),
            Self::CNAME => f.write_str("CNAME"),
            Self::SOA => f.write_str("SOA"),
            Self::PTR => f.write_str("PTR"),
            Self::MX => f.write_str("MX"),
            Self::TXT => f.write_str("TXT"),
            Self::AAAA => f.write_str("AAAA"),
            Self::SRV => f.write_str("SRV"),
            Self::OPT => f.write_str("OPT"),
            Self::DS => f.write_str("DS"),
            Self::RRSIG => f.write_str("RRSIG"),
            Self::NSEC => f.write_str("NSEC"),
            Self::DNSKEY => f.write_str("DNSKEY"),
            Self::SVCB => f.write_str("SVCB"),
            Self::HTTPS => f.write_str("HTTPS"),
            Self::CAA => f.write_str("CAA"),
            Self::ANY => f.write_str("ANY"),
            Self::Unknown(code) => write!(f, "TYPE{code}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsClass {
    IN,
    ANY,
    Unknown(u16),
}

impl DnsClass {
    pub fn from_code(code: u16) -> Self {
        match code {
            1 => Self::IN,
            255 => Self::ANY,
            other => Self::Unknown(other),
        }
    }

    pub fn code(self) -> u16 {
        match self {
            Self::IN => 1,
            Self::ANY => 255,
            Self::Unknown(code) => code,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    Unknown(u8),
}

impl ResponseCode {
    pub(crate) fn from_low_bits(bits: u16) -> Self {
        match bits & 0x000f {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            other => Self::Unknown(other as u8),
        }
    }

    pub(crate) fn low_bits(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NXDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::Unknown(code) => u16::from(code & 0x0f),
        }
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => f.write_str("NOERROR"),
            Self::FormErr => f.write_str("FORMERR"),
            Self::ServFail => f.write_str("SERVFAIL"),
            Self::NXDomain => f.write_str("NXDOMAIN"),
            Self::NotImp => f.write_str("NOTIMP"),
            Self::Refused => f.write_str("REFUSED"),
            Self::Unknown(code) => write!(f, "RCODE{code}"),
        }
    }
}
