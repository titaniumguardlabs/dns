use crate::dns::message::DnsMessage;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    Https3,
    #[cfg_attr(not(feature = "dnscrypt"), allow(dead_code))]
    DnsCrypt,
}

impl TransportProtocol {
    pub fn as_policy_value(self) -> &'static str {
        match self {
            Self::Udp | Self::Tcp => "dns",
            Self::Tls => "dot",
            Self::Https => "doh",
            Self::Quic => "doq",
            Self::Https3 => "doh3",
            Self::DnsCrypt => "dnscrypt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRequest {
    pub client_ip: IpAddr,
    pub protocol: TransportProtocol,
    pub message: DnsMessage,
}

impl DnsRequest {
    pub fn dnssec_ok(&self) -> bool {
        self.message.edns_dnssec_ok()
    }

    pub fn recursion_desired(&self) -> bool {
        self.message.header.recursion_desired
    }
}
