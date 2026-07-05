use crate::caching::DnsRecordCache;
use crate::config::RecursionConfig;
use crate::logging::LoggingPipeline;
use crate::policy::PolicyRuntime;
use std::net::IpAddr;
use std::sync::Arc;

mod authoritative;
mod recursive;
mod runtime;
mod zones;

use recursive::RecursiveResolver;
pub use runtime::RuntimeState;
use zones::AuthoritativeZones;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
pub struct Forwarder {
    recursive_resolver: RecursiveResolver,
    authoritative_zones: Arc<AuthoritativeZones>,
    cache: Arc<dyn DnsRecordCache>,
    logging: Arc<LoggingPipeline>,
    policy: Arc<PolicyRuntime>,
    runtime: RuntimeState,
    recursion: RecursionAuthorizer,
}

#[derive(Clone, Default)]
struct RecursionAuthorizer {
    enabled: bool,
    cidrs: Vec<IpCidr>,
}

#[derive(Clone)]
struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl RecursionAuthorizer {
    fn from_config(config: &RecursionConfig) -> DynResult<Self> {
        let cidrs = config
            .allowed_client_cidrs
            .iter()
            .map(|cidr| IpCidr::parse(cidr))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            enabled: config.enabled,
            cidrs,
        })
    }

    fn allows(&self, client_ip: IpAddr) -> bool {
        self.enabled && self.cidrs.iter().any(|cidr| cidr.contains(client_ip))
    }
}

impl IpCidr {
    fn parse(input: &str) -> Result<Self, String> {
        let (addr, prefix) = input
            .split_once('/')
            .ok_or_else(|| format!("CIDR must contain '/': {input}"))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid CIDR address: {input}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid CIDR prefix: {input}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("CIDR prefix out of range: {input}"));
        }
        Ok(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = prefix_mask(self.prefix, 32) as u32;
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = prefix_mask(self.prefix, 128);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

fn prefix_mask(prefix: u8, bits: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (u32::from(bits - prefix))
    }
}

#[cfg(test)]
mod tests;
