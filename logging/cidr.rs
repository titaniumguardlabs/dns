use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn parse(value: &str) -> Option<Self> {
        let (ip_part, prefix_part) = value.split_once('/')?;
        let ip: IpAddr = ip_part.parse().ok()?;
        let prefix: u8 = prefix_part.parse().ok()?;
        let max = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return None;
        }
        Some(Self {
            network: ip,
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                prefix_match(&net.octets(), &addr.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                prefix_match(&net.octets(), &addr.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_match(network: &[u8], value: &[u8], prefix: u8) -> bool {
    let full_bytes = (prefix / 8) as usize;
    let rem_bits = (prefix % 8) as usize;

    if network[..full_bytes] != value[..full_bytes] {
        return false;
    }

    if rem_bits == 0 {
        return true;
    }

    let mask = (!0u8) << (8 - rem_bits);
    (network[full_bytes] & mask) == (value[full_bytes] & mask)
}

pub fn truncate_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Ipv4Addr::new(octets[0], octets[1], octets[2], 0).to_string()
        }
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for byte in octets.iter_mut().skip(7) {
                *byte = 0;
            }
            Ipv6Addr::from(octets).to_string()
        }
    }
}
