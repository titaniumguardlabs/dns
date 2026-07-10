use super::{DynResult, parse_dns_name};
use crate::dns::RData;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn parse(value: &str) -> DynResult<RData> {
    let (priority, target, params) = parse_svcb_fields("SVCB", value)?;
    Ok(RData::SVCB {
        priority,
        target,
        params,
    })
}

pub(super) fn parse_svcb_fields(
    record_type: &str,
    value: &str,
) -> DynResult<(u16, crate::dns::DnsName, Vec<(u16, Vec<u8>)>)> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!(
            "invalid {record_type} value '{value}', expected: '<priority> <target> [key=value ...]'"
        )
        .into());
    }
    Ok((
        parts[0].parse()?,
        parse_dns_name(parts[1])?,
        parse_svcb_params(&parts[2..])?,
    ))
}

fn parse_svcb_params(parts: &[&str]) -> DynResult<Vec<(u16, Vec<u8>)>> {
    let mut params = Vec::new();
    let mut seen = HashSet::new();
    for part in parts {
        let (key_text, value) = part.split_once('=').unwrap_or((part, ""));
        let key = svcb_param_key(key_text)?;
        if !seen.insert(key) {
            return Err(format!("duplicate SVCB parameter: {key_text}").into());
        }
        params.push((key, svcb_param_value(key, value)?));
    }
    params.sort_by_key(|(key, _)| *key);
    Ok(params)
}

fn svcb_param_key(input: &str) -> DynResult<u16> {
    match input.to_ascii_lowercase().as_str() {
        "mandatory" => Ok(0),
        "alpn" => Ok(1),
        "no-default-alpn" => Ok(2),
        "port" => Ok(3),
        "ipv4hint" => Ok(4),
        "ech" => Ok(5),
        "ipv6hint" => Ok(6),
        other => other
            .strip_prefix("key")
            .ok_or_else(|| format!("unsupported SVCB parameter: {input}").into())
            .and_then(|value| Ok(value.parse()?)),
    }
}

fn svcb_param_value(key: u16, value: &str) -> DynResult<Vec<u8>> {
    match key {
        0 => {
            let mut out = Vec::new();
            for item in value.split(',').filter(|item| !item.is_empty()) {
                out.extend_from_slice(&svcb_param_key(item)?.to_be_bytes());
            }
            Ok(out)
        }
        1 => {
            let mut out = Vec::new();
            for item in value.split(',').filter(|item| !item.is_empty()) {
                let len = u8::try_from(item.len()).map_err(|_| "ALPN value too long")?;
                out.push(len);
                out.extend_from_slice(item.as_bytes());
            }
            Ok(out)
        }
        2 => {
            if !value.is_empty() {
                return Err("no-default-alpn must not have a value".into());
            }
            Ok(Vec::new())
        }
        3 => Ok(value.parse::<u16>()?.to_be_bytes().to_vec()),
        4 => value
            .split(',')
            .filter(|item| !item.is_empty())
            .map(|item| Ok(Ipv4Addr::from(item.parse::<Ipv4Addr>()?).octets().to_vec()))
            .collect::<DynResult<Vec<_>>>()
            .map(|chunks| chunks.into_iter().flatten().collect()),
        5 => {
            use base64::Engine;
            use base64::engine::general_purpose::STANDARD;
            Ok(STANDARD.decode(value)?)
        }
        6 => value
            .split(',')
            .filter(|item| !item.is_empty())
            .map(|item| Ok(Ipv6Addr::from(item.parse::<Ipv6Addr>()?).octets().to_vec()))
            .collect::<DynResult<Vec<_>>>()
            .map(|chunks| chunks.into_iter().flatten().collect()),
        _ => Ok(value.as_bytes().to_vec()),
    }
}
