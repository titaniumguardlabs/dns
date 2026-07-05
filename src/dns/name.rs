use crate::dns::wire::DnsDecoder;
use crate::dns::{DnsError, DnsResult};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName {
    labels: Vec<String>,
}

impl DnsName {
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    pub fn parse_ascii(input: &str) -> DnsResult<Self> {
        let trimmed = input.trim();
        if trimmed == "." {
            return Ok(Self::root());
        }

        let absolute = trimmed.strip_suffix('.').unwrap_or(trimmed);
        if absolute.is_empty() {
            return Err(DnsError::new("dns name must not be empty"));
        }

        let labels = absolute
            .split('.')
            .map(|label| {
                validate_label(label)?;
                Ok(label.to_ascii_lowercase())
            })
            .collect::<DnsResult<Vec<_>>>()?;
        let name = Self { labels };
        if name.wire_len() > 255 {
            return Err(DnsError::new("dns name exceeds 255 octets"));
        }
        Ok(name)
    }

    pub fn to_ascii(&self) -> String {
        if self.labels.is_empty() {
            ".".to_string()
        } else {
            format!("{}.", self.labels.join("."))
        }
    }

    pub(crate) fn wire_len(&self) -> usize {
        wire_len(&self.labels)
    }

    pub(crate) fn read(decoder: &mut DnsDecoder<'_>) -> DnsResult<Self> {
        let labels = decoder.read_name_labels(decoder.position(), true)?;
        let name = Self { labels };
        if name.wire_len() > 255 {
            return Err(DnsError::new("decoded dns name exceeds 255 octets"));
        }
        Ok(name)
    }

    pub(crate) fn emit(&self, out: &mut Vec<u8>) -> DnsResult<()> {
        for label in &self.labels {
            validate_label(label)?;
            out.push(u8::try_from(label.len()).map_err(|_| DnsError::new("label too long"))?);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        Ok(())
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_ascii())
    }
}

pub(crate) fn validate_label(label: &str) -> DnsResult<()> {
    if label.is_empty() {
        return Err(DnsError::new("dns labels must not be empty"));
    }
    if label.len() > 63 {
        return Err(DnsError::new("dns label exceeds 63 octets"));
    }
    if !label.is_ascii() {
        return Err(DnsError::new("dns labels must be ascii"));
    }
    Ok(())
}

pub(crate) fn wire_len(labels: &[String]) -> usize {
    labels.iter().map(|label| label.len() + 1).sum::<usize>() + 1
}
