use std::fmt;

pub type DnsResult<T> = Result<T, DnsError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsError {
    message: String,
}

impl DnsError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DnsError {}
