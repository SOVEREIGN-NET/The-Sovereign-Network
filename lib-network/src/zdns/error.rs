//! ZDNS error types

use std::fmt;

/// ZDNS resolver errors
#[derive(Debug, Clone)]
pub enum ZdnsError {
    /// Domain not found in registry
    DomainNotFound(String),
    /// Domain has expired
    DomainExpired(String),
    /// Invalid domain name format
    InvalidDomain(String),
    /// Registry lookup failed
    RegistryError(String),
    /// Cache operation failed
    CacheError(String),
}

impl fmt::Display for ZdnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZdnsError::DomainNotFound(domain) => {
                write!(f, "Domain not found: {}", domain)
            }
            ZdnsError::DomainExpired(domain) => {
                write!(f, "Domain has expired: {}", domain)
            }
            ZdnsError::InvalidDomain(domain) => {
                write!(f, "Invalid domain format: {}", domain)
            }
            ZdnsError::RegistryError(msg) => {
                write!(f, "Registry error: {}", msg)
            }
            ZdnsError::CacheError(msg) => {
                write!(f, "Cache error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ZdnsError {}

impl From<anyhow::Error> for ZdnsError {
    fn from(err: anyhow::Error) -> Self {
        ZdnsError::RegistryError(err.to_string())
    }
}
