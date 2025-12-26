//! Pure network operation logic
//!
//! Handles network validation and parameter checking.
//! All functions are pure - they only depend on their inputs.

use crate::error::{CliError, CliResult};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

/// Valid network operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkOp {
    Status,
    Peers,
    Test,
    Ping,
}

impl NetworkOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkOp::Status => "status",
            NetworkOp::Peers => "peers",
            NetworkOp::Test => "test",
            NetworkOp::Ping => "ping",
        }
    }
}

/// Validate socket address format
///
/// Socket addresses must be in format: IP:PORT
/// Pure function - depends only on input
pub fn validate_socket_address(addr: &str) -> CliResult<SocketAddr> {
    if addr.is_empty() {
        return Err(CliError::NetworkError(
            "Socket address cannot be empty".to_string(),
        ));
    }

    match SocketAddr::from_str(addr) {
        Ok(socket_addr) => {
            // Validate port is not reserved
            if socket_addr.port() == 0 {
                return Err(CliError::NetworkError(
                    "Socket port cannot be 0".to_string(),
                ));
            }
            Ok(socket_addr)
        }
        Err(_) => Err(CliError::NetworkError(format!(
            "Invalid socket address format: '{}'. Use IP:PORT (e.g., 192.168.1.164:9002)",
            addr
        ))),
    }
}

/// Validate ping count parameter
///
/// Ping count must be between 1 and 100
pub fn validate_ping_count(count: u32) -> CliResult<()> {
    if count == 0 {
        return Err(CliError::NetworkError(
            "Ping count must be at least 1".to_string(),
        ));
    }

    const MAX_PINGS: u32 = 100;
    if count > MAX_PINGS {
        return Err(CliError::NetworkError(format!(
            "Ping count cannot exceed {}",
            MAX_PINGS
        )));
    }

    Ok(())
}

/// Validate IP address
pub fn validate_ip_address(ip: &str) -> CliResult<IpAddr> {
    IpAddr::from_str(ip).map_err(|_| {
        CliError::NetworkError(format!("Invalid IP address: '{}'", ip))
    })
}

/// Check if address is localhost
pub fn is_localhost(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Check if address is private
pub fn is_private_address(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_socket_address_valid() {
        let result = validate_socket_address("127.0.0.1:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_validate_socket_address_valid_hostname() {
        let result = validate_socket_address("localhost:9002");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_socket_address_invalid_port_zero() {
        let result = validate_socket_address("127.0.0.1:0");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_socket_address_empty() {
        let result = validate_socket_address("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_socket_address_invalid_format() {
        let result = validate_socket_address("127.0.0.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_socket_address_invalid_ip() {
        let result = validate_socket_address("999.999.999.999:8080");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ping_count_valid() {
        assert!(validate_ping_count(1).is_ok());
        assert!(validate_ping_count(10).is_ok());
        assert!(validate_ping_count(100).is_ok());
    }

    #[test]
    fn test_validate_ping_count_zero() {
        assert!(validate_ping_count(0).is_err());
    }

    #[test]
    fn test_validate_ping_count_too_high() {
        assert!(validate_ping_count(101).is_err());
    }

    #[test]
    fn test_validate_ip_address_valid_ipv4() {
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("127.0.0.1").is_ok());
    }

    #[test]
    fn test_validate_ip_address_valid_ipv6() {
        assert!(validate_ip_address("::1").is_ok());
    }

    #[test]
    fn test_validate_ip_address_invalid() {
        assert!(validate_ip_address("999.999.999.999").is_err());
        assert!(validate_ip_address("invalid").is_err());
    }

    #[test]
    fn test_is_localhost() {
        let localhost: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let remote: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        assert!(is_localhost(&localhost));
        assert!(!is_localhost(&remote));
    }

    #[test]
    fn test_is_private_address() {
        let private: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let public: SocketAddr = "8.8.8.8:8080".parse().unwrap();
        assert!(is_private_address(&private));
        assert!(!is_private_address(&public));
    }
}
