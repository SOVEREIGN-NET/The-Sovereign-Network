use anyhow::{Result, Context};
use std::net::SocketAddr;
use std::str::FromStr;

/// Safe address parsing with proper error handling
pub fn parse_socket_addr(addr_str: &str) -> Result<SocketAddr> {
    SocketAddr::from_str(addr_str)
        .with_context(|| format!("Failed to parse socket address: {}", addr_str))
}

/// Safe address parsing with fallback
pub fn parse_socket_addr_or_default(addr_str: &str, default: SocketAddr) -> SocketAddr {
    parse_socket_addr(addr_str).unwrap_or(default)
}

/// Create a socket address from host and port with error handling
pub fn create_socket_addr(host: &str, port: u16) -> Result<SocketAddr> {
    let addr_str = format!("{}:{}", host, port);
    parse_socket_addr(&addr_str)
}

/// Parse a list of bootstrap peers from comma-separated string
pub fn parse_bootstrap_peers(peers_str: &str) -> Result<Vec<SocketAddr>> {
    if peers_str.trim().is_empty() {
        return Ok(vec![]);
    }
    
    peers_str
        .split(',')
        .map(|s| parse_socket_addr(s.trim()))
        .collect()
}

/// Safe conversion from usize to other numeric types
pub fn safe_usize_to_u64(value: usize) -> Result<u64> {
    value.try_into()
        .map_err(|_| anyhow::anyhow!("Value {} cannot be converted to u64", value))
}

/// Safe conversion with fallback
pub fn safe_usize_to_u64_or_default(value: usize, default: u64) -> u64 {
    safe_usize_to_u64(value).unwrap_or(default)
}

/// Get current timestamp safely
pub fn get_current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Get current timestamp in milliseconds safely  
pub fn get_current_timestamp_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_socket_addr() {
        assert!(parse_socket_addr("127.0.0.1:8080").is_ok());
        assert!(parse_socket_addr("invalid").is_err());
    }
    
    #[test]
    fn test_parse_bootstrap_peers() {
        let peers = parse_bootstrap_peers("127.0.0.1:8080,127.0.0.1:8081").unwrap();
        assert_eq!(peers.len(), 2);
        
        let empty_peers = parse_bootstrap_peers("").unwrap();
        assert!(empty_peers.is_empty());
    }
    
    #[test]
    fn test_timestamp_functions() {
        let ts1 = get_current_timestamp();
        let ts2 = get_current_timestamp_millis();
        
        assert!(ts1 > 0);
        assert!(ts2 > ts1); // milliseconds should be larger
    }
}
