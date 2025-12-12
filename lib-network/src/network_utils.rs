//! Network utility functions for lib-network
//! 
//! Provides common network-related utilities used throughout the networking layer.

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};

/// Get the local IP address of this machine
/// 
/// Attempts to determine the local IP address by connecting to a well-known
/// external address (8.8.8.8). This reveals which interface would be used
/// for external communication.
/// 
/// # Returns
/// 
/// Returns `IpAddr` which can be either IPv4 or IPv6. Falls back to localhost
/// (127.0.0.1) if unable to determine the actual local IP.
/// 
/// # Examples
/// 
/// ```no_run
/// use lib_network::network_utils::get_local_ip;
/// 
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let ip = get_local_ip().await?;
///     println!("Local IP: {}", ip);
///     Ok(())
/// }
/// ```
pub async fn get_local_ip() -> Result<IpAddr> {
    // Try to connect to a remote address to determine our local IP
    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            if let Ok(_) = socket.connect("8.8.8.8:80").await {
                if let Ok(local_addr) = socket.local_addr() {
                    return Ok(local_addr.ip());
                }
            }
        },
        Err(_) => {}
    }
    
    // Fallback to localhost
    Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_local_ip() {
        let ip = get_local_ip().await.expect("Failed to get local IP");
        
        // Should be a valid IP address
        match ip {
            IpAddr::V4(v4) => {
                // Should not be unspecified (0.0.0.0)
                assert!(!v4.is_unspecified());
            },
            IpAddr::V6(v6) => {
                // Should not be unspecified (::)
                assert!(!v6.is_unspecified());
            }
        }
    }

    #[tokio::test]
    async fn test_get_local_ip_returns_valid_address() {
        let ip = get_local_ip().await.expect("Failed to get local IP");
        
        // At minimum should return localhost if no network available
        // In a real network, should return actual local IP
        match ip {
            IpAddr::V4(v4) => {
                assert!(v4.is_loopback() || v4.is_private() || !v4.is_unspecified());
            },
            IpAddr::V6(v6) => {
                assert!(v6.is_loopback() || !v6.is_unspecified());
            }
        }
    }
}
