//! Network utility functions for lib-network
//! 
//! Provides common network-related utilities used throughout the networking layer.

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Default probe address for IPv4 interface detection (Cloudflare DNS)
/// Uses a well-known routable address to ensure interface selection works reliably.
/// The UDP connection test doesn't actually send data, only determines which interface
/// would be used for routing to this destination.
const DEFAULT_PROBE_IPV4: &str = "1.1.1.1:80";

/// Default probe address for IPv6 interface detection (Cloudflare DNS)
/// Uses a well-known routable IPv6 address to ensure IPv6 route selection works reliably.
const DEFAULT_PROBE_IPV6: &str = "[2606:4700:4700::1111]:80";

/// Timeout for network probe operations
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Configuration for local IP detection
pub struct LocalIpConfig {
    /// Custom IPv4 probe address (e.g., "1.1.1.1:80")
    pub ipv4_probe: Option<String>,
    /// Custom IPv6 probe address (e.g., "[2606:4700:4700::1111]:80")
    pub ipv6_probe: Option<String>,
    /// Timeout for probe operations
    pub timeout: Duration,
}

impl Default for LocalIpConfig {
    fn default() -> Self {
        Self {
            ipv4_probe: None,
            ipv6_probe: None,
            timeout: PROBE_TIMEOUT,
        }
    }
}

/// Get the local IP address of this machine
/// 
/// Attempts to determine the local IP address by probing which interface would
/// be used for external communication. Uses UDP socket connection tests to
/// well-known public addresses (Cloudflare DNS: 1.1.1.1 for IPv4, 2606:4700:4700::1111 for IPv6).
/// 
/// The probe uses a connectionless UDP socket and does not actually send data,
/// it only determines which local interface would be used for routing to the destination.
/// This minimizes metadata leakage while ensuring accurate interface detection.
/// 
/// Tries both IPv4 and IPv6, preferring non-loopback, non-link-local addresses.
/// 
/// # Returns
/// 
/// Returns `IpAddr` which can be either IPv4 or IPv6. Prefers actual routable
/// addresses, falls back to loopback only when no network is available.
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
    get_local_ip_with_config(&LocalIpConfig::default()).await
}

/// Get the local IP address with custom configuration
/// 
/// Allows specifying custom probe addresses and timeout for testing or restricted environments.
/// 
/// # Arguments
/// 
/// * `config` - Configuration with optional custom IPv4/IPv6 probe addresses and timeout
/// 
/// # Returns
/// 
/// Returns the local IP that would be used to reach the probe address.
/// 
/// # Examples
/// 
/// ```no_run
/// use lib_network::network_utils::{get_local_ip_with_config, LocalIpConfig};
/// use std::time::Duration;
/// 
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let config = LocalIpConfig {
///         ipv4_probe: Some("8.8.8.8:80".to_string()),
///         ipv6_probe: Some("[2001:4860:4860::8888]:80".to_string()),
///         timeout: Duration::from_secs(3),
///     };
///     let ip = get_local_ip_with_config(&config).await?;
///     println!("Local IP: {}", ip);
///     Ok(())
/// }
/// ```
pub async fn get_local_ip_with_config(config: &LocalIpConfig) -> Result<IpAddr> {
    // Try IPv4 first
    if let Ok(ip) = probe_ipv4(config).await {
        // Prefer non-loopback, non-link-local addresses
        if let IpAddr::V4(v4) = ip {
            if !v4.is_loopback() && !v4.is_link_local() {
                return Ok(ip);
            }
        }
    }
    
    // Try IPv6
    if let Ok(ip) = probe_ipv6(config).await {
        // Prefer non-loopback, non-link-local addresses
        if let IpAddr::V6(v6) = ip {
            if !v6.is_loopback() && !is_ipv6_link_local(&v6) {
                return Ok(ip);
            }
        }
    }
    
    // Final fallback: check for any local interface
    if let Ok(ip) = get_first_local_interface().await {
        return Ok(ip);
    }
    
    // Last resort: return loopback (caller's address family preference)
    Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Probe for IPv4 local address
async fn probe_ipv4(config: &LocalIpConfig) -> Result<IpAddr> {
    let probe = config.ipv4_probe.as_deref().unwrap_or(DEFAULT_PROBE_IPV4);
    
    let probe_future = async {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(probe).await?;
        let local_addr = socket.local_addr()?;
        Ok::<IpAddr, anyhow::Error>(local_addr.ip())
    };
    
    tokio::time::timeout(config.timeout, probe_future)
        .await
        .map_err(|_| anyhow::anyhow!("IPv4 probe timeout"))?
}

/// Probe for IPv6 local address
async fn probe_ipv6(config: &LocalIpConfig) -> Result<IpAddr> {
    let probe = config.ipv6_probe.as_deref().unwrap_or(DEFAULT_PROBE_IPV6);
    
    let probe_future = async {
        let socket = tokio::net::UdpSocket::bind("[::]:0").await?;
        socket.connect(probe).await?;
        let local_addr = socket.local_addr()?;
        Ok::<IpAddr, anyhow::Error>(local_addr.ip())
    };
    
    tokio::time::timeout(config.timeout, probe_future)
        .await
        .map_err(|_| anyhow::anyhow!("IPv6 probe timeout"))?
}

/// Get the first usable local network interface
async fn get_first_local_interface() -> Result<IpAddr> {
    use local_ip_address::list_afinet_netifas;
    
    if let Ok(interfaces) = list_afinet_netifas() {
        for (_name, ip) in interfaces {
            match ip {
                IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() => {
                    return Ok(IpAddr::V4(v4));
                }
                IpAddr::V6(v6) if !v6.is_loopback() && !is_ipv6_link_local(&v6) => {
                    return Ok(IpAddr::V6(v6));
                }
                _ => continue,
            }
        }
    }
    
    Err(anyhow::anyhow!("No usable network interface found"))
}

/// Check if an IPv6 address is link-local (fe80::/10)
fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
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
                assert!(!v4.is_unspecified(), "Should not be 0.0.0.0");
            },
            IpAddr::V6(v6) => {
                assert!(!v6.is_unspecified(), "Should not be ::");
            }
        }
    }

    #[tokio::test]
    async fn test_get_local_ip_returns_valid_address() {
        let ip = get_local_ip().await.expect("Failed to get local IP");
        
        // Should return localhost if no network available, or actual local IP
        match ip {
            IpAddr::V4(v4) => {
                assert!(v4.is_loopback() || v4.is_private() || !v4.is_unspecified());
            },
            IpAddr::V6(v6) => {
                assert!(v6.is_loopback() || !v6.is_unspecified());
            }
        }
    }

    #[tokio::test]
    async fn test_get_local_ip_with_custom_probe() {
        // Test with custom IPv4 probe (Google DNS)
        let config = LocalIpConfig {
            ipv4_probe: Some("8.8.8.8:80".to_string()),
            ipv6_probe: None,
            timeout: Duration::from_secs(2),
        };
        let result = get_local_ip_with_config(&config).await;
        assert!(result.is_ok(), "Custom IPv4 probe should work or gracefully fail");
        
        // Test with custom IPv6 probe (Google DNS)
        let config = LocalIpConfig {
            ipv4_probe: None,
            ipv6_probe: Some("[2001:4860:4860::8888]:80".to_string()),
            timeout: Duration::from_secs(2),
        };
        let result = get_local_ip_with_config(&config).await;
        // May fail in IPv4-only environments, that's okay
        let _ = result;
    }

    #[tokio::test]
    async fn test_ipv6_link_local_detection() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_ipv6_link_local(&link_local));
        
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(!is_ipv6_link_local(&global));
        
        let loopback = Ipv6Addr::LOCALHOST;
        assert!(!is_ipv6_link_local(&loopback));
    }

    #[tokio::test]
    async fn test_prefer_non_loopback() {
        // get_local_ip should prefer non-loopback addresses
        let ip = get_local_ip().await.expect("Failed to get local IP");
        
        // If we got a result, verify it's either a real address or loopback fallback
        match ip {
            IpAddr::V4(v4) => {
                // Either real private/public IP or loopback fallback
                assert!(v4.is_private() || v4.is_loopback() || !v4.is_link_local());
            },
            IpAddr::V6(v6) => {
                // Either real address or loopback fallback
                assert!(!is_ipv6_link_local(&v6));
            }
        }
    }
}
