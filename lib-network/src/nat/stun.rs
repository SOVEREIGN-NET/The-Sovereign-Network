//! Simple STUN client for public endpoint discovery (#2200)
//!
//! Uses the `stun` crate to send binding requests and parse XOR-MAPPED-ADDRESS
//! responses. This is a minimal implementation sufficient for NAT type detection
//! and public endpoint discovery.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// Default STUN server list (public, well-maintained servers).
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

/// STUN client for discovering public endpoints.
pub struct StunClient {
    servers: Vec<String>,
    timeout: Duration,
}

impl Default for StunClient {
    fn default() -> Self {
        Self {
            servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            timeout: Duration::from_secs(5),
        }
    }
}

impl StunClient {
    /// Create a new STUN client with default public servers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a STUN client with custom servers.
    pub fn with_servers(servers: Vec<String>) -> Self {
        Self {
            servers,
            timeout: Duration::from_secs(5),
        }
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Discover the public endpoint by sending STUN binding requests.
    ///
    /// Returns the first successful XOR-MAPPED-ADDRESS from any server,
    /// or an error if all servers fail.
    pub async fn discover_public_endpoint(&self, local_bind: SocketAddr) -> Result<SocketAddr> {
        for server in &self.servers {
            match self.query_server(server, local_bind).await {
                Ok(endpoint) => {
                    debug!(server = %server, endpoint = %endpoint, "STUN discovery succeeded");
                    return Ok(endpoint);
                }
                Err(e) => {
                    warn!(server = %server, error = %e, "STUN server failed");
                }
            }
        }
        Err(anyhow!("All STUN servers failed"))
    }

    /// Query a single STUN server for the public endpoint.
    async fn query_server(&self, server: &str, local_bind: SocketAddr) -> Result<SocketAddr> {
        let server_addr: SocketAddr = server.parse()?;

        let socket = UdpSocket::bind(local_bind).await?;
        socket.connect(server_addr).await?;

        // Build STUN binding request
        let mut msg = stun::message::Message::new();
        msg.typ = stun::message::MessageType {
            method: stun::message::METHOD_BINDING,
            class: stun::message::CLASS_REQUEST,
        };
        msg.transaction_id = stun::agent::TransactionId::new();
        msg.write_header();

        let req_bytes = msg.raw;

        // Send request with timeout
        let send_fut = socket.send(&req_bytes);
        let _ = tokio::time::timeout(self.timeout, send_fut).await??;

        let mut buf = vec![0u8; 1500];
        let recv_fut = socket.recv_from(&mut buf);
        let (len, from) = tokio::time::timeout(self.timeout, recv_fut).await??;
        buf.truncate(len);

        debug!(bytes = len, from = %from, "STUN response received");

        // Parse response
        let mut resp = stun::message::Message::new();
        resp.raw = buf;
        if let Err(e) = resp.decode() {
            return Err(anyhow!("STUN decode error: {}", e));
        }

        // Extract XOR-MAPPED-ADDRESS
        let mut xor_addr = stun::xoraddr::XorMappedAddress::default();
        if let Err(e) = stun::message::Getter::get_from(&mut xor_addr, &resp) {
            return Err(anyhow!("No XOR-MAPPED-ADDRESS in STUN response: {}", e));
        }

        Ok(SocketAddr::new(xor_addr.ip, xor_addr.port))
    }

    /// Perform a basic NAT type detection by comparing endpoints from two STUN servers.
    ///
    /// This is a simplified algorithm:
    /// - If both servers return the same mapped address -> FullCone or Public
    /// - If different mapped addresses -> Symmetric NAT
    /// - If no response from second server -> Restricted or PortRestricted
    ///
    /// A full implementation would require hairpinning tests and behavior analysis.
    pub async fn detect_nat_type(
        &self,
        local_bind: SocketAddr,
    ) -> Result<(super::NatType, SocketAddr)> {
        if self.servers.len() < 2 {
            return Err(anyhow!("NAT type detection requires at least 2 STUN servers"));
        }

        let primary = self.query_server(&self.servers[0], local_bind).await?;
        debug!(primary = %primary, "Primary STUN endpoint");

        let secondary = match self.query_server(&self.servers[1], local_bind).await {
            Ok(addr) => addr,
            Err(_) => {
                // Second server unreachable — likely restricted NAT
                return Ok((super::NatType::RestrictedCone, primary));
            }
        };
        debug!(secondary = %secondary, "Secondary STUN endpoint");

        if primary == secondary {
            // Same mapped address from different servers — likely full cone or public
            // We can't distinguish public vs full-cone without local IP comparison here
            Ok((super::NatType::FullCone, primary))
        } else {
            // Different mapped addresses — symmetric NAT
            Ok((super::NatType::Symmetric, primary))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_client_default_servers() {
        let client = StunClient::new();
        assert!(!client.servers.is_empty());
        assert_eq!(client.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_stun_client_custom_servers() {
        let client = StunClient::with_servers(vec!["stun.example.com:3478".to_string()]);
        assert_eq!(client.servers.len(), 1);
    }
}
