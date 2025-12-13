//! ZDNS Transport Layer
//!
//! UDP and TCP listeners for DNS protocol on port 53.
//! Resolves .zhtp and .sov domains to gateway IP address.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use anyhow::Result;

use super::resolver::ZdnsResolver;
use super::packet::{DnsPacket, MAX_UDP_SIZE};

/// Default DNS port
pub const DNS_PORT: u16 = 53;

/// ZDNS Server configuration
#[derive(Debug, Clone)]
pub struct ZdnsServerConfig {
    /// Port to listen on (default: 53)
    pub port: u16,
    /// Gateway IP address to return for resolved domains
    pub gateway_ip: Ipv4Addr,
    /// Default TTL for DNS responses (seconds)
    pub default_ttl: u32,
    /// Enable TCP support (in addition to UDP)
    pub enable_tcp: bool,
    /// Bind address (default: 0.0.0.0)
    pub bind_addr: IpAddr,
}

impl Default for ZdnsServerConfig {
    fn default() -> Self {
        Self {
            port: DNS_PORT,
            gateway_ip: Ipv4Addr::new(127, 0, 0, 1),
            default_ttl: 3600,
            enable_tcp: true,
            bind_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

impl ZdnsServerConfig {
    /// Create config for local development
    pub fn localhost() -> Self {
        Self {
            port: 5353, // Non-privileged port for testing
            gateway_ip: Ipv4Addr::new(127, 0, 0, 1),
            default_ttl: 60,
            enable_tcp: true,
            bind_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        }
    }

    /// Create config for production with specified gateway IP
    pub fn production(gateway_ip: Ipv4Addr) -> Self {
        Self {
            port: DNS_PORT,
            gateway_ip,
            default_ttl: 3600,
            enable_tcp: true,
            bind_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

/// ZDNS DNS Server
///
/// Listens on port 53 (or configured port) and resolves .zhtp/.sov domains
/// to the gateway IP address for browser-based access.
pub struct ZdnsTransportServer {
    /// Domain resolver with caching
    resolver: Arc<ZdnsResolver>,
    /// Server configuration
    config: ZdnsServerConfig,
    /// Running state
    is_running: Arc<RwLock<bool>>,
    /// Statistics
    stats: Arc<RwLock<TransportStats>>,
}

/// Transport statistics
#[derive(Debug, Default, Clone)]
pub struct TransportStats {
    /// Total UDP queries received
    pub udp_queries: u64,
    /// Total TCP queries received
    pub tcp_queries: u64,
    /// Successful resolutions
    pub resolved: u64,
    /// NXDOMAIN responses
    pub nxdomain: u64,
    /// Errors
    pub errors: u64,
    /// Non-.zhtp/.sov queries (ignored)
    pub ignored: u64,
}

impl ZdnsTransportServer {
    /// Create a new ZDNS transport server
    pub fn new(resolver: Arc<ZdnsResolver>, config: ZdnsServerConfig) -> Self {
        info!(
            port = config.port,
            gateway_ip = %config.gateway_ip,
            tcp_enabled = config.enable_tcp,
            "ZDNS transport server created"
        );

        Self {
            resolver,
            config,
            is_running: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
        }
    }

    /// Start the DNS server
    pub async fn start(&self) -> Result<()> {
        let bind_addr = SocketAddr::new(self.config.bind_addr, self.config.port);

        info!("Starting ZDNS transport server on {}", bind_addr);

        // Start UDP listener
        let udp_socket = UdpSocket::bind(bind_addr).await?;
        info!("UDP listener bound to {}", bind_addr);

        // Clone for UDP task
        let resolver = Arc::clone(&self.resolver);
        let config = self.config.clone();
        let stats = Arc::clone(&self.stats);
        let is_running = Arc::clone(&self.is_running);

        *self.is_running.write().await = true;

        // Spawn UDP handler
        let udp_handle = tokio::spawn(async move {
            Self::handle_udp(udp_socket, resolver, config, stats, is_running).await;
        });

        // Start TCP listener if enabled
        if self.config.enable_tcp {
            let tcp_listener = TcpListener::bind(bind_addr).await?;
            info!("TCP listener bound to {}", bind_addr);

            let resolver = Arc::clone(&self.resolver);
            let config = self.config.clone();
            let stats = Arc::clone(&self.stats);
            let is_running = Arc::clone(&self.is_running);

            tokio::spawn(async move {
                Self::handle_tcp(tcp_listener, resolver, config, stats, is_running).await;
            });
        }

        // Wait for UDP handler (main loop)
        let _ = udp_handle.await;

        Ok(())
    }

    /// Stop the DNS server
    pub async fn stop(&self) {
        info!("Stopping ZDNS transport server");
        *self.is_running.write().await = false;
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> TransportStats {
        self.stats.read().await.clone()
    }

    /// Handle UDP queries
    async fn handle_udp(
        socket: UdpSocket,
        resolver: Arc<ZdnsResolver>,
        config: ZdnsServerConfig,
        stats: Arc<RwLock<TransportStats>>,
        is_running: Arc<RwLock<bool>>,
    ) {
        let socket = Arc::new(socket);
        let mut buf = [0u8; MAX_UDP_SIZE];

        loop {
            if !*is_running.read().await {
                break;
            }

            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    stats.write().await.udp_queries += 1;

                    let data = buf[..len].to_vec();
                    let resolver = Arc::clone(&resolver);
                    let config = config.clone();
                    let stats = Arc::clone(&stats);
                    let socket_clone = Arc::clone(&socket);

                    // Process and respond in spawned task
                    tokio::spawn(async move {
                        if let Some(response) = Self::process_query(&data, &resolver, &config, &stats).await {
                            let response_bytes = response.serialize();
                            if let Err(e) = socket_clone.send_to(&response_bytes, src).await {
                                warn!("Failed to send UDP response to {}: {}", src, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    if *is_running.read().await {
                        error!("UDP recv error: {}", e);
                        stats.write().await.errors += 1;
                    }
                }
            }
        }
    }

    /// Handle TCP connections
    async fn handle_tcp(
        listener: TcpListener,
        resolver: Arc<ZdnsResolver>,
        config: ZdnsServerConfig,
        stats: Arc<RwLock<TransportStats>>,
        is_running: Arc<RwLock<bool>>,
    ) {
        loop {
            if !*is_running.read().await {
                break;
            }

            match listener.accept().await {
                Ok((stream, src)) => {
                    debug!("TCP connection from {}", src);
                    stats.write().await.tcp_queries += 1;

                    let resolver = Arc::clone(&resolver);
                    let config = config.clone();
                    let stats = Arc::clone(&stats);

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_tcp_connection(stream, &resolver, &config, &stats).await {
                            debug!("TCP connection error from {}: {}", src, e);
                        }
                    });
                }
                Err(e) => {
                    if *is_running.read().await {
                        error!("TCP accept error: {}", e);
                        stats.write().await.errors += 1;
                    }
                }
            }
        }
    }

    /// Handle a single TCP connection
    async fn handle_tcp_connection(
        mut stream: TcpStream,
        resolver: &ZdnsResolver,
        config: &ZdnsServerConfig,
        stats: &Arc<RwLock<TransportStats>>,
    ) -> Result<()> {
        // TCP DNS uses 2-byte length prefix
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;

        if len > 65535 {
            return Err(anyhow::anyhow!("DNS message too large: {}", len));
        }

        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;

        if let Some(response) = Self::process_query(&data, resolver, config, stats).await {
            let response_bytes = response.serialize();
            let len_bytes = (response_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len_bytes).await?;
            stream.write_all(&response_bytes).await?;
        }

        Ok(())
    }

    /// Process a DNS query and return response
    async fn process_query(
        data: &[u8],
        resolver: &ZdnsResolver,
        config: &ZdnsServerConfig,
        stats: &Arc<RwLock<TransportStats>>,
    ) -> Option<DnsPacket> {
        // Parse query
        let query = match DnsPacket::parse(data) {
            Ok(q) => q,
            Err(e) => {
                debug!("Failed to parse DNS query: {}", e);
                stats.write().await.errors += 1;
                return None;
            }
        };

        // Only handle queries (not responses)
        if query.is_response {
            return None;
        }

        // Get query name
        let domain = match query.query_name() {
            Some(d) => d,
            None => {
                stats.write().await.errors += 1;
                return Some(DnsPacket::servfail(&query));
            }
        };

        debug!(domain = %domain, "Processing DNS query");

        // Only handle .zhtp and .sov domains
        if !domain.ends_with(".zhtp") && !domain.ends_with(".sov") {
            debug!(domain = %domain, "Ignoring non-sovereign domain");
            stats.write().await.ignored += 1;
            return None; // Let other DNS servers handle it
        }

        // Only handle A record queries
        if !query.is_a_query() {
            debug!(domain = %domain, "Non-A query, returning NXDOMAIN");
            stats.write().await.nxdomain += 1;
            return Some(DnsPacket::nxdomain(&query));
        }

        // Resolve domain using ZDNS resolver (with caching)
        match resolver.resolve_web4(domain).await {
            Ok(_record) => {
                // Domain exists - return gateway IP
                debug!(
                    domain = %domain,
                    gateway_ip = %config.gateway_ip,
                    "Domain resolved, returning gateway IP"
                );
                stats.write().await.resolved += 1;
                Some(DnsPacket::a_record(&query, config.gateway_ip, config.default_ttl))
            }
            Err(e) => {
                // Domain not found or error
                debug!(domain = %domain, error = %e, "Domain not found");
                stats.write().await.nxdomain += 1;
                Some(DnsPacket::nxdomain(&query))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ZdnsServerConfig::default();
        assert_eq!(config.port, 53);
        assert_eq!(config.gateway_ip, Ipv4Addr::new(127, 0, 0, 1));
        assert!(config.enable_tcp);
    }

    #[test]
    fn test_config_localhost() {
        let config = ZdnsServerConfig::localhost();
        assert_eq!(config.port, 5353);
        assert_eq!(config.default_ttl, 60);
    }

    #[test]
    fn test_config_production() {
        let config = ZdnsServerConfig::production(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(config.port, 53);
        assert_eq!(config.gateway_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(config.default_ttl, 3600);
    }

    #[test]
    fn test_stats_default() {
        let stats = TransportStats::default();
        assert_eq!(stats.udp_queries, 0);
        assert_eq!(stats.tcp_queries, 0);
        assert_eq!(stats.resolved, 0);
    }
}
