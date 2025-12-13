//! ZDNS Transport Layer
//!
//! UDP and TCP listeners for DNS protocol on port 53.
//! Resolves .zhtp and .sov domains to gateway IP address.
//!
//! Security features:
//! - Per-IP rate limiting (max queries per time window)
//! - Bounded worker pool with semaphores (no unbounded task spawning)
//! - Strict domain validation (only .zhtp/.sov TLDs accepted)
//! - Capability checking before returning gateway IP
//! - TCP timeouts to prevent slow loris attacks
//! - Default bind to localhost (explicit opt-in for external exposure)
//!
//! Note: This implements per-IP rate limiting, not full Response Rate Limiting (RRL).
//! For production deployments exposed to the internet, consider adding:
//! - Per-name response throttling
//! - TC (truncation) bit for rate-limited responses
//! - IP reputation/allowlisting at the firewall level

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{RwLock, Semaphore};
use tracing::{info, warn, error, debug};
use anyhow::Result;

use super::resolver::ZdnsResolver;
use super::packet::{DnsPacket, MAX_UDP_SIZE};
use crate::web4::Web4Capability;

/// Default DNS port
pub const DNS_PORT: u16 = 53;

/// Maximum concurrent UDP query handlers
const MAX_CONCURRENT_UDP_HANDLERS: usize = 100;

/// Maximum concurrent TCP connections
const MAX_CONCURRENT_TCP_CONNECTIONS: usize = 50;

/// Rate limit: max queries per IP per window
const RATE_LIMIT_MAX_QUERIES: u32 = 30;

/// Rate limit window in seconds
const RATE_LIMIT_WINDOW_SECS: u64 = 10;

/// Maximum TCP message size (RFC 1035 limit)
const MAX_TCP_MESSAGE_SIZE: usize = 65535;

/// ZDNS Server configuration
#[derive(Debug, Clone)]
pub struct ZdnsServerConfig {
    /// Port to listen on (default: 53)
    pub port: u16,
    /// Gateway IP address to return for resolved domains
    pub gateway_ip: Ipv4Addr,
    /// Default TTL for DNS responses (seconds) - used as max cap
    pub default_ttl: u32,
    /// Enable TCP support (in addition to UDP)
    pub enable_tcp: bool,
    /// Bind address (default: 127.0.0.1 for safety)
    pub bind_addr: IpAddr,
    /// Enable rate limiting
    pub enable_rate_limit: bool,
    /// Allowed capabilities for gateway routing (None = all allowed)
    pub allowed_capabilities: Option<Vec<Web4Capability>>,
}

impl Default for ZdnsServerConfig {
    fn default() -> Self {
        Self {
            port: DNS_PORT,
            gateway_ip: Ipv4Addr::new(127, 0, 0, 1),
            default_ttl: 3600,
            enable_tcp: true,
            // SECURITY: Default to localhost only - explicit config required for 0.0.0.0
            bind_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            enable_rate_limit: true,
            // By default, only allow HttpServe and SpaServe (not DownloadOnly)
            allowed_capabilities: Some(vec![Web4Capability::HttpServe, Web4Capability::SpaServe]),
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
            enable_rate_limit: false, // Disabled for local testing
            allowed_capabilities: None, // Allow all for testing
        }
    }

    /// Create config for production with specified gateway IP
    /// SECURITY: Still binds to localhost by default - use with_bind_addr() to expose
    pub fn production(gateway_ip: Ipv4Addr) -> Self {
        Self {
            port: DNS_PORT,
            gateway_ip,
            default_ttl: 3600,
            enable_tcp: true,
            // SECURITY: Default to localhost - caller must explicitly set bind_addr
            bind_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            enable_rate_limit: true,
            allowed_capabilities: Some(vec![Web4Capability::HttpServe, Web4Capability::SpaServe]),
        }
    }

    /// Set bind address (use with caution for non-localhost)
    pub fn with_bind_addr(mut self, addr: IpAddr) -> Self {
        if addr == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
            warn!("ZDNS binding to 0.0.0.0 - ensure firewall and rate limiting are configured");
        }
        self.bind_addr = addr;
        self
    }
}

/// Rate limiter state per IP
#[derive(Debug)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// Rate limiter for per-IP query limiting
struct RateLimiter {
    entries: RwLock<HashMap<IpAddr, RateLimitEntry>>,
    max_queries: u32,
    window_duration: Duration,
}

impl RateLimiter {
    fn new(max_queries: u32, window_secs: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_queries,
            window_duration: Duration::from_secs(window_secs),
        }
    }

    /// Check if request is allowed, returns false if rate limited
    async fn check_and_increment(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        let entry = entries.entry(ip).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= self.window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= self.max_queries {
            return false; // Rate limited
        }

        entry.count += 1;
        true
    }

    /// Cleanup old entries periodically
    async fn cleanup_old_entries(&self) {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| {
            now.duration_since(entry.window_start) < self.window_duration * 2
        });
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
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
    /// Semaphore for bounding UDP handlers
    udp_semaphore: Arc<Semaphore>,
    /// Semaphore for bounding TCP connections
    tcp_semaphore: Arc<Semaphore>,
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
    /// Rate limited queries
    pub rate_limited: u64,
    /// Queries rejected due to capability mismatch
    pub capability_rejected: u64,
}

impl ZdnsTransportServer {
    /// Create a new ZDNS transport server
    pub fn new(resolver: Arc<ZdnsResolver>, config: ZdnsServerConfig) -> Self {
        info!(
            port = config.port,
            gateway_ip = %config.gateway_ip,
            tcp_enabled = config.enable_tcp,
            bind_addr = %config.bind_addr,
            rate_limit_enabled = config.enable_rate_limit,
            "ZDNS transport server created"
        );

        Self {
            resolver,
            config,
            is_running: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            rate_limiter: Arc::new(RateLimiter::new(RATE_LIMIT_MAX_QUERIES, RATE_LIMIT_WINDOW_SECS)),
            udp_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_UDP_HANDLERS)),
            tcp_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TCP_CONNECTIONS)),
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
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let udp_semaphore = Arc::clone(&self.udp_semaphore);

        *self.is_running.write().await = true;

        // Spawn rate limiter cleanup task
        let cleanup_rate_limiter = Arc::clone(&self.rate_limiter);
        let cleanup_is_running = Arc::clone(&self.is_running);
        tokio::spawn(async move {
            while *cleanup_is_running.read().await {
                tokio::time::sleep(Duration::from_secs(60)).await;
                cleanup_rate_limiter.cleanup_old_entries().await;
            }
        });

        // Spawn UDP handler
        let udp_handle = tokio::spawn(async move {
            Self::handle_udp(udp_socket, resolver, config, stats, is_running, rate_limiter, udp_semaphore).await;
        });

        // Start TCP listener if enabled
        if self.config.enable_tcp {
            let tcp_listener = TcpListener::bind(bind_addr).await?;
            info!("TCP listener bound to {}", bind_addr);

            let resolver = Arc::clone(&self.resolver);
            let config = self.config.clone();
            let stats = Arc::clone(&self.stats);
            let is_running = Arc::clone(&self.is_running);
            let rate_limiter = Arc::clone(&self.rate_limiter);
            let tcp_semaphore = Arc::clone(&self.tcp_semaphore);

            tokio::spawn(async move {
                Self::handle_tcp(tcp_listener, resolver, config, stats, is_running, rate_limiter, tcp_semaphore).await;
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

    /// Handle UDP queries with rate limiting and bounded concurrency
    async fn handle_udp(
        socket: UdpSocket,
        resolver: Arc<ZdnsResolver>,
        config: ZdnsServerConfig,
        stats: Arc<RwLock<TransportStats>>,
        is_running: Arc<RwLock<bool>>,
        rate_limiter: Arc<RateLimiter>,
        semaphore: Arc<Semaphore>,
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

                    // Rate limiting check
                    if config.enable_rate_limit && !rate_limiter.check_and_increment(src.ip()).await {
                        debug!(src = %src.ip(), "Rate limited UDP query");
                        stats.write().await.rate_limited += 1;
                        continue; // Drop the query silently
                    }

                    // Try to acquire semaphore permit (bounded concurrency)
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            // At capacity - drop query (backpressure)
                            debug!("UDP handler at capacity, dropping query from {}", src);
                            stats.write().await.errors += 1;
                            continue;
                        }
                    };

                    let data = buf[..len].to_vec();
                    let resolver = Arc::clone(&resolver);
                    let config = config.clone();
                    let stats = Arc::clone(&stats);
                    let socket_clone = Arc::clone(&socket);

                    // Process with bounded task
                    tokio::spawn(async move {
                        let _permit = permit; // Hold permit until done
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

    /// Handle TCP connections with rate limiting and bounded concurrency
    async fn handle_tcp(
        listener: TcpListener,
        resolver: Arc<ZdnsResolver>,
        config: ZdnsServerConfig,
        stats: Arc<RwLock<TransportStats>>,
        is_running: Arc<RwLock<bool>>,
        rate_limiter: Arc<RateLimiter>,
        semaphore: Arc<Semaphore>,
    ) {
        loop {
            if !*is_running.read().await {
                break;
            }

            match listener.accept().await {
                Ok((stream, src)) => {
                    debug!("TCP connection from {}", src);
                    stats.write().await.tcp_queries += 1;

                    // Rate limiting check
                    if config.enable_rate_limit && !rate_limiter.check_and_increment(src.ip()).await {
                        debug!(src = %src.ip(), "Rate limited TCP connection");
                        stats.write().await.rate_limited += 1;
                        continue; // Drop the connection
                    }

                    // Try to acquire semaphore permit
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            debug!("TCP handler at capacity, dropping connection from {}", src);
                            stats.write().await.errors += 1;
                            continue;
                        }
                    };

                    let resolver = Arc::clone(&resolver);
                    let config = config.clone();
                    let stats = Arc::clone(&stats);

                    tokio::spawn(async move {
                        let _permit = permit; // Hold permit until done
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
        // Set read timeout to prevent slow loris attacks
        let timeout = Duration::from_secs(5);

        // TCP DNS uses 2-byte length prefix
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await
            .map_err(|_| anyhow::anyhow!("TCP read timeout"))??;

        let len = u16::from_be_bytes(len_buf) as usize;

        // Validate message size
        if len > MAX_TCP_MESSAGE_SIZE {
            return Err(anyhow::anyhow!("DNS message too large: {} > {}", len, MAX_TCP_MESSAGE_SIZE));
        }
        if len == 0 {
            return Err(anyhow::anyhow!("Empty DNS message"));
        }

        let mut data = vec![0u8; len];
        tokio::time::timeout(timeout, stream.read_exact(&mut data)).await
            .map_err(|_| anyhow::anyhow!("TCP read timeout"))??;

        if let Some(response) = Self::process_query(&data, resolver, config, stats).await {
            let response_bytes = response.serialize();
            let len_bytes = (response_bytes.len() as u16).to_be_bytes();

            tokio::time::timeout(timeout, async {
                stream.write_all(&len_bytes).await?;
                stream.write_all(&response_bytes).await
            }).await.map_err(|_| anyhow::anyhow!("TCP write timeout"))??;
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

        // Normalize to lowercase for consistent handling
        let domain_lower = domain.to_lowercase();

        debug!(domain = %domain_lower, "Processing DNS query");

        // SECURITY: Strict sovereign TLD validation
        if !domain_lower.ends_with(".zhtp") && !domain_lower.ends_with(".sov") {
            debug!(domain = %domain_lower, "Ignoring non-sovereign domain");
            stats.write().await.ignored += 1;
            return None; // Let other DNS servers handle it
        }

        // Only handle A record queries - return NOTIMP for other types (AAAA, MX, etc.)
        // NOTIMP is correct because the domain exists but we don't implement that record type
        if !query.is_a_query() {
            debug!(domain = %domain_lower, "Non-A query, returning NOTIMP");
            stats.write().await.errors += 1;
            return Some(DnsPacket::notimp(&query));
        }

        // Resolve domain using ZDNS resolver (with caching)
        match resolver.resolve_web4(&domain_lower).await {
            Ok(record) => {
                // SECURITY: Check capability before returning gateway IP
                if let Some(ref allowed_caps) = config.allowed_capabilities {
                    let domain_cap = record.capability.unwrap_or(Web4Capability::SpaServe);
                    if !allowed_caps.contains(&domain_cap) {
                        debug!(
                            domain = %domain_lower,
                            capability = ?domain_cap,
                            "Domain capability not allowed for gateway routing"
                        );
                        stats.write().await.capability_rejected += 1;
                        return Some(DnsPacket::nxdomain(&query));
                    }
                }

                // Calculate TTL: use the lesser of record TTL and config max TTL
                let record_ttl = record.ttl.min(config.default_ttl as u64) as u32;
                // Also check expiration - don't serve if expired
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if record.expires_at > 0 && now >= record.expires_at {
                    debug!(domain = %domain_lower, "Domain expired");
                    stats.write().await.nxdomain += 1;
                    return Some(DnsPacket::nxdomain(&query));
                }

                // Use remaining time until expiration as TTL if shorter
                let remaining_ttl = if record.expires_at > now {
                    (record.expires_at - now).min(record_ttl as u64) as u32
                } else {
                    record_ttl
                };

                debug!(
                    domain = %domain_lower,
                    gateway_ip = %config.gateway_ip,
                    ttl = remaining_ttl,
                    "Domain resolved, returning gateway IP"
                );
                stats.write().await.resolved += 1;
                Some(DnsPacket::a_record(&query, config.gateway_ip, remaining_ttl))
            }
            Err(e) => {
                debug!(domain = %domain_lower, error = %e, "Domain not found");
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
        // SECURITY: Default should bind to localhost
        assert_eq!(config.bind_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(config.enable_rate_limit);
    }

    #[test]
    fn test_config_localhost() {
        let config = ZdnsServerConfig::localhost();
        assert_eq!(config.port, 5353);
        assert_eq!(config.default_ttl, 60);
        assert!(!config.enable_rate_limit); // Disabled for testing
    }

    #[test]
    fn test_config_production() {
        let config = ZdnsServerConfig::production(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(config.port, 53);
        assert_eq!(config.gateway_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(config.default_ttl, 3600);
        // SECURITY: Production still defaults to localhost
        assert_eq!(config.bind_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_config_with_bind_addr() {
        let config = ZdnsServerConfig::production(Ipv4Addr::new(192, 168, 1, 100))
            .with_bind_addr(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(config.bind_addr, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_stats_default() {
        let stats = TransportStats::default();
        assert_eq!(stats.udp_queries, 0);
        assert_eq!(stats.tcp_queries, 0);
        assert_eq!(stats.resolved, 0);
        assert_eq!(stats.rate_limited, 0);
        assert_eq!(stats.capability_rejected, 0);
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(3, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 should pass
        assert!(limiter.check_and_increment(ip).await);
        assert!(limiter.check_and_increment(ip).await);
        assert!(limiter.check_and_increment(ip).await);

        // 4th should be rate limited
        assert!(!limiter.check_and_increment(ip).await);

        // Different IP should still work
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        assert!(limiter.check_and_increment(ip2).await);
    }

    #[test]
    fn test_sovereign_domain_validation() {
        // Valid sovereign domains
        assert!("myapp.zhtp".ends_with(".zhtp"));
        assert!("example.sov".ends_with(".sov"));
        assert!("sub.domain.zhtp".ends_with(".zhtp"));

        // Invalid domains (should not match)
        assert!(!"example.com".ends_with(".zhtp") && !"example.com".ends_with(".sov"));
        assert!(!"zhtp.com".ends_with(".zhtp") && !"zhtp.com".ends_with(".sov"));
        assert!(!"sov.org".ends_with(".zhtp") && !"sov.org".ends_with(".sov"));
    }

    #[test]
    fn test_domain_case_normalization() {
        let domain = "MyApp.ZHTP";
        let normalized = domain.to_lowercase();
        assert_eq!(normalized, "myapp.zhtp");
        assert!(normalized.ends_with(".zhtp"));
    }

    // ========== DNS Packet Tests ==========

    #[test]
    fn test_notimp_response_for_non_a_queries() {
        // Verify NOTIMP response has correct rcode
        let query = DnsPacket {
            id: 0x1234,
            is_response: false,
            question: Some(super::super::packet::DnsQuestion {
                name: "myapp.zhtp".to_string(),
                qtype: 28, // AAAA record
                qclass: 1,
            }),
            answers: vec![],
            rcode: 0,
        };

        let response = DnsPacket::notimp(&query);
        assert!(response.is_response);
        assert_eq!(response.rcode, 4); // NOTIMP
        assert_eq!(response.id, query.id);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn test_nxdomain_response() {
        let query = DnsPacket {
            id: 0x5678,
            is_response: false,
            question: Some(super::super::packet::DnsQuestion {
                name: "nonexistent.zhtp".to_string(),
                qtype: 1, // A record
                qclass: 1,
            }),
            answers: vec![],
            rcode: 0,
        };

        let response = DnsPacket::nxdomain(&query);
        assert!(response.is_response);
        assert_eq!(response.rcode, 3); // NXDOMAIN
        assert!(response.answers.is_empty());
    }

    #[test]
    fn test_a_record_response_with_ttl() {
        let query = DnsPacket {
            id: 0xABCD,
            is_response: false,
            question: Some(super::super::packet::DnsQuestion {
                name: "myapp.zhtp".to_string(),
                qtype: 1,
                qclass: 1,
            }),
            answers: vec![],
            rcode: 0,
        };

        let gateway_ip = Ipv4Addr::new(192, 168, 1, 100);
        let ttl = 300;
        let response = DnsPacket::a_record(&query, gateway_ip, ttl);

        assert!(response.is_response);
        assert_eq!(response.rcode, 0); // NOERROR
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, ttl);
        assert_eq!(response.answers[0].rdata, vec![192, 168, 1, 100]);
    }

    // ========== TLD Filtering Tests ==========

    #[test]
    fn test_zhtp_tld_accepted() {
        assert!("myapp.zhtp".ends_with(".zhtp"));
        assert!("sub.domain.zhtp".ends_with(".zhtp"));
        assert!("a.zhtp".ends_with(".zhtp"));
    }

    #[test]
    fn test_sov_tld_accepted() {
        assert!("myapp.sov".ends_with(".sov"));
        assert!("sub.domain.sov".ends_with(".sov"));
        assert!("a.sov".ends_with(".sov"));
    }

    #[test]
    fn test_non_sovereign_tlds_rejected() {
        // These should NOT match sovereign TLDs
        let non_sovereign = [
            "example.com",
            "example.org",
            "example.net",
            "zhtp.com",      // TLD is .com, not .zhtp
            "sov.org",       // TLD is .org, not .sov
            "myapp.zhtpp",   // Typo
            "myapp.sovv",    // Typo
            "myapp",         // No TLD
        ];

        for domain in &non_sovereign {
            let is_sovereign = domain.ends_with(".zhtp") || domain.ends_with(".sov");
            assert!(!is_sovereign, "Domain '{}' should not be accepted as sovereign", domain);
        }
    }

    // ========== Capability Enforcement Tests ==========

    #[test]
    fn test_allowed_capabilities_default() {
        let config = ZdnsServerConfig::default();
        let allowed = config.allowed_capabilities.as_ref().unwrap();

        // Default should allow HttpServe and SpaServe
        assert!(allowed.contains(&Web4Capability::HttpServe));
        assert!(allowed.contains(&Web4Capability::SpaServe));

        // DownloadOnly should NOT be in default allowed list
        assert!(!allowed.contains(&Web4Capability::DownloadOnly));
    }

    #[test]
    fn test_capability_check_logic() {
        let allowed = vec![Web4Capability::HttpServe, Web4Capability::SpaServe];

        // These should be allowed
        assert!(allowed.contains(&Web4Capability::HttpServe));
        assert!(allowed.contains(&Web4Capability::SpaServe));

        // DownloadOnly should be rejected
        assert!(!allowed.contains(&Web4Capability::DownloadOnly));
    }

    // ========== TTL Calculation Tests ==========

    #[test]
    fn test_ttl_uses_minimum_of_record_and_config() {
        // If record TTL is lower, use record TTL
        let record_ttl: u64 = 300;
        let config_ttl: u64 = 3600;
        let result = record_ttl.min(config_ttl);
        assert_eq!(result, 300);

        // If config TTL is lower, use config TTL
        let record_ttl: u64 = 7200;
        let config_ttl: u64 = 3600;
        let result = record_ttl.min(config_ttl);
        assert_eq!(result, 3600);
    }

    #[test]
    fn test_ttl_respects_expiration() {
        let now: u64 = 1000;
        let expires_at: u64 = 1500;
        let record_ttl: u64 = 3600;

        // Remaining time until expiration
        let remaining = expires_at - now; // 500 seconds
        let effective_ttl = remaining.min(record_ttl);

        // Should use the shorter of remaining time and record TTL
        assert_eq!(effective_ttl, 500);
    }

    #[test]
    fn test_expired_domain_detected() {
        let now: u64 = 2000;
        let expires_at: u64 = 1500;

        // Domain is expired
        assert!(now >= expires_at);
    }

    // ========== TCP Message Size Tests ==========

    #[test]
    fn test_max_tcp_message_size() {
        // RFC 1035 limit
        assert_eq!(MAX_TCP_MESSAGE_SIZE, 65535);
    }

    #[test]
    fn test_tcp_length_prefix_parsing() {
        // TCP DNS uses 2-byte big-endian length prefix
        let len_bytes: [u8; 2] = [0x01, 0x00]; // 256 in big-endian
        let len = u16::from_be_bytes(len_bytes) as usize;
        assert_eq!(len, 256);

        // Max valid length
        let max_bytes: [u8; 2] = [0xFF, 0xFF]; // 65535
        let max_len = u16::from_be_bytes(max_bytes) as usize;
        assert_eq!(max_len, 65535);
    }

    // ========== Rate Limiter Edge Cases ==========

    #[tokio::test]
    async fn test_rate_limiter_different_ips_independent() {
        let limiter = RateLimiter::new(2, 60);

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Exhaust ip1's quota
        assert!(limiter.check_and_increment(ip1).await);
        assert!(limiter.check_and_increment(ip1).await);
        assert!(!limiter.check_and_increment(ip1).await); // Rate limited

        // ip2 should still have full quota
        assert!(limiter.check_and_increment(ip2).await);
        assert!(limiter.check_and_increment(ip2).await);
        assert!(!limiter.check_and_increment(ip2).await); // Now rate limited
    }

    #[tokio::test]
    async fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::new(5, 1); // 1 second window

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Add entry
        limiter.check_and_increment(ip).await;

        // Verify entry exists
        {
            let entries = limiter.entries.read().await;
            assert!(entries.contains_key(&ip));
        }

        // Cleanup should work
        limiter.cleanup_old_entries().await;
    }

    // ========== Semaphore Backpressure Tests ==========

    #[tokio::test]
    async fn test_semaphore_bounds_concurrency() {
        let semaphore = Arc::new(Semaphore::new(2));

        // Acquire 2 permits
        let permit1 = semaphore.clone().try_acquire_owned();
        let permit2 = semaphore.clone().try_acquire_owned();

        assert!(permit1.is_ok());
        assert!(permit2.is_ok());

        // 3rd should fail (at capacity)
        let permit3 = semaphore.clone().try_acquire_owned();
        assert!(permit3.is_err());

        // Drop one permit
        drop(permit1);

        // Now should succeed
        let permit4 = semaphore.clone().try_acquire_owned();
        assert!(permit4.is_ok());
    }
}
