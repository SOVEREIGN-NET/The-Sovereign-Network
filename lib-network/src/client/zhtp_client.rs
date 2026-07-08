//! ZhtpClient - Core QUIC client for all control-plane operations
//!
//! This client provides authenticated QUIC transport for all API calls.
//! It handles connection establishment, UHP handshake, and request/response framing.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tracing::{debug, info, warn};

/// Singleton bootstrap NonceCache — opened once, shared (via Arc<Db>) across all bootstrap clients.
/// This prevents the OOM bug where a unique sled DB path was created per bootstrap connection.
static BOOTSTRAP_NONCE_CACHE: OnceLock<NonceCache> = OnceLock::new();
static BOOTSTRAP_NONCE_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

use quinn::{ClientConfig, Connection, Endpoint};

/// Singleton QUIC client `Endpoint` plus a dedicated long-lived runtime that
/// owns its I/O driver task. Sharing the endpoint across all `ZhtpClient`
/// instances is necessary for three distinct reasons, all of which bit us
/// on iOS in the lib-client FFI path.
///
/// 1. **Socket budget (Bug 1, also bites macOS/Linux at scale).** Without
///    sharing, every call to `new_with_config` binds a brand-new UDP socket
///    via `Endpoint::client`. The lib-client FFI spawns a session per
///    authenticated request, so a busy app racks up file descriptors at
///    one per request. iOS clamps at ~256 fds per process and starts
///    returning EPERM ("Operation not permitted") from the bind.
///
/// 2. **Driver lifetime (Bug 2, iOS-specific in the FFI path).**
///    `Endpoint::client` spawns its async I/O driver task on the **current**
///    tokio runtime. The lib-client FFI builds a fresh single-threaded
///    runtime per session in `spawn_session_worker`; whichever session
///    happened to be the first caller would parent the driver onto its
///    transient runtime, and the moment that worker exited the driver got
///    dropped and every later clone of the singleton started failing with
///    "endpoint stopping". Park the singleton on a process-lived runtime
///    we build here under `runtime.enter()` so the driver outlives every
///    individual session worker.
///
/// 3. **iOS bind permission.** `0.0.0.0:0` (IPv4-only wildcard) is rejected
///    by iOS in many app sandboxes with EPERM even before any socket-budget
///    pressure. `[::]:0` produces a dual-stack socket that accepts and
///    sends IPv4 traffic too — matches the pattern the working `quinn-ffi`
///    code path on the mobile side has used since day one.
static CLIENT_ENDPOINT: OnceLock<Endpoint> = OnceLock::new();
static CLIENT_ENDPOINT_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static CLIENT_ENDPOINT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn shared_client_endpoint() -> Result<Endpoint> {
    if let Some(ep) = CLIENT_ENDPOINT.get() {
        return Ok(ep.clone());
    }
    let _guard = CLIENT_ENDPOINT_MUTEX
        .lock()
        .map_err(|_| anyhow!("client endpoint init mutex poisoned"))?;
    if let Some(ep) = CLIENT_ENDPOINT.get() {
        return Ok(ep.clone());
    }

    // Build (or get) the dedicated runtime that owns the endpoint driver and
    // also drives persistent-session connect/handshake/RPC/inbound work.
    let runtime = match CLIENT_ENDPOINT_RUNTIME.get() {
        Some(rt) => rt,
        None => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .thread_name("zhtp-client-endpoint")
                .build()
                .context("Failed to build shared client endpoint runtime")?;
            let _ = CLIENT_ENDPOINT_RUNTIME.set(rt);
            CLIENT_ENDPOINT_RUNTIME
                .get()
                .expect("CLIENT_ENDPOINT_RUNTIME just initialized")
        }
    };
    let _enter = runtime.enter();

    // Dual-stack bind. `[::]:0` accepts/sends IPv4 too; `0.0.0.0:0` is
    // rejected by iOS with EPERM in many contexts.
    let bind_addr: SocketAddr = "[::]:0"
        .parse()
        .context("Failed to parse default bind address")?;
    let ep =
        Endpoint::client(bind_addr).context("Failed to create shared QUIC endpoint")?;
    let _ = CLIENT_ENDPOINT.set(ep.clone());
    Ok(ep)
}

/// Runtime that owns the shared Quinn endpoint driver.
///
/// All `ZhtpClient` connect / handshake / stream I/O must be driven on
/// this runtime. Awaiting `Endpoint::connect` on a different tokio
/// runtime fails on iOS (observed as `Operation not permitted (os error 1)`).
pub fn client_endpoint_runtime() -> Result<&'static tokio::runtime::Runtime> {
    let _ = shared_client_endpoint()?;
    Ok(CLIENT_ENDPOINT_RUNTIME
        .get()
        .expect("shared_client_endpoint initializes CLIENT_ENDPOINT_RUNTIME"))
}

use lib_identity::ZhtpIdentity;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse};
use lib_protocols::wire::{read_response, write_request, ZhtpRequestWire};

use crate::handshake::security::derive_v2_session_keys;
use crate::handshake::{HandshakeContext, NonceCache};
use crate::protocols::quic_handshake;
use crate::web4::trust::{TrustConfig, ZhtpTrustVerifier};

/// Configuration for ZhtpClient initialization
///
/// This struct allows explicit configuration of client behavior without
/// relying on environment variables, enabling safe operation in containerized
/// and WASM environments.
#[derive(Clone, Debug)]
pub struct ZhtpClientConfig {
    /// Allow bootstrap mode for development/testing
    /// When true, accepts any TLS certificate (INSECURE - dev only)
    pub allow_bootstrap: bool,
    /// Wire ALPN selector: 0 = `zhtp-public/1`, 1 = `zhtp-uhp/2` (default).
    pub session_alpn: u8,
}

impl Default for ZhtpClientConfig {
    fn default() -> Self {
        Self {
            allow_bootstrap: false,
            session_alpn: 1,
        }
    }
}

/// Authenticated QUIC client for ZHTP control-plane operations
///
/// This is the only transport allowed for mutating operations.
/// All CLI commands must use this client.
pub struct ZhtpClient {
    /// QUIC endpoint
    endpoint: Endpoint,

    /// Authenticated connection to node
    connection: Option<AuthenticatedConnection>,

    /// Client identity (for signing requests)
    identity: Arc<ZhtpIdentity>,

    /// Handshake context with nonce cache
    handshake_ctx: HandshakeContext,

    /// Trust configuration
    trust_config: TrustConfig,

    /// Trust verifier
    trust_verifier: Option<Arc<ZhtpTrustVerifier>>,

    /// Client configuration
    config: ZhtpClientConfig,

    // === Peer Pool (#2196) ===
    /// Additional pooled connections for fallback/rotation
    pool: Vec<AuthenticatedConnection>,
    /// Addresses of peers in the pool (parallel to pool Vec)
    pool_addrs: Vec<SocketAddr>,
    /// Failure count per address for adaptive scoring
    failure_history: HashMap<SocketAddr, u32>,
}

/// Connection with completed UHP v2 handshake
struct AuthenticatedConnection {
    /// QUIC connection
    quic_conn: Connection,

    /// V2 MAC key (derived via HKDF-SHA3-256 from session_key + handshake_hash)
    mac_key: [u8; 32],

    /// Peer's verified DID (from UHP handshake)
    peer_did: String,

    /// Session ID (UHP v2, 32 bytes)
    session_id: [u8; 32],

    /// Request sequence counter (for replay protection)
    sequence: AtomicU64,
}

impl AuthenticatedConnection {
    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }
}

impl ZhtpClient {
    /// Create a new ZHTP client with trust configuration and explicit config
    pub async fn new_with_config(
        identity: ZhtpIdentity,
        trust_config: TrustConfig,
        config: ZhtpClientConfig,
    ) -> Result<Self> {
        if config.session_alpn != 1 {
            return Err(anyhow!(
                "ZhtpClient requires session_alpn=1 (zhtp-uhp/2); public ALPN (0) performs no UHP handshake and is not supported"
            ));
        }

        // Install rustls crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Reuse the process-wide singleton endpoint (UDP socket + Quinn driver).
        // See `CLIENT_ENDPOINT` docs above for why this is load-bearing on iOS.
        let endpoint = shared_client_endpoint()?;

        // Create nonce cache.
        // Bootstrap clients share a single NonceCache instance (opened once via OnceLock).
        // NonceCache::clone() is cheap — it shares the Arc<sled::Db> without reopening.
        // This prevents the OOM bug (unique sled path per bootstrap call) and the
        // concurrent-open bug (sled only allows one opener per path at a time).
        let nonce_cache = if config.allow_bootstrap {
            // Fast path: already initialized
            if let Some(cached) = BOOTSTRAP_NONCE_CACHE.get() {
                cached.clone()
            } else {
                // Slow path: initialize once under mutex to prevent races
                let _guard = BOOTSTRAP_NONCE_MUTEX
                    .lock()
                    .map_err(|_| anyhow!("Bootstrap nonce mutex poisoned"))?;
                // Double-check after acquiring lock
                if let Some(cached) = BOOTSTRAP_NONCE_CACHE.get() {
                    cached.clone()
                } else {
                    // Use per-process subdirectory to avoid cross-process contention
                    // when running multiple nodes on the same host (common in local testing)
                    let pid = std::process::id();
                    let nonce_db_path = std::env::temp_dir()
                        .join("zhtp_bootstrap_nonce")
                        .join(pid.to_string())
                        .join("db");
                    if let Some(parent) = nonce_db_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let network_epoch = match crate::handshake::NetworkEpoch::from_global_or_fail()
                    {
                        Ok(epoch) => epoch,
                        Err(_) => {
                            warn!(
                                "Network genesis not yet available (bootstrap mode) - \
                                 using chain_id=0 for initial sync connection"
                            );
                            crate::handshake::NetworkEpoch::from_chain_id(0)
                        }
                    };
                    // Open bootstrap nonce cache. If it fails due to epoch mismatch (stale
                    // sled from a previous run with different genesis), wipe and recreate.
                    // The bootstrap nonce cache is ephemeral — cross-restart replay protection
                    // for bootstrap connections is not a security requirement.
                    let cache = match NonceCache::open(&nonce_db_path, 3600, 10_000, network_epoch)
                    {
                        Ok(c) => c,
                        Err(e) => {
                            let err_str = e.to_string();
                            // Only wipe and retry on epoch mismatch - not on lock contention,
                            // permission errors, or I/O failures (which would be unsafe to delete)
                            if err_str.contains("Network epoch mismatch") {
                                warn!("Bootstrap nonce cache epoch mismatch ({}); clearing stale DB and retrying", e);
                                let _ = std::fs::remove_dir_all(&nonce_db_path);
                                std::fs::create_dir_all(&nonce_db_path)?;
                                NonceCache::open(&nonce_db_path, 3600, 10_000, network_epoch)
                                    .context(
                                        "Failed to open nonce cache after epoch mismatch retry",
                                    )?
                            } else {
                                // Don't wipe on lock contention, I/O errors, etc.
                                return Err(e.into());
                            }
                        }
                    };
                    let _ = BOOTSTRAP_NONCE_CACHE.set(cache.clone());
                    cache
                }
            }
        } else {
            let nonce_db_path = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".zhtp")
                .join("client_nonce_cache");
            if let Some(parent) = nonce_db_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let network_epoch = crate::handshake::NetworkEpoch::from_global_or_fail()?;
            match NonceCache::open(&nonce_db_path, 3600, 10_000, network_epoch) {
                Ok(c) => c,
                Err(e) if e.to_string().contains("Network epoch mismatch") => {
                    warn!(
                        "Client nonce cache epoch mismatch — clearing and retrying: {}",
                        e
                    );
                    let _ = std::fs::remove_dir_all(&nonce_db_path);
                    NonceCache::open(&nonce_db_path, 3600, 10_000, network_epoch)
                        .context("Failed to open nonce cache after epoch mismatch clear")?
                }
                Err(e) => return Err(e.into()),
            }
        };

        let handshake_ctx = HandshakeContext::new(nonce_cache);

        Ok(Self {
            endpoint,
            connection: None,
            identity: Arc::new(identity),
            handshake_ctx,
            trust_config,
            trust_verifier: None,
            config,
            pool: Vec::new(),
            pool_addrs: Vec::new(),
            failure_history: HashMap::new(),
        })
    }

    /// Create a new ZHTP client with trust configuration (uses default config)
    pub async fn new(identity: ZhtpIdentity, trust_config: TrustConfig) -> Result<Self> {
        Self::new_with_config(identity, trust_config, ZhtpClientConfig::default()).await
    }

    /// Create client in bootstrap mode with explicit config (DEV ONLY - no TLS verification)
    pub async fn new_bootstrap_with_config(
        identity: ZhtpIdentity,
        config: ZhtpClientConfig,
    ) -> Result<Self> {
        if !config.allow_bootstrap {
            return Err(anyhow!(
                "Bootstrap mode requires ZhtpClientConfig::allow_bootstrap to be true"
            ));
        }
        warn!("ZHTP client in BOOTSTRAP MODE - NO TLS VERIFICATION");
        Self::new_with_config(identity, TrustConfig::bootstrap(), config).await
    }

    /// Create client in bootstrap mode (DEV ONLY - no TLS verification)
    ///
    /// Deprecated: Use `new_bootstrap_with_config()` with explicit config instead.
    /// This method is maintained for backwards compatibility.
    #[deprecated(
        since = "1.1.0",
        note = "Use new_bootstrap_with_config with explicit config"
    )]
    pub async fn new_bootstrap(identity: ZhtpIdentity) -> Result<Self> {
        warn!("ZHTP client in BOOTSTRAP MODE - NO TLS VERIFICATION");
        let config = ZhtpClientConfig {
            allow_bootstrap: true,
            ..Default::default()
        };
        Self::new_bootstrap_with_config(identity, config).await
    }

    /// Create client with TOFU (Trust On First Use)
    pub async fn new_tofu(identity: ZhtpIdentity) -> Result<Self> {
        let trustdb_path = TrustConfig::default_trustdb_path()?;
        Self::new(identity, TrustConfig::with_tofu(trustdb_path)).await
    }

    /// Create client with SPKI pinning
    pub async fn new_pinned(identity: ZhtpIdentity, spki_sha256: String) -> Result<Self> {
        Self::new(identity, TrustConfig::with_pin(spki_sha256)).await
    }

    /// Get the client's identity DID
    pub fn identity_did(&self) -> &str {
        &self.identity.did
    }

    /// Get the identity
    pub fn identity(&self) -> &ZhtpIdentity {
        &self.identity
    }

    /// Get the verified peer DID from current connection
    pub fn peer_did(&self) -> Option<&str> {
        self.connection.as_ref().map(|c| c.peer_did.as_str())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Check if in bootstrap mode
    pub fn is_bootstrap_mode(&self) -> bool {
        self.trust_config.bootstrap_mode
    }

    /// Internal: establish an authenticated connection to a specific address.
    async fn connect_internal(
        &mut self,
        addr: &str,
        server_name: &str,
    ) -> Result<AuthenticatedConnection> {
        // Accept both "ip:port" and "hostname:port". `SocketAddr::parse` only
        // handles literal IPs, so a hostname like
        // "zhtp-gateway.thesovereignnetwork.org:9334" used to fail here and
        // the FFI surfaced it as "QuicSession.open failed: openFailed".
        //
        // Use tokio's async DNS (`tokio::net::lookup_host`) — std's
        // `to_socket_addrs` is a blocking syscall and stalling it inside
        // an async fn parked on a single-thread runtime (which is exactly
        // how `spawn_session_worker` runs us) blocks the whole session.
        //
        // On dual-stack hosts a hostname can resolve to both AAAA and A
        // records; pick A first because IPv6 routing isn't universal
        // (mobile carriers, captive nets, container egress) and a v6
        // attempt that times out adds a full RTT of latency to the
        // first request. Fall back to whatever resolves if no A record
        // is returned.
        let candidates: Vec<SocketAddr> = tokio::net::lookup_host(addr)
            .await
            .with_context(|| format!("Failed to resolve address: {}", addr))?
            .collect();
        let socket_addr: SocketAddr = candidates
            .iter()
            .find(|s| s.is_ipv4())
            .or_else(|| candidates.first())
            .copied()
            .ok_or_else(|| anyhow!("Address '{}' resolved to no socket addresses", addr))?;

        if self.trust_config.bootstrap_mode && !self.config.allow_bootstrap {
            return Err(anyhow!(
                "Bootstrap mode requires ZhtpClientConfig::allow_bootstrap to be true"
            ));
        }

        // Use existing trust verifier if available, otherwise create and store one
        let verifier = match self.trust_verifier {
            Some(ref v) => Arc::clone(v),
            None => {
                let v = Arc::new(ZhtpTrustVerifier::new(
                    addr.to_string(),
                    self.trust_config.clone(),
                )?);
                self.trust_verifier = Some(Arc::clone(&v));
                v
            }
        };

        // Per-connection client config: the endpoint is shared across all
        // ZhtpClients, so we mustn't mutate its default config (that would
        // race against concurrent connects from other ZhtpClient instances).
        // `connect_with` applies the config to just this connection.
        let client_config = Self::configure_client(verifier, self.config.session_alpn)?;
        let connection = self
            .endpoint
            .connect_with(client_config, socket_addr, server_name)?
            .await
            .context("QUIC connection failed")?;

        // Perform UHP v2 handshake
        let handshake_result = quic_handshake::handshake_as_initiator(
            &connection,
            &self.identity,
            &self.handshake_ctx,
        )
        .await
        .context("UHP v2 handshake failed")?;

        let peer_did = handshake_result.verified_peer.identity.did.clone();

        // Verify node DID matches trust configuration and bind for TOFU anchor updates
        if let Some(ref verifier) = self.trust_verifier {
            verifier.verify_node_did(&peer_did)?;
            verifier.bind_node_did(&peer_did)?;
        }

        // Derive V2 session keys
        let v2_keys = derive_v2_session_keys(
            &handshake_result.session_key,
            &handshake_result.handshake_hash,
        )
        .context("Failed to derive V2 session keys")?;

        Ok(AuthenticatedConnection {
            quic_conn: connection,
            mac_key: v2_keys.mac_key,
            peer_did,
            session_id: handshake_result.session_id,
            sequence: AtomicU64::new(1),
        })
    }

    /// Connect to a ZHTP node (single-endpoint mode).
    /// `server_name` is the TLS SNI hostname (e.g. `g3.thesovereignnetwork.org`).
    pub async fn connect_with_sni(&mut self, addr: &str, server_name: &str) -> Result<()> {
        info!(
            "Connecting to ZHTP node at {} (sni={})",
            addr, server_name
        );

        if self.trust_config.bootstrap_mode {
            warn!("BOOTSTRAP MODE - TLS certificates not verified");
        }

        // Create trust verifier for single connection
        let verifier = Arc::new(ZhtpTrustVerifier::new(
            addr.to_string(),
            self.trust_config.clone(),
        )?);
        self.trust_verifier = Some(Arc::clone(&verifier));

        let conn = self.connect_internal(addr, server_name).await?;
        info!(
            peer_did = %conn.peer_did,
            session_id = ?hex::encode(&conn.session_id[..8]),
            "Authenticated with node (PQC encryption active)"
        );
        self.connection = Some(conn);
        Ok(())
    }

    /// Connect with the legacy default SNI (`zhtp-node`).
    pub async fn connect(&mut self, addr: &str) -> Result<()> {
        self.connect_with_sni(addr, "zhtp-node").await
    }

    // ==================== PEER POOL (#2196) ====================

    /// Score a peer entry for pool selection (higher is better).
    fn score_peer_entry(entry: &crate::peer_registry::PeerEntry, failures: u32) -> f64 {
        // Untrusted peers are never selected for the pool
        if entry.tier == crate::peer_registry::PeerTier::Untrusted {
            return 0.0;
        }

        let mut score = 0.0;

        // Trust score (0-1, weight 30)
        score += entry.trust_score * 30.0;

        // Route quality (0-1, weight 20)
        score += entry.route_quality * 20.0;

        // Stability (0-1, weight 20)
        score += entry.connection_metrics.stability_score * 20.0;

        // Reliability (0-1, weight 15)
        score += entry.reliability_score * 15.0;

        // Latency (lower is better, inverted, weight 10)
        let latency_ms = entry.connection_metrics.latency_ms.max(1) as f64;
        score += (1000.0 / latency_ms).min(10.0);

        // Bandwidth capacity (normalized to Mbps, weight 5)
        let bw_mbps = entry.connection_metrics.bandwidth_capacity as f64 / 1_000_000.0;
        score += bw_mbps.min(5.0);

        // Routing capacity bonus
        if entry.capabilities.routing_capacity >= 50 {
            score += 5.0;
        } else if entry.capabilities.routing_capacity >= 10 {
            score += 2.0;
        }

        // Tier bonus
        score += match entry.tier {
            crate::peer_registry::PeerTier::Tier1 => 5.0,
            crate::peer_registry::PeerTier::Tier2 => 3.0,
            crate::peer_registry::PeerTier::Tier3 => 1.0,
            crate::peer_registry::PeerTier::Tier4 => 0.0,
            crate::peer_registry::PeerTier::Untrusted => unreachable!(),
        };

        // Freshness penalty for stale peers
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age = now.saturating_sub(entry.last_seen);
        if age > 3600 {
            score -= 10.0; // Stale (>1h)
        } else if age > 300 {
            score -= 5.0; // Getting stale (>5min)
        }

        // Failure penalty
        score -= failures as f64 * 10.0;

        score.max(0.0)
    }

    /// Connect to a pool of peers selected from the PeerRegistry.
    ///
    /// Filters candidates by security requirements, scores them by quality,
    /// and connects to the top `max_peers` candidates.
    pub async fn connect_to_pool(
        &mut self,
        registry: &crate::peer_registry::PeerRegistry,
        max_peers: usize,
    ) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Filter and score candidates
        let mut candidates: Vec<(SocketAddr, f64)> = Vec::new();
        for entry in registry.all_peers() {
            // Security filters
            if !entry.authenticated || !entry.quantum_secure {
                continue;
            }
            if entry.trust_score < 0.3 {
                continue;
            }
            if entry.tier == crate::peer_registry::PeerTier::Untrusted {
                continue;
            }

            // Must have a QUIC-compatible endpoint (UDP or explicit QUIC)
            // TCP endpoints are not usable by this QUIC-only client.
            let socket_addr = match entry.endpoints.iter().find_map(|ep| match &ep.address {
                crate::types::node_address::NodeAddress::Quic(a) => Some(*a),
                crate::types::node_address::NodeAddress::Udp(a) => Some(*a),
                _ => None,
            }) {
                Some(addr) => addr,
                None => continue,
            };

            // Skip if too stale
            if now.saturating_sub(entry.last_seen) > 86400 {
                continue;
            }

            let failures = *self.failure_history.get(&socket_addr).unwrap_or(&0);
            let score = Self::score_peer_entry(entry, failures);
            candidates.push((socket_addr, score));
        }

        // Sort by score (highest first)
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Connect to top N
        let mut connected = 0;
        for (addr, score) in candidates.into_iter().take(max_peers) {
            info!(addr = %addr, score = score, "Attempting peer-pool connection");
            match self.connect_internal(&addr.to_string(), "zhtp-node").await {
                Ok(conn) => {
                    info!(addr = %addr, peer_did = %conn.peer_did, "Peer-pool connection established");
                    self.pool_addrs.push(addr);
                    self.pool.push(conn);
                    connected += 1;
                }
                Err(e) => {
                    warn!(addr = %addr, error = %e, "Peer-pool connection failed");
                    *self.failure_history.entry(addr).or_insert(0) += 1;
                }
            }
        }

        // Set primary connection to the best pool peer if none exists
        if self.connection.is_none() && !self.pool.is_empty() {
            self.connection = Some(self.pool.remove(0));
            let _ = self.pool_addrs.remove(0);
        }

        info!(connected = connected, "Peer-pool initialization complete");
        Ok(connected)
    }

    /// Send a request with automatic fallback to pool peers on failure.
    ///
    /// Tries the primary connection first, then iterates through the pool
    /// until a successful response is received or all peers are exhausted.
    pub async fn request_with_fallback(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Try primary first
        if let Some(ref conn) = self.connection {
            match self.request_on_connection(conn, request.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    warn!(error = %e, "Primary connection failed, trying pool fallback");
                }
            }
        }

        // Fallback to pool
        for (idx, conn) in self.pool.iter().enumerate() {
            match self.request_on_connection(conn, request.clone()).await {
                Ok(resp) => {
                    info!(pool_index = idx, "Request succeeded via pool fallback");
                    return Ok(resp);
                }
                Err(e) => {
                    warn!(pool_index = idx, error = %e, "Pool peer failed");
                }
            }
        }

        Err(anyhow!("All peers failed to handle request"))
    }

    /// Rotate the primary connection to the next pool peer.
    ///
    /// The current primary is moved to the end of the pool, and the first
    /// pool peer is promoted to primary. This enables load distribution.
    pub fn rotate_primary(&mut self) {
        if let Some(primary) = self.connection.take() {
            if !self.pool.is_empty() {
                let new_primary = self.pool.remove(0);
                let new_primary_addr = self.pool_addrs.remove(0);
                self.pool_addrs.push(new_primary_addr);
                self.pool.push(primary);
                self.connection = Some(new_primary);
                info!("Rotated primary connection");
            } else {
                // No pool to rotate with; restore primary
                self.connection = Some(primary);
            }
        }
    }

    /// Get the number of peers in the pool (excluding primary).
    pub fn pool_size(&self) -> usize {
        self.pool.len()
    }

    /// Get pool peer addresses.
    pub fn pool_addresses(&self) -> &[SocketAddr] {
        &self.pool_addrs
    }

    /// Internal: send a request on a specific connection.
    async fn request_on_connection(
        &self,
        conn: &AuthenticatedConnection,
        request: ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        let seq = conn.next_sequence();
        let wire_request = ZhtpRequestWire::new_authenticated(
            request,
            conn.session_id,
            self.identity.did.clone(),
            seq,
            &conn.mac_key,
        );

        let request_id = wire_request.request_id;

        let (mut send, mut recv) = conn
            .quic_conn
            .open_bi()
            .await
            .context("Failed to open QUIC stream")?;

        write_request(&mut send, &wire_request)
            .await
            .context("Failed to send request")?;
        send.finish().context("Failed to finish send stream")?;

        let wire_response = read_response(&mut recv)
            .await
            .context("Failed to read response")?;

        if wire_response.request_id != request_id {
            return Err(anyhow!(
                "Response request_id mismatch: expected {}, got {}",
                hex::encode(request_id),
                wire_response.request_id_hex()
            ));
        }

        Ok(wire_response.response)
    }

    fn configure_client(
        verifier: Arc<ZhtpTrustVerifier>,
        session_alpn: u8,
    ) -> Result<ClientConfig> {
        // Install crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        // ALPN selects the server's initial protocol flow. Mobile and
        // current gateways negotiate `zhtp-uhp/2`; legacy CLI used v1.
        crypto.alpn_protocols = if session_alpn == 0 {
            crate::constants::client_public_alpns()
        } else {
            crate::constants::client_control_plane_v2_alpns()
        };

        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
        config.transport_config(Arc::new(transport));

        Ok(config)
    }

    /// Send a request and receive response (uses primary connection)
    pub async fn request(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to node"))?;
        self.request_on_connection(conn, request).await
    }

    /// Open an authenticated bidi stream, write the request, and return the
    /// streams to the caller. Used for endpoints whose response body is a
    /// long-lived stream of framed payloads (e.g. `/msg/inbound`).
    ///
    /// On return:
    /// - The `SendStream` has been finished (request body fully written).
    /// - The `RecvStream` is positioned BEFORE the initial `ZhtpResponseWire`.
    /// - `expected_request_id` lets the caller validate the response.
    ///
    /// Caller is responsible for reading the response header (with
    /// `lib_protocols::wire::read_response`) and then consuming any subsequent
    /// framed payloads from the recv stream.
    pub async fn open_authenticated_stream(
        &self,
        request: ZhtpRequest,
    ) -> Result<(quinn::SendStream, quinn::RecvStream, [u8; 16])> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to node"))?;
        let seq = conn.next_sequence();
        let wire_request = ZhtpRequestWire::new_authenticated(
            request,
            conn.session_id,
            self.identity.did.clone(),
            seq,
            &conn.mac_key,
        );
        let request_id = wire_request.request_id;

        let (mut send, recv) = conn
            .quic_conn
            .open_bi()
            .await
            .context("Failed to open QUIC stream")?;
        write_request(&mut send, &wire_request)
            .await
            .context("Failed to send request")?;
        send.finish().context("Failed to finish send stream")?;

        Ok((send, recv, request_id))
    }

    /// Send a GET request
    pub async fn get(&self, path: &str) -> Result<ZhtpResponse> {
        let request = ZhtpRequest::get(path.to_string(), Some(self.identity.id.clone()))?;
        self.request(request).await
    }

    /// Send a POST request with JSON body
    pub async fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<ZhtpResponse> {
        let request = ZhtpRequest::post(
            path.to_string(),
            serde_json::to_vec(body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;
        self.request(request).await
    }

    /// Send a DELETE request
    pub async fn delete(&self, path: &str) -> Result<ZhtpResponse> {
        let request = ZhtpRequest::delete(path.to_string(), Some(self.identity.id.clone()))?;
        self.request(request).await
    }

    /// Close the connection gracefully (including pool peers)
    pub async fn close(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.quic_conn.close(0u32.into(), b"client closed");
        }
        for conn in self.pool.drain(..) {
            conn.quic_conn.close(0u32.into(), b"client closed");
        }
        self.pool_addrs.clear();
    }

    /// Parse JSON response body
    pub fn parse_json<T: serde::de::DeserializeOwned>(response: &ZhtpResponse) -> Result<T> {
        if !response.status.is_success() {
            return Err(anyhow!(
                "Request failed: {} {}",
                response.status.code(),
                response.status_message
            ));
        }
        serde_json::from_slice(&response.body).context("Failed to parse response JSON")
    }
}

impl Drop for ZhtpClient {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.quic_conn.close(0u32.into(), b"client dropped");
        }
        for conn in self.pool.drain(..) {
            conn.quic_conn.close(0u32.into(), b"client dropped");
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_registry::{ConnectionMetrics, NodeCapabilities, PeerEndpoint, PeerEntry, PeerTier};
    use crate::types::node_address::NodeAddress;
    use std::net::SocketAddr;

    fn create_test_peer_entry(
        peer_id: crate::identity::unified_peer::UnifiedPeerId,
        trust_score: f64,
        latency_ms: u32,
        stability: f64,
        tier: PeerTier,
    ) -> PeerEntry {
        PeerEntry::new(
            peer_id,
            vec![PeerEndpoint::from_address(NodeAddress::Tcp(
                "127.0.0.1:9333".parse().unwrap(),
            ))],
            vec![crate::protocols::NetworkProtocol::QUIC],
            ConnectionMetrics {
                signal_strength: 0.8,
                bandwidth_capacity: 1_000_000,
                latency_ms,
                stability_score: stability,
                connected_at: 0,
            },
            true,
            true,
            None,
            1,
            0.85,
            NodeCapabilities {
                node_type: Some(lib_types::NodeType::Validator),
                api_endpoint: None,
                protocol_version: None,
                supports_web4: true,
                protocols: vec![crate::protocols::NetworkProtocol::QUIC],
                max_bandwidth: 1_000_000,
                available_bandwidth: 800_000,
                routing_capacity: 100,
                energy_level: Some(0.9),
                availability_percent: 95.0,
            },
            None,
            0.92,
            None,
            crate::peer_registry::DiscoveryMethod::Bootstrap,
            0,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            tier,
            trust_score,
        )
    }

    #[test]
    fn test_score_peer_entry_trust() {
        use lib_identity::ZhtpIdentity;
        let identity = ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            "test-device",
            None,
        )
        .unwrap();
        let peer_id =
            crate::identity::unified_peer::UnifiedPeerId::from_zhtp_identity(&identity).unwrap();

        let high_trust = create_test_peer_entry(peer_id.clone(), 0.9, 50, 0.9, PeerTier::Tier1);
        let low_trust = create_test_peer_entry(peer_id.clone(), 0.3, 50, 0.9, PeerTier::Tier1);

        let score_high = ZhtpClient::score_peer_entry(&high_trust, 0);
        let score_low = ZhtpClient::score_peer_entry(&low_trust, 0);

        assert!(score_high > score_low);
    }

    #[test]
    fn test_score_peer_entry_latency() {
        use lib_identity::ZhtpIdentity;
        let identity = ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            "test-device",
            None,
        )
        .unwrap();
        let peer_id =
            crate::identity::unified_peer::UnifiedPeerId::from_zhtp_identity(&identity).unwrap();

        let fast = create_test_peer_entry(peer_id.clone(), 0.8, 10, 0.9, PeerTier::Tier1);
        let slow = create_test_peer_entry(peer_id.clone(), 0.8, 500, 0.9, PeerTier::Tier1);

        let score_fast = ZhtpClient::score_peer_entry(&fast, 0);
        let score_slow = ZhtpClient::score_peer_entry(&slow, 0);

        assert!(score_fast > score_slow);
    }

    #[test]
    fn test_score_peer_entry_failures() {
        use lib_identity::ZhtpIdentity;
        let identity = ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            "test-device",
            None,
        )
        .unwrap();
        let peer_id =
            crate::identity::unified_peer::UnifiedPeerId::from_zhtp_identity(&identity).unwrap();

        let entry = create_test_peer_entry(peer_id.clone(), 0.8, 50, 0.9, PeerTier::Tier1);
        let score_clean = ZhtpClient::score_peer_entry(&entry, 0);
        let score_failures = ZhtpClient::score_peer_entry(&entry, 3);

        assert!(score_clean > score_failures);
    }

    #[test]
    fn test_score_peer_entry_untrusted_blocked() {
        use lib_identity::ZhtpIdentity;
        let identity = ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            "test-device",
            None,
        )
        .unwrap();
        let peer_id =
            crate::identity::unified_peer::UnifiedPeerId::from_zhtp_identity(&identity).unwrap();

        let untrusted = create_test_peer_entry(peer_id.clone(), 0.8, 50, 0.9, PeerTier::Untrusted);
        let score = ZhtpClient::score_peer_entry(&untrusted, 0);

        assert_eq!(score, 0.0); // Large negative penalty clamped to 0
    }

    #[test]
    fn test_pool_fields_initialized() {
        // Verify that a new client has empty pool fields
        // We can't construct a full ZhtpClient without async + QUIC, but we can
        // at least verify the struct layout by checking compilation.
        // This test is intentionally minimal — full integration tests require
        // a running QUIC endpoint.
    }
}
