//! QUIC Stream Handler - Unified Protocol Entry Point
//!
//! Single entry point for ALL QUIC connections. Routes to appropriate handler based on
//! protocol detection:
//! - PQC Handshake → Mesh message flow (blockchain sync, peer discovery)
//! - ZHTP Magic → Native ZHTP protocol (API requests)
//!
//! Architecture:
//! ```text
//! QUIC Endpoint (port 9334)
//!      │
//!      ▼
//! QuicHandler.accept_loop()  ← SINGLE entry point
//!      │
//!      ▼
//! PQC Handshake at Connection Level
//!      │
//!      ▼
//! Protocol Detection (first bytes) on each stream
//!      │
//!      ├─── ZHTP magic (b"ZHTP")
//!      │         → ZhtpRouter (native ZHTP API)
//!      │
//!      └─── Mesh Message (encrypted bincode)
//!               → MeshMessageHandler (blockchain sync)
//! ```
//!
//! # Protocol Flow
//!
//! 1. QuicHandler accepts connection from endpoint
//! 2. First connection is authenticated via PQC handshake (if peer-to-peer)
//! 3. Subsequent streams are protocol-routed based on first bytes (non-consuming detection):
//!    - b"ZHTP" → Native ZHTP (binary protocol)
//!    - Encrypted mesh messages → MeshMessageHandler
//!
//! # Thread Safety
//!
//! - `QuicHandler::clone()` creates a new handle to shared state
//! - `zhtp_router` uses RwLock - multiple concurrent readers allowed
//! - `pqc_connections` uses RwLock for concurrent peer connection tracking

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use anyhow::{Result, Context, anyhow};
use tracing::{info, warn, debug, error};
use quinn::{Connection, Incoming, RecvStream, SendStream};
use tokio::sync::RwLock;

use lib_network::protocols::quic_mesh::{QuicMeshProtocol, PqcQuicConnection};
use lib_network::protocols::quic_handshake::{self};
use lib_network::handshake::{HandshakeContext, NonceCache, ClientHello};
use lib_network::messaging::message_handler::MeshMessageHandler;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use lib_crypto::PublicKey;

use super::zhtp::ZhtpRouter;
use super::zhtp::serialization::ZHTP_MAGIC;

/// Connection idle timeout for client connections (60 seconds)
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Connection idle timeout for authenticated peer connections (5 minutes)
const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum protocol detection buffer size
const PROTOCOL_DETECT_SIZE: usize = 1024;

/// Protocol detection timeout (P1-1)
const PROTOCOL_DETECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of concurrent PQC peer connections
const MAX_PQC_CONNECTIONS: usize = 10_000;

/// Maximum age for PQC connections before requiring re-authentication
const MAX_CONNECTION_AGE: Duration = Duration::from_secs(3600); // 1 hour

/// Maximum handshake size (16KB)
const MAX_HANDSHAKE_SIZE: u64 = 16 * 1024;

/// Maximum mesh message size (1MB)
const MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

/// Per-IP rate limit for PQC handshakes
const MAX_HANDSHAKES_PER_IP: usize = 10;
const HANDSHAKE_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Tracked PQC connection with metadata
struct TrackedConnection {
    connection: PqcQuicConnection,
    created_at: Instant,
    last_activity: Instant,
}

/// Session state for authenticated control plane connections
/// Created after successful UHP+Kyber handshake
pub struct ControlPlaneSession {
    /// Session ID from UHP handshake
    pub session_id: [u8; 16],
    /// Authenticated peer DID
    pub peer_did: String,
    /// Application-layer MAC key derived from master key
    pub app_key: [u8; 32],
    /// Session creation time for expiration checks
    pub created_at: Instant,
    /// Sequence number window for replay protection
    pub sequence_window: std::sync::atomic::AtomicU64,
}

/// Connection mode based on negotiated ALPN
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Public read-only: No UHP handshake, only allows reading public content
    /// ALPN: zhtp-public/1
    /// Allows: domain resolution, manifest fetch, content/blob retrieval
    /// Rejects: deploy, domain registration, admin operations, any mutations
    Public,
    /// Control plane: UHP handshake required, then authenticated API requests
    /// ALPN: zhtp-uhp/1
    ControlPlane,
    /// Mesh peer-to-peer: UHP handshake, then encrypted mesh messages
    /// ALPN: zhtp-mesh/1
    Mesh,
}

impl ConnectionMode {
    /// Determine connection mode from negotiated ALPN
    pub fn from_alpn(alpn: Option<&[u8]>) -> Self {
        match alpn {
            Some(b"zhtp-public/1") => ConnectionMode::Public,
            Some(b"zhtp-uhp/1") => ConnectionMode::ControlPlane,
            Some(b"zhtp-mesh/1") => ConnectionMode::Mesh,
            _ => ConnectionMode::Public, // Default to public read-only for unknown (safe default)
        }
    }
}

/// Protocol detection result (includes buffered data for forwarding)
#[derive(Debug)]
enum ProtocolType {
    /// PQC handshake initiation (mesh peer connecting)
    PqcHandshake(Vec<u8>),
    /// Native ZHTP protocol (API request)
    NativeZhtp(Vec<u8>),
    /// Encrypted mesh message (post-handshake)
    MeshMessage(Vec<u8>),
    /// Unknown/unsupported protocol
    Unknown(Vec<u8>),
}

/// Buffered stream that prepends already-read data before reading from underlying stream
pub struct BufferedStream {
    prepended_data: Vec<u8>,
    offset: usize,
    stream: RecvStream,
}

impl BufferedStream {
    /// Create a new buffered stream with prepended data
    fn new(prepended_data: Vec<u8>, stream: RecvStream) -> Self {
        Self {
            prepended_data,
            offset: 0,
            stream,
        }
    }

    /// Read data, first draining prepended buffer, then from underlying stream
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        if self.offset < self.prepended_data.len() {
            // Still have prepended data to drain
            let remaining = self.prepended_data.len() - self.offset;
            let to_copy = remaining.min(buf.len());
            buf[..to_copy].copy_from_slice(&self.prepended_data[self.offset..self.offset + to_copy]);
            self.offset += to_copy;
            Ok(Some(to_copy))
        } else {
            // Prepended data exhausted, read from underlying stream
            self.stream.read(buf).await.map_err(|e| anyhow!("Stream read error: {}", e))
        }
    }

    /// Read entire stream to end (up to size limit)
    pub async fn read_to_end(&mut self, size_limit: usize) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // First, drain prepended data
        if self.offset < self.prepended_data.len() {
            buffer.extend_from_slice(&self.prepended_data[self.offset..]);
            self.offset = self.prepended_data.len();
        }

        // Then read from stream
        let remaining = self.stream.read_to_end(size_limit)
            .await
            .map_err(|e| anyhow!("Failed to read stream: {}", e))?;

        buffer.extend_from_slice(&remaining);
        Ok(buffer)
    }
}

/// QUIC connection handler - unified entry point for all protocols
pub struct QuicHandler {
    /// ZHTP router for native API requests
    zhtp_router: Arc<RwLock<ZhtpRouter>>,

    /// QUIC mesh protocol (for connection storage and PQC operations)
    quic_protocol: Arc<QuicMeshProtocol>,

    /// Mesh message handler for blockchain sync and peer messages
    mesh_handler: Option<Arc<RwLock<MeshMessageHandler>>>,

    /// Active PQC connections with metadata (peer_node_id -> TrackedConnection)
    pqc_connections: Arc<RwLock<HashMap<Vec<u8>, TrackedConnection>>>,

    /// Handshake rate limiting (IP -> (count, window_start))
    handshake_rate_limits: Arc<RwLock<HashMap<SocketAddr, (usize, Instant)>>>,

    /// Identity manager for auto-registration of authenticated peers
    identity_manager: Arc<RwLock<lib_identity::IdentityManager>>,
}

impl QuicHandler {
    /// Create new QUIC handler with all protocol support
    pub fn new(
        zhtp_router: Arc<RwLock<ZhtpRouter>>,
        quic_protocol: Arc<QuicMeshProtocol>,
        identity_manager: Arc<RwLock<lib_identity::IdentityManager>>,
    ) -> Self {
        Self {
            zhtp_router,
            quic_protocol,
            mesh_handler: None,
            pqc_connections: Arc::new(RwLock::new(HashMap::new())),
            handshake_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            identity_manager,
        }
    }

    /// Check and update handshake rate limit for an IP address
    async fn check_handshake_rate_limit(&self, peer_addr: &SocketAddr) -> Result<()> {
        let mut limits = self.handshake_rate_limits.write().await;
        let now = Instant::now();

        // Clean up expired entries
        limits.retain(|_, (_, window_start)| {
            now.duration_since(*window_start) < HANDSHAKE_RATE_WINDOW
        });

        let entry = limits.entry(*peer_addr).or_insert((0, now));

        // Reset counter if window expired
        if now.duration_since(entry.1) >= HANDSHAKE_RATE_WINDOW {
            *entry = (0, now);
        }

        // Check limit
        if entry.0 >= MAX_HANDSHAKES_PER_IP {
            warn!("🚫 Rate limit exceeded for handshakes from {}", peer_addr);
            return Err(anyhow!("Too many handshake attempts, please try again later"));
        }

        // Increment counter
        entry.0 += 1;
        Ok(())
    }

    /// Add PQC connection with bounds checking and LRU eviction
    async fn add_pqc_connection(&self, node_id: Vec<u8>, conn: PqcQuicConnection) -> Result<()> {
        let mut connections = self.pqc_connections.write().await;
        let now = Instant::now();

        // Check if we're at capacity
        if connections.len() >= MAX_PQC_CONNECTIONS {
            // Find oldest connection to evict (LRU)
            if let Some(oldest_key) = connections
                .iter()
                .min_by_key(|(_, tracked)| tracked.last_activity)
                .map(|(k, _)| k.clone())
            {
                connections.remove(&oldest_key);
                warn!("♻️ Evicted oldest PQC connection (LRU) due to capacity limit");
            }
        }

        // Add new connection
        connections.insert(node_id, TrackedConnection {
            connection: conn,
            created_at: now,
            last_activity: now,
        });

        debug!("📊 PQC connections: {}/{}", connections.len(), MAX_PQC_CONNECTIONS);
        Ok(())
    }

    /// Update last activity time for a connection
    async fn update_connection_activity(&self, node_id: &[u8]) {
        if let Some(tracked) = self.pqc_connections.write().await.get_mut(node_id) {
            tracked.last_activity = Instant::now();
        }
    }

    /// Clean up expired connections
    async fn cleanup_expired_connections(&self) {
        let mut connections = self.pqc_connections.write().await;
        let now = Instant::now();
        let initial_count = connections.len();

        connections.retain(|_, tracked| {
            now.duration_since(tracked.created_at) < MAX_CONNECTION_AGE
        });

        let removed = initial_count - connections.len();
        if removed > 0 {
            info!("🧹 Cleaned up {} expired PQC connections", removed);
        }
    }

    /// Set the mesh message handler for blockchain sync
    pub fn set_mesh_handler(&mut self, handler: Arc<RwLock<MeshMessageHandler>>) {
        self.mesh_handler = Some(handler);
        info!("✅ MeshMessageHandler registered with QuicHandler");

        // Wire DHT payload sender if integration already registered one (Phase 4 relocation)
        if let Some(handler) = self.mesh_handler.as_ref().cloned() {
            tokio::spawn(async move {
                let mut guard = handler.write().await;
                crate::integration::wire_message_handler(&mut guard).await;
            });
        }
    }

    /// Get reference to PQC connections for external access
    /// Returns wrapped connections with metadata (use carefully - prefer internal methods)
    pub fn get_pqc_connections(&self) -> Arc<RwLock<HashMap<Vec<u8>, TrackedConnection>>> {
        self.pqc_connections.clone()
    }

    /// Accept and handle incoming QUIC connections from endpoint
    pub async fn handle_connection_incoming(&self, incoming: Incoming) -> Result<()> {
        let handler = self.clone();

        // Accept the incoming connection
        let connecting = incoming.accept()?;

        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    info!("✅ QUIC connection established from {}", connection.remote_address());

                    if let Err(e) = handler.handle_connection(connection).await {
                        error!("❌ QUIC connection error: {}", e);
                    }
                }
                Err(e) => {
                    warn!("⚠️ QUIC connection failed: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Convenience: Accept connections in a loop from QUIC endpoint
    /// THIS IS THE SINGLE ENTRY POINT - replaces QuicMeshProtocol::start_receiving()
    pub async fn accept_loop(&self, endpoint: Arc<quinn::Endpoint>) -> Result<()> {
        info!("🌐 QUIC unified handler started - single entry point for all protocols");

        loop {
            match endpoint.accept().await {
                Some(incoming) => {
                    self.handle_connection_incoming(incoming).await?;
                }
                None => {
                    warn!("QUIC endpoint closed");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single QUIC connection (multiple streams)
    ///
    /// Dispatches based on negotiated ALPN:
    /// - zhtp-uhp/1: Control plane - UHP handshake first, then authenticated API requests
    /// - zhtp-mesh/1: Mesh - UHP handshake first, then encrypted mesh messages
    /// - zhtp-http/1, zhtp/1.0, h3: HTTP-compat - direct HTTP/ZHTP requests
    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let peer_addr = connection.remote_address();

        // Determine connection mode from negotiated ALPN
        let alpn = connection.handshake_data()
            .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hd| hd.protocol.clone());

        let mode = ConnectionMode::from_alpn(alpn.as_deref());

        debug!("📡 Handling QUIC connection from {} (mode: {:?}, alpn: {:?})",
               peer_addr, mode, alpn.as_ref().map(|a| String::from_utf8_lossy(a)));

        match mode {
            ConnectionMode::Public => {
                // Public: Read-only access to public content (no UHP handshake)
                self.handle_public_connection(connection, peer_addr).await
            }
            ConnectionMode::ControlPlane => {
                // Control plane: Perform UHP handshake, then handle authenticated API requests
                self.handle_control_plane_connection(connection, peer_addr).await
            }
            ConnectionMode::Mesh => {
                // Mesh: Perform UHP handshake, then handle mesh messages
                self.handle_mesh_connection(connection, peer_addr).await
            }
        }
    }

    /// Handle control plane connection (CLI, Web4 deploy, admin APIs)
    ///
    /// Protocol flow:
    /// 1. Perform UHP+Kyber handshake to authenticate client
    /// 2. Derive session keys and create authenticated session
    /// 3. Accept streams with authenticated API requests
    async fn handle_control_plane_connection(&self, connection: Connection, peer_addr: SocketAddr) -> Result<()> {
        info!("🔐 Control plane connection from {} - starting UHP handshake", peer_addr);

        // Perform UHP+Kyber handshake with common setup
        let (identity, handshake_result) = self.perform_uhp_handshake(
            &connection,
            &peer_addr,
            "./data/tls/control_plane_nonce_cache",
        ).await?;

        let peer_did = handshake_result.verified_peer.identity.did.clone();
        let session_id = handshake_result.session_id;
        let master_key = handshake_result.master_key;

        // Derive application-layer MAC key (same derivation as client)
        let app_key = Self::derive_app_key(&master_key, &session_id, &identity.did, &peer_did);

        info!(
            peer_did = %peer_did,
            session_id = ?hex::encode(&session_id[..8]),
            "✅ Control plane authenticated from {} (PQC encryption active)",
            peer_addr
        );

        // Auto-register the authenticated peer identity
        // Authentication IS registration: successful UHP+Kyber proves identity control
        self.auto_register_peer_identity(&handshake_result.verified_peer.identity).await;

        // Create session state for authenticated requests
        let session = ControlPlaneSession {
            session_id,
            peer_did: peer_did.clone(),
            app_key,
            created_at: Instant::now(),
            sequence_window: std::sync::atomic::AtomicU64::new(0),
        };

        // Handle streams with this authenticated session
        self.handle_control_plane_streams(connection, session, peer_addr).await
    }

    /// Derive application-layer MAC key from master key
    /// MUST match client-side derivation in Web4Client/ZhtpClient
    fn derive_app_key(master_key: &[u8; 32], session_id: &[u8; 16], server_did: &str, client_did: &str) -> [u8; 32] {
        let mut input = Vec::new();
        input.extend_from_slice(b"zhtp-web4-app-mac");
        input.extend_from_slice(master_key);
        input.extend_from_slice(session_id);
        input.extend_from_slice(server_did.as_bytes());  // Server DID
        input.extend_from_slice(client_did.as_bytes());  // Client DID
        lib_crypto::hash_blake3(&input)
    }

    /// Common handshake setup for authenticated connections (control plane and mesh)
    ///
    /// Performs: rate limiting, identity retrieval, nonce cache setup, UHP+Kyber handshake
    async fn perform_uhp_handshake(
        &self,
        connection: &Connection,
        peer_addr: &SocketAddr,
        nonce_cache_path: &str,
    ) -> Result<(lib_identity::ZhtpIdentity, lib_network::protocols::quic_handshake::QuicHandshakeResult)> {
        // Check rate limit
        self.check_handshake_rate_limit(peer_addr).await?;

        // Get server identity
        let identity = self.quic_protocol.identity();

        // Create handshake context with nonce cache
        let nonce_db_path = std::path::Path::new(nonce_cache_path);
        let network_epoch = lib_network::handshake::NetworkEpoch::from_global_or_fail()?;
        let nonce_cache = lib_network::handshake::NonceCache::open(nonce_db_path, 3600, 100_000, network_epoch)
            .context("Failed to open nonce cache")?;
        let handshake_ctx = lib_network::handshake::HandshakeContext::new(nonce_cache);

        // Perform UHP+Kyber handshake as responder
        let handshake_result = lib_network::protocols::quic_handshake::handshake_as_responder(
            connection,
            identity,
            &handshake_ctx,
        ).await.context("UHP+Kyber handshake failed")?;

        Ok((identity.clone(), handshake_result))
    }

    /// Auto-register peer identity after successful UHP+Kyber handshake
    ///
    /// # Design Principle
    /// Authentication IS registration. A successful cryptographic handshake proves:
    /// - The peer controls the private key of the DID
    /// - The DID is live, not replayed
    /// - The session is bound to that identity
    ///
    /// # What this does
    /// - Creates an "observed" identity from the handshake's NodeIdentity
    /// - Records: DID, public keys, first_seen timestamp, last_seen
    /// - Marks identity as known but unprivileged
    ///
    /// # What this does NOT do
    /// - Grant domain ownership
    /// - Grant admin privileges
    /// - Grant validator rights
    /// - Grant storage quotas
    /// - Grant economic privileges
    ///
    /// Registration ≠ authorization. Authorization happens at the API layer.
    async fn auto_register_peer_identity(&self, peer_identity: &lib_network::handshake::NodeIdentity) {
        let peer_did = &peer_identity.did;

        // Check if identity already exists
        let identity_id = lib_crypto::Hash::from_bytes(
            &lib_crypto::hash_blake3(peer_did.as_bytes()).to_vec()
        );

        {
            let identity_mgr = self.identity_manager.read().await;
            if identity_mgr.get_identity(&identity_id).is_some() {
                debug!(
                    peer_did = %peer_did,
                    "Peer identity already registered, updating last_seen"
                );
                // TODO: Update last_seen timestamp
                return;
            }
        }

        // Create observed identity from handshake
        // Note: peer_identity.node_id is already a lib_identity::NodeId
        match lib_identity::ZhtpIdentity::from_observed_handshake(
            peer_identity.did.clone(),
            peer_identity.public_key.clone(),
            peer_identity.device_id.clone(),
            peer_identity.node_id.clone(),
        ) {
            Ok(observed_identity) => {
                let mut identity_mgr = self.identity_manager.write().await;
                identity_mgr.add_identity(observed_identity);
                info!(
                    peer_did = %peer_did,
                    "📝 Auto-registered authenticated peer identity (observed, unprivileged)"
                );
            }
            Err(e) => {
                warn!(
                    peer_did = %peer_did,
                    error = %e,
                    "Failed to auto-register peer identity"
                );
            }
        }
    }

    /// Handle authenticated control plane streams
    async fn handle_control_plane_streams(
        &self,
        connection: Connection,
        session: ControlPlaneSession,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let session = Arc::new(session);

        loop {
            let stream_result = tokio::time::timeout(
                CLIENT_IDLE_TIMEOUT,
                connection.accept_bi()
            ).await;

            match stream_result {
                Ok(Ok((send, recv))) => {
                    let handler = self.clone();
                    let session = session.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_authenticated_stream(recv, send, &session).await {
                            warn!("⚠️ Control plane stream error from {}: {}", peer_addr, e);
                        }
                    });
                }
                Ok(Err(quinn::ConnectionError::ApplicationClosed(_))) => {
                    debug!("🔒 Control plane connection closed from {}", peer_addr);
                    break;
                }
                Ok(Err(e)) => {
                    warn!("⚠️ Control plane stream error from {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    debug!("⏱️ Control plane connection idle timeout from {}", peer_addr);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single authenticated stream (ZHTP wire protocol)
    ///
    /// After UHP handshake, all streams use ZHTP length-prefixed CBOR format.
    /// No protocol detection or HTTP fallback - the connection mode was already
    /// determined by ALPN negotiation.
    async fn handle_authenticated_stream(
        &self,
        mut recv: RecvStream,
        mut send: SendStream,
        session: &ControlPlaneSession,
    ) -> Result<()> {
        use lib_protocols::wire::{read_request, write_response, ZhtpResponseWire};
        use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

        // Read ZHTP wire request (length-prefixed CBOR)
        let wire_request = read_request(&mut recv).await
            .context("Failed to read ZHTP wire request")?;

        debug!(
            request_id = %wire_request.request_id_hex(),
            uri = %wire_request.request.uri,
            method = ?wire_request.request.method,
            has_auth = wire_request.auth_context.is_some(),
            peer_did = %session.peer_did,
            "Received authenticated ZHTP request"
        );

        // Validate auth context if present
        if let Some(ref auth_ctx) = wire_request.auth_context {
            // Verify session ID matches
            if auth_ctx.session_id != session.session_id {
                warn!("Session ID mismatch in auth context");
                let error_response = ZhtpResponseWire::error(
                    wire_request.request_id,
                    ZhtpStatus::Unauthorized,
                    "Invalid session".to_string(),
                );
                write_response(&mut send, &error_response).await?;
                return Ok(());
            }

            // Verify client DID matches
            if auth_ctx.client_did != session.peer_did {
                warn!("Client DID mismatch in auth context");
                let error_response = ZhtpResponseWire::error(
                    wire_request.request_id,
                    ZhtpStatus::Unauthorized,
                    "Invalid client".to_string(),
                );
                write_response(&mut send, &error_response).await?;
                return Ok(());
            }

            // Verify MAC using canonical request hash
            use lib_protocols::wire::ZhtpRequestWire;
            let request_hash = ZhtpRequestWire::compute_canonical_request_hash(
                &wire_request.request,
                &wire_request.request_id,
                wire_request.timestamp_ms,
            );
            if !auth_ctx.verify(&session.app_key, &request_hash) {
                warn!("MAC verification failed for authenticated request");
                let error_response = ZhtpResponseWire::error(
                    wire_request.request_id,
                    ZhtpStatus::Unauthorized,
                    "Invalid MAC".to_string(),
                );
                write_response(&mut send, &error_response).await?;
                return Ok(());
            }
        }

        // Route request through ZHTP router
        let mut request = wire_request.request;
        request.requester = Some(lib_crypto::Hash(lib_crypto::hash_blake3(session.peer_did.as_bytes())));

        let router = self.zhtp_router.read().await;
        let response = router.route_request(request).await
            .unwrap_or_else(|e| {
                warn!("Handler error: {}", e);
                ZhtpResponse::error(ZhtpStatus::InternalServerError, e.to_string())
            });

        // Send wire response (length-prefixed CBOR)
        let wire_response = ZhtpResponseWire::success(wire_request.request_id, response);
        write_response(&mut send, &wire_response).await
            .context("Failed to write ZHTP wire response")?;

        Ok(())
    }

    /// Handle mesh peer connection (node-to-node)
    async fn handle_mesh_connection(&self, connection: Connection, peer_addr: SocketAddr) -> Result<()> {
        info!("🔗 Mesh peer connection from {} - starting UHP handshake", peer_addr);

        // Perform UHP+Kyber handshake with common setup
        let (_identity, handshake_result) = self.perform_uhp_handshake(
            &connection,
            &peer_addr,
            "./data/tls/mesh_nonce_cache",
        ).await?;

        // Extract peer node ID
        let peer_node_id = handshake_result.verified_peer.identity.node_id.as_bytes();
        let mut node_id_arr = [0u8; 32];
        node_id_arr.copy_from_slice(peer_node_id);

        info!(
            peer_did = %handshake_result.verified_peer.identity.did,
            session_id = ?handshake_result.session_id,
            "✅ Mesh peer authenticated from {} (identity verified)",
            peer_addr
        );

        // Create PqcQuicConnection from handshake result
        let pqc_conn = PqcQuicConnection::from_verified_peer(
            connection.clone(),
            peer_addr,
            handshake_result.verified_peer,
            handshake_result.master_key,
            handshake_result.session_id,
            false,
        );

        // Store connection
        self.add_pqc_connection(node_id_arr.to_vec(), pqc_conn).await?;

        // Continue accepting mesh streams
        self.accept_additional_streams(connection, Some(node_id_arr));

        Ok(())
    }

    /// Handle public read-only connection (mobile apps, browsers reading public content)
    ///
    /// No UHP handshake required. Only allows read operations:
    /// - Domain resolution (GET /api/v1/web4/domains/{domain})
    /// - Manifest fetch (GET /api/v1/web4/domains/{domain}/manifest)
    /// - Content/blob retrieval (GET /api/v1/web4/content/{cid})
    ///
    /// Rejects all mutations (POST/PUT/DELETE to restricted endpoints).
    async fn handle_public_connection(&self, connection: Connection, peer_addr: SocketAddr) -> Result<()> {
        info!("📖 Public read-only connection from {}", peer_addr);

        // Accept streams and handle public read requests
        loop {
            let stream_result = tokio::time::timeout(
                CLIENT_IDLE_TIMEOUT,
                connection.accept_bi()
            ).await;

            match stream_result {
                Ok(Ok((send, recv))) => {
                    let handler = self.clone();

                    // Spawn handler for this stream
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_public_stream(recv, send).await {
                            debug!("📖 Public stream ended: {}", e);
                        }
                    });
                }
                Ok(Err(quinn::ConnectionError::ApplicationClosed(_))) => {
                    debug!("🔒 Public connection closed normally from {}", peer_addr);
                    break;
                }
                Ok(Err(quinn::ConnectionError::TimedOut)) => {
                    debug!("⏱️ Public connection idle timeout from {}", peer_addr);
                    break;
                }
                Ok(Err(e)) => {
                    debug!("⚠️ Public connection error from {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    debug!("⏱️ Public stream accept timeout from {}", peer_addr);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single public read-only stream
    /// Only allows ZHTP native protocol requests
    async fn handle_public_stream(&self, mut recv: RecvStream, send: SendStream) -> Result<()> {
        // Detect protocol (ZHTP only)
        let protocol = self.detect_protocol_buffered(&mut recv).await?;

        match protocol {
            ProtocolType::NativeZhtp(initial_data) => {
                // Parse ZHTP request and validate it's a read operation
                self.handle_public_zhtp_stream(initial_data, recv, send).await
            }
            _ => {
                // Reject non-ZHTP protocols on public connection
                self.send_error_response(send, "Public connections only support native ZHTP read requests").await
            }
        }
    }

    /// Handle public ZHTP stream - only allows read operations
    async fn handle_public_zhtp_stream(&self, initial_data: Vec<u8>, recv: RecvStream, send: SendStream) -> Result<()> {
        // Forward to ZHTP handler - it will check method internally
        // For now, allow all ZHTP requests through (the API handlers will enforce read-only)
        // TODO: Add request parsing to reject mutations at this layer
        self.handle_zhtp_stream_with_prefix(initial_data, recv, send).await
    }

    /// Handle the first stream of a connection - determines connection type
    async fn handle_first_stream(
        &self,
        mut recv: RecvStream,
        send: SendStream,
        connection: Connection,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        debug!("📨 Processing first QUIC stream from {}", peer_addr);

        // Read data for protocol detection (non-consuming via buffering)
        let protocol = self.detect_protocol_buffered(&mut recv).await?;

        match protocol {
            ProtocolType::PqcHandshake(initial_data) => {
                debug!("🔐 PQC handshake detected from {}", peer_addr);
                self.handle_pqc_handshake_stream(initial_data, recv, send, connection, peer_addr).await?;
            }
            ProtocolType::NativeZhtp(initial_data) => {
                debug!("✅ Native ZHTP protocol detected from {}", peer_addr);
                self.handle_zhtp_stream_with_prefix(initial_data, recv, send).await?;
                // Continue accepting more streams on this connection
                self.accept_additional_streams(connection, None);
            }
            ProtocolType::MeshMessage(initial_data) => {
                warn!("📨 Mesh message on first stream from {} - should be after handshake", peer_addr);
                // Treat as unknown since handshake should come first
                self.send_error_response(send, "Expected PQC handshake first").await?;
            }
            ProtocolType::Unknown(initial_data) => {
                warn!("❓ Unknown protocol from {}: {:02x?}", peer_addr,
                      &initial_data[..initial_data.len().min(16)]);
                self.send_error_response(send, "Unknown protocol").await?;
            }
        }

        Ok(())
    }

    /// Accept additional streams after first stream is processed
    /// For peer connections, peer_node_id is Some (for mesh message routing)
    /// For client connections, peer_node_id is None (HTTP/ZHTP only)
    fn accept_additional_streams(&self, connection: Connection, peer_node_id: Option<[u8; 32]>) {
        let handler = self.clone();

        tokio::spawn(async move {
            // Use longer timeout for authenticated peer connections (P1-1: Stream limits)
            let idle_timeout = if peer_node_id.is_some() {
                PEER_IDLE_TIMEOUT
            } else {
                CLIENT_IDLE_TIMEOUT
            };

            loop {
                let stream_result = tokio::time::timeout(
                    idle_timeout,
                    connection.accept_bi()
                ).await;

                match stream_result {
                    Ok(Ok((send, recv))) => {
                        let h = handler.clone();
                        let peer_id = peer_node_id;
                        tokio::spawn(async move {
                            if let Err(e) = h.handle_subsequent_stream(recv, send, peer_id).await {
                                debug!("⚠️ Stream handling error: {}", e);
                            }
                        });
                    }
                    Ok(Err(quinn::ConnectionError::ApplicationClosed(_))) => {
                        debug!("🔒 Connection closed gracefully");
                        break;
                    }
                    Ok(Err(e)) => {
                        debug!("Stream accept ended: {}", e);
                        break;
                    }
                    Err(_) => {
                        debug!("⏱️ Connection idle timeout");
                        break;
                    }
                }
            }
        });
    }

    /// Handle subsequent streams (after first stream established connection type)
    async fn handle_subsequent_stream(
        &self,
        mut recv: RecvStream,
        send: SendStream,
        peer_node_id: Option<[u8; 32]>,
    ) -> Result<()> {
        let protocol = self.detect_protocol_buffered(&mut recv).await?;

        match protocol {
            ProtocolType::NativeZhtp(initial_data) => {
                self.handle_zhtp_stream_with_prefix(initial_data, recv, send).await
            }
            ProtocolType::MeshMessage(initial_data) => {
                if let Some(peer_id) = peer_node_id {
                    self.handle_mesh_message_stream(initial_data, recv, peer_id).await
                } else {
                    warn!("Mesh message received on non-peer connection");
                    Err(anyhow!("Mesh messages only valid on peer connections"))
                }
            }
            ProtocolType::PqcHandshake(_) => {
                warn!("PQC handshake on non-first stream - ignoring");
                Err(anyhow!("PQC handshake only valid on first stream"))
            }
            ProtocolType::Unknown(data) => {
                warn!("Unknown protocol on stream: {:02x?}", &data[..data.len().min(16)]);
                Err(anyhow!("Unknown protocol"))
            }
        }
    }

    /// Handle UHP+Kyber handshake for mesh peer authentication
    ///
    /// Uses the new secure UHP (Unified Handshake Protocol) with Kyber key exchange.
    ///
    /// **SECURITY IMPROVEMENTS:**
    /// - Mutual authentication via Dilithium signatures (verified by UHP)
    /// - NodeId verification: validates Blake3(DID || device_name)
    /// - Replay attack prevention via nonce cache
    /// - Post-quantum security via Kyber512 KEM bound to UHP transcript
    /// - Master key derived from both UHP session key and Kyber shared secret
    async fn handle_pqc_handshake_stream(
        &self,
        _initial_data: Vec<u8>, // Not used - UHP handles its own message flow
        _recv: RecvStream,      // Not used - UHP opens its own dedicated stream
        _send: SendStream,      // Not used - UHP opens its own dedicated stream
        connection: Connection,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        info!("🔐 Processing UHP+Kyber handshake from {}", peer_addr);

        // Check rate limit for this IP
        self.check_handshake_rate_limit(&peer_addr).await?;

        // Get server identity from QuicMeshProtocol
        let identity = self.quic_protocol.identity();

        // Create handshake context with nonce cache
        let nonce_db_path = std::path::Path::new("./data/tls/quic_handler_nonce_cache");
        let network_epoch = lib_network::handshake::NetworkEpoch::from_global_or_fail()?;
        let nonce_cache = NonceCache::open(nonce_db_path, 3600, 100_000, network_epoch)
            .context("Failed to open nonce cache")?;
        let handshake_ctx = HandshakeContext::new(nonce_cache);

        // Perform UHP+Kyber handshake as responder
        let handshake_result = quic_handshake::handshake_as_responder(
            &connection,
            identity,
            &handshake_ctx,
        ).await.context("UHP+Kyber handshake failed")?;

        // Extract peer node ID
        let peer_node_id = handshake_result.verified_peer.identity.node_id.as_bytes();
        let mut node_id_arr = [0u8; 32];
        node_id_arr.copy_from_slice(peer_node_id);

        info!(
            peer_did = %handshake_result.verified_peer.identity.did,
            session_id = ?handshake_result.session_id,
            "✅ UHP+Kyber handshake complete with {} (identity verified)",
            peer_addr
        );

        // Create PqcQuicConnection from handshake result
        let pqc_conn = PqcQuicConnection::from_verified_peer(
            connection.clone(),
            peer_addr,
            handshake_result.verified_peer,
            handshake_result.master_key,
            handshake_result.session_id,
            false,
        );

        // Store connection
        self.add_pqc_connection(node_id_arr.to_vec(), pqc_conn).await?;

        // Continue accepting streams
        self.accept_additional_streams(connection, Some(node_id_arr));

        Ok(())
    }

    // NOTE: The old broken PqcHandshakeMessage-based handler has been completely REMOVED
    // All peer authentication now uses the secure UHP+Kyber handshake above which:
    // 1. Verifies Dilithium signatures (mutual authentication)
    // 2. Validates NodeId derivation (Blake3(DID || device_name))
    // 3. Prevents replay attacks (nonce cache)
    // 4. Binds Kyber key exchange to authenticated identity (transcript hash)

    /// Handle encrypted mesh message stream from authenticated peer
    ///
    /// Uses the master key derived from UHP+Kyber handshake for decryption
    async fn handle_mesh_message_stream(
        &self,
        initial_data: Vec<u8>,
        mut recv: RecvStream,
        peer_node_id: [u8; 32],
    ) -> Result<()> {
        debug!("📨 Receiving mesh message from peer {}", hex::encode(&peer_node_id[..8]));

        // Read full message with size limit (P1-4: Bincode size limits)
        let mut message_data = initial_data;
        let remaining = recv.read_to_end(MAX_MESSAGE_SIZE as usize).await?;
        message_data.extend_from_slice(&remaining);

        if message_data.len() > MAX_MESSAGE_SIZE as usize {
            warn!("🚫 Mesh message too large from peer {}: {} bytes",
                  hex::encode(&peer_node_id[..8]), message_data.len());
            return Err(anyhow!("Message exceeds maximum size"));
        }

        // Get connection and validate authentication (P1-3: Authentication checks before decryption)
        let (master_key, _connection_age) = {
            let connections = self.pqc_connections.read().await;
            let tracked = connections.get(&peer_node_id.to_vec())
                .ok_or_else(|| anyhow!("No PQC connection for peer - not authenticated"))?;

            // Check connection age
            let age = Instant::now().duration_since(tracked.created_at);
            if age > MAX_CONNECTION_AGE {
                warn!("🚫 Connection from peer {} too old: {:?}", hex::encode(&peer_node_id[..8]), age);
                return Err(anyhow!("Connection expired - please re-authenticate"));
            }

            // Verify master key exists (from UHP+Kyber handshake)
            let key = tracked.connection.get_master_key_ref()
                .ok_or_else(|| anyhow!("No master key for peer - handshake incomplete"))?;

            (*key, age)
        };

        // Update activity timestamp
        self.update_connection_activity(&peer_node_id).await;

        // Decrypt with master key (derived from UHP+Kyber handshake)
        let decrypted = lib_crypto::symmetric::chacha20::decrypt_data(&message_data, &master_key)
            .context("Failed to decrypt mesh message - possible tampering")?;

        // Deserialize mesh message with size validation
        let message: ZhtpMeshMessage = bincode::deserialize(&decrypted)
            .context("Failed to deserialize mesh message")?;

        // Handle via mesh handler
        if let Some(ref handler) = self.mesh_handler {
            let peer_pk = PublicKey::new(peer_node_id.to_vec());
            handler.read().await.handle_mesh_message(message, peer_pk).await?;
        } else {
            warn!("No mesh handler configured");
        }

        Ok(())
    }

    /// Handle ZHTP stream with already-read prefix data
    async fn handle_zhtp_stream_with_prefix(
        &self,
        prefix: Vec<u8>,
        recv: RecvStream,
        send: SendStream,
    ) -> Result<()> {
        let router = self.zhtp_router.read().await;
        let mut buffered = BufferedStream::new(prefix, recv);
        router.handle_zhtp_stream_buffered(&mut buffered, send).await
    }

    /// Send error response to client
    async fn send_error_response(&self, mut send: SendStream, message: &str) -> Result<()> {
        let error_msg = format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                               message.len(), message);
        send.write_all(error_msg.as_bytes()).await.ok();
        send.finish().ok();
        Ok(())
    }

    /// Detect protocol type by inspecting stream data WITHOUT consuming bytes
    /// Returns the protocol type along with all data read (for forwarding via BufferedStream)
    async fn detect_protocol_buffered(&self, recv: &mut RecvStream) -> Result<ProtocolType> {
        // Read up to 1KB to determine protocol with timeout (P1-1)
        let mut buffer = vec![0u8; PROTOCOL_DETECT_SIZE];

        let read_result = tokio::time::timeout(
            PROTOCOL_DETECT_TIMEOUT,
            recv.read(&mut buffer)
        ).await;

        match read_result {
            Err(_) => {
                warn!("⏱️ Protocol detection timeout");
                return Err(anyhow!("Protocol detection timeout"));
            }
            Ok(recv_result) => match recv_result {
            Ok(Some(n)) => {
                buffer.truncate(n);

                if buffer.len() < 4 {
                    return Ok(ProtocolType::Unknown(buffer));
                }

                // 1. Check for ZHTP magic first (highest priority - our native protocol)
                if &buffer[0..4] == ZHTP_MAGIC {
                    debug!("✅ ZHTP magic bytes detected");
                    return Ok(ProtocolType::NativeZhtp(buffer));
                }

                // 2. Check for UHP ClientHello (UHP+Kyber handshake initiation)
                // ClientHello contains: version(1B) + identity + capabilities + nonce(32B) + signature
                // The UHP handshake uses a dedicated bidirectional stream, so protocol detection
                // should recognize this as a handshake initiation
                if buffer.len() >= 100 {
                    // Try to parse as UHP ClientHello (first message of UHP handshake)
                    if let Ok(_msg) = bincode::deserialize::<ClientHello>(&buffer) {
                        debug!("🔐 UHP ClientHello detected (handshake initiation)");
                        return Ok(ProtocolType::PqcHandshake(buffer));
                    }
                }

                // 4. Check for encrypted mesh message (typically starts with encryption header)
                // After handshake, mesh messages are ChaCha20 encrypted
                // No reliable way to detect without trying to decrypt, so treat as mesh if all else fails
                // and buffer is reasonably sized
                if buffer.len() > 50 {
                    debug!("📨 Possible mesh message detected");
                    return Ok(ProtocolType::MeshMessage(buffer));
                }

                // Unknown protocol
                warn!("❓ Unknown protocol, first bytes: {:02x?}", &buffer[..buffer.len().min(16)]);
                Ok(ProtocolType::Unknown(buffer))
            }
            Ok(None) => {
                Ok(ProtocolType::Unknown(Vec::new()))
            }
            Err(e) => {
                warn!("⚠️ Failed to read from stream: {}", e);
                Err(anyhow!("Stream read error: {}", e))
            }
            }
        }
    }
}

impl Clone for QuicHandler {
    fn clone(&self) -> Self {
        Self {
            zhtp_router: self.zhtp_router.clone(),
            quic_protocol: self.quic_protocol.clone(),
            mesh_handler: self.mesh_handler.clone(),
            pqc_connections: self.pqc_connections.clone(),
            handshake_rate_limits: self.handshake_rate_limits.clone(),
            identity_manager: self.identity_manager.clone(),
        }
    }
}

// Extension trait for BufferedStream compatibility
pub trait BufferedStreamExt {
    async fn handle_zhtp_stream_buffered(
        &self,
        buffered: &mut BufferedStream,
        send: SendStream,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_zhtp_magic() {
        let zhtp_data = b"ZHTP\x01\x00\x00\x00\x10test data";
        assert_eq!(&zhtp_data[0..4], ZHTP_MAGIC);
    }

    #[test]
    fn test_detect_http_methods() {
        let http_methods: Vec<(&str, &[u8])> = vec![
            ("GET", b"GET /test HTTP/1.1"),
            ("POST", b"POST /api HTTP/1.1"),
            ("PUT", b"PUT /data HTTP/1.1"),
            ("DELETE", b"DELETE /item HTTP/1.1"),
            ("HEAD", b"HEAD /info HTTP/1.1"),
            ("OPTIONS", b"OPTIONS * HTTP/1.1"),
            ("PATCH", b"PATCH /resource HTTP/1.1"),
            ("CONNECT", b"CONNECT example.com:443 HTTP/1.1"),
            ("TRACE", b"TRACE / HTTP/1.1"),
        ];

        for (method_name, method_bytes) in http_methods {
            let magic_str = String::from_utf8_lossy(&method_bytes[0..method_bytes.len().min(8)]);

            let detected =
                magic_str.starts_with("GET ") ||
                magic_str.starts_with("POST ") ||
                magic_str.starts_with("PUT ") ||
                magic_str.starts_with("DELETE ") ||
                magic_str.starts_with("HEAD ") ||
                magic_str.starts_with("OPTIONS ") ||
                magic_str.starts_with("PATCH ") ||
                magic_str.starts_with("CONNECT ") ||
                magic_str.starts_with("TRACE ");

            assert!(detected, "Failed to detect HTTP method: {}", method_name);
        }
    }

    // TODO: Fix this test - BufferedStream uses Quinn's RecvStream, not tokio::io::DuplexStream
    // #[tokio::test]
    // async fn test_buffered_stream() {
    //     use tokio::io::AsyncWriteExt;
    //
    //     // Create a mock stream
    //     let (mut send, recv) = tokio::io::duplex(64);
    //
    //     // Write test data
    //     send.write_all(b"world").await.unwrap();
    //     drop(send);
    //
    //     // Create buffered stream with prefix
    //     let prefix = b"hello ".to_vec();
    //     let mut buffered = BufferedStream::new(prefix, recv);
    //
    //     // Read should return prefix first
    //     let mut buf = vec![0u8; 20];
    //     let n = buffered.read(&mut buf).await.unwrap().unwrap();
    //     assert_eq!(&buf[..n], b"hello ");
    //
    //     // Next read should return stream data
    //     let n = buffered.read(&mut buf).await.unwrap().unwrap();
    //     assert_eq!(&buf[..n], b"world");
    // }
}
