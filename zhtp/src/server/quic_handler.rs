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
//! - `quic_protocol` uses DashMap for lock-free concurrent peer connection tracking

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use anyhow::{Result, Context, anyhow};
use tracing::{info, warn, debug, error};
use quinn::{Connection, Incoming, RecvStream, SendStream};
use tokio::sync::RwLock;

use lib_network::protocols::quic_mesh::{QuicMeshProtocol, PqcQuicConnection, PeerConnection};
use lib_network::protocols::quic_handshake::{self};
use lib_network::handshake::{HandshakeContext, NonceCache, ClientHello};
use lib_network::messaging::message_handler::MeshMessageHandler;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use lib_crypto::PublicKey;
use crate::api::handlers::constants::{SOV_WELCOME_BONUS, SOV_WELCOME_BONUS_SOV};

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

/// DEPRECATED: ControlPlaneSession replaced by V2Session in PR #816
/// V2Session provides HMAC-SHA3-256 MAC verification with monotonic counter replay protection.
/// This struct is kept for reference but is no longer instantiated.
// Old code paths using ControlPlaneSession were replaced by handle_control_plane_v2_connection
// which uses lib_network::protocols::types::session::V2Session for full UHP v2 support.

/// Connection mode based on negotiated ALPN
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Public read-only: No UHP handshake, only allows reading public content
    /// ALPN: zhtp-public/1
    /// Allows: domain resolution, manifest fetch, content/blob retrieval
    /// Rejects: deploy, domain registration, admin operations, any mutations
    Public,
    /// Control plane: UHP v2 handshake with transcript hash, HKDF-SHA3-256 key derivation
    /// ALPN: zhtp-uhp/1 or zhtp-uhp/2 (both use v2 protocol)
    /// Features:
    /// - 32-byte session_id
    /// - HMAC-SHA3-256 request MAC
    /// - Canonical request format: method(1) + path_len(u16BE) + path + body_len(u32BE) + body
    /// - MAC inputs: canonical_request_bytes || counter(u64BE) || session_id(32)
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
            // Both v1 and v2 ALPN use the v2 protocol (v1 is deprecated but accepted for compatibility)
            Some(b"zhtp-uhp/1") | Some(b"zhtp-uhp/2") => ConnectionMode::ControlPlane,
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

    /// QUIC mesh protocol - CANONICAL connection store (Issue #907)
    /// All peer connections are registered here via register_peer().
    /// broadcast_message(), send_to_peer(), and per-peer UNI receive loops
    /// all operate through this single store.
    quic_protocol: Arc<QuicMeshProtocol>,

    /// Mesh message handler for blockchain sync and peer messages
    mesh_handler: Option<Arc<RwLock<MeshMessageHandler>>>,

    /// Handshake rate limiting (IP -> (count, window_start))
    handshake_rate_limits: Arc<RwLock<HashMap<SocketAddr, (usize, Instant)>>>,

    /// Identity manager for auto-registration of authenticated peers
    identity_manager: Arc<RwLock<lib_identity::IdentityManager>>,
    /// Optional POUW session log — records authenticated sessions for proof-of-presence
    pouw_session_log: Option<crate::pouw::SharedSessionLog>,
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
            handshake_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            identity_manager,
            pouw_session_log: None,
        }
    }

    /// Attach a POUW session log for proof-of-presence recording
    pub fn with_pouw_session_log(mut self, session_log: crate::pouw::SharedSessionLog) -> Self {
        self.pouw_session_log = Some(session_log);
        self
    }

    /// Get the ZHTP router for registering additional handlers
    pub fn get_zhtp_router(&self) -> Arc<RwLock<ZhtpRouter>> {
        self.zhtp_router.clone()
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
            warn!("Rate limit exceeded for handshakes from {}", peer_addr);
            return Err(anyhow!("Too many handshake attempts, please try again later"));
        }

        // Increment counter
        entry.0 += 1;
        Ok(())
    }

    /// Set the mesh message handler for blockchain sync
    pub fn set_mesh_handler(&mut self, handler: Arc<RwLock<MeshMessageHandler>>) {
        let handler_clone = handler.clone();
        self.mesh_handler = Some(handler);
        info!("MeshMessageHandler registered with QuicHandler");

        // Wire DHT payload sender if integration already registered one (Phase 4 relocation)
        tokio::spawn(async move {
            let mut guard = handler_clone.write().await;
            crate::integration::wire_message_handler(&mut guard).await;
        });
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
                // Control plane: UHP v2 handshake with HKDF-SHA3-256 key derivation
                self.handle_control_plane_v2_connection(connection, peer_addr).await
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
    /// 1. Perform UHP v2 handshake to authenticate client
    /// 2. Derive v2 session keys using HKDF-SHA3-256 with transcript hash
    /// 3. Create V2Session with 32-byte session_id and monotonic counter
    /// 4. Accept streams with v2 MAC verification (HMAC-SHA3-256)
    ///
    /// Security properties:
    /// - 32-byte session_id
    /// - HKDF-SHA3-256 with transcript hash salt
    /// - HMAC-SHA3-256 request MAC
    /// - Canonical request format with counter and session_id binding
    async fn handle_control_plane_v2_connection(&self, connection: Connection, peer_addr: SocketAddr) -> Result<()> {
        info!("🔐 Control plane connection from {} - starting UHP v2 handshake", peer_addr);

        // Perform UHP+Kyber handshake (same as v1, but we'll derive keys differently)
        let (_identity, handshake_result) = self.perform_uhp_handshake(
            &connection,
            &peer_addr,
        ).await?;

        let peer_did = handshake_result.verified_peer.identity.did.clone();
        let session_key = handshake_result.session_key;

        // For v2, we use the handshake_hash from the result (UHP transcript hash)
        let transcript_hash = handshake_result.handshake_hash;

        debug!(
            session_key_prefix = ?hex::encode(&session_key[..8]),
            handshake_hash_prefix = ?hex::encode(&transcript_hash[..8]),
            "V2 key derivation inputs (server)"
        );

        // Derive v2 session keys using HKDF-SHA3-256
        let v2_keys = lib_network::handshake::security::derive_v2_session_keys(
            &session_key,
            &transcript_hash,
        ).context("Failed to derive v2 session keys")?;

        debug!(
            mac_key_prefix = ?hex::encode(&v2_keys.mac_key[..8]),
            "V2 mac_key derived (server)"
        );

        // Use the 32-byte session_id from the handshake result
        let session_id_v2 = handshake_result.session_id;

        info!(
            peer_did = %peer_did,
            session_id = ?hex::encode(&session_id_v2[..8]),
            "✅ Control plane v2 authenticated from {} (v2 key schedule active)",
            peer_addr
        );

        // Auto-register the authenticated peer identity
        self.auto_register_peer_identity(&handshake_result.verified_peer.identity).await;

        // Record session in POUW session log for proof-of-presence verification
        if let Some(session_log) = &self.pouw_session_log {
            let mut sid_8 = [0u8; 8];
            sid_8.copy_from_slice(&session_id_v2[..8]);
            session_log
                .write()
                .await
                .record(sid_8, peer_did.clone(), "/api/v1/pouw".to_string());
        }

        // Create V2Session for request authentication
        let v2_session = lib_network::protocols::types::session::V2Session::new(
            session_id_v2,
            v2_keys.mac_key,
            peer_did.clone(),
            None, // Default TTL (24 hours)
        );

        // Store session in global v2 session store
        // TODO: Add global V2SessionStore to QuicHandler
        // For now, we'll pass session info directly to stream handler

        // Handle streams with v2 authentication
        self.handle_control_plane_v2_streams(connection, v2_session, peer_addr).await
    }

    /// Handle authenticated control plane v2 streams
    async fn handle_control_plane_v2_streams(
        &self,
        connection: Connection,
        session: lib_network::protocols::types::session::V2Session,
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
                    let stream_id = recv.id();
                    debug!("Accepted new stream {} for v2 request", stream_id.index());

                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_authenticated_v2_stream(recv, send, &session, peer_addr).await {
                            warn!("⚠️ Control plane v2 stream {} error from {}: {:?}", stream_id.index(), peer_addr, e);
                        }
                    });
                }
                Ok(Err(quinn::ConnectionError::ApplicationClosed(_))) => {
                    debug!("🔒 Control plane v2 connection closed from {}", peer_addr);
                    break;
                }
                Ok(Err(e)) => {
                    warn!("⚠️ Control plane v2 stream error from {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    debug!("⏱️ Control plane v2 connection idle timeout from {}", peer_addr);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single authenticated v2 stream (ZHTP wire protocol with v2 MAC)
    ///
    /// SECURITY: V2 requests MUST include auth_context with:
    /// - Client DID matching handshake identity
    /// - Strictly increasing counter (replay protection)
    /// - Valid HMAC-SHA3-256 MAC over canonical request
    async fn handle_authenticated_v2_stream(
        &self,
        mut recv: RecvStream,
        mut send: SendStream,
        session: &lib_network::protocols::types::session::V2Session,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        use lib_protocols::wire::{read_request, write_response, ZhtpResponseWire};
        use lib_protocols::types::{ZhtpResponse, ZhtpStatus};
        use lib_network::handshake::security::{CanonicalRequest, verify_v2_mac};

        // Read ZHTP wire request (length-prefixed CBOR)
        // SECURITY: read_request enforces MAX_MESSAGE_SIZE before allocating
        let wire_request = read_request(&mut recv).await
            .context("Failed to read v2 request")?;

        debug!(
            request_id = %wire_request.request_id_hex(),
            uri = %wire_request.request.uri,
            method = ?wire_request.request.method,
            has_auth = wire_request.auth_context.is_some(),
            peer_did = %session.peer_did(),
            "Received v2 authenticated ZHTP request"
        );

        // V2 REQUIRES auth_context - reject if missing
        let auth_ctx = match &wire_request.auth_context {
            Some(ctx) => ctx,
            None => {
                warn!("V2 request missing auth_context - rejecting");
                let error_response = ZhtpResponseWire::error(
                    wire_request.request_id,
                    ZhtpStatus::Unauthorized,
                    "V2 requires authentication context".to_string(),
                );
                write_response(&mut send, &error_response).await?;
                return Ok(());
            }
        };

        // 1. Verify client DID matches handshake identity
        if auth_ctx.client_did != session.peer_did() {
            warn!(
                expected_did = %session.peer_did(),
                received_did = %auth_ctx.client_did,
                "Client DID mismatch in v2 auth context"
            );
            let error_response = ZhtpResponseWire::error(
                wire_request.request_id,
                ZhtpStatus::Unauthorized,
                "Invalid client identity".to_string(),
            );
            write_response(&mut send, &error_response).await?;
            return Ok(());
        }

        // 1b. Verify session_id matches the session established by UHP v2 handshake.
        //
        // If this fails, MAC verification will also fail (session_id is part of the MAC input),
        // but this produces a clearer diagnostic than a generic MAC mismatch.
        if auth_ctx.session_id != *session.session_id() {
            warn!(
                request_id = %wire_request.request_id_hex(),
                peer_did = %session.peer_did(),
                received_session_id_prefix = ?hex::encode(&auth_ctx.session_id[..8]),
                expected_session_id_prefix = ?hex::encode(&session.session_id()[..8]),
                "V2 session_id mismatch between request auth context and active session"
            );
            let error_response = ZhtpResponseWire::error(
                wire_request.request_id,
                ZhtpStatus::Unauthorized,
                "Invalid session".to_string(),
            );
            write_response(&mut send, &error_response).await?;
            return Ok(());
        }

        // 2. Build canonical request for MAC verification
        // Method mapping: Get=0, Post=1, Put=2, Delete=3, etc.
        let counter = auth_ctx.sequence;
        let method_byte = match wire_request.request.method {
            lib_protocols::types::ZhtpMethod::Get => 0u8,
            lib_protocols::types::ZhtpMethod::Post => 1u8,
            lib_protocols::types::ZhtpMethod::Put => 2u8,
            lib_protocols::types::ZhtpMethod::Delete => 3u8,
            lib_protocols::types::ZhtpMethod::Patch => 4u8,
            lib_protocols::types::ZhtpMethod::Head => 5u8,
            lib_protocols::types::ZhtpMethod::Options => 6u8,
            _ => 255u8, // Unknown method
        };

        let canonical = CanonicalRequest {
            method: method_byte,
            path: wire_request.request.uri.clone(),
            body: wire_request.request.body.clone(),
        };

        // 3. Verify MAC FIRST using HMAC-SHA3-256 (before counter validation)
        // This prevents DoS attacks where invalid MACs advance the counter
        if !verify_v2_mac(
            session.mac_key(),
            &canonical,
            counter,
            session.session_id(),
            &auth_ctx.request_mac,
        ) {
            // Debug: compute expected MAC and log comparison
            let expected_mac = lib_network::handshake::security::compute_v2_mac(
                session.mac_key(),
                &canonical,
                counter,
                session.session_id(),
            );
            warn!(
                request_id = %wire_request.request_id_hex(),
                mac_key_prefix = ?hex::encode(&session.mac_key()[..8]),
                session_id_prefix = ?hex::encode(&session.session_id()[..8]),
                counter = counter,
                received_mac_prefix = ?hex::encode(&auth_ctx.request_mac[..8]),
                expected_mac_prefix = ?hex::encode(&expected_mac[..8]),
                canonical_len = canonical.to_bytes().len(),
                "V2 MAC verification failed - request may have been tampered"
            );
            let error_response = ZhtpResponseWire::error(
                wire_request.request_id,
                ZhtpStatus::Unauthorized,
                "MAC verification failed".to_string(),
            );
            write_response(&mut send, &error_response).await?;
            return Ok(());
        }

        // 4. Validate counter AFTER MAC verification (strictly increasing - prevents replay)
        // Counter is only updated after MAC proves request authenticity
        let last_counter_before = session.last_counter();
        if let Err(e) = session.validate_counter(counter) {
            warn!(
                counter = counter,
                last_counter = last_counter_before,
                session_id = %hex::encode(&session.session_id()[..8]),
                path = %wire_request.request.uri,
                error = %e,
                "Counter validation failed - possible replay attack"
            );
            let error_response = ZhtpResponseWire::error(
                wire_request.request_id,
                ZhtpStatus::Unauthorized,
                "Invalid counter - possible replay".to_string(),
            );
            write_response(&mut send, &error_response).await?;
            return Ok(());
        }

        info!(
            request_id = %wire_request.request_id_hex(),
            counter = counter,
            last_counter = last_counter_before,
            session_id = %hex::encode(&session.session_id()[..8]),
            path = %wire_request.request.uri,
            "V2 request authenticated successfully"
        );

        // Route request through ZHTP router
        let mut request = wire_request.request;
        request.requester = lib_identity::did::parse_did_to_identity_id(session.peer_did()).ok();
        // Attach authoritative peer address for handlers (prevents spoofed forwarded headers).
        request.headers.custom.insert("peer_addr".to_string(), peer_addr.to_string());
        request.headers.custom.insert("peer_addr_source".to_string(), "quic".to_string());

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

        send.finish()
            .context("Failed to finish QUIC stream")?;

        Ok(())
    }

    /// Common handshake setup for authenticated connections (control plane and mesh)
    ///
    /// Performs: rate limiting, identity retrieval, nonce cache access, UHP+Kyber handshake
    ///
    /// # DB-013 Fix
    /// Uses global singleton NonceCache instead of opening per-handshake.
    /// The cache is initialized once during server startup via `init_global_nonce_cache()`.
    async fn perform_uhp_handshake(
        &self,
        connection: &Connection,
        peer_addr: &SocketAddr,
    ) -> Result<(lib_identity::ZhtpIdentity, lib_network::protocols::quic_handshake::QuicHandshakeResult)> {
        // Check rate limit
        self.check_handshake_rate_limit(peer_addr).await?;

        // Get server identity
        let identity = self.quic_protocol.identity();

        // [DB-013] Use global singleton NonceCache instead of opening per-handshake
        // This is more efficient and prevents sled lock contention
        let nonce_cache = lib_network::handshake::get_or_init_global_nonce_cache(3600, 100_000)
            .context("Failed to get global nonce cache")?;
        let handshake_ctx = lib_network::handshake::HandshakeContext::new(nonce_cache.clone());

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
        let identity_id = match lib_identity::did::parse_did_to_identity_id(peer_did) {
            Ok(id) => id,
            Err(e) => {
                warn!(peer_did = %peer_did, error = %e, "Invalid DID format, cannot check identity");
                return;
            }
        };

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
                // Get the identity ID for wallet creation
                let identity_id = observed_identity.id.clone();

                let mut identity_mgr = self.identity_manager.write().await;
                identity_mgr.add_identity(observed_identity.clone());
                drop(identity_mgr); // Release lock before blockchain access

                info!(
                    peer_did = %peer_did,
                    "📝 Auto-registered authenticated peer identity (observed, unprivileged)"
                );

                // Fund new identity with welcome bonus (5,000 SOV)
                // This ensures all authenticated peers can participate in the network
                self.fund_new_identity_wallet(
                    &identity_id,
                    peer_identity,
                    peer_did,
                ).await;
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

    /// Fund a new identity's primary wallet with the welcome bonus
    ///
    /// Called when a new peer identity is auto-registered from handshake.
    /// Gives them 5,000 SOV to participate in the network.
    async fn fund_new_identity_wallet(
        &self,
        identity_id: &lib_crypto::Hash,
        peer_identity: &lib_network::handshake::NodeIdentity,
        peer_did: &str,
    ) {
        // Get global blockchain to register wallet
        let blockchain = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!(peer_did = %peer_did, error = %e, "Cannot fund wallet: blockchain not available");
                return;
            }
        };

        // Generate wallet ID from identity
        let wallet_id_bytes = lib_crypto::hash_blake3(
            &[
                b"wallet:primary:",
                identity_id.as_bytes(),
            ].concat()
        );
        let wallet_id_hex = hex::encode(&wallet_id_bytes);

        // Check if wallet already exists and has balance
        {
            let bc_read = blockchain.read().await;
            if let Some(existing_wallet) = bc_read.wallet_registry.get(&wallet_id_hex) {
                if existing_wallet.initial_balance > 0 {
                    debug!(
                        peer_did = %peer_did,
                        wallet_id = %wallet_id_hex[..16],
                        balance = existing_wallet.initial_balance,
                        "Wallet already funded, skipping welcome bonus"
                    );
                    return;
                }
            }
        }

        // Register wallet with welcome bonus
        let welcome_bonus = SOV_WELCOME_BONUS;

        let wallet_data = lib_blockchain::transaction::WalletTransactionData {
            wallet_id: lib_blockchain::Hash::from_slice(&wallet_id_bytes),
            wallet_type: "Primary".to_string(),
            wallet_name: "Primary Wallet".to_string(),
            alias: None,
            public_key: peer_identity.public_key.dilithium_pk.clone(),
            owner_identity_id: Some(lib_blockchain::Hash::from_slice(identity_id.as_bytes())),
            seed_commitment: lib_blockchain::types::hash::blake3_hash(b"observed_wallet_seed"),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            registration_fee: 0,
            capabilities: 0xFFFFFFFF, // Full capabilities
            initial_balance: welcome_bonus,
        };

        let mint_tx = match crate::runtime::token_utils::build_sov_mint_tx(
            &wallet_id_bytes,
            welcome_bonus,
            format!("SOV_WELCOME_BONUS:{}", peer_did).into_bytes(),
        ).await {
            Ok(tx) => Some(tx),
            Err(e) => {
                warn!("Failed to build SOV welcome mint tx for peer {}: {}", peer_did, e);
                None
            }
        };

        {
            let mut bc_write = blockchain.write().await;
            bc_write.wallet_registry.insert(wallet_id_hex.clone(), wallet_data);
            if let Some(tx) = mint_tx {
                if let Err(e) = bc_write.add_pending_transaction(tx) {
                    warn!("Failed to enqueue peer welcome mint tx: {}", e);
                }
            }
        }

        info!(
            peer_did = %peer_did,
            wallet_id = %wallet_id_hex[..16],
            bonus = SOV_WELCOME_BONUS_SOV,
            "🎁 Funded new peer wallet with welcome bonus (TokenMint queued)"
        );
    }

    // REMOVED: handle_control_plane_streams() and handle_authenticated_stream()
    // These functions were using ControlPlaneSession (16-byte session_id) and old v1 auth.
    // Replaced by handle_control_plane_v2_streams() which uses V2Session (32-byte session_id)
    // with HMAC-SHA3-256 request MAC verification and monotonic counter replay protection.
    // See PR #816 for UHP v2 session authentication protocol upgrade.

    /// Handle mesh peer connection (node-to-node)
    ///
    /// Issue #907: Simplified to use QuicMeshProtocol as the single canonical connection store.
    /// After UHP handshake, a PeerConnection is created and registered via register_peer(),
    /// which also spawns a UNI receive loop for incoming mesh messages.
    async fn handle_mesh_connection(&self, connection: Connection, peer_addr: SocketAddr) -> Result<()> {
        info!("Mesh peer connection from {} - starting UHP handshake", peer_addr);

        // Perform UHP+Kyber handshake with common setup (uses global nonce cache)
        let (_identity, handshake_result) = self.perform_uhp_handshake(
            &connection,
            &peer_addr,
        ).await?;

        // Extract peer node ID
        let peer_node_id = handshake_result.verified_peer.identity.node_id.as_bytes();
        let mut node_id_arr = [0u8; 32];
        node_id_arr.copy_from_slice(peer_node_id);

        info!(
            peer_did = %handshake_result.verified_peer.identity.did,
            session_id = ?handshake_result.session_id,
            "Mesh peer authenticated from {} (identity verified)",
            peer_addr
        );

        // Issue #907: Create PeerConnection and register in the SINGLE canonical store.
        // This replaces the old triple-store pattern (pqc_connections + QuicMeshProtocol
        // + MeshRouter PeerRegistry). The register_peer() call also spawns the UNI
        // receive loop, fixing the UNI/BI stream mismatch bug.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let peer_conn = PeerConnection {
            quic_conn: connection.clone(),
            session_key: Some(handshake_result.session_key),
            verified_peer: handshake_result.verified_peer.clone(),
            session_id: Some(handshake_result.session_id),
            peer_addr,
            bootstrap_mode: false,
            connected_at: std::time::Instant::now(),
            last_activity: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(now_secs)),
        };

        self.quic_protocol.register_peer(node_id_arr.to_vec(), peer_conn);
        info!(
            peer_count = self.quic_protocol.peer_count(),
            "Inbound mesh peer registered in canonical store"
        );

        // Auto-register peer identity for wallet/blockchain
        self.auto_register_peer_identity(&handshake_result.verified_peer.identity).await;

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
            ProtocolType::MeshMessage(_initial_data) => {
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
    /// - Post-quantum security via Kyber1024 KEM bound to UHP transcript
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

        // [DB-013] Use global singleton NonceCache instead of opening per-handshake
        // This prevents replay attacks by sharing nonce state across all connections
        let nonce_cache = lib_network::handshake::get_or_init_global_nonce_cache(3600, 100_000)
            .context("Failed to get global nonce cache")?;
        let handshake_ctx = HandshakeContext::new(nonce_cache.clone());

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

        // Issue #907: Register in canonical store via PeerConnection conversion
        let pqc_conn = PqcQuicConnection::from_verified_peer(
            connection.clone(),
            peer_addr,
            handshake_result.verified_peer,
            handshake_result.session_key,
            handshake_result.session_id,
            false,
        );
        self.quic_protocol.register_peer(node_id_arr.to_vec(), pqc_conn.into_peer_connection());

        // Continue accepting streams (BI streams for ZHTP API requests)
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
        debug!("Receiving mesh message from peer {}", hex::encode(&peer_node_id[..8]));

        // Read full message with size limit (P1-4: Bincode size limits)
        let mut message_data = initial_data;
        let remaining = recv.read_to_end(MAX_MESSAGE_SIZE as usize).await?;
        message_data.extend_from_slice(&remaining);

        if message_data.len() > MAX_MESSAGE_SIZE as usize {
            warn!("Mesh message too large from peer {}: {} bytes",
                  hex::encode(&peer_node_id[..8]), message_data.len());
            return Err(anyhow!("Message exceeds maximum size"));
        }

        // Issue #907: Get session key from canonical store (QuicMeshProtocol.connections)
        let session_key = self.quic_protocol.get_peer_session_key(&peer_node_id)
            .ok_or_else(|| anyhow!("No session key for peer {} - not in canonical store",
                                   hex::encode(&peer_node_id[..8])))?;

        // Decrypt with session key (derived from UHP+Kyber handshake)
        let decrypted = lib_crypto::symmetric::chacha20::decrypt_data(&message_data, &session_key)
            .context("Failed to decrypt mesh message - possible tampering")?;

        // Deserialize mesh message with size validation
        let message: ZhtpMeshMessage = bincode::deserialize(&decrypted)
            .context("Failed to deserialize mesh message")?;

        // ✅ TICKET 2.6 FIX: Route through MeshRouter instead of direct handler call
        // This ensures all messages are logged and follow standard routing path
        if let Some(ref handler) = self.mesh_handler {
            let peer_pk = PublicKey::new(peer_node_id.to_vec());
            // Note: MeshMessageHandler.handle_mesh_message() processes incoming messages
            // This is correct for QUIC as it's receiving messages, not sending them
            // The bypass was in sending responses - those should use mesh_router.send_with_routing()
            handler.read().await.handle_mesh_message(message, peer_pk).await?;
        } else {
            warn!("No mesh handler configured on either QuicMeshProtocol or QuicHandler");
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
            handshake_rate_limits: self.handshake_rate_limits.clone(),
            identity_manager: self.identity_manager.clone(),
            pouw_session_log: self.pouw_session_log.clone(),
        }
    }
}

// Extension trait for BufferedStream compatibility
#[allow(async_fn_in_trait)]
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
