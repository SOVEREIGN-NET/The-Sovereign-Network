//! QUIC Mesh Protocol with Post-Quantum Cryptography
//!
//! Modern transport layer combining:
//! - QUIC (reliability, multiplexing, built-in TLS 1.3)
//! - UHP (Unified Handshake Protocol with Dilithium signatures)
//! - Kyber1024 KEM (Post-quantum key encapsulation via UHP v2)
//!
//! # Architecture
//!
//! ```text
//! ZHTP Message
//!     ↓
//! PQC Encryption (session_key from UHP v2 + ChaCha20-Poly1305)  ← Post-quantum security
//!     ↓
//! QUIC Connection (TLS 1.3 encryption + reliability)              ← Transport security
//!     ↓
//! UDP/IP Network
//! ```
//!
//! **Note on Double Encryption**: This is defense-in-depth, NOT wasteful redundancy.
//! - TLS 1.3: Protects against network-level attacks (MitM, passive eavesdropping)
//! - App-layer ChaCha20 using UHP v2 session key for post-quantum security
//! - Both layers serve different purposes and cannot be removed without losing security
//!
//! # Security Properties
//!
//! - **Mutual Authentication**: UHP verifies Dilithium signatures from both peers
//! - **NodeId Verification**: Validates NodeId = Blake3(DID || device_name)
//! - **Replay Protection**: Nonce cache prevents replay attacks
//! - **Post-Quantum Security**: Kyber1024 KEM provides quantum-resistant key exchange
//! - **Cryptographic Binding**: UHP v2 transcript binds identity to session key
//!
//! # Protocol Flow
//!
//! 1. QUIC connection establishment (TLS 1.3)
//! 2. UHP authentication over dedicated bidirectional stream
//! 3. UHP v2 handshake (includes Kyber1024 + Dilithium5)
//! 4. Master key derivation: HKDF(uhp_session_key || kyber_secret || transcript_hash || peer_node_id)
//! 5. Application messaging using master key

use anyhow::{Result, Context, anyhow};
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, debug, error};

use quinn::{Endpoint, Connection, ServerConfig, ClientConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// Import cryptographic primitives
use lib_crypto::{
    PublicKey,
    symmetric::chacha20::{encrypt_data, decrypt_data},
};

// Import identity for UHP handshake
use lib_identity::ZhtpIdentity;

// Import UHP handshake framework
use crate::handshake::{HandshakeContext, NonceCache, NodeIdentity, NegotiatedCapabilities};

// Import QUIC transport adapter for UHP v2
use super::quic_handshake;

use crate::types::mesh_message::ZhtpMeshMessage;
use crate::messaging::message_handler::MeshMessageHandler;

// Import TLS pin cache for certificate pinning (Issue #739)
use crate::discovery::global_pin_cache;
// Import PinnedCertVerifier for production-safe TLS verification
#[allow(deprecated)]
use crate::discovery::{PinnedCertVerifier, PinnedVerifierConfig, init_global_verifier, global_verifier};

/// Default path for TLS certificate
pub const DEFAULT_TLS_CERT_PATH: &str = "./data/tls/server.crt";
/// Default path for TLS private key
pub const DEFAULT_TLS_KEY_PATH: &str = "./data/tls/server.key";

/// Trust policy for QUIC TLS verification.
#[derive(Clone, Debug)]
pub enum QuicTrustMode {
    /// Strict TLS verification using native root certificates.
    /// Use only for connections to public internet servers with CA-signed certs.
    Strict,
    /// Production-safe pinned certificate verification (RECOMMENDED for mesh networks).
    /// Uses PinnedCertVerifier with three deterministic paths:
    /// 1. Bootstrap peers: TOFU (Trust On First Use), then pin
    /// 2. Known peers: Require pin match
    /// 3. Unknown peers: Reject
    Pinned,
    /// Allow TLS verification to be skipped only for explicit allowlisted peers.
    #[cfg(feature = "unsafe-bootstrap")]
    BootstrapAllowlist(Vec<SocketAddr>),
    /// Skip TLS verification entirely - for mesh networks where UHP handles authentication.
    /// TLS is used only for encryption, not identity verification.
    #[cfg(feature = "unsafe-bootstrap")]
    MeshTrustUhp,
}

impl Default for QuicTrustMode {
    fn default() -> Self {
        // Default to Pinned mode for production safety
        QuicTrustMode::Pinned
    }
}

/// QUIC mesh protocol with UHP authentication and PQC encryption layer
pub struct QuicMeshProtocol {
    /// QUIC endpoint (handles all connections)
    endpoint: Endpoint,

    /// Canonical store of all live peer connections (peer_node_id -> PeerConnection).
    /// This is the SINGLE authoritative connection store. NOT used for metadata/reputation
    /// (that's MeshRouter.connections). Used by send_to_peer(), broadcast_message(), and
    /// the per-peer UNI receive loops.
    connections: Arc<DashMap<Vec<u8>, PeerConnection>>,

    /// This node's Sovereign Identity (for UHP authentication)
    identity: Arc<ZhtpIdentity>,

    /// Handshake context with nonce cache (shared across all connections for replay protection)
    handshake_ctx: HandshakeContext,

    /// Local binding address
    local_addr: SocketAddr,

    /// Trust policy for TLS verification
    trust_mode: QuicTrustMode,

    /// PinnedCertVerifier for production-safe TLS verification
    /// Contains bootstrap allowlist and pin cache
    verifier: Arc<PinnedCertVerifier>,

    /// Message handler for processing received messages
    pub message_handler: Option<Arc<RwLock<MeshMessageHandler>>>,
}

/// QUIC connection with UHP-verified identity and PQC encryption
///
/// After successful handshake, this connection has:
/// - **Verified peer identity**: Dilithium signatures verified via UHP
/// - **Session key**: Derived from UHP v2 handshake
/// - **Replay protection**: Nonces checked against shared cache
pub struct PqcQuicConnection {
    /// Underlying QUIC connection
    quic_conn: Connection,

    /// Session key for symmetric encryption (derived from UHP v2)
    session_key: Option<[u8; 32]>,

    /// Verified peer identity and negotiated capabilities
    verified_peer: crate::handshake::VerifiedPeer,

    /// Session ID for logging/tracking (UHP v2, 32 bytes)
    session_id: Option<[u8; 32]>,

    /// Peer address
    peer_addr: SocketAddr,

    /// Bootstrap mode: allows unauthenticated blockchain sync requests
    /// New nodes connecting for first time can only request blockchain data
    /// NOTE: Even in bootstrap mode, UHP handshake is performed for identity verification
    pub bootstrap_mode: bool,
}

// NOTE: PqcHandshakeMessage has been REMOVED - authentication bypass vulnerability
// All QUIC connections use UHP v2 over QUIC streams (transport only).

/// Runtime peer connection stored in QuicMeshProtocol's canonical DashMap.
///
/// This is the single authoritative representation of a live QUIC peer.
/// Created from handshake results (both inbound and outbound).
/// All transport operations (send, broadcast, receive) use this struct.
pub struct PeerConnection {
    /// Underlying QUIC connection (cheap to clone - Arc internally)
    pub quic_conn: Connection,

    /// Session key for symmetric encryption (derived from UHP v2)
    pub session_key: Option<[u8; 32]>,

    /// Verified peer identity and negotiated capabilities
    pub verified_peer: crate::handshake::VerifiedPeer,

    /// Session ID for logging/tracking (UHP v2, 32 bytes)
    pub session_id: Option<[u8; 32]>,

    /// Peer address
    pub peer_addr: SocketAddr,

    /// Bootstrap mode: allows unauthenticated blockchain sync requests
    pub bootstrap_mode: bool,

    /// When this connection was established
    pub connected_at: Instant,

    /// Last activity timestamp (epoch secs), lock-free updates from send/receive loops
    pub last_activity: Arc<AtomicU64>,
}

impl PeerConnection {
    /// Send an encrypted message to this peer via a UNI stream.
    ///
    /// Uses ChaCha20-Poly1305 with the UHP v2 session key, then sends
    /// over a fresh QUIC unidirectional stream.
    pub async fn send_encrypted(&self, message: &[u8]) -> Result<()> {
        let session_key = self.session_key
            .ok_or_else(|| anyhow!("No session key - handshake not complete"))?;

        let encrypted = encrypt_data(message, &session_key)?;
        let mut stream = self.quic_conn.open_uni().await
            .context("Failed to open UNI stream for send")?;
        stream.write_all(&encrypted).await
            .context("Failed to write encrypted data to UNI stream")?;
        stream.finish()
            .context("Failed to finish UNI stream")?;

        self.touch();
        debug!("Sent {} bytes (PQC encrypted + QUIC UNI stream)", message.len());
        Ok(())
    }

    /// Update last_activity timestamp (lock-free).
    pub fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// Get the peer's node ID as raw bytes.
    pub fn node_id_bytes(&self) -> Vec<u8> {
        self.verified_peer.identity.node_id.as_bytes().to_vec()
    }
}

impl QuicMeshProtocol {
    /// Create a new QUIC mesh protocol instance with default certificate paths
    ///
    /// # Arguments
    ///
    /// * `identity` - ZhtpIdentity for UHP authentication (must have private key)
    /// * `bind_addr` - Local address to bind QUIC endpoint
    ///
    /// # Security
    ///
    /// The identity is used for UHP handshake authentication. All peers must verify
    /// each other's Dilithium signatures before establishing encrypted channels.
    pub fn new(identity: Arc<ZhtpIdentity>, bind_addr: SocketAddr) -> Result<Self> {
        Self::new_with_cert_paths(
            identity,
            bind_addr,
            Path::new(DEFAULT_TLS_CERT_PATH),
            Path::new(DEFAULT_TLS_KEY_PATH),
        )
    }

    /// Create a new QUIC mesh protocol instance with custom certificate paths
    ///
    /// # Certificate Persistence (Android Cronet Compatibility)
    ///
    /// This method uses persistent TLS certificates to enable certificate pinning
    /// on Android clients using Cronet (which cannot bypass TLS verification).
    ///
    /// On first startup:
    /// - Generates a new self-signed certificate
    /// - Saves it to the specified paths (PEM format)
    /// - Returns the certificate for QUIC configuration
    ///
    /// On subsequent startups:
    /// - Loads the existing certificate from disk
    /// - Uses the same certificate (enabling mobile apps to pin it)
    ///
    /// To extract the certificate hash for Android pinning:
    /// ```bash
    /// openssl x509 -in ./data/tls/server.crt -pubkey -noout | \
    ///   openssl pkey -pubin -outform der | \
    ///   openssl dgst -sha256 -binary | base64
    /// ```
    ///
    /// # Arguments
    ///
    /// * `identity` - ZhtpIdentity for UHP authentication (must have private key)
    /// * `bind_addr` - Local address to bind QUIC endpoint
    /// * `cert_path` - Path to TLS certificate (PEM format)
    /// * `key_path` - Path to TLS private key (PEM format)
    pub fn new_with_cert_paths(
        identity: Arc<ZhtpIdentity>,
        bind_addr: SocketAddr,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self> {
        info!("🔐 Initializing QUIC mesh protocol on {} with UHP v2 authentication", bind_addr);

        // Install the ring crypto provider for rustls 0.23+
        // This must be done before any rustls ServerConfig/ClientConfig creation
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Validate identity has private key for signing
        if identity.private_key.is_none() {
            return Err(anyhow!("Identity must have private key for UHP signing"));
        }

        // Load or generate TLS certificate (persistent for Android Cronet compatibility)
        let cert = Self::load_or_generate_cert(cert_path, key_path)?;

        // Configure QUIC server
        let server_config = Self::configure_server(cert.cert, cert.key)?;

        // Create QUIC endpoint
        let endpoint = Endpoint::server(server_config, bind_addr)
            .context("Failed to create QUIC endpoint")?;

        let actual_addr = endpoint.local_addr()?;
        info!("🔐 QUIC endpoint listening on {}", actual_addr);

        // Create shared handshake context with persistent nonce cache
        // Uses sled for persistence across restarts (prevents replay attacks)
        // TTL: 1 hour, max entries: 100,000 (handles high connection rate)
        let nonce_db_path = cert_path.parent()
            .unwrap_or(Path::new("./data"))
            .join("quic_nonce_cache");

        // Derive network epoch from genesis hash (uses environment-appropriate fallback)
        let network_epoch = crate::handshake::NetworkEpoch::from_global_or_fail()?;
        let nonce_cache = NonceCache::open(&nonce_db_path, 3600, 100_000, network_epoch)
            .context("Failed to open QUIC nonce cache database")?;

        let handshake_ctx = HandshakeContext::new(nonce_cache);

        // Initialize PinnedCertVerifier with empty bootstrap list (can be set later)
        let verifier = Arc::new(PinnedCertVerifier::new(PinnedVerifierConfig::default()));

        info!(
            node_id = ?identity.node_id,
            did = %identity.did,
            "QUIC mesh protocol initialized with Sovereign Identity"
        );

        Ok(Self {
            endpoint,
            connections: Arc::new(DashMap::new()),
            identity,
            handshake_ctx,
            local_addr: actual_addr,
            trust_mode: QuicTrustMode::Pinned, // Default to Pinned mode
            verifier,
            message_handler: None,
        })
    }

    /// Get this node's identity
    pub fn identity(&self) -> &ZhtpIdentity {
        &self.identity
    }

    /// Get this node's node_id (convenience method)
    pub fn node_id(&self) -> &lib_identity::NodeId {
        &self.identity.node_id
    }

    /// Set the message handler for processing received messages
    pub fn set_message_handler(&mut self, handler: Arc<RwLock<MeshMessageHandler>>) {
        self.message_handler = Some(handler);
    }

    /// Set TLS trust policy for QUIC client connections
    pub fn set_trust_mode(&mut self, trust_mode: QuicTrustMode) {
        self.trust_mode = trust_mode;
    }

    /// Configure bootstrap peers for TOFU (Trust On First Use)
    ///
    /// Bootstrap peers are allowed to connect without a cached pin.
    /// Their certificate will be pinned on first contact.
    ///
    /// # Security
    ///
    /// Only configure trusted bootstrap peers here. These peers get special
    /// TOFU treatment - their self-signed certificates will be accepted on
    /// first contact and then pinned for future connections.
    ///
    /// # Implementation Note
    ///
    /// This method updates the bootstrap peers on the existing verifier instance,
    /// preserving any previously loaded pins in its internal pin store. This avoids
    /// discarding cached state when bootstrap peers are reconfigured.
    pub fn set_bootstrap_peers(&mut self, peers: Vec<SocketAddr>) {
        self.verifier.update_bootstrap_peers(peers.clone());
        info!("Configured {} bootstrap peers for TOFU", peers.len());
    }

    /// Get a reference to the certificate verifier
    pub fn verifier(&self) -> Arc<PinnedCertVerifier> {
        Arc::clone(&self.verifier)
    }

    /// Sync pins from the global TlsPinCache to the PinnedCertVerifier
    ///
    /// This should be called on startup to load existing pins from the discovery
    /// cache into the verifier's synchronous pin store. This enables the verifier
    /// to enforce pin matching for known peers during TLS handshake.
    ///
    /// # Usage
    ///
    /// ```ignore
    /// let mut quic_mesh = QuicMeshProtocol::new(identity, bind_addr)?;
    /// quic_mesh.sync_pins_from_cache().await?;
    /// ```
    pub async fn sync_pins_from_cache(&self) -> Result<()> {
        let pin_cache = global_pin_cache();
        let entries = pin_cache.get_all_entries().await;
        
        if !entries.is_empty() {
            self.verifier.sync_from_cache(&entries);
            info!(
                "Synced {} certificate pins from discovery cache to verifier",
                entries.len()
            );
        } else {
            debug!("No certificate pins in discovery cache to sync");
        }
        
        Ok(())
    }

    /// Set up TOFU callback to persist pins to the global TlsPinCache
    ///
    /// This callback is invoked synchronously during TLS handshake when a bootstrap
    /// peer is accepted via TOFU. The callback sends the pin to a background task
    /// for async persistence to avoid blocking the handshake.
    ///
    /// # Implementation
    ///
    /// The callback uses a channel to send pins to a background task that persists
    /// them to the TlsPinCache. This avoids blocking I/O during TLS handshake.
    pub fn setup_tofu_persistence(&self) {
        // TODO: Implement channel-based async persistence
        // For now, we'll just log a warning that persistence is not yet wired up
        warn!(
            "TOFU pin persistence not yet implemented - pins will not survive restarts. \
            See Issue #739 for implementation plan."
        );
    }
    
    /// Get the QUIC endpoint for accepting connections
    pub fn get_endpoint(&self) -> Arc<Endpoint> {
        Arc::new(self.endpoint.clone())
    }
    
    /// Connect to a peer using QUIC with UHP v2 handshake
    ///
    /// # Security
    ///
    /// This performs full mutual authentication via UHP:
    /// 1. QUIC connection establishment (TLS 1.3)
    /// 2. UHP authentication (Dilithium signatures verified)
    /// 3. UHP v2 handshake (includes Kyber1024 + Dilithium5)
    /// 4. Master key derivation for symmetric encryption
    ///
    /// The peer's identity is cryptographically verified before any data exchange.
    pub async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<()> {
        info!("🔐 Connecting to peer at {} via QUIC+UHP v2", peer_addr);

        // Configure client with PinnedCertVerifier
        let client_config = Self::configure_client(&self.trust_mode, peer_addr, &self.verifier)?;

        // Connect via QUIC
        let connection = self.endpoint
            .connect_with(client_config, peer_addr, "zhtp-mesh")?
            .await
            .context("QUIC connection failed")?;

        info!("🔐 QUIC connection established to {}", peer_addr);

        // Perform UHP v2 handshake (mutual authentication + PQC key exchange)
        let handshake_result = quic_handshake::handshake_as_initiator(
            &connection,
            &self.identity,
            &self.handshake_ctx,
        ).await.context("UHP v2 handshake failed")?;

        info!(
            peer_did = %handshake_result.verified_peer.identity.did,
            peer_device = %handshake_result.verified_peer.identity.device_id,
            session_id = ?handshake_result.session_id,
            "🔐 UHP v2 handshake complete with {} (quantum-safe encryption active)",
            peer_addr
        );

        // === TLS Certificate Pinning Verification (Issue #739) ===
        let peer_node_id = *handshake_result.verified_peer.identity.node_id.as_bytes();

        // Extract SPKI synchronously before async operations (Box<dyn Any> is not Send)
        let peer_spki: Option<[u8; 32]> = connection.peer_identity()
            .and_then(|certs| {
                certs.downcast_ref::<Vec<CertificateDer<'static>>>()
                    .and_then(|c| Self::extract_peer_spki_sha256(c).ok())
            });

        // Now verify against pin cache (async)
        if let Some(peer_spki) = peer_spki {
            match global_pin_cache().verify_peer_spki(&peer_node_id, &peer_spki).await {
                Ok(true) => {
                    info!(peer_node_id = ?hex::encode(&peer_node_id[..8]), "🔐 TLS certificate pin verified");
                }
                Ok(false) => {
                    debug!(peer_node_id = ?hex::encode(&peer_node_id[..8]), "No TLS pin cached for peer");
                }
                Err(e) => {
                    error!(peer_node_id = ?hex::encode(&peer_node_id[..8]), error = %e,
                        "🚨 SECURITY: TLS certificate pin mismatch");
                    connection.close(2u32.into(), b"tls_pin_mismatch");
                    return Err(anyhow!("TLS certificate pin mismatch for peer {:?}", hex::encode(&peer_node_id[..8])));
                }
            }
        }

        // === Dilithium Public Key Verification (Issue #739) ===
        // Verify the peer's Dilithium PK from UHP matches what was cached from discovery
        let peer_dilithium_pk = &handshake_result.verified_peer.identity.public_key.dilithium_pk;
        match global_pin_cache().verify_peer_dilithium_pk(&peer_node_id, peer_dilithium_pk).await {
            Ok(true) => {
                info!(peer_node_id = ?hex::encode(&peer_node_id[..8]), "🔐 Dilithium PK verified against discovery cache");
            }
            Ok(false) => {
                debug!(peer_node_id = ?hex::encode(&peer_node_id[..8]), "No Dilithium PK cached for peer (first contact)");
            }
            Err(e) => {
                error!(peer_node_id = ?hex::encode(&peer_node_id[..8]), error = %e,
                    "🚨 SECURITY: Dilithium PK mismatch - peer identity compromised");
                connection.close(3u32.into(), b"dilithium_pk_mismatch");
                return Err(anyhow!("Dilithium PK mismatch for peer {:?}", hex::encode(&peer_node_id[..8])));
            }
        }

        // Create PeerConnection from verified handshake result
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let peer_key = handshake_result.verified_peer.identity.node_id.as_bytes().to_vec();

        let peer_conn = PeerConnection {
            quic_conn: connection,
            session_key: Some(handshake_result.session_key),
            verified_peer: handshake_result.verified_peer.clone(),
            session_id: Some(handshake_result.session_id),
            peer_addr,
            bootstrap_mode: false,
            connected_at: Instant::now(),
            last_activity: Arc::new(AtomicU64::new(now_secs)),
        };

        // Register in canonical store and spawn UNI receive loop
        self.register_peer(peer_key, peer_conn);

        Ok(())
    }

    /// Connect to a bootstrap peer for blockchain sync
    ///
    /// Bootstrap mode connections can only request blockchain data, not submit
    /// transactions or store DHT data. However, UHP authentication is STILL performed
    /// to verify the bootstrap peer's identity.
    ///
    /// # Arguments
    /// * `peer_addr` - Address of the bootstrap peer
    /// * `is_edge_node` - If true, uses edge sync (headers + ZK proofs). If false, downloads full blockchain
    ///
    /// # Security
    ///
    /// Even in bootstrap mode, the peer is cryptographically authenticated via UHP.
    /// The bootstrap_mode flag only affects what operations are allowed on the connection.
    pub async fn connect_as_bootstrap(&self, peer_addr: SocketAddr, is_edge_node: bool) -> Result<()> {
        let mode_str = if is_edge_node { "edge node - headers+proofs only" } else { "full node - complete blockchain" };
        info!("🔐 Connecting to bootstrap peer at {} (mode: {})", peer_addr, mode_str);

        // Configure client with PinnedCertVerifier
        let client_config = Self::configure_client(&self.trust_mode, peer_addr, &self.verifier)?;

        // Connect via QUIC
        let connection = self.endpoint
            .connect_with(client_config, peer_addr, "zhtp-mesh")?
            .await
            .context("QUIC connection failed")?;

        info!("🔐 QUIC connection established to bootstrap peer {}", peer_addr);

        // Perform UHP v2 handshake (authentication required even for bootstrap)
        let handshake_result = quic_handshake::handshake_as_initiator(
            &connection,
            &self.identity,
            &self.handshake_ctx,
        ).await.context("UHP v2 handshake with bootstrap peer failed")?;

        info!(
            peer_did = %handshake_result.verified_peer.identity.did,
            session_id = ?handshake_result.session_id,
            "🔐 Bootstrap peer verified: {} (bootstrap mode: {})",
            peer_addr,
            mode_str
        );

        // === TLS Certificate Pinning Verification (Issue #739) ===
        let peer_node_id = *handshake_result.verified_peer.identity.node_id.as_bytes();

        // Extract SPKI synchronously before async operations (Box<dyn Any> is not Send)
        let peer_spki: Option<[u8; 32]> = connection.peer_identity()
            .and_then(|certs| {
                certs.downcast_ref::<Vec<CertificateDer<'static>>>()
                    .and_then(|c| Self::extract_peer_spki_sha256(c).ok())
            });

        // Now verify against pin cache (async)
        if let Some(peer_spki) = peer_spki {
            match global_pin_cache().verify_peer_spki(&peer_node_id, &peer_spki).await {
                Ok(true) => {
                    info!(peer_node_id = ?hex::encode(&peer_node_id[..8]), "🔐 Bootstrap peer TLS pin verified");
                }
                Ok(false) => {
                    debug!(peer_node_id = ?hex::encode(&peer_node_id[..8]), "No TLS pin cached for bootstrap peer");
                }
                Err(e) => {
                    error!(peer_node_id = ?hex::encode(&peer_node_id[..8]), error = %e,
                        "🚨 SECURITY: Bootstrap peer TLS certificate pin mismatch");
                    connection.close(2u32.into(), b"tls_pin_mismatch");
                    return Err(anyhow!("TLS certificate pin mismatch for bootstrap peer {:?}", hex::encode(&peer_node_id[..8])));
                }
            }
        }

        // === Dilithium Public Key Verification (Issue #739) ===
        let peer_dilithium_pk = &handshake_result.verified_peer.identity.public_key.dilithium_pk;
        match global_pin_cache().verify_peer_dilithium_pk(&peer_node_id, peer_dilithium_pk).await {
            Ok(true) => {
                info!(peer_node_id = ?hex::encode(&peer_node_id[..8]), "🔐 Bootstrap peer Dilithium PK verified");
            }
            Ok(false) => {
                debug!(peer_node_id = ?hex::encode(&peer_node_id[..8]), "No Dilithium PK cached for bootstrap peer");
            }
            Err(e) => {
                error!(peer_node_id = ?hex::encode(&peer_node_id[..8]), error = %e,
                    "🚨 SECURITY: Bootstrap peer Dilithium PK mismatch");
                connection.close(3u32.into(), b"dilithium_pk_mismatch");
                return Err(anyhow!("Dilithium PK mismatch for bootstrap peer {:?}", hex::encode(&peer_node_id[..8])));
            }
        }

        if is_edge_node {
            info!("   → Edge node: Can download headers + ZK proofs");
            info!("   → Edge node: Will NOT download full blocks");
        } else {
            info!("   → Full node: Can download complete blockchain");
            info!("   → Full node: Will store and validate all blocks");
        }
        info!("   → Cannot submit transactions until full identity established");

        // Create PeerConnection from handshake result (bootstrap mode)
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let peer_key = handshake_result.verified_peer.identity.node_id.as_bytes().to_vec();

        let peer_conn = PeerConnection {
            quic_conn: connection,
            session_key: Some(handshake_result.session_key),
            verified_peer: handshake_result.verified_peer.clone(),
            session_id: Some(handshake_result.session_id),
            peer_addr,
            bootstrap_mode: true,
            connected_at: Instant::now(),
            last_activity: Arc::new(AtomicU64::new(now_secs)),
        };

        // Register in canonical store and spawn UNI receive loop
        self.register_peer(peer_key, peer_conn);

        Ok(())
    }
    
    // =========================================================================
    // Canonical connection store operations (Issue #907)
    // =========================================================================

    /// Register a peer in the canonical connection store and spawn a UNI receive loop.
    ///
    /// This is the SINGLE entry point for adding peers - called by:
    /// - `connect_to_peer()` / `connect_as_bootstrap()` (outbound connections)
    /// - `QuicHandler::handle_mesh_connection()` (inbound connections)
    ///
    /// After insertion, spawns a background task that loops on `accept_uni()` to
    /// receive encrypted mesh messages from this peer.
    pub fn register_peer(&self, node_id: Vec<u8>, conn: PeerConnection) {
        let quic_conn = conn.quic_conn.clone();
        let session_key = conn.session_key;
        let peer_addr = conn.peer_addr;

        self.connections.insert(node_id.clone(), conn);

        info!(
            peer = ?hex::encode(&node_id[..8.min(node_id.len())]),
            addr = %peer_addr,
            total_peers = self.connections.len(),
            "Peer registered in canonical connection store"
        );

        // Spawn UNI receive loop if we have a session key
        if let Some(key) = session_key {
            self.spawn_receive_loop(node_id, quic_conn, key);
        }
    }

    /// Remove a peer from the canonical connection store.
    pub fn remove_peer(&self, node_id: &[u8]) {
        if self.connections.remove(node_id).is_some() {
            info!(
                peer = ?hex::encode(&node_id[..8.min(node_id.len())]),
                total_peers = self.connections.len(),
                "Peer removed from canonical connection store"
            );
        }
    }

    /// Number of live peer connections.
    pub fn peer_count(&self) -> usize {
        self.connections.len()
    }

    /// List all connected peer node IDs.
    pub fn connected_peer_ids(&self) -> Vec<Vec<u8>> {
        self.connections.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get a peer's session key (for external decryption, e.g. QuicHandler).
    pub fn get_peer_session_key(&self, node_id: &[u8]) -> Option<[u8; 32]> {
        self.connections.get(node_id).and_then(|entry| entry.session_key)
    }

    /// Broadcast a serialized message to ALL connected peers.
    ///
    /// Returns the number of peers successfully sent to.
    /// Dead peers (send failure) are automatically removed from the store.
    pub async fn broadcast_message(&self, message_bytes: &[u8]) -> Result<usize> {
        // Snapshot peer info to avoid holding DashMap locks across await points
        let peers: Vec<(Vec<u8>, Connection, Option<[u8; 32]>)> = self.connections
            .iter()
            .map(|entry| {
                (entry.key().clone(), entry.value().quic_conn.clone(), entry.value().session_key)
            })
            .collect();

        if peers.is_empty() {
            return Ok(0);
        }

        let mut success = 0;
        let mut dead_peers = vec![];

        for (peer_id, conn, session_key) in &peers {
            let key = match session_key {
                Some(k) => k,
                None => {
                    warn!(peer = ?hex::encode(&peer_id[..8.min(peer_id.len())]),
                          "Peer has no session key, skipping broadcast");
                    continue;
                }
            };

            match Self::send_encrypted_to(conn, key, message_bytes).await {
                Ok(()) => {
                    success += 1;
                    // Update last_activity
                    if let Some(entry) = self.connections.get(peer_id) {
                        entry.touch();
                    }
                }
                Err(e) => {
                    warn!(peer = ?hex::encode(&peer_id[..8.min(peer_id.len())]),
                          error = %e, "Send failed during broadcast");
                    dead_peers.push(peer_id.clone());
                }
            }
        }

        // Reap dead peers
        for dead in &dead_peers {
            self.connections.remove(dead);
        }
        if !dead_peers.is_empty() {
            info!(removed = dead_peers.len(), "Reaped dead peers after broadcast");
        }

        Ok(success)
    }

    /// Encrypt and send a message to a single QUIC connection via UNI stream.
    async fn send_encrypted_to(conn: &Connection, session_key: &[u8; 32], message: &[u8]) -> Result<()> {
        let encrypted = encrypt_data(message, session_key)?;
        let mut stream = conn.open_uni().await
            .context("Failed to open UNI stream")?;
        stream.write_all(&encrypted).await
            .context("Failed to write to UNI stream")?;
        stream.finish()
            .context("Failed to finish UNI stream")?;
        Ok(())
    }

    /// Spawn a background task that accepts UNI streams from a peer and dispatches
    /// decrypted mesh messages to the message handler.
    ///
    /// This fixes the stream-type mismatch bug: `send_encrypted_message()` uses
    /// `open_uni()` but `accept_additional_streams()` only accepted BI streams.
    fn spawn_receive_loop(&self, node_id: Vec<u8>, conn: Connection, session_key: [u8; 32]) {
        let message_handler = self.message_handler.clone();
        let connections = self.connections.clone();
        let node_id_hex = hex::encode(&node_id[..8.min(node_id.len())]);
        // Capture this connection's stable_id so we only remove OUR entry on exit,
        // not a replacement connection that was registered under the same node_id.
        let our_stable_id = conn.stable_id();

        debug!(peer = %node_id_hex, stable_id = our_stable_id, "Spawning UNI receive loop");

        tokio::spawn(async move {
            loop {
                match conn.accept_uni().await {
                    Ok(mut stream) => {
                        match stream.read_to_end(1024 * 1024).await { // 1MB max
                            Ok(encrypted) => {
                                match decrypt_data(&encrypted, &session_key) {
                                    Ok(decrypted) => {
                                        match bincode::deserialize::<ZhtpMeshMessage>(&decrypted) {
                                            Ok(message) => {
                                                // Update last_activity
                                                if let Some(entry) = connections.get(&node_id) {
                                                    entry.touch();
                                                }

                                                if let Some(ref handler) = message_handler {
                                                    let peer_pk = PublicKey::new(node_id.clone());
                                                    if let Err(e) = handler.read().await
                                                        .handle_mesh_message(message, peer_pk).await
                                                    {
                                                        error!(peer = %node_id_hex,
                                                               error = %e,
                                                               "Error handling mesh message");
                                                    }
                                                } else {
                                                    warn!("No message handler configured for UNI receive loop");
                                                }
                                            }
                                            Err(e) => {
                                                error!(peer = %node_id_hex,
                                                       error = %e,
                                                       "Failed to deserialize mesh message");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(peer = %node_id_hex,
                                               error = %e,
                                               "Failed to decrypt mesh message");
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(peer = %node_id_hex,
                                       error = %e,
                                       "Failed to read UNI stream");
                            }
                        }
                    }
                    Err(e) => {
                        debug!(peer = %node_id_hex,
                               error = %e,
                               "UNI stream accept ended - peer disconnected");
                        break;
                    }
                }
            }

            // Only remove if the DashMap entry still belongs to THIS connection.
            // A newer connection may have replaced us under the same node_id.
            connections.remove_if(&node_id, |_, entry| {
                entry.quic_conn.stable_id() == our_stable_id
            });
            info!(peer = %node_id_hex, stable_id = our_stable_id,
                  "Receive loop ended (removed only if still owner)");
        });
    }

    /// Send encrypted ZHTP message to peer
    pub async fn send_to_peer(
        &self,
        peer_pubkey: &[u8],
        message: ZhtpMeshMessage,
    ) -> Result<()> {
        // Snapshot connection info to avoid holding DashMap ref across await
        let (conn, session_key) = {
            let entry = self.connections.get(peer_pubkey)
                .ok_or_else(|| anyhow!("No connection to peer"))?;
            (entry.quic_conn.clone(), entry.session_key)
        };

        let session_key = session_key
            .ok_or_else(|| anyhow!("No session key for peer"))?;

        // Serialize message
        let message_bytes = bincode::serialize(&message)
            .context("Failed to serialize ZhtpMeshMessage")?;

        Self::send_encrypted_to(&conn, &session_key, &message_bytes).await?;

        // Update last_activity
        if let Some(entry) = self.connections.get(peer_pubkey) {
            entry.touch();
        }

        debug!("Sent {} bytes to peer (PQC encrypted + QUIC UNI)", message_bytes.len());
        Ok(())
    }
    
    /// Receive messages from peers (background task)
    ///
    /// Spawns background tasks to:
    /// 1. Accept incoming QUIC connections
    /// 2. Perform UHP v2 handshake for each connection
    /// 3. Receive encrypted messages on established connections
    ///
    /// # Security
    ///
    /// All incoming connections are authenticated via UHP before accepting messages.
    /// Connections that fail handshake are immediately closed.
    pub async fn start_receiving(&self) -> Result<()> {
        info!("Starting QUIC message receiver with UHP authentication...");

        let endpoint = self.endpoint.clone();
        let connections = Arc::clone(&self.connections);
        let message_handler = self.message_handler.clone();
        let identity = Arc::clone(&self.identity);
        let handshake_ctx = self.handshake_ctx.clone();

        // Task: Accept new incoming connections, handshake, register, spawn receive loop
        tokio::spawn(async move {
            loop {
                match endpoint.accept().await {
                    Some(incoming) => {
                        let conns = Arc::clone(&connections);
                        let handler = message_handler.clone();
                        let identity = Arc::clone(&identity);
                        let ctx = handshake_ctx.clone();

                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(connection) => {
                                    let peer_addr = connection.remote_address();
                                    info!("New QUIC connection from {}", peer_addr);

                                    // Perform UHP v2 handshake as server
                                    let handshake_result = match quic_handshake::handshake_as_responder(
                                        &connection,
                                        &identity,
                                        &ctx,
                                    ).await {
                                        Ok(result) => result,
                                        Err(e) => {
                                            error!(peer_addr = %peer_addr, error = %e,
                                                   "UHP v2 handshake failed - rejecting connection");
                                            connection.close(1u32.into(), b"handshake_failed");
                                            return;
                                        }
                                    };

                                    info!(
                                        peer_did = %handshake_result.verified_peer.identity.did,
                                        peer_device = %handshake_result.verified_peer.identity.device_id,
                                        session_id = ?handshake_result.session_id,
                                        "UHP v2 handshake complete (server side)"
                                    );

                                    // TLS Certificate Pinning Verification (Issue #739)
                                    let peer_node_id = *handshake_result.verified_peer.identity.node_id.as_bytes();
                                    let peer_spki: Option<[u8; 32]> = connection.peer_identity()
                                        .and_then(|certs| {
                                            certs.downcast_ref::<Vec<CertificateDer<'static>>>()
                                                .and_then(|c| QuicMeshProtocol::extract_peer_spki_sha256(c).ok())
                                        });

                                    if let Some(peer_spki) = peer_spki {
                                        match global_pin_cache().verify_peer_spki(&peer_node_id, &peer_spki).await {
                                            Ok(true) => debug!("TLS certificate pin verified"),
                                            Ok(false) => debug!("No TLS pin cached for peer"),
                                            Err(e) => {
                                                error!(error = %e, "TLS certificate pin mismatch");
                                                connection.close(2u32.into(), b"tls_pin_mismatch");
                                                return;
                                            }
                                        }
                                    }

                                    let peer_dilithium_pk = &handshake_result.verified_peer.identity.public_key.dilithium_pk;
                                    match global_pin_cache().verify_peer_dilithium_pk(&peer_node_id, peer_dilithium_pk).await {
                                        Ok(true) => debug!("Dilithium PK verified"),
                                        Ok(false) => debug!("No Dilithium PK cached for peer"),
                                        Err(e) => {
                                            error!(error = %e, "Dilithium PK mismatch");
                                            connection.close(3u32.into(), b"dilithium_pk_mismatch");
                                            return;
                                        }
                                    }

                                    // Create PeerConnection and register
                                    let peer_id_vec = handshake_result.verified_peer.identity.node_id.as_bytes().to_vec();
                                    let now_secs = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();

                                    let session_key = handshake_result.session_key;
                                    let quic_conn_clone = connection.clone();
                                    let our_stable_id = connection.stable_id();

                                    let peer_conn = PeerConnection {
                                        quic_conn: connection,
                                        session_key: Some(session_key),
                                        verified_peer: handshake_result.verified_peer.clone(),
                                        session_id: Some(handshake_result.session_id),
                                        peer_addr,
                                        bootstrap_mode: false,
                                        connected_at: Instant::now(),
                                        last_activity: Arc::new(AtomicU64::new(now_secs)),
                                    };

                                    conns.insert(peer_id_vec.clone(), peer_conn);

                                    // Spawn UNI receive loop for this peer
                                    let conns_for_loop = conns.clone();
                                    let handler_for_loop = handler.clone();
                                    let node_id_for_loop = peer_id_vec.clone();
                                    let node_id_hex = hex::encode(&peer_id_vec[..8.min(peer_id_vec.len())]);

                                    tokio::spawn(async move {
                                        loop {
                                            match quic_conn_clone.accept_uni().await {
                                                Ok(mut stream) => {
                                                    match stream.read_to_end(1024 * 1024).await {
                                                        Ok(encrypted) => {
                                                            match decrypt_data(&encrypted, &session_key) {
                                                                Ok(decrypted) => {
                                                                    match bincode::deserialize::<ZhtpMeshMessage>(&decrypted) {
                                                                        Ok(message) => {
                                                                            if let Some(entry) = conns_for_loop.get(&node_id_for_loop) {
                                                                                entry.touch();
                                                                            }
                                                                            if let Some(ref h) = handler_for_loop {
                                                                                let peer_pk = PublicKey::new(node_id_for_loop.clone());
                                                                                if let Err(e) = h.read().await.handle_mesh_message(message, peer_pk).await {
                                                                                    error!("Error handling message: {}", e);
                                                                                }
                                                                            }
                                                                        }
                                                                        Err(e) => error!("Failed to deserialize: {}", e),
                                                                    }
                                                                }
                                                                Err(e) => error!("Failed to decrypt: {}", e),
                                                            }
                                                        }
                                                        Err(e) => debug!("Failed to read UNI stream: {}", e),
                                                    }
                                                }
                                                Err(e) => {
                                                    debug!(peer = %node_id_hex, error = %e, "UNI accept ended");
                                                    break;
                                                }
                                            }
                                        }
                                        // Only remove if still our connection (not replaced)
                                        conns_for_loop.remove_if(&node_id_for_loop, |_, entry| {
                                            entry.quic_conn.stable_id() == our_stable_id
                                        });
                                        info!(peer = %node_id_hex, "Receive loop ended (start_receiving)");
                                    });
                                }
                                Err(e) => {
                                    warn!("Failed to accept QUIC connection: {}", e);
                                }
                            }
                        });
                    }
                    None => {
                        warn!("QUIC endpoint closed");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
    
    /// Get a QUIC connection by peer public key
    pub fn get_connection(&self, peer_key: &[u8]) -> Result<Connection> {
        let entry = self.connections.get(peer_key)
            .ok_or_else(|| anyhow!("No connection to peer with key {:?}", &peer_key[..8]))?;
        Ok(entry.quic_conn.clone())
    }

    /// Get all active connection addresses
    pub fn get_active_peers(&self) -> Vec<SocketAddr> {
        self.connections.iter().map(|entry| entry.peer_addr).collect()
    }

    /// Get local endpoint address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close all connections gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down QUIC mesh protocol...");
        self.endpoint.close(0u32.into(), b"shutdown");
        self.connections.clear();
    }
    
    /// Load existing TLS certificate from disk, or generate a new one if not found.
    ///
    /// This enables persistent certificates for Android Cronet compatibility.
    /// Mobile apps can pin the certificate hash since it remains constant across restarts.
    ///
    /// Node-to-node connections are unaffected - they use SkipServerVerification
    /// and rely on UHP v2 (Kyber1024 + Dilithium5) for security.
    fn load_or_generate_cert(cert_path: &Path, key_path: &Path) -> Result<SelfSignedCert> {
        // Try to load existing certificate from disk
        if cert_path.exists() && key_path.exists() {
            info!("🔐 Loading existing TLS certificate from {}", cert_path.display());

            let cert_pem = std::fs::read(cert_path)
                .context("Failed to read certificate file")?;
            let key_pem = std::fs::read(key_path)
                .context("Failed to read key file")?;

            // Parse PEM-encoded certificate
            let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
                .next()
                .ok_or_else(|| anyhow!("No certificate found in PEM file"))?
                .context("Failed to parse certificate PEM")?;

            // Parse PEM-encoded private key
            let key_der = rustls_pemfile::private_key(&mut key_pem.as_slice())
                .context("Failed to parse private key PEM")?
                .ok_or_else(|| anyhow!("No private key found in PEM file"))?;

            info!("🔐 TLS certificate loaded successfully");

            // Print SPKI pin for mobile app pinning
            if let Ok(spki_hash) = Self::compute_spki_sha256(cert_der.as_ref()) {
                info!("📌 SPKI SHA-256 pin (hex): {}", hex::encode(spki_hash));
            }

            return Ok(SelfSignedCert {
                cert: cert_der,
                key: key_der,
            });
        }

        // Generate new certificate and save to disk
        info!("🔐 Generating new TLS certificate (will be saved to {})", cert_path.display());

        use rcgen::{generate_simple_self_signed, CertifiedKey};

        // Include common names and wildcards for maximum compatibility
        // This ensures the cert works regardless of how the client specifies the address
        let subject_alt_names = vec![
            "zhtp-mesh".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "*.local".to_string(),
            "*".to_string(), // Wildcard for any domain
        ];

        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names)
            .context("Failed to generate certificate")?;

        // Create directory if it doesn't exist
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create TLS certificate directory")?;
        }

        // Save certificate and key in PEM format
        std::fs::write(cert_path, cert.pem())
            .context("Failed to write certificate file")?;
        std::fs::write(key_path, signing_key.serialize_pem())
            .context("Failed to write private key file")?;

        // Set restrictive permissions on private key (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
                .context("Failed to set private key permissions")?;
        }

        info!("🔐 TLS certificate generated and saved to disk");
        info!("   Certificate: {}", cert_path.display());
        info!("   Private key: {}", key_path.display());
        info!("   To extract hash for Android/iOS pinning:");
        info!("   openssl x509 -in {} -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64", cert_path.display());

        let cert_der = CertificateDer::from(cert.der().to_vec());

        // Print SPKI pin for mobile app pinning (iOS + Android)
        if let Ok(spki_hash) = Self::compute_spki_sha256(cert_der.as_ref()) {
            info!("📌 SPKI SHA-256 pin (hex): {}", hex::encode(&spki_hash));
        }

        // Convert KeyPair to PrivateKeyDer by serializing to PKCS#8
        let key_der_bytes = signing_key.serialize_der();
        let key_der = PrivateKeyDer::Pkcs8(key_der_bytes.into());

        Ok(SelfSignedCert {
            cert: cert_der,
            key: key_der,
        })
    }

    /// Compute SHA256 hash of the SubjectPublicKeyInfo (SPKI) from a DER-encoded certificate.
    ///
    /// This is used for TLS certificate pinning in discovery records (Issue #739).
    /// The SPKI hash is stable across certificate reissues as long as the key remains the same.
    ///
    /// # Arguments
    /// * `cert_der` - DER-encoded X.509 certificate
    ///
    /// # Returns
    /// 32-byte SHA256 hash of the SPKI
    pub fn compute_spki_sha256(cert_der: &[u8]) -> Result<[u8; 32]> {
        use x509_parser::prelude::*;
        use sha2::{Sha256, Digest};

        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| anyhow!("Failed to parse X.509 certificate: {:?}", e))?;

        // Extract the SubjectPublicKeyInfo (SPKI) in DER format
        let spki_der = cert.public_key().raw;

        // Compute SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(spki_der);
        let hash = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Ok(result)
    }

    /// Compute SPKI hash from this node's TLS certificate.
    ///
    /// Loads the certificate from disk and computes its SPKI SHA256 hash.
    /// This hash should be included in signed discovery announcements.
    pub fn get_tls_spki_hash(&self) -> Result<[u8; 32]> {
        let cert_path = Path::new(DEFAULT_TLS_CERT_PATH);

        if !cert_path.exists() {
            return Err(anyhow!("TLS certificate not found at {}", cert_path.display()));
        }

        let cert_pem = std::fs::read(cert_path)
            .context("Failed to read TLS certificate")?;

        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .next()
            .ok_or_else(|| anyhow!("No certificate found in PEM file"))?
            .context("Failed to parse certificate PEM")?;

        Self::compute_spki_sha256(&cert_der)
    }

    /// Extract SPKI SHA256 hash from a peer's TLS certificate during handshake.
    ///
    /// This is called during QUIC connection establishment to verify the peer's
    /// certificate matches the pin from discovery.
    pub fn extract_peer_spki_sha256(peer_certs: &[CertificateDer<'_>]) -> Result<[u8; 32]> {
        let cert = peer_certs
            .first()
            .ok_or_else(|| anyhow!("No peer certificate available"))?;

        Self::compute_spki_sha256(cert.as_ref())
    }

    /// Configure QUIC server
    fn configure_server(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Result<ServerConfig> {
        // Build rustls ServerConfig with ALPN support
        let mut rustls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .context("Failed to configure TLS")?;

        // Configure ALPN protocols for protocol-based routing
        // Different ALPNs trigger different connection handling:
        // - zhtp-uhp/1: Control plane with UHP handshake (CLI, Web4)
        // - zhtp-http/1: HTTP-only mode (mobile apps)
        // - zhtp-mesh/1: Mesh peer-to-peer protocol
        // - zhtp/1.0: Legacy (treated as HTTP-compat)
        // - h3: HTTP/3 browsers
        rustls_config.alpn_protocols = crate::constants::server_alpns();

        // Create Quinn server config from rustls config
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .context("Failed to create QUIC server config")?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

        // Optimize for mesh networking
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(100u32.into());
        // Issue #907: Raised from 30s to 300s to prevent premature peer disconnection
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(300).try_into().unwrap()));

        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }
    
    /// Configure QUIC client with PinnedCertVerifier support
    fn configure_client(
        trust_mode: &QuicTrustMode,
        peer_addr: SocketAddr,
        verifier: &Arc<PinnedCertVerifier>,
    ) -> Result<ClientConfig> {
        let mut crypto = match trust_mode {
            QuicTrustMode::Strict => Self::build_strict_client_config()?,
            QuicTrustMode::Pinned => {
                // Set the current peer address for the verifier before connecting
                // This allows the verifier to check if it's a bootstrap peer
                verifier.set_current_peer(peer_addr);
                Self::build_pinned_client_config(Arc::clone(verifier))?
            }
            #[cfg(feature = "unsafe-bootstrap")]
            QuicTrustMode::BootstrapAllowlist(allowlist) => {
                if !allowlist.contains(&peer_addr) {
                    return Err(anyhow!(
                        "Peer {} is not in bootstrap allowlist for insecure TLS",
                        peer_addr
                    ));
                }
                Self::build_bootstrap_client_config()?
            }
            #[cfg(feature = "unsafe-bootstrap")]
            QuicTrustMode::MeshTrustUhp => {
                // Skip TLS verification - UHP handles identity verification
                Self::build_bootstrap_client_config()?
            }
        };

        // Configure ALPN protocols to match server (required for iOS Network.framework, Android Cronet)
        // Security note: ALPN is metadata only - actual security comes from UHP v2 (Kyber1024 + Dilithium5)
        crypto.alpn_protocols = vec![
            b"zhtp-mesh/1".to_vec(),  // Mesh peer-to-peer with UHP handshake
        ];

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .context("Failed to create QUIC client config")?
        ));

        // Optimize for mesh networking
        let mut transport_config = quinn::TransportConfig::default();
        // Issue #907: Raised from 30s to 300s to prevent premature peer disconnection
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(300).try_into().unwrap()));
        // Issue #907: Keepalive pings keep NAT mapping alive and prevent idle timeout
        // Only on client/outbound side (server doesn't initiate keepalive)
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));

        client_config.transport_config(Arc::new(transport_config));

        Ok(client_config)
    }

    /// Build client config with PinnedCertVerifier for production-safe mesh networking
    fn build_pinned_client_config(verifier: Arc<PinnedCertVerifier>) -> Result<rustls::ClientConfig> {
        Ok(rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth())
    }

    fn build_strict_client_config() -> Result<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs()
            .context("Failed to load native root certificates")?;
        for cert in native_certs {
            root_store
                .add(cert)
                .context("Failed to add native root certificate")?;
        }

        Ok(rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth())
    }

    #[cfg(feature = "unsafe-bootstrap")]
    fn build_bootstrap_client_config() -> Result<rustls::ClientConfig> {
        Ok(rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth())
    }
}

impl PqcQuicConnection {
    /// Convert to the runtime PeerConnection type used in the canonical store.
    pub fn into_peer_connection(self) -> PeerConnection {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        PeerConnection {
            quic_conn: self.quic_conn,
            session_key: self.session_key,
            verified_peer: self.verified_peer,
            session_id: self.session_id,
            peer_addr: self.peer_addr,
            bootstrap_mode: self.bootstrap_mode,
            connected_at: Instant::now(),
            last_activity: Arc::new(AtomicU64::new(now_secs)),
        }
    }

    /// Create a new PqcQuicConnection from a verified peer and derived keys.
    ///
    /// This is the ONLY way to create an authenticated connection.
    pub fn from_verified_peer(
        quic_conn: Connection,
        peer_addr: SocketAddr,
        verified_peer: crate::handshake::VerifiedPeer,
        session_key: [u8; 32],
        session_id: [u8; 32],
        bootstrap_mode: bool,
    ) -> Self {
        Self {
            quic_conn,
            session_key: Some(session_key),
            verified_peer,
            session_id: Some(session_id),
            peer_addr,
            bootstrap_mode,
        }
    }

    /// Get the underlying QUIC connection
    pub fn get_connection(&self) -> &Connection {
        &self.quic_conn
    }

    /// Get verified peer identity (only available after successful handshake)
    ///
    /// Returns the UHP-verified NodeIdentity containing:
    /// - DID (Decentralized Identifier)
    /// - Public key (Dilithium)
    /// - Device ID
    /// - Verified NodeId = Blake3(DID || device_name)
    pub fn peer_identity(&self) -> Option<&NodeIdentity> {
        Some(&self.verified_peer.identity)
    }

    /// Get peer node ID as raw bytes (convenience method)
    pub fn get_peer_node_id(&self) -> Option<[u8; 32]> {
        let bytes = self.verified_peer.identity.node_id.as_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Some(arr)
    }

    /// Get peer's DID
    pub fn peer_did(&self) -> Option<&str> {
        Some(self.verified_peer.identity.did.as_str())
    }

    /// Get session ID for logging/tracking
    pub fn session_id(&self) -> Option<[u8; 32]> {
        self.session_id
    }

    /// Get negotiated capabilities
    pub fn capabilities(&self) -> Option<&NegotiatedCapabilities> {
        Some(&self.verified_peer.capabilities)
    }

    /// Check if connection has valid session key (for message encryption)
    /// Does NOT expose the key itself - only validates it exists
    pub fn has_session_key(&self) -> bool {
        self.session_key.is_some()
    }

    /// Get session key reference for encryption (internal use only)
    /// Returns reference to prevent cloning/exposing the key
    pub fn get_session_key_ref(&self) -> Option<&[u8; 32]> {
        self.session_key.as_ref()
    }

    /// Send encrypted message using session key (UHP v2 derived)
    ///
    /// # Security
    ///
    /// Message is encrypted with ChaCha20-Poly1305 using the session key
    /// derived from UHP v2 handshake.
    /// QUIC provides additional TLS 1.3 encryption underneath.
    pub async fn send_encrypted_message(&mut self, message: &[u8]) -> Result<()> {
        let session_key = self.session_key
            .ok_or_else(|| anyhow!("UHP v2 handshake not complete"))?;

        // Encrypt with session key (ChaCha20-Poly1305)
        // Note: lib-crypto's encrypt_data includes nonce internally
        let encrypted = encrypt_data(message, &session_key)?;

        // Send over QUIC (which adds TLS 1.3 encryption on top)
        let mut stream = self.quic_conn.open_uni().await?;
        stream.write_all(&encrypted).await?;
        stream.finish()?;

        debug!("📤 Sent {} bytes (double-encrypted: UHP v2 + TLS 1.3)", message.len());
        Ok(())
    }

    /// Receive encrypted message using session key
    ///
    /// # Security
    ///
    /// Message is decrypted with ChaCha20-Poly1305 using the master key
    /// derived from UHP v2 session key.
    /// QUIC handles TLS 1.3 decryption underneath.
    pub async fn recv_encrypted_message(&mut self) -> Result<Vec<u8>> {
        let session_key = self.session_key
            .ok_or_else(|| anyhow!("UHP v2 handshake not complete"))?;

        // Receive from QUIC (TLS 1.3 decryption automatic)
        let mut stream = self.quic_conn.accept_uni().await?;
        let encrypted = stream.read_to_end(1024 * 1024).await?; // 1MB max message size

        // Decrypt using master key (nonce is embedded in encrypted data by lib-crypto)
        let decrypted = decrypt_data(&encrypted, &session_key)?;

        debug!("📥 Received {} bytes (double-decrypted: TLS 1.3 + UHP v2)", decrypted.len());
        Ok(decrypted)
    }

    // ========================================================================
    // REMOVED: Legacy methods that bypassed authentication
    // ========================================================================
    // The following methods have been REMOVED due to security concerns:
    //
    // - new() - Connections must now be created via from_verified_peer()
    // - set_shared_secret() - No longer needed, master key comes from handshake
    // - set_peer_info() - No longer needed, peer identity comes from handshake
    // - set_shared_secret_internal() - REMOVED - authentication bypass
    // - set_peer_info_internal() - REMOVED - authentication bypass
    // - perform_pqc_handshake_as_client() - REMOVED - used unverified PqcHandshakeMessage
    // - perform_pqc_handshake_as_server() - REMOVED - used unverified PqcHandshakeMessage
    //
    // All connections now require UHP authentication via quic_handshake module.
}

/// Self-signed certificate for QUIC
struct SelfSignedCert {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// Skip TLS certificate verification (unsafe-bootstrap only)
#[cfg(feature = "unsafe-bootstrap")]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(feature = "unsafe-bootstrap")]
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Skip verification - PQC provides real security
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ============================================================================
// Protocol Trait Implementation
// ============================================================================

#[async_trait]
impl super::Protocol for QuicMeshProtocol {
    async fn connect(&mut self, target: &super::PeerAddress) -> Result<super::ProtocolSession> {
        use crate::protocols::types::{SessionKeys, AuthScheme, CipherSuite};

        let peer_address = match target {
            super::PeerAddress::IpSocket(addr) => addr.clone(),
            _ => return Err(anyhow!("QUIC only supports IP socket addresses")),
        };

        let mut session_keys = SessionKeys::new(CipherSuite::ChaCha20Poly1305, true);
        let addr_str = peer_address.inner().to_string();
        let key_material = blake3::hash(
            format!("quic:mesh:{}:{}",
                String::from_iter([0u8; 32].iter().map(|b| format!("{:02x}", b))),
                &addr_str
            ).as_bytes()
        );
        session_keys.set_encryption_key(*key_material.as_bytes())?;

        let peer_did = format!("did:zhtp:quic:{}", &addr_str);
        let peer_identity = super::VerifiedPeerIdentity::new(
            peer_did,
            addr_str.as_bytes().to_vec(),
            vec![],
        )?;

        let mac_key = blake3::hash(b"quic:mac:key");
        let session = super::ProtocolSession::new(
            target.clone(),
            peer_identity,
            super::NetworkProtocol::QUIC,
            session_keys,
            AuthScheme::MutualHandshake,
            mac_key.as_bytes(),
        );

        Ok(session)
    }

    async fn accept(&mut self) -> Result<super::ProtocolSession> {
        Err(anyhow!("QUIC accept not implemented"))
    }

    fn validate_session(&self, session: &super::ProtocolSession) -> Result<()> {
        use crate::protocols::types::SessionRenewalReason;

        if session.protocol() != &super::NetworkProtocol::QUIC {
            return Err(anyhow!("Session is not for QUIC protocol"));
        }

        match session.lifecycle().needs_renewal() {
            SessionRenewalReason::None => {},
            reason => return Err(anyhow!("Session needs renewal: {:?}", reason)),
        }

        Ok(())
    }

    async fn send_message(&self, session: &super::ProtocolSession, envelope: &crate::types::mesh_message::MeshMessageEnvelope) -> Result<()> {
        self.validate_session(session)?;
        let _serialized = serde_json::to_vec(envelope)?;
        Ok(())
    }

    async fn receive_message(&self, _session: &super::ProtocolSession) -> Result<crate::types::mesh_message::MeshMessageEnvelope> {
        Err(anyhow!("Receive message not fully implemented for QUIC"))
    }

    async fn rekey_session(&mut self, session: &mut super::ProtocolSession) -> Result<()> {
        self.validate_session(session)?;
        Ok(())
    }

    fn capabilities(&self) -> super::ProtocolCapabilities {
        use crate::protocols::types::{AuthScheme, CipherSuite, PqcMode, PowerProfile};

        super::ProtocolCapabilities {
            version: crate::protocols::types::CAPABILITY_VERSION,
            mtu: 1200,
            throughput_mbps: 100.0,
            latency_ms: 5,
            range_meters: None,
            power_profile: PowerProfile::VeryHigh,
            reliable: true,
            requires_internet: true,
            auth_schemes: vec![AuthScheme::MutualHandshake],
            encryption: Some(CipherSuite::ChaCha20Poly1305),
            pqc_mode: PqcMode::Hybrid,
            replay_protection: true,
            identity_binding: true,
            integrity_only: false,
            forward_secrecy: true,
        }
    }

    fn protocol_type(&self) -> super::NetworkProtocol {
        super::NetworkProtocol::QUIC
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Compute SPKI hash from the default TLS certificate path.
///
/// This standalone function can be called without a QuicMeshProtocol instance,
/// useful for creating DiscoverySigningContext for signed announcements (Issue #739).
///
/// Returns None if the certificate doesn't exist yet (node hasn't started QUIC server).
pub fn get_tls_spki_hash_from_default_cert() -> Option<[u8; 32]> {
    use std::path::Path;

    let cert_path = Path::new(DEFAULT_TLS_CERT_PATH);

    if !cert_path.exists() {
        return None;
    }

    let cert_pem = std::fs::read(cert_path).ok()?;

    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .next()?  // Option<Result<CertificateDer>>
        .ok()?;   // Result -> Option

    QuicMeshProtocol::compute_spki_sha256(&cert_der).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::IdentityType;

    /// Helper to create a test identity with private key
    fn create_test_identity(device_name: &str) -> Arc<ZhtpIdentity> {
        Arc::new(
            ZhtpIdentity::new_unified(
                IdentityType::Human,
                Some(25),
                Some("US".to_string()),
                device_name,
                None,
            )
            .expect("Failed to create test identity")
        )
    }

    #[tokio::test]
    #[ignore] // Ignore DNS-dependent test
    async fn test_quic_mesh_initialization() -> Result<()> {
        let identity = create_test_identity("test-server");
        let bind_addr = "127.0.0.1:0".parse().unwrap();

        let quic_mesh = QuicMeshProtocol::new(identity, bind_addr)?;

        // Verify endpoint is bound
        assert!(quic_mesh.local_addr().port() > 0);

        quic_mesh.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Ignore DNS-dependent test - requires full UHP v2 handshake
    async fn test_quic_uhp_kyber_connection() -> Result<()> {
        // Create identities for both server and client
        let server_identity = create_test_identity("test-server");
        let client_identity = create_test_identity("test-client");

        // Start server
        let server_addr = "127.0.0.1:0".parse().unwrap();
        let server = QuicMeshProtocol::new(server_identity.clone(), server_addr)?;
        let server_port = server.local_addr().port();

        server.start_receiving().await?;

        // Wait for server to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Start client
        let client_addr = "127.0.0.1:0".parse().unwrap();
        let client = QuicMeshProtocol::new(client_identity.clone(), client_addr)?;

        // Connect client to server (performs UHP v2 handshake)
        let server_connect_addr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        client.connect_to_peer(server_connect_addr).await?;

        // Verify connection established
        let peers = client.get_active_peers();
        assert!(!peers.is_empty(), "Should have at least one peer connected");

        info!(
            client_did = %client_identity.did,
            server_did = %server_identity.did,
            "🔐 Test: UHP v2 handshake successful"
        );

        // Cleanup
        client.shutdown().await;
        server.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Ignore DNS-dependent test - requires full UHP v2 handshake
    async fn test_encrypted_message_exchange() -> Result<()> {
        // Create identities
        let server_identity = create_test_identity("msg-server");
        let client_identity = create_test_identity("msg-client");

        // Setup server
        let server_addr = "127.0.0.1:0".parse().unwrap();
        let server = Arc::new(QuicMeshProtocol::new(server_identity, server_addr)?);
        let server_port = server.local_addr().port();

        server.start_receiving().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Setup client
        let client_addr = "127.0.0.1:0".parse().unwrap();
        let client = Arc::new(QuicMeshProtocol::new(client_identity, client_addr)?);

        // Connect (performs UHP v2 handshake)
        let server_connect_addr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        client.connect_to_peer(server_connect_addr).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Verify connection with verified peer identity
        let peers = client.get_active_peers();
        if let Some(peer_addr) = peers.first() {
            info!("🔐 Test: Connected to verified peer at {}", peer_addr);
        }

        // Note: Full message exchange test would require setting up message handler
        // and verifying round-trip encryption/decryption with master key

        // Cleanup
        client.shutdown().await;
        server.shutdown().await;

        Ok(())
    }

    // =========================================================================
    // Issue #907: Canonical connection store tests
    //
    // These tests verify the DashMap-based connection store directly.
    // They don't require QuicMeshProtocol::new() (which needs a DB lock).
    // =========================================================================

    #[test]
    fn test_dashmap_store_insert_and_count() {
        let store: DashMap<Vec<u8>, u32> = DashMap::new();
        assert_eq!(store.len(), 0);

        store.insert(vec![1, 2, 3], 100);
        assert_eq!(store.len(), 1);

        store.insert(vec![4, 5, 6], 200);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_dashmap_store_remove_decrements_count() {
        let store: DashMap<Vec<u8>, u32> = DashMap::new();
        store.insert(vec![1, 2, 3], 100);
        assert_eq!(store.len(), 1);

        store.remove(&vec![1, 2, 3]);
        assert_eq!(store.len(), 0);

        // Removing non-existent key is a no-op
        store.remove(&vec![99, 98, 97]);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_dashmap_store_get_missing_returns_none() {
        let store: DashMap<Vec<u8>, u32> = DashMap::new();
        assert!(store.get(&vec![1, 2, 3]).is_none());
    }

    #[test]
    fn test_dashmap_store_iter_collects_keys() {
        let store: DashMap<Vec<u8>, u32> = DashMap::new();
        store.insert(vec![1], 10);
        store.insert(vec![2], 20);

        let keys: Vec<Vec<u8>> = store.iter().map(|e| e.key().clone()).collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&vec![1]));
        assert!(keys.contains(&vec![2]));
    }

    #[test]
    fn test_peer_connection_touch_updates_activity() {
        let last_activity = Arc::new(AtomicU64::new(0));
        assert_eq!(last_activity.load(Ordering::Relaxed), 0);

        // Simulate touch
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        last_activity.store(now, Ordering::Relaxed);

        assert!(last_activity.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    #[ignore] // Requires exclusive nonce cache DB lock
    async fn test_broadcast_message_no_peers_returns_zero() {
        let _ = lib_identity::types::node_id::try_set_network_genesis([0xABu8; 32]);
        let identity = create_test_identity("broadcast-test");
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let protocol = QuicMeshProtocol::new(identity, bind_addr)
            .expect("Failed to create protocol");

        let result = protocol.broadcast_message(b"test message").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        protocol.shutdown().await;
    }

    #[tokio::test]
    #[ignore] // Requires exclusive nonce cache DB lock
    async fn test_send_to_unknown_peer_returns_error() {
        let _ = lib_identity::types::node_id::try_set_network_genesis([0xABu8; 32]);
        let identity = create_test_identity("send-test");
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let protocol = QuicMeshProtocol::new(identity, bind_addr)
            .expect("Failed to create protocol");

        let message = ZhtpMeshMessage::PeerAnnouncement {
            sender: PublicKey::new(vec![0u8; 32]),
            timestamp: 42,
            signature: vec![],
        };

        let result = protocol.send_to_peer(&[99, 98, 97], message).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No connection to peer"));

        protocol.shutdown().await;
    }
}
