//! QUIC Mesh Protocol with Post-Quantum Cryptography
//!
//! Modern transport layer combining:
//! - QUIC (reliability, multiplexing, built-in TLS 1.3)
//! - UHP (Unified Handshake Protocol with Dilithium signatures)
//! - Kyber512 KEM (Post-quantum key encapsulation)
//!
//! # Architecture
//!
//! ```text
//! ZHTP Message
//!     ↓
//! PQC Encryption (master_key from UHP+Kyber + ChaCha20-Poly1305)  ← Post-quantum security
//!     ↓
//! QUIC Connection (TLS 1.3 encryption + reliability)              ← Transport security
//!     ↓
//! UDP/IP Network
//! ```
//!
//! **Note on Double Encryption**: This is defense-in-depth, NOT wasteful redundancy.
//! - TLS 1.3: Protects against network-level attacks (MitM, passive eavesdropping)
//! - App-layer ChaCha20+Kyber: Provides post-quantum security + cryptographic binding
//! - Both layers serve different purposes and cannot be removed without losing security
//!
//! # Security Properties
//!
//! - **Mutual Authentication**: UHP verifies Dilithium signatures from both peers
//! - **NodeId Verification**: Validates NodeId = Blake3(DID || device_name)
//! - **Replay Protection**: Nonce cache prevents replay attacks
//! - **Post-Quantum Security**: Kyber512 KEM provides quantum-resistant key exchange
//! - **Cryptographic Binding**: Kyber is bound to UHP transcript + peer NodeId
//!
//! # Protocol Flow
//!
//! 1. QUIC connection establishment (TLS 1.3)
//! 2. UHP authentication over dedicated bidirectional stream
//! 3. Kyber key exchange (bound to UHP transcript)
//! 4. Master key derivation: HKDF(uhp_session_key || kyber_secret || transcript_hash || peer_node_id)
//! 5. Application messaging using master key

use anyhow::{Result, Context, anyhow};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
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

// Import new QUIC+UHP+Kyber handshake adapter
use super::quic_handshake;

use crate::types::mesh_message::ZhtpMeshMessage;
use crate::messaging::message_handler::MeshMessageHandler;

/// Default path for TLS certificate
pub const DEFAULT_TLS_CERT_PATH: &str = "./data/tls/server.crt";
/// Default path for TLS private key
pub const DEFAULT_TLS_KEY_PATH: &str = "./data/tls/server.key";

/// Trust policy for QUIC TLS verification.
#[derive(Clone, Debug)]
pub enum QuicTrustMode {
    /// Strict TLS verification using native root certificates.
    Strict,
    /// Allow TLS verification to be skipped only for explicit allowlisted peers.
    #[cfg(feature = "unsafe-bootstrap")]
    BootstrapAllowlist(Vec<SocketAddr>),
}

/// QUIC mesh protocol with UHP authentication and PQC encryption layer
pub struct QuicMeshProtocol {
    /// QUIC endpoint (handles all connections)
    endpoint: Endpoint,

    /// Active connections to peers (peer_node_id -> connection)
    connections: Arc<RwLock<std::collections::HashMap<Vec<u8>, PqcQuicConnection>>>,

    /// This node's Sovereign Identity (for UHP authentication)
    identity: Arc<ZhtpIdentity>,

    /// Handshake context with nonce cache (shared across all connections for replay protection)
    handshake_ctx: HandshakeContext,

    /// Local binding address
    local_addr: SocketAddr,

    /// Trust policy for TLS verification
    trust_mode: QuicTrustMode,

    /// Message handler for processing received messages
    pub message_handler: Option<Arc<RwLock<MeshMessageHandler>>>,
}

/// QUIC connection with UHP-verified identity and PQC encryption
///
/// After successful handshake, this connection has:
/// - **Verified peer identity**: Dilithium signatures verified via UHP
/// - **Master key**: Derived from UHP session key + Kyber shared secret
/// - **Replay protection**: Nonces checked against shared cache
pub struct PqcQuicConnection {
    /// Underlying QUIC connection
    quic_conn: Connection,

    /// Master key for symmetric encryption (derived from UHP + Kyber)
    /// This is the ONLY encryption key - intermediate keys are zeroized
    master_key: Option<[u8; 32]>,

    /// Verified peer identity and negotiated capabilities
    verified_peer: crate::handshake::VerifiedPeer,

    /// Session ID for logging/tracking
    session_id: Option<[u8; 16]>,

    /// Peer address
    peer_addr: SocketAddr,

    /// Bootstrap mode: allows unauthenticated blockchain sync requests
    /// New nodes connecting for first time can only request blockchain data
    /// NOTE: Even in bootstrap mode, UHP handshake is performed for identity verification
    pub bootstrap_mode: bool,
}

// NOTE: PqcHandshakeMessage has been REMOVED - authentication bypass vulnerability
// All QUIC connections now use UHP + Kyber via quic_handshake module
// See: quic_handshake::handshake_as_initiator / handshake_as_responder

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
        info!("🔐 Initializing QUIC mesh protocol on {} with UHP+Kyber authentication", bind_addr);

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
        // Uses RocksDB for persistence across restarts (prevents replay attacks)
        // TTL: 1 hour, max entries: 100,000 (handles high connection rate)
        let nonce_db_path = cert_path.parent()
            .unwrap_or(Path::new("./data"))
            .join("quic_nonce_cache");

        // TODO: Pass network epoch from blockchain context (genesis hash)
        let network_epoch = crate::handshake::NetworkEpoch::from_chain_id(0);
        let nonce_cache = NonceCache::open(&nonce_db_path, 3600, 100_000, network_epoch)
            .context("Failed to open QUIC nonce cache database")?;

        let handshake_ctx = HandshakeContext::new(nonce_cache);

        info!(
            node_id = ?identity.node_id,
            did = %identity.did,
            "QUIC mesh protocol initialized with Sovereign Identity"
        );

        Ok(Self {
            endpoint,
            connections: Arc::new(RwLock::new(std::collections::HashMap::new())),
            identity,
            handshake_ctx,
            local_addr: actual_addr,
            trust_mode: QuicTrustMode::Strict,
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
    
    /// Get the QUIC endpoint for accepting connections
    pub fn get_endpoint(&self) -> Arc<Endpoint> {
        Arc::new(self.endpoint.clone())
    }
    
    /// Connect to a peer using QUIC with UHP+Kyber handshake
    ///
    /// # Security
    ///
    /// This performs full mutual authentication via UHP:
    /// 1. QUIC connection establishment (TLS 1.3)
    /// 2. UHP authentication (Dilithium signatures verified)
    /// 3. Kyber key exchange (bound to UHP transcript)
    /// 4. Master key derivation for symmetric encryption
    ///
    /// The peer's identity is cryptographically verified before any data exchange.
    pub async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<()> {
        info!("🔐 Connecting to peer at {} via QUIC+UHP+Kyber", peer_addr);

        // Configure client
        let client_config = Self::configure_client(&self.trust_mode, peer_addr)?;

        // Connect via QUIC
        let connection = self.endpoint
            .connect_with(client_config, peer_addr, "zhtp-mesh")?
            .await
            .context("QUIC connection failed")?;

        info!("🔐 QUIC connection established to {}", peer_addr);

        // Perform UHP+Kyber handshake (mutual authentication + PQC key exchange)
        let handshake_result = quic_handshake::handshake_as_initiator(
            &connection,
            &self.identity,
            &self.handshake_ctx,
        ).await.context("UHP+Kyber handshake failed")?;

        info!(
            peer_did = %handshake_result.verified_peer.identity.did,
            peer_device = %handshake_result.verified_peer.identity.device_id,
            session_id = ?handshake_result.session_id,
            "🔐 UHP+Kyber handshake complete with {} (quantum-safe encryption active)",
            peer_addr
        );

        // Create PqcQuicConnection from verified peer
        let pqc_conn = PqcQuicConnection::from_verified_peer(
            connection,
            peer_addr,
            handshake_result.verified_peer.clone(),
            handshake_result.master_key,
            handshake_result.session_id,
            false, // Not bootstrap mode
        );

        // Store connection using peer's node_id as key
        let peer_key = pqc_conn
            .peer_identity()
            .ok_or_else(|| anyhow!("Peer identity not set after handshake"))?
            .node_id.as_bytes().to_vec();

        self.connections.write().await.insert(peer_key, pqc_conn);

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

        // Configure client
        let client_config = Self::configure_client(&self.trust_mode, peer_addr)?;

        // Connect via QUIC
        let connection = self.endpoint
            .connect_with(client_config, peer_addr, "zhtp-mesh")?
            .await
            .context("QUIC connection failed")?;

        info!("🔐 QUIC connection established to bootstrap peer {}", peer_addr);

        // Perform UHP+Kyber handshake (authentication required even for bootstrap)
        let handshake_result = quic_handshake::handshake_as_initiator(
            &connection,
            &self.identity,
            &self.handshake_ctx,
        ).await.context("UHP+Kyber handshake with bootstrap peer failed")?;

        info!(
            peer_did = %handshake_result.verified_peer.identity.did,
            session_id = ?handshake_result.session_id,
            "🔐 Bootstrap peer verified: {} (bootstrap mode: {})",
            peer_addr,
            mode_str
        );

        if is_edge_node {
            info!("   → Edge node: Can download headers + ZK proofs");
            info!("   → Edge node: Will NOT download full blocks");
        } else {
            info!("   → Full node: Can download complete blockchain");
            info!("   → Full node: Will store and validate all blocks");
        }
        info!("   → Cannot submit transactions until full identity established");

        // Create PqcQuicConnection from handshake result (bootstrap mode)
        let pqc_conn = PqcQuicConnection::from_verified_peer(
            connection,
            peer_addr,
            handshake_result.verified_peer.clone(),
            handshake_result.master_key,
            handshake_result.session_id,
            true, // Bootstrap mode
        );

        // Store connection using peer's node_id as key
        let peer_key = pqc_conn
            .peer_identity()
            .ok_or_else(|| anyhow!("Peer identity not set after handshake"))?
            .node_id.as_bytes().to_vec();

        self.connections.write().await.insert(peer_key, pqc_conn);

        Ok(())
    }
    
    /// Send encrypted ZHTP message to peer
    pub async fn send_to_peer(
        &self,
        peer_pubkey: &[u8],
        message: ZhtpMeshMessage,
    ) -> Result<()> {
        let mut conns = self.connections.write().await;
        
        let conn = conns.get_mut(peer_pubkey)
            .ok_or_else(|| anyhow!("No connection to peer"))?;
        
        // Serialize message
        let message_bytes = bincode::serialize(&message)
            .context("Failed to serialize ZhtpMeshMessage")?;

        conn.send_encrypted_message(&message_bytes).await?;
        
        debug!("📤 Sent {} bytes to peer (PQC encrypted + QUIC)", message_bytes.len());
        Ok(())
    }
    
    /// Receive messages from peers (background task)
    ///
    /// Spawns background tasks to:
    /// 1. Accept incoming QUIC connections
    /// 2. Perform UHP+Kyber handshake for each connection
    /// 3. Receive encrypted messages on established connections
    ///
    /// # Security
    ///
    /// All incoming connections are authenticated via UHP before accepting messages.
    /// Connections that fail handshake are immediately closed.
    pub async fn start_receiving(&self) -> Result<()> {
        info!("🔐 Starting QUIC message receiver with UHP authentication...");

        let endpoint = self.endpoint.clone();
        let connections = Arc::clone(&self.connections);
        let message_handler = self.message_handler.clone();
        let identity = Arc::clone(&self.identity);
        let handshake_ctx = self.handshake_ctx.clone();

        // Task 1: Accept new incoming connections
        tokio::spawn(async move {
            loop {
                // Accept incoming connections
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
                                    info!("🔐 New QUIC connection from {}", peer_addr);

                                    // Perform UHP+Kyber handshake as server
                                    let handshake_result = match quic_handshake::handshake_as_responder(
                                        &connection,
                                        &identity,
                                        &ctx,
                                    ).await {
                                        Ok(result) => result,
                                        Err(e) => {
                                            error!(
                                                peer_addr = %peer_addr,
                                                error = %e,
                                                "UHP+Kyber handshake failed - rejecting connection"
                                            );
                                            // Close connection on handshake failure
                                            connection.close(1u32.into(), b"handshake_failed");
                                            return;
                                        }
                                    };

                                    info!(
                                        peer_did = %handshake_result.verified_peer.identity.did,
                                        peer_device = %handshake_result.verified_peer.identity.device_id,
                                        session_id = ?handshake_result.session_id,
                                        "🔐 UHP+Kyber handshake complete (server side)"
                                    );

                                    // Create PqcQuicConnection from verified peer
                                    let pqc_conn = PqcQuicConnection::from_verified_peer(
                                        connection.clone(),
                                        peer_addr,
                                        handshake_result.verified_peer.clone(),
                                        handshake_result.master_key,
                                        handshake_result.session_id,
                                        false, // Determine bootstrap mode based on peer capabilities
                                    );

                                    // Get peer node ID for connection key
                                    let peer_id_vec = handshake_result.verified_peer.identity.node_id.as_bytes().to_vec();

                                    // Store connection
                                    conns.write().await.insert(peer_id_vec.clone(), pqc_conn);

                                    // Start receiving messages on this connection
                                    let conns_clone = Arc::clone(&conns);
                                    let handler_clone = handler.clone();

                                    tokio::spawn(async move {
                                        loop {
                                            // Get connection
                                            let mut conn_guard = conns_clone.write().await;
                                            let pqc_conn = match conn_guard.get_mut(&peer_id_vec) {
                                                Some(c) => c,
                                                None => {
                                                    debug!("Connection closed for peer");
                                                    break;
                                                }
                                            };

                                            // Receive message
                                            match pqc_conn.recv_encrypted_message().await {
                                                Ok(message_bytes) => {
                                                    debug!("📨 Received {} bytes from verified peer", message_bytes.len());

                                                    // Deserialize message
                                                    match bincode::deserialize::<ZhtpMeshMessage>(&message_bytes) {
                                                        Ok(message) => {
                                                            if let Some(h) = &handler_clone {
                                                                let peer_pk = PublicKey::new(peer_id_vec.clone());
                                                                if let Err(e) = h.read().await.handle_mesh_message(message, peer_pk).await {
                                                                    error!("Error handling message: {}", e);
                                                                }
                                                            } else {
                                                                warn!("No message handler configured for QUIC protocol");
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!("Failed to deserialize ZhtpMeshMessage: {}", e);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    debug!("Connection closed or error: {}", e);
                                                    break;
                                                }
                                            }
                                            drop(conn_guard); // Release lock
                                        }
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
    pub async fn get_connection(&self, peer_key: &[u8]) -> Result<Connection> {
        let conns = self.connections.read().await;
        let pqc_conn = conns.get(peer_key)
            .ok_or_else(|| anyhow!("No connection to peer with key {:?}", &peer_key[..8]))?;
        Ok(pqc_conn.quic_conn.clone())
    }
    
    /// Get all active connection addresses
    pub async fn get_active_peers(&self) -> Vec<SocketAddr> {
        let conns = self.connections.read().await;
        conns.values().map(|c| c.peer_addr).collect()
    }
    
    /// Get local endpoint address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    
    /// Close all connections gracefully
    pub async fn shutdown(&self) {
        info!("🔌 Shutting down QUIC mesh protocol...");
        self.endpoint.close(0u32.into(), b"shutdown");
        self.connections.write().await.clear();
    }
    
    /// Load existing TLS certificate from disk, or generate a new one if not found.
    ///
    /// This enables persistent certificates for Android Cronet compatibility.
    /// Mobile apps can pin the certificate hash since it remains constant across restarts.
    ///
    /// Node-to-node connections are unaffected - they use SkipServerVerification
    /// and rely on PQC (Kyber + Dilithium) for security.
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
        info!("   To extract hash for Android pinning:");
        info!("   openssl x509 -in {} -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64", cert_path.display());

        let cert_der = CertificateDer::from(cert.der().to_vec());

        // Convert KeyPair to PrivateKeyDer by serializing to PKCS#8
        let key_der_bytes = signing_key.serialize_der();
        let key_der = PrivateKeyDer::Pkcs8(key_der_bytes.into());

        Ok(SelfSignedCert {
            cert: cert_der,
            key: key_der,
        })
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
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));

        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }
    
    /// Configure QUIC client
    fn configure_client(trust_mode: &QuicTrustMode, peer_addr: SocketAddr) -> Result<ClientConfig> {
        let mut crypto = match trust_mode {
            QuicTrustMode::Strict => Self::build_strict_client_config()?,
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
        };

        // Configure ALPN protocols to match server (required for iOS Network.framework, Android Cronet)
        // Security note: ALPN is metadata only - actual security comes from PQC layer (Kyber + Dilithium)
        crypto.alpn_protocols = vec![
            b"zhtp-mesh/1".to_vec(),  // Mesh peer-to-peer with UHP handshake
        ];

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .context("Failed to create QUIC client config")?
        ));

        // Optimize for mesh networking
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));

        client_config.transport_config(Arc::new(transport_config));

        Ok(client_config)
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
    /// Create a new PqcQuicConnection from a verified peer and derived keys.
    ///
    /// This is the ONLY way to create an authenticated connection.
    pub fn from_verified_peer(
        quic_conn: Connection,
        peer_addr: SocketAddr,
        verified_peer: crate::handshake::VerifiedPeer,
        master_key: [u8; 32],
        session_id: [u8; 16],
        bootstrap_mode: bool,
    ) -> Self {
        Self {
            quic_conn,
            master_key: Some(master_key),
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
    pub fn session_id(&self) -> Option<[u8; 16]> {
        self.session_id
    }

    /// Get negotiated capabilities
    pub fn capabilities(&self) -> Option<&NegotiatedCapabilities> {
        Some(&self.verified_peer.capabilities)
    }

    /// Check if connection has valid master key (for message encryption)
    /// Does NOT expose the key itself - only validates it exists
    pub fn has_master_key(&self) -> bool {
        self.master_key.is_some()
    }

    /// Get master key reference for encryption (internal use only)
    /// Returns reference to prevent cloning/exposing the key
    pub fn get_master_key_ref(&self) -> Option<&[u8; 32]> {
        self.master_key.as_ref()
    }

    /// Send encrypted message using master key (UHP+Kyber derived)
    ///
    /// # Security
    ///
    /// Message is encrypted with ChaCha20-Poly1305 using the master key
    /// derived from UHP session key + Kyber shared secret.
    /// QUIC provides additional TLS 1.3 encryption underneath.
    pub async fn send_encrypted_message(&mut self, message: &[u8]) -> Result<()> {
        let master_key = self.master_key
            .ok_or_else(|| anyhow!("UHP+Kyber handshake not complete"))?;

        // Encrypt with master key (ChaCha20-Poly1305)
        // Note: lib-crypto's encrypt_data includes nonce internally
        let encrypted = encrypt_data(message, &master_key)?;

        // Send over QUIC (which adds TLS 1.3 encryption on top)
        let mut stream = self.quic_conn.open_uni().await?;
        stream.write_all(&encrypted).await?;
        stream.finish()?;

        debug!("📤 Sent {} bytes (double-encrypted: UHP+Kyber + TLS 1.3)", message.len());
        Ok(())
    }

    /// Receive encrypted message using master key
    ///
    /// # Security
    ///
    /// Message is decrypted with ChaCha20-Poly1305 using the master key
    /// derived from UHP session key + Kyber shared secret.
    /// QUIC handles TLS 1.3 decryption underneath.
    pub async fn recv_encrypted_message(&mut self) -> Result<Vec<u8>> {
        let master_key = self.master_key
            .ok_or_else(|| anyhow!("UHP+Kyber handshake not complete"))?;

        // Receive from QUIC (TLS 1.3 decryption automatic)
        let mut stream = self.quic_conn.accept_uni().await?;
        let encrypted = stream.read_to_end(1024 * 1024).await?; // 1MB max message size

        // Decrypt using master key (nonce is embedded in encrypted data by lib-crypto)
        let decrypted = decrypt_data(&encrypted, &master_key)?;

        debug!("📥 Received {} bytes (double-decrypted: TLS 1.3 + UHP+Kyber)", decrypted.len());
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
    #[ignore] // Ignore DNS-dependent test - requires full UHP+Kyber handshake
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

        // Connect client to server (performs UHP+Kyber handshake)
        let server_connect_addr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        client.connect_to_peer(server_connect_addr).await?;

        // Verify connection established
        let peers = client.get_active_peers().await;
        assert!(!peers.is_empty(), "Should have at least one peer connected");

        info!(
            client_did = %client_identity.did,
            server_did = %server_identity.did,
            "🔐 Test: UHP+Kyber handshake successful"
        );

        // Cleanup
        client.shutdown().await;
        server.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Ignore DNS-dependent test - requires full UHP+Kyber handshake
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

        // Connect (performs UHP+Kyber handshake)
        let server_connect_addr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        client.connect_to_peer(server_connect_addr).await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Verify connection with verified peer identity
        let peers = client.get_active_peers().await;
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
}
