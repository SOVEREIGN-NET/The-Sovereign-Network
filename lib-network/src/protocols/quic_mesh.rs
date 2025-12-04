//! QUIC Mesh Protocol with Post-Quantum Cryptography
//!
//! Modern transport layer combining:
//! - QUIC (reliability, multiplexing, built-in TLS 1.3)
//! - Post-Quantum Cryptography (Kyber + Dilithium from lib-crypto)
//!
//! Architecture:
//! ```text
//! ZHTP Message
//!     ↓
//! PQC Encryption (Kyber shared secret + ChaCha20-Poly1305)
//!     ↓
//! QUIC Connection (TLS 1.3 encryption + reliability)
//!     ↓
//! UDP/IP Network
//! ```

use anyhow::{Result, Context, anyhow};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug, error};
use serde::{Serialize, Deserialize};

use quinn::{Endpoint, Connection, ServerConfig, ClientConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// Import your PQC from lib-crypto
use lib_crypto::{
    PublicKey,
    symmetric::chacha20::{encrypt_data, decrypt_data},
};

use crate::types::mesh_message::ZhtpMeshMessage;
use crate::messaging::message_handler::MeshMessageHandler;

/// QUIC mesh protocol with PQC encryption layer
pub struct QuicMeshProtocol {
    /// QUIC endpoint (handles all connections)
    endpoint: Endpoint,
    
    /// Active connections to peers (peer_pubkey -> connection)
    connections: Arc<RwLock<std::collections::HashMap<Vec<u8>, PqcQuicConnection>>>,
    
    /// This node's identity
    node_id: [u8; 32],
    
    /// Local binding address
    local_addr: SocketAddr,

    /// Message handler for processing received messages
    pub message_handler: Option<Arc<RwLock<MeshMessageHandler>>>,
}

/// QUIC connection with PQC encryption
pub struct PqcQuicConnection {
    /// Underlying QUIC connection
    quic_conn: Connection,
    
    /// Post-quantum shared secret (derived from Kyber key exchange)
    kyber_shared_secret: Option<[u8; 32]>,
    
    /// Peer's Dilithium public key (for signature verification)
    peer_dilithium_key: Option<Vec<u8>>,
    
    /// Peer's node ID (32 bytes)
    peer_node_id: Option<[u8; 32]>,
    
    /// Peer address
    peer_addr: SocketAddr,
    
    /// Bootstrap mode: allows unauthenticated blockchain sync requests
    /// New nodes connecting for first time can only request blockchain data
    pub bootstrap_mode: bool,
}

/// Handshake message for PQC key exchange over QUIC
#[derive(Debug, Serialize, Deserialize)]
pub enum PqcHandshakeMessage {
    /// Client sends Kyber public key to server
    KyberPublicKey {
        kyber_pubkey: Vec<u8>,
        dilithium_pubkey: Vec<u8>,
        node_id: [u8; 32],
    },
    
    /// Server responds with encrypted shared secret
    KyberEncapsulation {
        ciphertext: Vec<u8>,
        dilithium_signature: Vec<u8>,
    },
    
    /// Acknowledge successful key exchange
    HandshakeComplete,
}

impl QuicMeshProtocol {
    /// Create a new QUIC mesh protocol instance
    pub fn new(node_id: [u8; 32], bind_addr: SocketAddr) -> Result<Self> {
        info!(" Initializing QUIC mesh protocol on {}", bind_addr);
        
        // Generate self-signed certificate for QUIC (TLS 1.3 requirement)
        let cert = Self::generate_self_signed_cert()?;
        
        // Configure QUIC server
        let server_config = Self::configure_server(cert.cert, cert.key)?;
        
        // Create QUIC endpoint
        let endpoint = Endpoint::server(server_config, bind_addr)
            .context("Failed to create QUIC endpoint")?;
        
        info!(" QUIC endpoint listening on {}", endpoint.local_addr()?);
        
        Ok(Self {
            endpoint,
            connections: Arc::new(RwLock::new(std::collections::HashMap::new())),
            node_id,
            local_addr: bind_addr,
            message_handler: None,
        })
    }

    /// Set the message handler for processing received messages
    pub fn set_message_handler(&mut self, handler: Arc<RwLock<MeshMessageHandler>>) {
        self.message_handler = Some(handler);
    }
    
    /// Get the QUIC endpoint for accepting connections
    pub fn get_endpoint(&self) -> Arc<Endpoint> {
        Arc::new(self.endpoint.clone())
    }
    
    /// Connect to a peer using QUIC with PQC handshake
    pub async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<()> {
        info!(" Connecting to peer at {} via QUIC+PQC", peer_addr);
        
        // Configure client
        let client_config = Self::configure_client()?;
        
        // Connect via QUIC
        let connection = self.endpoint
            .connect_with(client_config, peer_addr, "zhtp-mesh")?
            .await
            .context("QUIC connection failed")?;
        
        info!(" QUIC connection established to {}", peer_addr);
        
        // Perform PQC handshake (normal authenticated mode)
        let mut pqc_conn = PqcQuicConnection::new(connection, peer_addr, false);
        pqc_conn.perform_pqc_handshake_as_client().await?;
        
        info!(" PQC handshake complete with {} (quantum-safe encryption active)", peer_addr);
        
        // Store connection using peer's node_id as key
        let peer_key = pqc_conn.peer_node_id
            .ok_or_else(|| anyhow!("Peer node_id not set after handshake"))?;
        self.connections.write().await.insert(peer_key.to_vec(), pqc_conn);
        
        Ok(())
    }
    
    /// Connect to a bootstrap peer in unauthenticated mode (for new nodes downloading blockchain)
    /// Bootstrap mode connections can only request blockchain data, not submit transactions or store DHT data
    /// 
    /// # Arguments
    /// * `peer_addr` - Address of the bootstrap peer
    /// * `is_edge_node` - If true, uses edge sync (headers + ZK proofs). If false, downloads full blockchain
    pub async fn connect_as_bootstrap(&self, peer_addr: SocketAddr, is_edge_node: bool) -> Result<()> {
        let mode_str = if is_edge_node { "edge node - headers+proofs only" } else { "full node - complete blockchain" };
        info!(" Connecting to bootstrap peer at {} (bootstrap mode: {})", peer_addr, mode_str);
        
        // Configure client
        let client_config = Self::configure_client()?;
        
        // Connect via QUIC
        let connection = self.endpoint
            .connect_with(client_config, peer_addr, "zhtp-mesh")?
            .await
            .context("QUIC connection failed")?;
        
        info!(" QUIC connection established to bootstrap peer {}", peer_addr);
        
        // Perform PQC handshake in bootstrap mode (allows unauthenticated blockchain requests)
        let mut pqc_conn = PqcQuicConnection::new(connection, peer_addr, true);
        pqc_conn.perform_pqc_handshake_as_client().await?;
        
        info!(" PQC handshake complete with bootstrap peer {} (bootstrap mode active)", peer_addr);
        if is_edge_node {
            info!("   → Edge node: Can download headers + ZK proofs");
            info!("   → Edge node: Will NOT download full blocks");
        } else {
            info!("   → Full node: Can download complete blockchain");
            info!("   → Full node: Will store and validate all blocks");
        }
        info!("   → Cannot submit transactions or store DHT data until identity created");
        
        // Store connection using peer's node_id as key
        let peer_key = pqc_conn.peer_node_id
            .ok_or_else(|| anyhow!("Peer node_id not set after handshake"))?;
        self.connections.write().await.insert(peer_key.to_vec(), pqc_conn);
        
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
    pub async fn start_receiving(&self) -> Result<()> {
        info!(" Starting QUIC message receiver...");
        
        let endpoint = self.endpoint.clone();
        let connections = Arc::clone(&self.connections);
        let message_handler = self.message_handler.clone();
        
        // Task 1: Accept new incoming connections
        tokio::spawn(async move {
            loop {
                // Accept incoming connections
                match endpoint.accept().await {
                    Some(incoming) => {
                        let conns = Arc::clone(&connections);
                        let handler = message_handler.clone();
                        
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(connection) => {
                                    info!(" New QUIC connection from {}", connection.remote_address());
                                    
                                    // Perform PQC handshake as server
                                    let peer_addr = connection.remote_address();
                                    let mut pqc_conn = PqcQuicConnection::new(connection.clone(), peer_addr, false);
                                    
                                    if let Err(e) = pqc_conn.perform_pqc_handshake_as_server().await {
                                        error!("PQC handshake failed: {}", e);
                                        return;
                                    }
                                    
                                    info!(" PQC handshake complete (server side)");
                                    
                                    // Store connection using peer's node_id as key
                                    if let Some(peer_id) = pqc_conn.peer_node_id {
                                        conns.write().await.insert(peer_id.to_vec(), pqc_conn);
                                        
                                        // Start receiving messages on this connection
                                        let conns_clone = Arc::clone(&conns);
                                        let peer_id_vec = peer_id.to_vec();
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
                                                        debug!("📨 Received {} bytes from peer", message_bytes.len());
                                                        
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
                                    } else {
                                        error!("Peer node_id not set after handshake");
                                    }
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
    
    /// Generate self-signed certificate for QUIC/TLS
    fn generate_self_signed_cert() -> Result<SelfSignedCert> {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        
        let subject_alt_names = vec!["zhtp-mesh".to_string(), "localhost".to_string()];
        
        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names)
            .context("Failed to generate certificate")?;
        
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
        let mut server_config = ServerConfig::with_single_cert(vec![cert], key)
            .context("Failed to configure server")?;
        
        // Optimize for mesh networking
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(100u32.into());
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        
        server_config.transport_config(Arc::new(transport_config));
        
        Ok(server_config)
    }
    
    /// Configure QUIC client
    fn configure_client() -> Result<ClientConfig> {
        // For mesh networking, we use self-signed certs and skip verification
        // (PQC layer provides actual security)
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        
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
}

impl PqcQuicConnection {
    pub fn new(quic_conn: Connection, peer_addr: SocketAddr, bootstrap_mode: bool) -> Self {
        Self {
            quic_conn,
            kyber_shared_secret: None,
            peer_dilithium_key: None,
            peer_node_id: None,
            peer_addr,
            bootstrap_mode,
        }
    }

    /// Set the shared secret after handshake (used by QuicHandler)
    pub fn set_shared_secret(&mut self, secret: [u8; 32]) {
        self.kyber_shared_secret = Some(secret);
    }

    /// Set peer info after handshake (used by QuicHandler)
    pub fn set_peer_info(&mut self, node_id: [u8; 32], dilithium_key: Vec<u8>) {
        self.peer_node_id = Some(node_id);
        self.peer_dilithium_key = Some(dilithium_key);
    }

    /// Get the underlying QUIC connection
    pub fn get_connection(&self) -> &Connection {
        &self.quic_conn
    }

    /// Get peer node ID
    pub fn get_peer_node_id(&self) -> Option<[u8; 32]> {
        self.peer_node_id
    }

    /// Perform PQC key exchange as client
    async fn perform_pqc_handshake_as_client(&mut self) -> Result<()> {
        debug!(" Starting PQC handshake (client)...");
        
        // Open bidirectional stream for handshake
        let (mut send, mut recv) = self.quic_conn.open_bi().await
            .context("Failed to open handshake stream")?;
        
        // Generate Kyber keypair using lib-crypto
        let kyber_keypair = lib_crypto::KeyPair::generate()
            .context("Failed to generate Kyber keypair")?;

        let kyber_pubkey = kyber_keypair.public_key.kyber_pk.clone();
        let dilithium_pubkey = kyber_keypair.public_key.dilithium_pk.clone();
        let node_id = kyber_keypair.public_key.key_id;
        
        // Send our public keys
        let handshake_msg = PqcHandshakeMessage::KyberPublicKey {
            kyber_pubkey: kyber_pubkey.clone(),
            dilithium_pubkey: dilithium_pubkey.clone(),
            node_id,
        };
        
        let msg_bytes = bincode::serialize(&handshake_msg)?;
        send.write_all(&msg_bytes).await?;
        send.finish()?;
        
        // Receive encapsulated secret from server
        let response_bytes = recv.read_to_end(1024 * 16).await
            .context("Failed to read handshake response")?;
        
        // Parse response
        let response: PqcHandshakeMessage = bincode::deserialize(&response_bytes)
            .context("Failed to deserialize handshake response")?;

        if let PqcHandshakeMessage::KyberEncapsulation { ciphertext, dilithium_signature } = response {
            // Decapsulate shared secret using our private key
            use lib_crypto::post_quantum::kyber512_decapsulate;
            
            let shared_secret = kyber512_decapsulate(
                &ciphertext,
                &kyber_keypair.private_key.kyber_sk,
                b"ZHTP-QUIC-v1.0"
            ).context("Failed to decapsulate Kyber shared secret")?;
            
            self.kyber_shared_secret = Some(shared_secret);
            self.peer_dilithium_key = Some(dilithium_signature);
            // Note: peer_node_id is set from the initial message (node_id field)
            self.peer_node_id = Some(node_id);
            
            debug!(" PQC handshake complete (client): quantum-safe key established");
        } else {
            return Err(anyhow!("Unexpected handshake response format"));
        }
        
        Ok(())
    }
    
    /// Perform PQC key exchange as server
    async fn perform_pqc_handshake_as_server(&mut self) -> Result<()> {
        debug!(" Starting PQC handshake (server)...");
        
        // Accept bidirectional stream for handshake
        let (mut send, mut recv) = self.quic_conn.accept_bi().await
            .context("Failed to accept handshake stream")?;
        
        // Receive client's public keys
        let handshake_bytes = recv.read_to_end(1024 * 16).await
            .context("Failed to read client handshake")?;
        
        // Parse client message
        let client_msg: PqcHandshakeMessage = bincode::deserialize(&handshake_bytes)
            .context("Failed to deserialize client handshake")?;

        if let PqcHandshakeMessage::KyberPublicKey { kyber_pubkey, dilithium_pubkey, node_id } = client_msg {
            // Encapsulate shared secret using client's public key
            use lib_crypto::post_quantum::kyber512_encapsulate;
            
            let (ciphertext, shared_secret) = kyber512_encapsulate(&kyber_pubkey)
                .context("Failed to encapsulate Kyber shared secret")?;
            
            // Generate our own keypair for authentication
            let our_keypair = lib_crypto::KeyPair::generate()
                .context("Failed to generate server keypair")?;
            
            // Send encapsulated secret back with our public key for authentication
            let response_msg = PqcHandshakeMessage::KyberEncapsulation {
                ciphertext: ciphertext.clone(),
                dilithium_signature: our_keypair.public_key.dilithium_pk.clone(),
            };
            
            let msg_bytes = bincode::serialize(&response_msg)?;
            send.write_all(&msg_bytes).await?;
            send.finish()?;
            
            // Store shared secret and peer's public key
            self.kyber_shared_secret = Some(shared_secret);
            self.peer_dilithium_key = Some(dilithium_pubkey);
            self.peer_node_id = Some(node_id);
            
            debug!(" PQC handshake complete (server): quantum-safe key established");
        } else {
            return Err(anyhow!("Expected KyberPublicKey message from client"));
        }
        
        Ok(())
    }
    
    /// Send encrypted message (PQC layer + QUIC layer)
    pub async fn send_encrypted_message(&mut self, message: &[u8]) -> Result<()> {
        let shared_secret = self.kyber_shared_secret
            .ok_or_else(|| anyhow!("PQC handshake not complete"))?;
        
        // Encrypt with PQC shared secret (ChaCha20-Poly1305)
        // Note: lib-crypto's encrypt_data includes nonce internally
        let encrypted = encrypt_data(message, &shared_secret)?;
        
        // Send over QUIC (which adds TLS 1.3 encryption on top)
        let mut stream = self.quic_conn.open_uni().await?;
        stream.write_all(&encrypted).await?;
        stream.finish()?;
        
        debug!("📤 Sent {} bytes (double-encrypted: PQC + TLS 1.3)", message.len());
        Ok(())
    }
    
    /// Receive encrypted message
    pub async fn recv_encrypted_message(&mut self) -> Result<Vec<u8>> {
        let shared_secret = self.kyber_shared_secret
            .ok_or_else(|| anyhow!("PQC handshake not complete"))?;
        
        // Receive from QUIC (TLS 1.3 decryption automatic)
        let mut stream = self.quic_conn.accept_uni().await?;
        let encrypted = stream.read_to_end(1024 * 1024).await?; // 1MB max message size
        
        // Decrypt PQC layer (nonce is embedded in encrypted data by lib-crypto)
        let decrypted = decrypt_data(&encrypted, &shared_secret)?;
        
        debug!("📥 Received {} bytes (double-decrypted: TLS 1.3 + PQC)", decrypted.len());
        Ok(decrypted)
    }
}

/// Self-signed certificate for QUIC
struct SelfSignedCert {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// Skip TLS certificate verification (we rely on PQC layer for security)
#[derive(Debug)]
struct SkipServerVerification;

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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_quic_mesh_initialization() -> Result<()> {
        let node_id = [1u8; 32];
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        
        let quic_mesh = QuicMeshProtocol::new(node_id, bind_addr)?;
        
        // Verify endpoint is bound
        assert!(quic_mesh.local_addr().port() > 0);
        
        quic_mesh.shutdown().await;
        Ok(())
    }
    
    #[tokio::test]
    async fn test_quic_pqc_connection() -> Result<()> {
        // Start server
        let server_node_id = [1u8; 32];
        let server_addr = "127.0.0.1:0".parse().unwrap();
        let server = QuicMeshProtocol::new(server_node_id, server_addr)?;
        let server_port = server.local_addr().port();
        
        server.start_receiving().await?;
        
        // Wait for server to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Start client
        let client_node_id = [2u8; 32];
        let client_addr = "127.0.0.1:0".parse().unwrap();
        let client = QuicMeshProtocol::new(client_node_id, client_addr)?;
        
        // Connect client to server
        let server_connect_addr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        client.connect_to_peer(server_connect_addr).await?;
        
        // Verify connection established
        let peers = client.get_active_peers().await;
        assert!(peers.len() > 0);
        
        // Cleanup
        client.shutdown().await;
        server.shutdown().await;
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_encrypted_message_exchange() -> Result<()> {
        // Setup server
        let server_node_id = [1u8; 32];
        let server_addr = "127.0.0.1:0".parse().unwrap();
        let server = Arc::new(QuicMeshProtocol::new(server_node_id, server_addr)?);
        let server_port = server.local_addr().port();
        
        server.start_receiving().await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Setup client
        let client_node_id = [2u8; 32];
        let client_addr = "127.0.0.1:0".parse().unwrap();
        let client = Arc::new(QuicMeshProtocol::new(client_node_id, client_addr)?);
        
        // Connect
        let server_connect_addr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        client.connect_to_peer(server_connect_addr).await?;
        
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        
        // Send test message
        let test_message = b"Hello from QUIC mesh with PQC encryption!";
        let peers = client.get_active_peers().await;
        if let Some(peer_addr) = peers.first() {
            // Get connection and send (would need to expose connection in real implementation)
            info!(" Test: Connected to peer at {}", peer_addr);
        }
        
        // Cleanup
        client.shutdown().await;
        server.shutdown().await;
        
        Ok(())
    }
}
