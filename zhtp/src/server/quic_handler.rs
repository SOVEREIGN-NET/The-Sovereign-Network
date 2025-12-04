//! QUIC Stream Handler - Unified Protocol Entry Point
//!
//! Single entry point for ALL QUIC connections. Routes to appropriate handler based on
//! protocol detection:
//! - PQC Handshake → Mesh message flow (blockchain sync, peer discovery)
//! - ZHTP Magic → Native ZHTP protocol (API requests)
//! - HTTP Methods → HTTP compatibility layer (legacy clients)
//!
//! Architecture:
//! ```text
//! QUIC Endpoint (port 9334)
//!      │
//!      ▼
//! QuicHandler.accept_loop()  ← SINGLE entry point
//!      │
//!      ▼
//! Protocol Detection (first bytes)
//!      │
//!      ├─── bincode enum tag (0x00) + large payload
//!      │         → PQC handshake → MeshMessageHandler
//!      │
//!      ├─── ZHTP magic (b"ZHTP")
//!      │         → ZhtpRouter (native ZHTP API)
//!      │
//!      └─── HTTP method (GET/POST/PUT/DELETE/HEAD/OPTIONS)
//!               → HttpCompatibilityLayer (HTTP-over-QUIC)
//! ```

use std::sync::Arc;
use std::net::SocketAddr;
use anyhow::{Result, Context};
use tracing::{info, warn, debug, error};
use quinn::{Connection, Incoming, RecvStream, SendStream};
use tokio::sync::RwLock;

use lib_network::protocols::quic_mesh::{QuicMeshProtocol, PqcHandshakeMessage, PqcQuicConnection};
use lib_network::messaging::message_handler::MeshMessageHandler;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use lib_crypto::PublicKey;

use super::zhtp::{ZhtpRouter, HttpCompatibilityLayer};
use super::zhtp::serialization::ZHTP_MAGIC;

/// Protocol detection result
#[derive(Debug)]
enum ProtocolType {
    /// PQC handshake initiation (mesh peer connecting)
    PqcHandshake(Vec<u8>),
    /// Native ZHTP protocol (API request)
    NativeZhtp(Vec<u8>),
    /// Legacy HTTP (needs compatibility conversion)
    LegacyHttp(Vec<u8>),
    /// Unknown/unsupported protocol
    Unknown(Vec<u8>),
}

/// QUIC connection handler - unified entry point for all protocols
pub struct QuicHandler {
    /// ZHTP router for native API requests
    zhtp_router: Arc<RwLock<ZhtpRouter>>,

    /// HTTP compatibility layer for legacy clients
    http_compat: Arc<HttpCompatibilityLayer>,

    /// QUIC mesh protocol (for connection storage and PQC operations)
    quic_protocol: Arc<QuicMeshProtocol>,

    /// Mesh message handler for blockchain sync and peer messages
    mesh_handler: Option<Arc<RwLock<MeshMessageHandler>>>,

    /// Active PQC connections (peer_node_id -> PqcQuicConnection)
    pqc_connections: Arc<RwLock<std::collections::HashMap<Vec<u8>, PqcQuicConnection>>>,
}

impl QuicHandler {
    /// Create new QUIC handler with all protocol support
    pub fn new(
        zhtp_router: Arc<RwLock<ZhtpRouter>>,
        quic_protocol: Arc<QuicMeshProtocol>,
    ) -> Self {
        let http_compat = Arc::new(HttpCompatibilityLayer::new(
            zhtp_router.clone()
        ));

        Self {
            zhtp_router,
            http_compat,
            quic_protocol,
            mesh_handler: None,
            pqc_connections: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Set the mesh message handler for blockchain sync
    pub fn set_mesh_handler(&mut self, handler: Arc<RwLock<MeshMessageHandler>>) {
        self.mesh_handler = Some(handler);
        info!("✅ MeshMessageHandler registered with QuicHandler");
    }

    /// Get reference to PQC connections for external access
    pub fn get_pqc_connections(&self) -> Arc<RwLock<std::collections::HashMap<Vec<u8>, PqcQuicConnection>>> {
        self.pqc_connections.clone()
    }
    
    /// Accept and handle incoming QUIC connections from endpoint
    /// This should be called from a loop that accepts from endpoint.accept().await
    pub async fn handle_connection_incoming(&self, incoming: Incoming) -> Result<()> {
        let handler = self.clone();
        
        // Accept the incoming connection (consumes Incoming, returns Connecting)
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
    
    /// DEPRECATED: Old function signature - use handle_connection_incoming instead
    /// This function signature doesn't work with quinn's Incoming type
    #[deprecated(note = "Use handle_connection_incoming with quinn::Connecting instead")]
    pub async fn handle_incoming(&self, _incoming: Incoming) -> Result<()> {
        warn!("⚠️ handle_incoming called with wrong signature - use handle_connection_incoming");
        Ok(())
    }
    
    /// Convenience: Accept connections in a loop from QUIC endpoint
    pub async fn accept_loop(&self, endpoint: Arc<quinn::Endpoint>) -> Result<()> {
        info!("🌐 QUIC handler started - listening for connections");
        
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
    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let peer_addr = connection.remote_address();
        debug!("📡 Handling QUIC connection from {}", peer_addr);

        // First stream determines connection type
        let first_stream_result = connection.accept_bi().await;

        match first_stream_result {
            Ok((send, recv)) => {
                // Detect protocol on first stream
                let handler = self.clone();
                let conn_clone = connection.clone();

                // Handle first stream - this determines connection type
                let result = handler.handle_first_stream(recv, send, conn_clone, peer_addr).await;

                if let Err(e) = result {
                    warn!("⚠️ First stream handling error: {}", e);
                }
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!("🔒 Connection closed before first stream");
                return Ok(());
            }
            Err(e) => {
                warn!("⚠️ Failed to accept first stream: {}", e);
                return Err(e.into());
            }
        }

        Ok(())
    }

    /// Handle the first stream of a connection - determines connection type
    async fn handle_first_stream(
        &self,
        mut recv: RecvStream,
        mut send: SendStream,
        connection: Connection,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        debug!("📨 Processing first QUIC stream from {}", peer_addr);

        // Read enough data to detect protocol
        let protocol = self.detect_protocol(&mut recv).await?;

        match protocol {
            ProtocolType::PqcHandshake(initial_data) => {
                debug!("🔐 PQC handshake detected from {}", peer_addr);
                self.handle_pqc_connection(initial_data, recv, send, connection, peer_addr).await?;
            }
            ProtocolType::NativeZhtp(initial_data) => {
                debug!("✅ Native ZHTP protocol detected from {}", peer_addr);
                self.handle_zhtp_stream_with_prefix(initial_data, recv, send).await?;
                // Continue accepting more streams on this connection (spawns background task)
                self.accept_additional_streams(connection);
            }
            ProtocolType::LegacyHttp(initial_data) => {
                debug!("🔄 Legacy HTTP detected from {} (compatibility mode)", peer_addr);
                self.handle_http_stream_with_prefix(initial_data, recv, send).await?;
                // Continue accepting more streams on this connection (spawns background task)
                self.accept_additional_streams(connection);
            }
            ProtocolType::Unknown(initial_data) => {
                warn!("❓ Unknown protocol from {}: {:?}", peer_addr, &initial_data[..initial_data.len().min(16)]);
                return Err(anyhow::anyhow!("Unknown protocol"));
            }
        }

        Ok(())
    }

    /// Accept additional streams after first stream is processed (for HTTP/ZHTP)
    fn accept_additional_streams(&self, connection: Connection) {
        let handler = self.clone();

        tokio::spawn(async move {
            loop {
                match connection.accept_bi().await {
                    Ok((send, recv)) => {
                        let h = handler.clone();
                        tokio::spawn(async move {
                            if let Err(e) = h.handle_subsequent_stream(recv, send).await {
                                warn!("⚠️ Stream handling error: {}", e);
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        debug!("🔒 Connection closed gracefully");
                        break;
                    }
                    Err(e) => {
                        debug!("Stream accept ended: {}", e);
                        break;
                    }
                }
            }
        });
    }

    /// Handle subsequent streams (after first stream established connection type)
    async fn handle_subsequent_stream(&self, mut recv: RecvStream, send: SendStream) -> Result<()> {
        let protocol = self.detect_protocol(&mut recv).await?;

        match protocol {
            ProtocolType::NativeZhtp(initial_data) => {
                self.handle_zhtp_stream_with_prefix(initial_data, recv, send).await
            }
            ProtocolType::LegacyHttp(initial_data) => {
                self.handle_http_stream_with_prefix(initial_data, recv, send).await
            }
            ProtocolType::PqcHandshake(_) => {
                warn!("PQC handshake on non-first stream - ignoring");
                Err(anyhow::anyhow!("PQC handshake only valid on first stream"))
            }
            ProtocolType::Unknown(data) => {
                warn!("Unknown protocol on stream: {:?}", &data[..data.len().min(16)]);
                Err(anyhow::anyhow!("Unknown protocol"))
            }
        }
    }

    /// Handle PQC handshake and establish mesh connection
    async fn handle_pqc_connection(
        &self,
        initial_data: Vec<u8>,
        _recv: RecvStream,
        mut send: SendStream,
        connection: Connection,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        info!("🔐 Processing PQC handshake from {}", peer_addr);

        // Parse the client's handshake message
        let client_msg: PqcHandshakeMessage = bincode::deserialize(&initial_data)
            .context("Failed to deserialize PQC handshake")?;

        let (peer_node_id, kyber_pubkey, dilithium_pubkey) = match client_msg {
            PqcHandshakeMessage::KyberPublicKey { kyber_pubkey, dilithium_pubkey, node_id } => {
                (node_id, kyber_pubkey, dilithium_pubkey)
            }
            _ => {
                return Err(anyhow::anyhow!("Expected KyberPublicKey message"));
            }
        };

        // Encapsulate shared secret using client's Kyber public key
        let (ciphertext, shared_secret) = lib_crypto::post_quantum::kyber512_encapsulate(&kyber_pubkey)
            .context("Failed to encapsulate Kyber shared secret")?;

        // Generate our own keypair for authentication
        let our_keypair = lib_crypto::KeyPair::generate()
            .context("Failed to generate server keypair")?;

        // Send encapsulation response
        let response_msg = PqcHandshakeMessage::KyberEncapsulation {
            ciphertext,
            dilithium_signature: our_keypair.public_key.dilithium_pk.clone(),
        };

        let response_bytes = bincode::serialize(&response_msg)?;
        send.write_all(&response_bytes).await?;
        send.finish()?;

        info!("✅ PQC handshake complete with {} (node: {})",
              peer_addr, hex::encode(&peer_node_id[..8]));

        // Create PQC connection wrapper
        let mut pqc_conn = PqcQuicConnection::new(connection.clone(), peer_addr, false);
        pqc_conn.set_shared_secret(shared_secret);
        pqc_conn.set_peer_info(peer_node_id, dilithium_pubkey);

        // Store connection
        self.pqc_connections.write().await.insert(peer_node_id.to_vec(), pqc_conn);

        // Start receiving encrypted mesh messages on this connection
        self.start_mesh_message_receiver(connection, peer_node_id, shared_secret).await;

        Ok(())
    }

    /// Start receiving encrypted mesh messages from a PQC-authenticated peer
    async fn start_mesh_message_receiver(
        &self,
        connection: Connection,
        peer_node_id: [u8; 32],
        shared_secret: [u8; 32],
    ) {
        let mesh_handler = self.mesh_handler.clone();
        let pqc_connections = self.pqc_connections.clone();
        let peer_id_vec = peer_node_id.to_vec();

        tokio::spawn(async move {
            info!("📡 Starting mesh message receiver for peer {}", hex::encode(&peer_node_id[..8]));

            loop {
                // Accept unidirectional stream for incoming messages
                match connection.accept_uni().await {
                    Ok(mut recv) => {
                        // Read encrypted message
                        match recv.read_to_end(1024 * 1024).await {
                            Ok(encrypted) => {
                                // Decrypt with shared secret
                                match lib_crypto::symmetric::chacha20::decrypt_data(&encrypted, &shared_secret) {
                                    Ok(decrypted) => {
                                        // Deserialize mesh message
                                        match bincode::deserialize::<ZhtpMeshMessage>(&decrypted) {
                                            Ok(message) => {
                                                debug!("📨 Received mesh message from peer");
                                                if let Some(ref handler) = mesh_handler {
                                                    let peer_pk = PublicKey::new(peer_id_vec.clone());
                                                    if let Err(e) = handler.read().await
                                                        .handle_mesh_message(message, peer_pk).await {
                                                        error!("Error handling mesh message: {}", e);
                                                    }
                                                } else {
                                                    warn!("No mesh handler configured");
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to deserialize mesh message: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to decrypt mesh message: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Stream read error: {}", e);
                                break;
                            }
                        }
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        debug!("🔒 Mesh connection closed");
                        break;
                    }
                    Err(e) => {
                        debug!("Mesh connection error: {}", e);
                        break;
                    }
                }
            }

            // Remove connection on close
            pqc_connections.write().await.remove(&peer_id_vec);
            info!("📡 Mesh message receiver stopped for peer {}", hex::encode(&peer_node_id[..8]));
        });
    }

    /// Handle ZHTP stream with already-read prefix data
    async fn handle_zhtp_stream_with_prefix(
        &self,
        prefix: Vec<u8>,
        recv: RecvStream,
        send: SendStream,
    ) -> Result<()> {
        let router = self.zhtp_router.read().await;
        router.handle_zhtp_stream_with_prefix(prefix, recv, send).await
    }

    /// Handle HTTP stream with already-read prefix data
    async fn handle_http_stream_with_prefix(
        &self,
        prefix: Vec<u8>,
        recv: RecvStream,
        send: SendStream,
    ) -> Result<()> {
        self.http_compat.handle_http_over_quic_with_prefix(prefix, recv, send).await
    }

    /// Detect protocol type by inspecting stream data
    /// Returns the protocol type along with all data read (for forwarding)
    async fn detect_protocol(&self, recv: &mut RecvStream) -> Result<ProtocolType> {
        // Read up to 1KB to determine protocol
        // PQC handshake is large (~1KB+), HTTP/ZHTP headers are smaller
        let mut buffer = vec![0u8; 1024];

        match recv.read(&mut buffer).await {
            Ok(Some(n)) => {
                buffer.truncate(n);

                if buffer.len() < 4 {
                    return Ok(ProtocolType::Unknown(buffer));
                }

                // Check for ZHTP magic first (most specific)
                if &buffer[0..4] == ZHTP_MAGIC {
                    debug!("✅ ZHTP magic bytes detected");
                    return Ok(ProtocolType::NativeZhtp(buffer));
                }

                // Check for HTTP methods
                let magic_str = String::from_utf8_lossy(&buffer[0..4]);
                if magic_str.starts_with("GET ") ||
                   magic_str.starts_with("POST") ||
                   magic_str.starts_with("PUT ") ||
                   magic_str.starts_with("DELE") ||
                   magic_str.starts_with("HEAD") ||
                   magic_str.starts_with("OPTI") {
                    debug!("🔄 HTTP method detected: {}", &magic_str[0..4]);
                    return Ok(ProtocolType::LegacyHttp(buffer));
                }

                // Check for PQC handshake (bincode enum variant 0 + large data)
                // KyberPublicKey variant has: enum_tag(4 bytes) + kyber_pk(~800B) + dilithium_pk(~1KB) + node_id(32B)
                if buffer[0] == 0x00 && buffer.len() > 100 {
                    // Likely PQC handshake - try to parse
                    if bincode::deserialize::<PqcHandshakeMessage>(&buffer).is_ok() {
                        debug!("🔐 PQC handshake message detected");
                        return Ok(ProtocolType::PqcHandshake(buffer));
                    }
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
                Err(e.into())
            }
        }
    }
}

impl Clone for QuicHandler {
    fn clone(&self) -> Self {
        Self {
            zhtp_router: self.zhtp_router.clone(),
            http_compat: self.http_compat.clone(),
            quic_protocol: self.quic_protocol.clone(),
            mesh_handler: self.mesh_handler.clone(),
            pqc_connections: self.pqc_connections.clone(),
        }
    }
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
    fn test_detect_http_method() {
        let http_methods: Vec<&[u8]> = vec![
            b"GET /test HTTP/1.1",
            b"POST /api HTTP/1.1",
            b"PUT /data HTTP/1.1",
            b"DELETE /item HTTP/1.1",
            b"HEAD /info HTTP/1.1",
            b"OPTIONS * HTTP/1.1",
        ];

        for method in http_methods {
            let first_bytes = &method[0..4];
            let magic_str = String::from_utf8_lossy(first_bytes);
            
            assert!(
                magic_str.starts_with("GET ") ||
                magic_str.starts_with("POST") ||
                magic_str.starts_with("PUT ") ||
                magic_str.starts_with("DELE") ||
                magic_str.starts_with("HEAD") ||
                magic_str.starts_with("OPTI"),
                "Failed to detect HTTP method: {}", magic_str
            );
        }
    }
}
