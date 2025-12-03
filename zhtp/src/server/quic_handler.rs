//! QUIC Stream Handler - Native ZHTP Protocol
//!
//! Handles incoming QUIC connections and routes streams to appropriate handlers.
//! Replaces tcp_handler.rs and udp_handler.rs with unified QUIC-based approach.

use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn, debug, error};
use quinn::{Connection, Incoming, RecvStream, SendStream};
use tokio::sync::RwLock;

use lib_network::protocols::quic_mesh::QuicMeshProtocol;

use super::zhtp::{ZhtpRouter, HttpCompatibilityLayer};
use super::zhtp::serialization::ZHTP_MAGIC;

/// Protocol detection result
#[derive(Debug)]
enum ProtocolType {
    /// Native ZHTP protocol
    NativeZhtp,
    /// Legacy HTTP (needs compatibility conversion)
    LegacyHttp,
    /// Unknown/unsupported protocol
    Unknown,
}

/// QUIC connection handler
pub struct QuicHandler {
    /// ZHTP router for native requests
    zhtp_router: Arc<RwLock<ZhtpRouter>>,
    
    /// HTTP compatibility layer
    http_compat: Arc<HttpCompatibilityLayer>,
    
    /// QUIC mesh protocol
    quic_protocol: Arc<QuicMeshProtocol>,
}

impl QuicHandler {
    /// Create new QUIC handler
    pub fn new(
        zhtp_router: Arc<RwLock<ZhtpRouter>>,
        quic_protocol: Arc<QuicMeshProtocol>,
    ) -> Self {
        // HTTP compatibility layer will clone router when needed
        let http_compat = Arc::new(HttpCompatibilityLayer::new(
            zhtp_router.clone()
        ));
        
        Self {
            zhtp_router,
            http_compat,
            quic_protocol,
        }
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
        debug!("📡 Handling QUIC connection from {}", connection.remote_address());
        
        loop {
            // Accept bidirectional stream
            let stream = match connection.accept_bi().await {
                Ok((send, recv)) => (send, recv),
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    debug!("🔒 Connection closed gracefully");
                    break;
                }
                Err(e) => {
                    warn!("⚠️ Stream accept error: {}", e);
                    break;
                }
            };
            
            let handler = self.clone();
            
            // Spawn task for each stream (enables parallel requests)
            tokio::spawn(async move {
                if let Err(e) = handler.handle_stream(stream.1, stream.0).await {
                    warn!("⚠️ Stream handling error: {}", e);
                }
            });
        }
        
        Ok(())
    }
    
    /// Handle a single QUIC stream
    async fn handle_stream(&self, mut recv: RecvStream, send: SendStream) -> Result<()> {
        debug!("📨 Processing QUIC stream");
        
        // Detect protocol type
        let protocol = self.detect_protocol(&mut recv).await?;
        
        match protocol {
            ProtocolType::NativeZhtp => {
                debug!("✅ Native ZHTP protocol detected");
                let router = self.zhtp_router.read().await;
                router.handle_zhtp_stream(recv, send).await?;
            }
            ProtocolType::LegacyHttp => {
                debug!("🔄 Legacy HTTP detected (compatibility mode)");
                self.http_compat.handle_http_over_quic(recv, send).await?;
            }
            ProtocolType::Unknown => {
                warn!("❌ Unknown protocol detected, closing stream");
                return Err(anyhow::anyhow!("Unknown protocol"));
            }
        }
        
        Ok(())
    }
    
    /// Detect protocol type by inspecting stream data
    async fn detect_protocol(&self, recv: &mut RecvStream) -> Result<ProtocolType> {
        // Read first 4 bytes to check for ZHTP magic
        let mut magic_buf = [0u8; 4];
        
        match recv.read_exact(&mut magic_buf).await {
            Ok(_) => {
                if &magic_buf == ZHTP_MAGIC {
                    debug!("✅ ZHTP magic bytes detected: {:?}", magic_buf);
                    return Ok(ProtocolType::NativeZhtp);
                }
                
                // Check if it looks like HTTP
                let magic_str = String::from_utf8_lossy(&magic_buf);
                if magic_str.starts_with("GET ") || 
                   magic_str.starts_with("POST") || 
                   magic_str.starts_with("PUT ") || 
                   magic_str.starts_with("DELE") || 
                   magic_str.starts_with("HEAD") || 
                   magic_str.starts_with("OPTI") {
                    debug!("🔄 HTTP method detected: {}", magic_str);
                    return Ok(ProtocolType::LegacyHttp);
                }
                
                warn!("❓ Unknown protocol magic: {:?}", magic_buf);
                Ok(ProtocolType::Unknown)
            }
            Err(e) => {
                warn!("⚠️ Failed to read protocol magic: {}", e);
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
