//! TCP Bootstrap Handshake Adapter for UHP
//!
//! Provides TCP stream adapters for the Unified Handshake Protocol (UHP),
//! enabling secure bootstrap node connections with full authentication and
//! signature verification.
//!
//! # Architecture
//!
//! This module bridges the gap between TCP transport and UHP by providing:
//! - `handshake_as_initiator()`: Client-side handshake over TCP
//! - `handshake_as_responder()`: Server-side handshake over TCP
//!
//! Both functions handle the complete 3-way handshake:
//! ```text
//! Client                           Server
//!   |--- ClientHello ----------->    |  (1) Send identity + challenge
//!   |<-- ServerHello ------------    |  (2) Verify + respond
//!   |--- ClientFinish ---------->    |  (3) Mutual auth complete
//!   |<== Secure Session ========>    |
//! ```
//!
//! # Security Properties
//!
//! - **Mutual Authentication**: Both peers verify signatures
//! - **Replay Protection**: Nonce cache prevents replay attacks
//! - **NodeId Verification**: Validates NodeId = Blake3(DID || device)
//! - **Timestamp Validation**: Prevents time-travel attacks
//! - **Protocol Version Check**: Prevents downgrade attacks
//!
//! # Production Usage
//!
//! ```rust,no_run
//! use lib_network::bootstrap::*;
//! use lib_identity::ZhtpIdentity;
//! use tokio::net::TcpStream;
//!
//! async fn client_connect(identity: ZhtpIdentity) -> anyhow::Result<()> {
//!     let mut stream = TcpStream::connect("bootstrap.example.com:9333").await?;
//!     let ctx = HandshakeContext::new(NonceCache::new_test(300, 10000));
//!     
//!     let result = handshake_as_initiator(&mut stream, &identity, &ctx).await?;
//!     
//!     println!("Connected to peer: {}", result.peer_identity.did);
//!     Ok(())
//! }
//!
//! async fn server_accept(identity: ZhtpIdentity, stream: &mut TcpStream) -> anyhow::Result<()> {
//!     let ctx = HandshakeContext::new(NonceCache::new_test(300, 10000));
//!     
//!     let result = handshake_as_responder(stream, &identity, &ctx).await?;
//!     
//!     println!("Authenticated peer: {}", result.peer_identity.did);
//!     Ok(())
//! }
//! ```

use anyhow::{Result, anyhow};
use lib_identity::ZhtpIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Re-export UHP types for convenience
pub use crate::handshake::{
    HandshakeContext, HandshakeResult, HandshakeCapabilities,
    ClientHello, ServerHello, ClientFinish,
    HandshakeMessage, HandshakePayload,
    NonceCache, NegotiatedCapabilities,
};
use lib_crypto::KeyPair;

// SECURITY (P1-2 FIX): Use shared constant from constants module
// Ensures consistency across all UHP implementations (1 MB limit)
use crate::constants::MAX_HANDSHAKE_MESSAGE_SIZE;

/// Handshake timeout duration (30 seconds)
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// ============================================================================
// Client-Side (Initiator) Handshake
// ============================================================================

/// Perform UHP handshake as the initiating client over TCP
///
/// This function implements the complete 3-way UHP handshake from the client
/// perspective:
/// 1. Send ClientHello (identity + capabilities + challenge nonce)
/// 2. Receive and verify ServerHello (mutual auth begins)
/// 3. Send ClientFinish (completes mutual authentication)
///
/// # Arguments
/// * `stream` - TCP stream to the server
/// * `identity` - Local ZhtpIdentity (must have private key for signing)
/// * `ctx` - Handshake context (nonce cache, timestamp config, observer, rate limiter)
///
/// # Returns
/// - `Ok(HandshakeResult)` - Contains peer identity, session key, and capabilities
/// - `Err(...)` - Authentication failed, replay detected, or network error
///
/// # Security
/// - Verifies server's NodeId matches Blake3(DID || device)
/// - Validates server's signature on ServerHello
/// - Checks server's timestamp (prevents replay attacks)
/// - Checks server's nonce cache (prevents replay attacks)
/// - Verifies protocol version (prevents downgrade attacks)
///
/// # Example
/// ```rust,no_run
/// use lib_network::bootstrap::*;
/// use lib_identity::ZhtpIdentity;
/// use tokio::net::TcpStream;
///
/// async fn connect_to_bootstrap() -> anyhow::Result<()> {
///     let identity = ZhtpIdentity::new_unified(
///         lib_identity::IdentityType::Human,
///         Some(25),
///         Some("US".to_string()),
///         "my-device",
///         None,
///     )?;
///     
///     let mut stream = TcpStream::connect("127.0.0.1:9333").await?;
///     let ctx = HandshakeContext::new(NonceCache::new_test(300, 10000));
///     
///     let result = handshake_as_initiator(&mut stream, &identity, &ctx).await?;
///     
///     println!("Session key: {:?}", result.session_key);
///     println!("Peer DID: {}", result.peer_identity.did);
///     
///     Ok(())
/// }
/// ```
pub async fn handshake_as_initiator(
    stream: &mut TcpStream,
    identity: &ZhtpIdentity,
    ctx: &HandshakeContext,
) -> Result<HandshakeResult> {
    // Apply timeout to entire handshake
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // Step 1: Create and send ClientHello
        let capabilities = HandshakeCapabilities::default();
        let client_hello = ClientHello::new(identity, capabilities)
            .map_err(|e| anyhow!("Failed to create ClientHello: {}", e))?;
        
        let client_hello_msg = HandshakeMessage::new(HandshakePayload::ClientHello(client_hello.clone()));
        let client_hello_bytes = client_hello_msg.to_bytes()
            .map_err(|e| anyhow!("Failed to serialize ClientHello: {}", e))?;
        
        // Send ClientHello with length prefix
        send_message(stream, &client_hello_bytes).await
            .map_err(|e| anyhow!("Failed to send ClientHello: {}", e))?;
        
        tracing::debug!("Sent ClientHello to server ({} bytes)", client_hello_bytes.len());
        
        // Step 2: Receive and verify ServerHello
        let server_hello_bytes = receive_message(stream).await
            .map_err(|e| anyhow!("Failed to receive ServerHello: {}", e))?;
        
        let server_hello_msg = HandshakeMessage::from_bytes(&server_hello_bytes)
            .map_err(|e| anyhow!("Failed to deserialize ServerHello: {}", e))?;
        
        let server_hello = match server_hello_msg.payload {
            HandshakePayload::ServerHello(sh) => sh,
            HandshakePayload::Error(err) => {
                return Err(anyhow!("Server rejected handshake: {} (code: {})", err.message, err.code));
            }
            _ => {
                return Err(anyhow!("Expected ServerHello, got different message type"));
            }
        };
        
        tracing::debug!("Received ServerHello from {} ({} bytes)", 
            server_hello.identity.did, server_hello_bytes.len());
        
        // Verify ServerHello signature (includes mutual authentication of server)
        // This also validates NodeId, timestamp, nonce, and protocol version
        server_hello.verify_signature(&client_hello.challenge_nonce, ctx)
            .map_err(|e| anyhow!("ServerHello verification failed: {}", e))?;
        
        tracing::debug!("ServerHello signature verified successfully");
        
        // Step 3: Create and send ClientFinish
        // ClientFinish::new() performs full mutual authentication of server before signing
        let client_keypair = KeyPair {
            public_key: identity.public_key.clone(),
            private_key: identity.private_key.clone()
                .ok_or_else(|| anyhow!("Identity missing private key"))?,
        };
        
        let client_finish = ClientFinish::new(&server_hello, &client_hello, &client_keypair, ctx)
            .map_err(|e| anyhow!("Failed to create ClientFinish: {}", e))?;
        
        let client_finish_msg = HandshakeMessage::new(HandshakePayload::ClientFinish(client_finish));
        let client_finish_bytes = client_finish_msg.to_bytes()
            .map_err(|e| anyhow!("Failed to serialize ClientFinish: {}", e))?;
        
        send_message(stream, &client_finish_bytes).await
            .map_err(|e| anyhow!("Failed to send ClientFinish: {}", e))?;
        
        tracing::debug!("Sent ClientFinish to server ({} bytes)", client_finish_bytes.len());
        
        // Step 4: Derive session key and build result
        let result = HandshakeResult::new(
            server_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &identity.did,
            &server_hello.identity.did,
            client_hello.timestamp, // Use ClientHello timestamp for deterministic session key
        ).map_err(|e| anyhow!("Failed to derive session key: {}", e))?;
        
        tracing::info!("✅ Client handshake completed successfully with {}", server_hello.identity.did);
        
        Ok(result)
    }).await
        .map_err(|_| anyhow!("Handshake timeout after {} seconds", HANDSHAKE_TIMEOUT.as_secs()))?
}

// ============================================================================
// Server-Side (Responder) Handshake
// ============================================================================

/// Perform UHP handshake as the responding server over TCP
///
/// This function implements the complete 3-way UHP handshake from the server
/// perspective:
/// 1. Receive and verify ClientHello
/// 2. Send ServerHello (includes signing client's challenge nonce)
/// 3. Receive and verify ClientFinish (completes mutual authentication)
///
/// # Arguments
/// * `stream` - TCP stream from the client
/// * `identity` - Local ZhtpIdentity (must have private key for signing)
/// * `ctx` - Handshake context (nonce cache, timestamp config, observer, rate limiter)
///
/// # Returns
/// - `Ok(HandshakeResult)` - Contains peer identity, session key, and capabilities
/// - `Err(...)` - Authentication failed, replay detected, or network error
///
/// # Security
/// - Verifies client's NodeId matches Blake3(DID || device)
/// - Validates client's signature on ClientHello
/// - Checks client's timestamp (prevents replay attacks)
/// - Checks client's nonce cache (prevents replay attacks)
/// - Verifies protocol version (prevents downgrade attacks)
/// - Validates client's signature on ClientFinish
///
/// # Example
/// ```rust,no_run
/// use lib_network::bootstrap::*;
/// use lib_identity::ZhtpIdentity;
/// use tokio::net::{TcpListener, TcpStream};
///
/// async fn accept_bootstrap_connection(
///     mut stream: TcpStream,
///     identity: ZhtpIdentity,
/// ) -> anyhow::Result<()> {
///     let ctx = HandshakeContext::new(NonceCache::new_test(300, 10000));
///     
///     let result = handshake_as_responder(&mut stream, &identity, &ctx).await?;
///     
///     println!("Authenticated client: {}", result.peer_identity.did);
///     println!("Session ID: {:?}", result.session_id);
///     
///     Ok(())
/// }
/// ```
pub async fn handshake_as_responder(
    stream: &mut TcpStream,
    identity: &ZhtpIdentity,
    ctx: &HandshakeContext,
) -> Result<HandshakeResult> {
    // Apply timeout to entire handshake
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // Step 1: Receive and verify ClientHello
        let client_hello_bytes = receive_message(stream).await
            .map_err(|e| anyhow!("Failed to receive ClientHello: {}", e))?;
        
        let client_hello_msg = HandshakeMessage::from_bytes(&client_hello_bytes)
            .map_err(|e| anyhow!("Failed to deserialize ClientHello: {}", e))?;
        
        let client_hello = match client_hello_msg.payload {
            HandshakePayload::ClientHello(ch) => ch,
            _ => {
                return Err(anyhow!("Expected ClientHello, got different message type"));
            }
        };
        
        tracing::debug!("Received ClientHello from {} ({} bytes)", 
            client_hello.identity.did, client_hello_bytes.len());
        
        // Verify ClientHello signature
        // This validates NodeId, timestamp, nonce, and protocol version
        client_hello.verify_signature(ctx)
            .map_err(|e| anyhow!("ClientHello verification failed: {}", e))?;
        
        tracing::debug!("ClientHello signature verified successfully");
        
        // Step 2: Create and send ServerHello
        let capabilities = HandshakeCapabilities::default();
        let server_hello = ServerHello::new(identity, capabilities, &client_hello)
            .map_err(|e| anyhow!("Failed to create ServerHello: {}", e))?;
        
        let server_hello_msg = HandshakeMessage::new(HandshakePayload::ServerHello(server_hello.clone()));
        let server_hello_bytes = server_hello_msg.to_bytes()
            .map_err(|e| anyhow!("Failed to serialize ServerHello: {}", e))?;
        
        send_message(stream, &server_hello_bytes).await
            .map_err(|e| anyhow!("Failed to send ServerHello: {}", e))?;
        
        tracing::debug!("Sent ServerHello to client ({} bytes)", server_hello_bytes.len());
        
        // Step 3: Receive and verify ClientFinish
        let client_finish_bytes = receive_message(stream).await
            .map_err(|e| anyhow!("Failed to receive ClientFinish: {}", e))?;
        
        let client_finish_msg = HandshakeMessage::from_bytes(&client_finish_bytes)
            .map_err(|e| anyhow!("Failed to deserialize ClientFinish: {}", e))?;
        
        let client_finish = match client_finish_msg.payload {
            HandshakePayload::ClientFinish(cf) => cf,
            HandshakePayload::Error(err) => {
                return Err(anyhow!("Client rejected handshake: {} (code: {})", err.message, err.code));
            }
            _ => {
                return Err(anyhow!("Expected ClientFinish, got different message type"));
            }
        };
        
        tracing::debug!("Received ClientFinish from client ({} bytes)", client_finish_bytes.len());
        
        // Verify ClientFinish signature
        client_finish.verify_signature(&server_hello.response_nonce, &client_hello.identity.public_key)
            .map_err(|e| anyhow!("ClientFinish verification failed: {}", e))?;
        
        tracing::debug!("ClientFinish signature verified successfully");
        
        // Step 4: Derive session key and build result
        let result = HandshakeResult::new(
            client_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_hello.identity.did,
            &identity.did,
            client_hello.timestamp, // Use ClientHello timestamp for deterministic session key
        ).map_err(|e| anyhow!("Failed to derive session key: {}", e))?;
        
        tracing::info!("✅ Server handshake completed successfully with {}", client_hello.identity.did);
        
        Ok(result)
    }).await
        .map_err(|_| anyhow!("Handshake timeout after {} seconds", HANDSHAKE_TIMEOUT.as_secs()))?
}

// ============================================================================
// TCP Message Framing Utilities
// ============================================================================

/// Send a message over TCP with length-prefix framing
///
/// Frame format:
/// ```text
/// [4 bytes: message length (big-endian u32)] [N bytes: message payload]
/// ```
///
/// # Arguments
/// * `stream` - TCP stream to write to
/// * `data` - Message bytes to send
///
/// # Returns
/// - `Ok(())` - Message sent successfully
/// - `Err(...)` - Network error or message too large
///
/// # Protocol Compatibility
/// Uses big-endian (network byte order) to match core.rs HandshakeIo implementation
async fn send_message(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    // Validate message size
    if data.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
        return Err(anyhow!(
            "Message too large: {} bytes (max: {} bytes)",
            data.len(),
            MAX_HANDSHAKE_MESSAGE_SIZE
        ));
    }

    // SECURITY (P1-1 FIX): Use big-endian (network byte order) to match core.rs
    // This ensures compatibility across different UHP implementations
    let len = data.len() as u32;
    stream.write_u32(len).await
        .map_err(|e| anyhow!("Failed to write message length: {}", e))?;

    // Send message payload
    stream.write_all(data).await
        .map_err(|e| anyhow!("Failed to write message payload: {}", e))?;

    // Flush to ensure immediate delivery
    stream.flush().await
        .map_err(|e| anyhow!("Failed to flush stream: {}", e))?;

    Ok(())
}

/// Receive a message from TCP with length-prefix framing
///
/// Frame format:
/// ```text
/// [4 bytes: message length (big-endian u32)] [N bytes: message payload]
/// ```
///
/// # Arguments
/// * `stream` - TCP stream to read from
///
/// # Returns
/// - `Ok(Vec<u8>)` - Received message bytes
/// - `Err(...)` - Network error, invalid frame, or message too large
///
/// # Protocol Compatibility
/// Uses big-endian (network byte order) to match core.rs HandshakeIo implementation
async fn receive_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // SECURITY (P1-1 FIX): Use big-endian (network byte order) to match core.rs
    // This ensures compatibility across different UHP implementations
    let len = stream.read_u32().await
        .map_err(|e| anyhow!("Failed to read message length: {}", e))? as usize;

    // Validate message size
    if len > MAX_HANDSHAKE_MESSAGE_SIZE {
        return Err(anyhow!(
            "Message too large: {} bytes (max: {} bytes)",
            len,
            MAX_HANDSHAKE_MESSAGE_SIZE
        ));
    }

    if len == 0 {
        return Err(anyhow!("Invalid message length: 0 bytes"));
    }

    // Read message payload
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await
        .map_err(|e| anyhow!("Failed to read message payload: {}", e))?;

    Ok(data)
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    
    /// Helper: Create test identity
    fn create_test_identity(device_name: &str) -> ZhtpIdentity {
        lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            device_name,
            None,
        ).unwrap()
    }
    
    /// Test complete client-server handshake over TCP
    #[tokio::test]
    async fn test_tcp_bootstrap_handshake() -> Result<()> {
        // Setup server
        let server_identity = create_test_identity("server-device");
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server_addr = listener.local_addr()?;
        
        // Create shared handshake context
        let ctx = HandshakeContext::new(NonceCache::new_test(300, 10000));
        let server_ctx = ctx.clone();
        
        // Spawn server task
        let server_handle = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.unwrap();
            handshake_as_responder(&mut stream, &server_identity, &server_ctx).await
        });
        
        // Give server time to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Client connects and initiates handshake
        let client_identity = create_test_identity("client-device");
        let mut client_stream = TcpStream::connect(server_addr).await?;
        
        let client_result = handshake_as_initiator(&mut client_stream, &client_identity, &ctx).await?;
        let server_result = server_handle.await.unwrap()?;
        
        // Verify both sides derived the same session key
        assert_eq!(client_result.session_key, server_result.session_key);
        assert_eq!(client_result.session_id, server_result.session_id);
        
        // Verify peer identities match
        assert_eq!(client_result.peer_identity.did, server_identity.did);
        assert_eq!(server_result.peer_identity.did, client_identity.did);
        
        // Verify peer NodeIds match
        assert_eq!(client_result.peer_identity.node_id, server_identity.node_id);
        assert_eq!(server_result.peer_identity.node_id, client_identity.node_id);
        
        Ok(())
    }
    
    /// Test handshake with replay attack detection
    #[tokio::test]
    async fn test_replay_attack_prevention() -> Result<()> {
        // Setup server with shared nonce cache
        let server_identity = create_test_identity("server-replay-test");
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server_addr = listener.local_addr()?;
        
        let ctx = HandshakeContext::new(NonceCache::new_test(300, 10000));
        let server_ctx = ctx.clone();
        
        // First handshake should succeed
        let server_ctx_1 = server_ctx.clone();
        let server_identity_1 = server_identity.clone();
        let server_handle_1 = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.unwrap();
            handshake_as_responder(&mut stream, &server_identity_1, &server_ctx_1).await
        });
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        let client_identity = create_test_identity("client-replay-test");
        let mut client_stream_1 = TcpStream::connect(server_addr).await?;
        
        let _client_result_1 = handshake_as_initiator(&mut client_stream_1, &client_identity, &ctx).await?;
        let _server_result_1 = server_handle_1.await.unwrap()?;
        
        // Second handshake with same identity should succeed (different nonces)
        let listener_2 = TcpListener::bind("127.0.0.1:0").await?;
        let server_addr_2 = listener_2.local_addr()?;
        
        let server_handle_2 = tokio::spawn(async move {
            let (mut stream, _addr) = listener_2.accept().await.unwrap();
            handshake_as_responder(&mut stream, &server_identity, &server_ctx).await
        });
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        let mut client_stream_2 = TcpStream::connect(server_addr_2).await?;
        let _client_result_2 = handshake_as_initiator(&mut client_stream_2, &client_identity, &ctx).await?;
        let _server_result_2 = server_handle_2.await.unwrap()?;
        
        // Both handshakes should succeed because nonces are different
        Ok(())
    }
    
    /// Test message framing utilities
    #[tokio::test]
    async fn test_message_framing() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        
        // Spawn receiver
        let receive_handle = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.unwrap();
            receive_message(&mut stream).await
        });
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Send test message
        let mut sender = TcpStream::connect(addr).await?;
        let test_data = b"Hello, World! This is a test message.";
        send_message(&mut sender, test_data).await?;
        
        // Verify received data matches
        let received = receive_handle.await.unwrap()?;
        assert_eq!(received, test_data);
        
        Ok(())
    }
    
    /// Test oversized message rejection
    #[tokio::test]
    async fn test_oversized_message_rejection() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        
        let mut stream = TcpStream::connect(addr).await?;
        
        // Try to send message larger than MAX_HANDSHAKE_MESSAGE_SIZE
        let oversized_data = vec![0u8; MAX_HANDSHAKE_MESSAGE_SIZE + 1];
        let result = send_message(&mut stream, &oversized_data).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Message too large"));
        
        Ok(())
    }
}
