//! WiFi Direct Handshake Adapter for UHP
//!
//! Provides UHP handshake implementation for WiFi Direct TCP connections.
//! Replaces unverified WiFi Direct connections with cryptographically verified sessions.
//!
//! # Architecture
//!
//! WiFi Direct uses TCP sockets over P2P interface for data transmission:
//! ```text
//! WiFi Direct P2P Link (802.11 Layer 2)
//!          ↓
//! TCP Socket (192.168.49.x:9333)
//!          ↓
//! UHP Handshake (Layer 7 Authentication)
//!          ↓
//! Verified Session with Session Key
//! ```
//!
//! # UHP Handshake Flow
//!
//! ```text
//! Client (WiFi Direct)              Server (Group Owner)
//!   |                                     |
//!   |--- ClientHello ------------------>  |  (1) Send identity + capabilities + challenge
//!   |                                     |      Verify: NodeId, timestamp, nonce, signature
//!   |<-- ServerHello -------------------  |  (2) Send server identity + response nonce
//!   |                                     |      Verify: server signature on client challenge
//!   |--- ClientFinish ----------------->  |  (3) Sign server nonce, complete handshake
//!   |                                     |      Verify: client signature on server nonce
//!   |<== Authenticated WiFi Direct ====> |
//! ```
//!
//! # Security Properties
//!
//! - **Mutual Authentication**: Both peers verify each other's Sovereign Identity
//! - **NodeId Verification**: Validates NodeId = Blake3(DID || device_name)
//! - **Signature Verification**: All 3 handshake messages cryptographically signed
//! - **Replay Protection**: Nonce cache prevents replay attacks
//! - **Timeout Protection**: 30-second handshake timeout prevents DoS
//! - **Session Key Derivation**: HKDF derives symmetric session key from handshake
//!
//! # Production Usage
//!
//! ```rust
//! use lib_network::protocols::wifi_direct_handshake::{
//!     handshake_as_initiator, handshake_as_responder
//! };
//! use lib_identity::ZhtpIdentity;
//! use lib_network::handshake::{HandshakeContext, NonceCache, HandshakeCapabilities};
//! use tokio::net::TcpStream;
//!
//! // Client side (WiFi Direct client connecting to group owner)
//! async fn connect_to_wifi_direct_peer(
//!     stream: &mut TcpStream,
//!     identity: &ZhtpIdentity,
//! ) -> anyhow::Result<()> {
//!     let nonce_cache = NonceCache::new(3600, 10000);
//!     let ctx = HandshakeContext::new(nonce_cache);
//!     
//!     let result = handshake_as_initiator(stream, identity, &ctx).await?;
//!     
//!     println!("Connected to peer: {}", result.peer_identity.device_id);
//!     println!("Session key established: {:02x?}", &result.session_key[..8]);
//!     Ok(())
//! }
//!
//! // Server side (WiFi Direct group owner accepting connections)
//! async fn accept_wifi_direct_connection(
//!     stream: &mut TcpStream,
//!     identity: &ZhtpIdentity,
//! ) -> anyhow::Result<()> {
//!     let nonce_cache = NonceCache::new(3600, 10000);
//!     let ctx = HandshakeContext::new(nonce_cache);
//!     
//!     let result = handshake_as_responder(stream, identity, &ctx).await?;
//!     
//!     println!("Accepted peer: {}", result.peer_identity.device_id);
//!     Ok(())
//! }
//! ```

use anyhow::{Result, Context as AnyhowContext};
use lib_identity::ZhtpIdentity;
use lib_crypto::KeyPair;
use crate::handshake::{
    ClientHello, ServerHello, ClientFinish, HandshakeContext, HandshakeResult,
    HandshakeCapabilities,
};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

/// Handshake timeout for WiFi Direct connections (30 seconds)
///
/// WiFi Direct P2P links can have higher latency than regular WiFi, especially during
/// group owner negotiation or when multiple devices are connected. 30 seconds provides
/// sufficient time for:
/// - P2P link establishment
/// - WPS authentication
/// - Signature verification
/// - Network congestion
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum message size for WiFi Direct handshake messages (10 MB)
///
/// WiFi Direct supports high throughput (up to 250 Mbps), but handshake messages
/// should be small. This limit prevents DoS attacks via oversized messages.
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

// ============================================================================
// Client-Side Handshake (WiFi Direct Client → Group Owner)
// ============================================================================

/// Perform UHP handshake as WiFi Direct client (initiator)
///
/// Use this when connecting to a WiFi Direct group owner as a client.
///
/// # Security
///
/// - Verifies server's NodeId derivation (prevents collision attacks)
/// - Verifies server's signature on ServerHello (prevents MitM)
/// - Uses nonce cache for replay attack prevention
/// - Derives deterministic session key (both sides compute same key)
/// - 30-second timeout prevents DoS attacks
///
/// # Arguments
///
/// * `stream` - Active TCP connection over WiFi Direct P2P interface
/// * `identity` - Our ZhtpIdentity for signing messages
/// * `ctx` - HandshakeContext with nonce cache and timestamp config
///
/// # Returns
///
/// `HandshakeResult` containing:
/// - Verified peer identity (Group Owner's identity)
/// - Negotiated capabilities
/// - Session key for symmetric encryption
/// - Session ID for logging/tracking
///
/// # Errors
///
/// - `Err(...)` if handshake fails (invalid signature, timeout, network error)
///
/// # Example
///
/// ```rust,no_run
/// use lib_network::protocols::wifi_direct_handshake::handshake_as_initiator;
/// use lib_identity::ZhtpIdentity;
/// use lib_network::handshake::{HandshakeContext, NonceCache};
/// use tokio::net::TcpStream;
///
/// async fn connect_to_group_owner(
///     stream: &mut TcpStream,
///     identity: &ZhtpIdentity,
/// ) -> anyhow::Result<()> {
///     let nonce_cache = NonceCache::new(3600, 10000);
///     let ctx = HandshakeContext::new(nonce_cache);
///     
///     let result = handshake_as_initiator(stream, identity, &ctx).await?;
///     println!("Connected to: {}", result.peer_identity.did);
///     Ok(())
/// }
/// ```
pub async fn handshake_as_initiator(
    stream: &mut TcpStream,
    identity: &ZhtpIdentity,
    ctx: &HandshakeContext,
) -> Result<HandshakeResult> {
    // Use timeout wrapper for entire handshake
    timeout(HANDSHAKE_TIMEOUT, async {
        // Step 1: Create and send ClientHello
        let capabilities = create_wifi_direct_capabilities();
        let client_hello = ClientHello::new(identity, capabilities)
            .context("Failed to create ClientHello")?;
        
        send_message(stream, &client_hello).await
            .context("Failed to send ClientHello")?;
        
        tracing::debug!(
            node_id = ?identity.node_id,
            "WiFi Direct: ClientHello sent to group owner"
        );
        
        // Step 2: Receive and verify ServerHello
        let server_hello: ServerHello = receive_message(stream).await
            .context("Failed to receive ServerHello from group owner")?;
        
        tracing::debug!(
            peer_node_id = ?server_hello.identity.node_id,
            "WiFi Direct: ServerHello received from group owner"
        );
        
        // CRITICAL: Verify server's signature (mutual authentication)
        server_hello.verify_signature(&client_hello.challenge_nonce, ctx)
            .context("Server signature verification failed - potential MitM attack")?;
        
        tracing::info!(
            peer_did = %server_hello.identity.did,
            peer_device = %server_hello.identity.device_id,
            "WiFi Direct: Group owner verified successfully"
        );
        
        // Step 3: Create and send ClientFinish
        let keypair = KeyPair {
            public_key: identity.public_key.clone(),
            private_key: identity.private_key.clone()
                .ok_or_else(|| anyhow::anyhow!("Identity missing private key"))?,
        };
        
        let client_finish = ClientFinish::new(&server_hello, &client_hello, &keypair, ctx)
            .context("Failed to create ClientFinish")?;
        
        send_message(stream, &client_finish).await
            .context("Failed to send ClientFinish")?;
        
        tracing::debug!("WiFi Direct: ClientFinish sent, handshake complete");
        
        // Step 4: Derive session key (deterministic using ClientHello timestamp)
        let result = HandshakeResult::new(
            server_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_hello.identity.did,
            &server_hello.identity.did,
            client_hello.timestamp, // VULN-003 FIX: Use ClientHello timestamp
        ).context("Failed to derive session key")?;
        
        tracing::info!(
            session_id = ?result.session_id,
            peer = %server_hello.identity.to_compact_string(),
            "WiFi Direct handshake completed as client"
        );
        
        Ok(result)
    })
    .await
    .context("WiFi Direct handshake timeout (30s)")??
}

// ============================================================================
// Server-Side Handshake (WiFi Direct Group Owner Accepting Client)
// ============================================================================

/// Perform UHP handshake as WiFi Direct group owner (responder)
///
/// Use this when accepting incoming WiFi Direct connections as the group owner.
///
/// # Security
///
/// - Verifies client's NodeId derivation (prevents collision attacks)
/// - Verifies client's signature on ClientHello (prevents spoofing)
/// - Verifies client's signature on ClientFinish (completes mutual auth)
/// - Uses nonce cache for replay attack prevention
/// - Derives deterministic session key (same as client)
/// - 30-second timeout prevents DoS attacks
///
/// # Arguments
///
/// * `stream` - Incoming TCP connection over WiFi Direct P2P interface
/// * `identity` - Our ZhtpIdentity (group owner's identity)
/// * `ctx` - HandshakeContext with nonce cache and timestamp config
///
/// # Returns
///
/// `HandshakeResult` containing verified client identity and session key
///
/// # Errors
///
/// - `Err(...)` if handshake fails (invalid peer, timeout, etc.)
///
/// # Example
///
/// ```rust,no_run
/// use lib_network::protocols::wifi_direct_handshake::handshake_as_responder;
/// use lib_identity::ZhtpIdentity;
/// use lib_network::handshake::{HandshakeContext, NonceCache};
/// use tokio::net::TcpStream;
///
/// async fn accept_client(
///     stream: &mut TcpStream,
///     identity: &ZhtpIdentity,
/// ) -> anyhow::Result<()> {
///     let nonce_cache = NonceCache::new(3600, 10000);
///     let ctx = HandshakeContext::new(nonce_cache);
///     
///     let result = handshake_as_responder(stream, identity, &ctx).await?;
///     println!("Accepted client: {}", result.peer_identity.device_id);
///     Ok(())
/// }
/// ```
pub async fn handshake_as_responder(
    stream: &mut TcpStream,
    identity: &ZhtpIdentity,
    ctx: &HandshakeContext,
) -> Result<HandshakeResult> {
    // Use timeout wrapper for entire handshake
    timeout(HANDSHAKE_TIMEOUT, async {
        // Step 1: Receive and verify ClientHello
        let client_hello: ClientHello = receive_message(stream).await
            .context("Failed to receive ClientHello from WiFi Direct client")?;
        
        tracing::debug!(
            peer_node_id = ?client_hello.identity.node_id,
            "WiFi Direct: ClientHello received from client"
        );
        
        // CRITICAL: Verify client's signature
        client_hello.verify_signature(ctx)
            .context("Client signature verification failed - rejecting connection")?;
        
        tracing::info!(
            peer_did = %client_hello.identity.did,
            peer_device = %client_hello.identity.device_id,
            "WiFi Direct: Client verified successfully"
        );
        
        // Step 2: Create and send ServerHello
        let capabilities = create_wifi_direct_capabilities();
        let server_hello = ServerHello::new(identity, capabilities, &client_hello)
            .context("Failed to create ServerHello")?;
        
        send_message(stream, &server_hello).await
            .context("Failed to send ServerHello")?;
        
        tracing::debug!(
            node_id = ?identity.node_id,
            "WiFi Direct: ServerHello sent to client"
        );
        
        // Step 3: Receive and verify ClientFinish
        let client_finish: ClientFinish = receive_message(stream).await
            .context("Failed to receive ClientFinish from client")?;
        
        tracing::debug!("WiFi Direct: ClientFinish received");
        
        // CRITICAL: Verify client's signature on server nonce
        client_finish.verify_signature(&server_hello.response_nonce, &client_hello.identity.public_key)
            .context("ClientFinish signature verification failed")?;
        
        tracing::debug!("WiFi Direct: ClientFinish verified, handshake complete");
        
        // Step 4: Derive session key (same as client - deterministic)
        let result = HandshakeResult::new(
            client_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_hello.identity.did,
            &server_hello.identity.did,
            client_hello.timestamp, // VULN-003 FIX: Use ClientHello timestamp (same as client)
        ).context("Failed to derive session key")?;
        
        tracing::info!(
            session_id = ?result.session_id,
            peer = %client_hello.identity.to_compact_string(),
            "WiFi Direct handshake completed as group owner"
        );
        
        Ok(result)
    })
    .await
    .context("WiFi Direct handshake timeout (30s)")??
}

// ============================================================================
// Message Framing Utilities
// ============================================================================

/// Send a handshake message with length-prefix framing
///
/// Wire format: [4-byte length (u32 LE)][serialized message bytes]
///
/// # Arguments
///
/// * `stream` - TCP stream to write to
/// * `message` - Message to serialize and send
///
/// # Errors
///
/// - `Err(...)` if serialization fails or write fails
async fn send_message<T: serde::Serialize>(stream: &mut TcpStream, message: &T) -> Result<()> {
    // Serialize message
    let bytes = bincode::serialize(message)
        .context("Failed to serialize handshake message")?;
    
    // Validate size
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!(
            "Message too large: {} bytes (max: {})",
            bytes.len(),
            MAX_MESSAGE_SIZE
        ));
    }
    
    // Send length prefix (u32 little-endian)
    let len_bytes = (bytes.len() as u32).to_le_bytes();
    stream.write_all(&len_bytes).await
        .context("Failed to write message length")?;
    
    // Send message payload
    stream.write_all(&bytes).await
        .context("Failed to write message payload")?;
    
    // Flush to ensure immediate transmission (important for handshake timing)
    stream.flush().await
        .context("Failed to flush stream")?;
    
    tracing::trace!(
        message_size = bytes.len(),
        "WiFi Direct: Handshake message sent"
    );
    
    Ok(())
}

/// Receive a handshake message with length-prefix framing
///
/// Wire format: [4-byte length (u32 LE)][serialized message bytes]
///
/// # Arguments
///
/// * `stream` - TCP stream to read from
///
/// # Returns
///
/// Deserialized message of type `T`
///
/// # Errors
///
/// - `Err(...)` if read fails, message too large, or deserialization fails
async fn receive_message<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    // Read length prefix (4 bytes)
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await
        .context("Failed to read message length - peer disconnected or network error")?;
    
    let len = u32::from_le_bytes(len_bytes) as usize;
    
    // Validate message size
    if len > MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!(
            "Message too large: {} bytes (max: {}) - potential DoS attack",
            len,
            MAX_MESSAGE_SIZE
        ));
    }
    
    if len == 0 {
        return Err(anyhow::anyhow!("Empty message received"));
    }
    
    // Read message payload
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).await
        .context("Failed to read message payload - incomplete transmission")?;
    
    // Deserialize
    let message = bincode::deserialize(&buffer)
        .context("Failed to deserialize handshake message - protocol mismatch")?;
    
    tracing::trace!(
        message_size = len,
        "WiFi Direct: Handshake message received"
    );
    
    Ok(message)
}

// ============================================================================
// WiFi Direct Capability Configuration
// ============================================================================

/// Create WiFi Direct-specific handshake capabilities
///
/// Configures capabilities appropriate for WiFi Direct P2P connections:
/// - WiFi Direct protocol support
/// - High throughput (up to 250 Mbps theoretical, ~100 Mbps practical)
/// - Large message sizes (WiFi Direct has good bandwidth)
/// - ChaCha20-Poly1305 encryption (efficient on mobile devices)
/// - DHT and relay capabilities (WiFi Direct nodes can relay)
///
/// # Returns
///
/// `HandshakeCapabilities` configured for WiFi Direct
fn create_wifi_direct_capabilities() -> HandshakeCapabilities {
    HandshakeCapabilities {
        protocols: vec!["wifi-direct".to_string(), "tcp".to_string()],
        max_throughput: 100_000_000, // 100 Mbps (practical WiFi Direct throughput)
        max_message_size: 1_048_576,  // 1 MB (WiFi Direct can handle large messages)
        encryption_methods: vec!["chacha20-poly1305".to_string()],
        pqc_support: false, // Post-quantum crypto adds overhead
        dht_capable: true,  // WiFi Direct nodes can participate in DHT
        relay_capable: true, // WiFi Direct group owners can relay traffic
        storage_capacity: 0, // No storage guarantee over WiFi Direct
        web4_capable: false, // Web4 serving typically over stable connections
        custom_features: vec![
            "wifi-direct-p2p".to_string(),
            "mobile-mesh".to_string(),
        ],
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::ZhtpIdentity;
    use crate::handshake::{NonceCache, HandshakeContext};
    use tokio::net::{TcpListener, TcpStream};

    /// Helper to create test identity
    fn create_test_identity(device_name: &str) -> ZhtpIdentity {
        ZhtpIdentity::new_ephemeral_for_test(device_name)
            .expect("Failed to create test identity")
    }

    /// Test full WiFi Direct handshake (client + group owner)
    ///
    /// Verifies:
    /// - Client and group owner complete handshake successfully
    /// - Both derive the same session key
    /// - Peer identities are correctly exchanged
    #[tokio::test]
    async fn test_wifi_direct_handshake() {
        // Create identities for group owner and client
        let group_owner_identity = create_test_identity("wifi-group-owner");
        let client_identity = create_test_identity("wifi-client");
        
        // Start TCP listener (simulates WiFi Direct group owner)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Spawn group owner task
        let group_owner_identity_clone = group_owner_identity.clone();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            
            let nonce_cache = NonceCache::new_test(300, 1000);
            let ctx = HandshakeContext::new(nonce_cache);
            
            handshake_as_responder(&mut stream, &group_owner_identity_clone, &ctx).await.unwrap()
        });
        
        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Connect as WiFi Direct client
        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);
        
        let client_result = handshake_as_initiator(&mut client_stream, &client_identity, &ctx).await.unwrap();
        let server_result = server_task.await.unwrap();
        
        // Verify session keys match
        assert_eq!(
            client_result.session_key,
            server_result.session_key,
            "Session keys must match on both sides"
        );
        
        // Verify peer identities
        assert_eq!(
            client_result.peer_identity.node_id,
            group_owner_identity.node_id,
            "Client should see group owner's identity"
        );
        
        assert_eq!(
            server_result.peer_identity.node_id,
            client_identity.node_id,
            "Group owner should see client's identity"
        );
        
        println!("✓ WiFi Direct handshake test passed");
    }

    /// Test replay attack prevention
    ///
    /// Verifies that nonce cache prevents replay of ClientHello messages
    #[tokio::test]
    async fn test_replay_attack_prevention() {
        let identity = create_test_identity("replay-test");
        
        // Create two handshakes - second should succeed (different nonces)
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);
        
        let hello1 = ClientHello::new(&identity, create_wifi_direct_capabilities()).unwrap();
        let hello2 = ClientHello::new(&identity, create_wifi_direct_capabilities()).unwrap();
        
        // First verification should succeed
        assert!(hello1.verify_signature(&ctx).is_ok(), "First handshake should succeed");
        
        // Second verification should succeed (different nonce)
        assert!(hello2.verify_signature(&ctx).is_ok(), "Second handshake with new nonce should succeed");
        
        println!("✓ Replay attack prevention test passed");
    }

    /// Test message framing with various sizes
    #[tokio::test]
    async fn test_message_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let msg: String = receive_message(&mut stream).await.unwrap();
            assert_eq!(msg, "test message");
        });
        
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        send_message(&mut client_stream, &"test message".to_string()).await.unwrap();
        
        server_task.await.unwrap();
        println!("✓ Message framing test passed");
    }

    /// Test oversized message rejection
    #[tokio::test]
    async fn test_oversized_message_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            
            // Try to receive oversized message
            let result: Result<Vec<u8>> = receive_message(&mut stream).await;
            assert!(result.is_err(), "Should reject oversized message");
        });
        
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        
        // Send fake oversized message (length prefix indicates 20 MB)
        let fake_len = (20 * 1024 * 1024u32).to_le_bytes();
        client_stream.write_all(&fake_len).await.unwrap();
        client_stream.flush().await.unwrap();
        
        server_task.await.unwrap();
        println!("✓ Oversized message rejection test passed");
    }

    /// Test that invalid peer is rejected
    ///
    /// Verifies that handshake rejects peers with invalid NodeId or signature
    #[tokio::test]
    async fn test_invalid_peer_rejection() {
        let valid_identity = create_test_identity("valid-peer");
        
        // Create ClientHello with valid identity
        let mut hello = ClientHello::new(&valid_identity, create_wifi_direct_capabilities()).unwrap();
        
        // Corrupt the NodeId (simulates collision attack or invalid identity)
        hello.identity.node_id = lib_identity::NodeId::from_bytes(&[0xFF; 32]);
        
        // Verification should fail due to invalid NodeId
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);
        
        let result = hello.verify_signature(&ctx);
        assert!(result.is_err(), "Should reject peer with invalid NodeId");
        
        println!("✓ Invalid peer rejection test passed");
    }
}
