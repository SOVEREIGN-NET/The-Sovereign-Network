//! QUIC Handshake Adapter for UHP with Post-Quantum Key Exchange
//!
//! Provides authenticated handshake for QUIC connections using:
//! - **UHP (Unified Handshake Protocol)**: Mutual authentication via Dilithium signatures
//! - **Kyber512 KEM**: Post-quantum key encapsulation bound to authenticated identity
//!
//! # Architecture
//!
//! ```text
//! QUIC Connection (quinn)
//!          ↓
//! Dedicated Bidirectional Stream
//!          ↓
//! Phase 1: UHP Authentication
//!   - ClientHello (identity + capabilities + Dilithium signature)
//!   - ServerHello (identity + challenge response + Dilithium signature)
//!   - ClientFinish (signature on server nonce)
//!          ↓
//! Phase 2: Kyber Key Exchange (bound to UHP transcript)
//!   - KyberRequest (client's Kyber public key)
//!   - KyberResponse (server's ciphertext)
//!          ↓
//! Master Key Derivation
//!   quic_mesh_master = HKDF(uhp_session_key || pqc_shared_secret || transcript_hash || peer_node_id)
//!          ↓
//! Verified PQC Session
//! ```
//!
//! # Security Properties
//!
//! - **Mutual Authentication**: Both peers verify Dilithium signatures (UHP)
//! - **NodeId Verification**: Validates NodeId = Blake3(DID || device_name)
//! - **Replay Protection**: Nonce cache prevents replay attacks
//! - **Post-Quantum Security**: Kyber512 KEM provides quantum-resistant key exchange
//! - **Cryptographic Binding**: Kyber exchange is bound to UHP transcript hash and peer NodeId
//! - **Key Zeroization**: Intermediate keys (UHP session key, raw Kyber secret) are zeroized after use
//!
//! # Usage
//!
//! ```rust,ignore
//! use lib_network::protocols::quic_handshake::{handshake_as_initiator, handshake_as_responder};
//! use lib_identity::ZhtpIdentity;
//! use lib_network::handshake::{HandshakeContext, NonceCache};
//! use quinn::Connection;
//!
//! // Client side
//! async fn connect(conn: &Connection, identity: &ZhtpIdentity) -> anyhow::Result<()> {
//!     let nonce_cache = NonceCache::new(3600, 10000);
//!     let ctx = HandshakeContext::new(nonce_cache);
//!
//!     let result = handshake_as_initiator(conn, identity, &ctx).await?;
//!     println!("Connected to: {}", result.peer_identity.did);
//!     println!("Master key established: {:02x?}", &result.master_key[..8]);
//!     Ok(())
//! }
//! ```

use anyhow::{Result, Context as AnyhowContext, anyhow};
use lib_identity::ZhtpIdentity;
use lib_crypto::{KeyPair, hash_blake3};
use lib_crypto::kdf::hkdf::hkdf_sha3;
use lib_crypto::post_quantum::kyber::{kyber512_keypair, kyber512_encapsulate, kyber512_decapsulate};
use crate::handshake::{
    ClientHello, ServerHello, ClientFinish, HandshakeContext, HandshakeResult,
    HandshakeCapabilities, NodeIdentity, PqcCapability,
};
use quinn::Connection;
use tokio::time::{timeout, Duration};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

// Use consistent message size limit
use crate::constants::MAX_HANDSHAKE_MESSAGE_SIZE;

/// Maximum QUIC handshake message size (16 KB - more constrained than general UHP)
/// QUIC handshake should be lean; 16KB is more than enough for identity + capabilities
const MAX_QUIC_HANDSHAKE_MSG: usize = 16 * 1024;

/// Handshake timeout for QUIC connections (30 seconds)
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Protocol version for QUIC+UHP+Kyber handshake
/// Bump this when making breaking changes to the handshake protocol
const QUIC_HANDSHAKE_VERSION: u8 = 1;

// ============================================================================
// Kyber Exchange Messages
// ============================================================================

/// Kyber key exchange request (client → server)
///
/// Sent after UHP authentication completes to establish PQC shared secret.
/// Bound to the UHP transcript to prevent splice attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KyberRequest {
    /// Protocol version
    version: u8,
    /// Client's Kyber512 public key
    kyber_pubkey: Vec<u8>,
    /// Hash of UHP transcript (ClientHello || ServerHello || ClientFinish)
    /// Binds Kyber exchange to the authenticated session
    uhp_transcript_hash: [u8; 32],
}

/// Kyber key exchange response (server → client)
///
/// Contains the encapsulated shared secret that only the client can decapsulate.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KyberResponse {
    /// Protocol version
    version: u8,
    /// Kyber512 ciphertext (encapsulated shared secret)
    ciphertext: Vec<u8>,
    /// Server's UHP transcript hash (must match client's)
    uhp_transcript_hash: [u8; 32],
}

// ============================================================================
// Handshake Result
// ============================================================================

/// Result of a successful QUIC handshake with UHP + Kyber
///
/// Contains the verified peer identity and derived master key.
#[derive(Debug, Clone)]
pub struct QuicHandshakeResult {
    /// Verified peer identity from UHP handshake
    pub peer_identity: NodeIdentity,

    /// Negotiated session capabilities
    pub capabilities: crate::handshake::NegotiatedCapabilities,

    /// QUIC mesh master key derived from UHP + Kyber
    /// This is the ONLY key that should be used; intermediate keys are zeroized
    pub master_key: [u8; 32],

    /// Session ID for logging/tracking
    pub session_id: [u8; 16],

    /// Timestamp when handshake completed
    pub completed_at: u64,
}

// ============================================================================
// Client-Side Handshake (Initiator)
// ============================================================================

/// Perform QUIC handshake as initiator (client side)
///
/// # Flow
///
/// 1. Open dedicated bidirectional stream for handshake
/// 2. Execute UHP authentication (ClientHello → ServerHello → ClientFinish)
/// 3. Execute Kyber key exchange (KyberRequest → KyberResponse)
/// 4. Derive master key from UHP session key + Kyber shared secret
/// 5. Zeroize intermediate keys
/// 6. Close handshake stream
///
/// # Security
///
/// - Verifies server's Dilithium signature on ServerHello
/// - Verifies server's NodeId derivation (Blake3(DID || device_name))
/// - Uses nonce cache for replay attack prevention
/// - Binds Kyber exchange to UHP transcript hash + peer NodeId
/// - Zeroizes intermediate keys after master key derivation
///
/// # Arguments
///
/// * `conn` - Active QUIC connection
/// * `identity` - Our ZhtpIdentity for signing UHP messages
/// * `ctx` - HandshakeContext with nonce cache and timestamp config
///
/// # Returns
///
/// `QuicHandshakeResult` containing verified peer identity and master key
///
/// # Errors
///
/// - Network I/O failure
/// - Invalid peer signature
/// - NodeId verification failure
/// - Replay attack detected
/// - Kyber encapsulation/decapsulation failure
/// - Handshake timeout (30s)
pub async fn handshake_as_initiator(
    conn: &Connection,
    identity: &ZhtpIdentity,
    ctx: &HandshakeContext,
) -> Result<QuicHandshakeResult> {
    timeout(HANDSHAKE_TIMEOUT, async {
        // Open dedicated bidirectional stream for handshake
        let (mut send, mut recv) = conn.open_bi().await
            .context("Failed to open handshake stream")?;

        debug!(
            local_node_id = ?identity.node_id,
            peer_addr = %conn.remote_address(),
            "QUIC handshake: starting as initiator"
        );

        // ================================================================
        // Phase 1: UHP Authentication
        // ================================================================

        // Step 1: Create and send ClientHello
        let capabilities = create_quic_capabilities();
        let client_hello = ClientHello::new(identity, capabilities)
            .context("Failed to create ClientHello")?;

        let client_hello_bytes = bincode::serialize(&client_hello)
            .context("Failed to serialize ClientHello")?;

        send_framed(&mut send, &client_hello_bytes).await
            .context("Failed to send ClientHello")?;

        debug!("QUIC handshake: ClientHello sent");

        // Step 2: Receive and verify ServerHello
        let server_hello_bytes = recv_framed(&mut recv).await
            .context("Failed to receive ServerHello")?;

        let server_hello: ServerHello = bincode::deserialize(&server_hello_bytes)
            .context("Failed to deserialize ServerHello")?;

        debug!(
            peer_node_id = ?server_hello.identity.node_id,
            "QUIC handshake: ServerHello received"
        );

        // Step 3: Create and send ClientFinish
        // NOTE: ClientFinish::new() performs server signature verification internally
        // (validates timestamp, checks nonce cache, verifies Dilithium signature)
        let keypair = KeyPair {
            public_key: identity.public_key.clone(),
            private_key: identity.private_key.clone()
                .ok_or_else(|| anyhow!("Identity missing private key"))?,
        };

        let client_finish = ClientFinish::new(&server_hello, &client_hello, &keypair, ctx)
            .context("Failed to create ClientFinish")?;

        // Server verified! Log the peer info
        info!(
            peer_did = %server_hello.identity.did,
            peer_device = %server_hello.identity.device_id,
            "QUIC handshake: server verified successfully"
        );

        let client_finish_bytes = bincode::serialize(&client_finish)
            .context("Failed to serialize ClientFinish")?;

        send_framed(&mut send, &client_finish_bytes).await
            .context("Failed to send ClientFinish")?;

        debug!("QUIC handshake: ClientFinish sent, UHP authentication complete");

        // Compute UHP session key (for binding to Kyber)
        let mut uhp_session_key = HandshakeResult::new(
            server_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_hello.identity.did,
            &server_hello.identity.did,
            client_hello.timestamp,
        ).context("Failed to derive UHP session key")?.session_key;

        // Compute UHP transcript hash for Kyber binding
        let uhp_transcript_hash = compute_uhp_transcript_hash(
            &client_hello_bytes,
            &server_hello_bytes,
            &client_finish_bytes,
            "INITIATOR",
        );

        // ================================================================
        // Phase 2: Kyber Key Exchange (bound to UHP)
        // ================================================================

        // Generate Kyber keypair
        let (kyber_pk, kyber_sk) = kyber512_keypair();

        // Send KyberRequest
        let kyber_request = KyberRequest {
            version: QUIC_HANDSHAKE_VERSION,
            kyber_pubkey: kyber_pk,
            uhp_transcript_hash,
        };

        let kyber_request_bytes = bincode::serialize(&kyber_request)
            .context("Failed to serialize KyberRequest")?;

        send_framed(&mut send, &kyber_request_bytes).await
            .context("Failed to send KyberRequest")?;

        debug!("QUIC handshake: KyberRequest sent");

        // Receive KyberResponse
        let kyber_response_bytes = recv_framed(&mut recv).await
            .context("Failed to receive KyberResponse")?;

        let kyber_response: KyberResponse = bincode::deserialize(&kyber_response_bytes)
            .context("Failed to deserialize KyberResponse")?;

        // Verify transcript hash matches (prevents splice attacks)
        if kyber_response.uhp_transcript_hash != uhp_transcript_hash {
            return Err(anyhow!("Kyber transcript hash mismatch - potential splice attack"));
        }

        // Decapsulate shared secret
        let mut pqc_shared_secret = kyber512_decapsulate(
            &kyber_response.ciphertext,
            &kyber_sk,
            b"ZHTP-QUIC-KEM-v1.0",
        ).context("Failed to decapsulate Kyber shared secret")?;

        debug!("QUIC handshake: Kyber key exchange complete");

        // ================================================================
        // Phase 3: Master Key Derivation
        // ================================================================

        // DEBUG: Log all inputs to master key derivation for session ID debugging
        debug!(
            uhp_session_key = %hex::encode(&uhp_session_key[..8]),
            pqc_shared_secret = %hex::encode(&pqc_shared_secret[..8]),
            uhp_transcript_hash = %hex::encode(&uhp_transcript_hash[..8]),
            server_node_id = %hex::encode(&server_hello.identity.node_id.as_bytes()[..8]),
            "INITIATOR: Master key derivation inputs"
        );

        let master_key = derive_quic_master_key(
            &uhp_session_key,
            &pqc_shared_secret,
            &uhp_transcript_hash,
            server_hello.identity.node_id.as_bytes(),
        )?;

        // Zeroize intermediate keys
        uhp_session_key.zeroize();
        pqc_shared_secret.zeroize();

        // Close handshake stream
        send.finish()
            .context("Failed to finish handshake stream")?;

        // Build result
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&master_key[..16]);

        let completed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        info!(
            session_id = ?session_id,
            peer = %server_hello.identity.to_compact_string(),
            "QUIC handshake completed as initiator"
        );

        Ok(QuicHandshakeResult {
            peer_identity: server_hello.identity,
            capabilities: server_hello.negotiated,
            master_key,
            session_id,
            completed_at,
        })
    })
    .await
    .map_err(|_| anyhow!("QUIC handshake timeout (30s)"))?
}

// ============================================================================
// Server-Side Handshake (Responder)
// ============================================================================

/// Perform QUIC handshake as responder (server side)
///
/// # Flow
///
/// 1. Accept dedicated bidirectional stream for handshake
/// 2. Execute UHP authentication (receive ClientHello → send ServerHello → receive ClientFinish)
/// 3. Execute Kyber key exchange (receive KyberRequest → send KyberResponse)
/// 4. Derive master key from UHP session key + Kyber shared secret
/// 5. Zeroize intermediate keys
///
/// # Security
///
/// - Verifies client's Dilithium signature on ClientHello
/// - Verifies client's NodeId derivation (Blake3(DID || device_name))
/// - Verifies client's signature on ClientFinish
/// - Uses nonce cache for replay attack prevention
/// - Binds Kyber exchange to UHP transcript hash + peer NodeId
/// - Zeroizes intermediate keys after master key derivation
///
/// # Arguments
///
/// * `conn` - Incoming QUIC connection
/// * `identity` - Our ZhtpIdentity for signing UHP messages
/// * `ctx` - HandshakeContext with nonce cache and timestamp config
///
/// # Returns
///
/// `QuicHandshakeResult` containing verified peer identity and master key
pub async fn handshake_as_responder(
    conn: &Connection,
    identity: &ZhtpIdentity,
    ctx: &HandshakeContext,
) -> Result<QuicHandshakeResult> {
    timeout(HANDSHAKE_TIMEOUT, async {
        // Accept dedicated bidirectional stream for handshake
        let (mut send, mut recv) = conn.accept_bi().await
            .context("Failed to accept handshake stream")?;

        debug!(
            local_node_id = ?identity.node_id,
            peer_addr = %conn.remote_address(),
            "QUIC handshake: starting as responder"
        );

        // ================================================================
        // Phase 1: UHP Authentication
        // ================================================================

        // Step 1: Receive and verify ClientHello
        let client_hello_bytes = recv_framed(&mut recv).await
            .context("Failed to receive ClientHello")?;

        let client_hello: ClientHello = bincode::deserialize(&client_hello_bytes)
            .context("Failed to deserialize ClientHello")?;

        debug!(
            peer_node_id = ?client_hello.identity.node_id,
            "QUIC handshake: ClientHello received"
        );

        // CRITICAL: Verify client's signature
        client_hello.verify_signature(ctx)
            .context("Client signature verification failed - rejecting connection")?;

        info!(
            peer_did = %client_hello.identity.did,
            peer_device = %client_hello.identity.device_id,
            "QUIC handshake: client verified successfully"
        );

        // Step 2: Create and send ServerHello
        let capabilities = create_quic_capabilities();
        let server_hello = ServerHello::new(identity, capabilities, &client_hello)
            .context("Failed to create ServerHello")?;

        let server_hello_bytes = bincode::serialize(&server_hello)
            .context("Failed to serialize ServerHello")?;

        send_framed(&mut send, &server_hello_bytes).await
            .context("Failed to send ServerHello")?;

        debug!("QUIC handshake: ServerHello sent");

        // Step 3: Receive and verify ClientFinish
        let client_finish_bytes = recv_framed(&mut recv).await
            .context("Failed to receive ClientFinish")?;

        let client_finish: ClientFinish = bincode::deserialize(&client_finish_bytes)
            .context("Failed to deserialize ClientFinish")?;

        // CRITICAL: Verify client's signature on server nonce
        client_finish.verify_signature(&server_hello.response_nonce, &client_hello.identity.public_key)
            .context("ClientFinish signature verification failed")?;

        debug!("QUIC handshake: ClientFinish verified, UHP authentication complete");

        // Compute UHP session key (for binding to Kyber)
        let mut uhp_session_key = HandshakeResult::new(
            client_hello.identity.clone(),
            server_hello.negotiated.clone(),
            &client_hello.challenge_nonce,
            &server_hello.response_nonce,
            &client_hello.identity.did,
            &server_hello.identity.did,
            client_hello.timestamp,
        ).context("Failed to derive UHP session key")?.session_key;

        // Compute UHP transcript hash for Kyber binding
        let uhp_transcript_hash = compute_uhp_transcript_hash(
            &client_hello_bytes,
            &server_hello_bytes,
            &client_finish_bytes,
            "RESPONDER",
        );

        // ================================================================
        // Phase 2: Kyber Key Exchange (bound to UHP)
        // ================================================================

        // Receive KyberRequest
        let kyber_request_bytes = recv_framed(&mut recv).await
            .context("Failed to receive KyberRequest")?;

        let kyber_request: KyberRequest = bincode::deserialize(&kyber_request_bytes)
            .context("Failed to deserialize KyberRequest")?;

        // Verify protocol version
        if kyber_request.version != QUIC_HANDSHAKE_VERSION {
            return Err(anyhow!(
                "Kyber protocol version mismatch: expected {}, got {}",
                QUIC_HANDSHAKE_VERSION,
                kyber_request.version
            ));
        }

        // Verify transcript hash matches (prevents splice attacks)
        if kyber_request.uhp_transcript_hash != uhp_transcript_hash {
            return Err(anyhow!("Kyber transcript hash mismatch - potential splice attack"));
        }

        debug!("QUIC handshake: KyberRequest received and verified");

        // Encapsulate shared secret using client's public key
        // NOTE: kdf_info must match the one used in decapsulate by the initiator
        let (ciphertext, mut pqc_shared_secret) = kyber512_encapsulate(
            &kyber_request.kyber_pubkey,
            b"ZHTP-QUIC-KEM-v1.0",
        ).context("Failed to encapsulate Kyber shared secret")?;

        // Send KyberResponse
        let kyber_response = KyberResponse {
            version: QUIC_HANDSHAKE_VERSION,
            ciphertext,
            uhp_transcript_hash,
        };

        let kyber_response_bytes = bincode::serialize(&kyber_response)
            .context("Failed to serialize KyberResponse")?;

        send_framed(&mut send, &kyber_response_bytes).await
            .context("Failed to send KyberResponse")?;

        debug!("QUIC handshake: KyberResponse sent, key exchange complete");

        // ================================================================
        // Phase 3: Master Key Derivation
        // ================================================================

        // DEBUG: Log all inputs to master key derivation for session ID debugging
        debug!(
            uhp_session_key = %hex::encode(&uhp_session_key[..8]),
            pqc_shared_secret = %hex::encode(&pqc_shared_secret[..8]),
            uhp_transcript_hash = %hex::encode(&uhp_transcript_hash[..8]),
            server_node_id = %hex::encode(&server_hello.identity.node_id.as_bytes()[..8]),
            "RESPONDER: Master key derivation inputs"
        );

        // Use responder's (server's) node ID for key derivation
        // NOTE: Both initiator and responder must use the SAME node ID (responder's)
        // to derive matching master keys and session IDs
        let master_key = derive_quic_master_key(
            &uhp_session_key,
            &pqc_shared_secret,
            &uhp_transcript_hash,
            server_hello.identity.node_id.as_bytes(),
        )?;

        // Zeroize intermediate keys
        uhp_session_key.zeroize();
        pqc_shared_secret.zeroize();

        // Close handshake stream (server side)
        send.finish()
            .context("Failed to finish handshake stream")?;

        // Build result
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&master_key[..16]);

        let completed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        info!(
            session_id = ?session_id,
            peer = %client_hello.identity.to_compact_string(),
            "QUIC handshake completed as responder"
        );

        Ok(QuicHandshakeResult {
            peer_identity: client_hello.identity,
            capabilities: server_hello.negotiated,
            master_key,
            session_id,
            completed_at,
        })
    })
    .await
    .map_err(|_| anyhow!("QUIC handshake timeout (30s)"))?
}

// ============================================================================
// Key Derivation
// ============================================================================

/// Derive QUIC mesh master key from UHP session key and Kyber shared secret
///
/// # Security
///
/// - Binds UHP identity authentication to PQC key exchange
/// - Includes transcript hash to prevent transcript manipulation
/// - Includes peer NodeId for additional binding
/// - Uses HKDF-SHA3 for secure key derivation
///
/// Formula:
/// ```text
/// IKM = uhp_session_key || pqc_shared_secret || uhp_transcript_hash || peer_node_id
/// master_key = HKDF-Expand(HKDF-Extract(salt="zhtp-quic-mesh", IKM), info="zhtp-quic-master", L=32)
/// ```
fn derive_quic_master_key(
    uhp_session_key: &[u8; 32],
    pqc_shared_secret: &[u8; 32],
    uhp_transcript_hash: &[u8; 32],
    peer_node_id: &[u8],
) -> Result<[u8; 32]> {
    // Concatenate input keying material
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + peer_node_id.len());
    ikm.extend_from_slice(uhp_session_key);
    ikm.extend_from_slice(pqc_shared_secret);
    ikm.extend_from_slice(uhp_transcript_hash);
    ikm.extend_from_slice(peer_node_id);

    // First pass: extract with salt
    let salt_info = b"zhtp-quic-mesh";
    let extracted = hkdf_sha3(&ikm, salt_info, 32)
        .context("HKDF extract failed")?;

    // Second pass: expand with domain separation
    let expand_info = b"zhtp-quic-master";
    let expanded = hkdf_sha3(&extracted, expand_info, 32)
        .context("HKDF expand failed")?;

    // Zeroize intermediate IKM
    ikm.zeroize();

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&expanded);

    Ok(master_key)
}

/// Compute UHP transcript hash from all handshake message bytes
///
/// Used to bind Kyber exchange to the authenticated UHP session.
fn compute_uhp_transcript_hash(
    client_hello_bytes: &[u8],
    server_hello_bytes: &[u8],
    client_finish_bytes: &[u8],
    role: &str,
) -> [u8; 32] {
    // DEBUG: Log byte lengths and first 16 bytes of each message
    debug!(
        role = %role,
        client_hello_len = client_hello_bytes.len(),
        server_hello_len = server_hello_bytes.len(),
        client_finish_len = client_finish_bytes.len(),
        client_hello_head = %hex::encode(&client_hello_bytes[..std::cmp::min(16, client_hello_bytes.len())]),
        server_hello_head = %hex::encode(&server_hello_bytes[..std::cmp::min(16, server_hello_bytes.len())]),
        client_finish_head = %hex::encode(&client_finish_bytes[..std::cmp::min(16, client_finish_bytes.len())]),
        "Transcript hash inputs"
    );

    let mut transcript = Vec::with_capacity(
        client_hello_bytes.len() + server_hello_bytes.len() + client_finish_bytes.len()
    );
    transcript.extend_from_slice(client_hello_bytes);
    transcript.extend_from_slice(server_hello_bytes);
    transcript.extend_from_slice(client_finish_bytes);

    let hash = hash_blake3(&transcript);

    debug!(
        role = %role,
        transcript_len = transcript.len(),
        transcript_hash = %hex::encode(&hash[..8]),
        "Transcript hash computed"
    );

    hash
}

// ============================================================================
// Message Framing
// ============================================================================

/// Send a length-prefixed message over QUIC send stream
///
/// Wire format: [4-byte length (big-endian)][message bytes]
async fn send_framed(send: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
    // Validate size
    if data.len() > MAX_QUIC_HANDSHAKE_MSG {
        return Err(anyhow!(
            "Message too large: {} bytes (max: {})",
            data.len(),
            MAX_QUIC_HANDSHAKE_MSG
        ));
    }

    // Send length prefix (4 bytes, big-endian / network byte order)
    let len_bytes = (data.len() as u32).to_be_bytes();
    send.write_all(&len_bytes).await
        .context("Failed to write message length")?;

    // Send message payload
    send.write_all(data).await
        .context("Failed to write message payload")?;

    Ok(())
}

/// Receive a length-prefixed message from QUIC receive stream
///
/// Wire format: [4-byte length (big-endian)][message bytes]
async fn recv_framed(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    // Read length prefix (4 bytes, big-endian)
    let mut len_bytes = [0u8; 4];
    recv.read_exact(&mut len_bytes).await
        .context("Failed to read message length")?;

    let len = u32::from_be_bytes(len_bytes) as usize;

    // Validate size (DoS protection)
    if len > MAX_QUIC_HANDSHAKE_MSG {
        return Err(anyhow!(
            "Message too large: {} bytes (max: {})",
            len,
            MAX_QUIC_HANDSHAKE_MSG
        ));
    }

    // Read message bytes
    let mut data = vec![0u8; len];
    recv.read_exact(&mut data).await
        .context("Failed to read message payload")?;

    Ok(data)
}

// ============================================================================
// Capabilities
// ============================================================================

/// Create QUIC-specific capabilities for handshake negotiation
fn create_quic_capabilities() -> HandshakeCapabilities {
    HandshakeCapabilities {
        protocols: vec!["quic".to_string()],
        max_throughput: 100_000_000, // 100 MB/s (QUIC is fast)
        max_message_size: 10_485_760, // 10 MB
        encryption_methods: vec![
            "chacha20-poly1305".to_string(),
            "aes-256-gcm".to_string(),
        ],
        pqc_capability: PqcCapability::Kyber1024Dilithium5, // Full PQC support
        dht_capable: true,
        relay_capable: true,
        storage_capacity: 0, // Negotiated separately
        web4_capable: true,
        custom_features: vec![
            "quic-pqc-v1".to_string(), // Mark this as PQC-enabled QUIC
        ],
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uhp_transcript_hash_deterministic() {
        let client_hello = b"client_hello_data";
        let server_hello = b"server_hello_data";
        let client_finish = b"client_finish_data";

        let hash1 = compute_uhp_transcript_hash(client_hello, server_hello, client_finish, "client");
        let hash2 = compute_uhp_transcript_hash(client_hello, server_hello, client_finish, "client");

        assert_eq!(hash1, hash2, "Transcript hash should be deterministic");
    }

    #[test]
    fn test_uhp_transcript_hash_changes_with_input() {
        let client_hello = b"client_hello_data";
        let server_hello = b"server_hello_data";
        let client_finish = b"client_finish_data";

        let hash1 = compute_uhp_transcript_hash(client_hello, server_hello, client_finish, "client");
        let hash2 = compute_uhp_transcript_hash(b"different", server_hello, client_finish, "client");

        assert_ne!(hash1, hash2, "Transcript hash should change with input");
    }

    #[test]
    fn test_master_key_derivation() -> Result<()> {
        let uhp_key = [0x42u8; 32];
        let pqc_secret = [0x84u8; 32];
        let transcript_hash = [0xAAu8; 32];
        let peer_node_id = [0xBBu8; 32];

        let master1 = derive_quic_master_key(&uhp_key, &pqc_secret, &transcript_hash, &peer_node_id)?;
        let master2 = derive_quic_master_key(&uhp_key, &pqc_secret, &transcript_hash, &peer_node_id)?;

        // Should be deterministic
        assert_eq!(master1, master2);

        // Should be 32 bytes
        assert_eq!(master1.len(), 32);

        // Should change if any input changes
        let master3 = derive_quic_master_key(&[0x43u8; 32], &pqc_secret, &transcript_hash, &peer_node_id)?;
        assert_ne!(master1, master3);

        Ok(())
    }

    #[test]
    fn test_quic_capabilities() {
        let caps = create_quic_capabilities();

        assert!(caps.protocols.contains(&"quic".to_string()));
        assert!(caps.pqc_capability.is_enabled());
        assert!(caps.custom_features.contains(&"quic-pqc-v1".to_string()));
    }

    // ========================================================================
    // CRITICAL SECURITY TESTS: Signature Rejection
    // ========================================================================
    //
    // These tests verify that QUIC handshake REJECTS invalid signatures.
    // If any of these fail, the identity model is compromised.
    //
    // Kyber512 Choice Documentation:
    // - Kyber512 = NIST Level 1 security (suitable for session keys)
    // - Kyber768 = NIST Level 3, Kyber1024 = NIST Level 5
    // - For ephemeral handshakes, Kyber512 is optimal: lighter, faster,
    //   works well on mobile/BLE, and provides adequate security for
    //   session bootstrapping (not long-term secrets).
    // - Upgrade to Kyber1024 only if high-value long-term secrets are introduced.
    // ========================================================================

    use crate::handshake::{ClientHello, NonceCache, HandshakeContext, HandshakeCapabilities};

    /// Helper to create test identity
    fn create_test_identity(device_name: &str) -> lib_identity::ZhtpIdentity {
        lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            device_name,
            None,
        ).expect("Failed to create test identity")
    }

    /// Test: QUIC rejects ClientHello with corrupted NodeId
    ///
    /// CRITICAL SECURITY TEST
    /// If this fails, attackers can impersonate any identity by forging NodeIds.
    #[tokio::test]
    async fn test_quic_rejects_invalid_node_id() {
        let valid_identity = create_test_identity("quic-test-peer");

        // Create ClientHello with valid identity
        let mut hello = ClientHello::new(&valid_identity, create_quic_capabilities()).unwrap();

        // Corrupt the NodeId (simulates collision attack or identity theft)
        hello.identity.node_id = lib_identity::NodeId::from_bytes([0xFF; 32]);

        // Verification MUST fail due to NodeId mismatch
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);

        let result = hello.verify_signature(&ctx);
        assert!(result.is_err(), "CRITICAL: QUIC must reject peer with invalid NodeId");

        println!("✓ QUIC correctly rejects invalid NodeId");
    }

    /// Test: QUIC rejects ClientHello with tampered DID
    ///
    /// CRITICAL SECURITY TEST
    /// If this fails, attackers can claim any DID without proper keys.
    #[tokio::test]
    async fn test_quic_rejects_tampered_did() {
        let valid_identity = create_test_identity("quic-did-test");

        // Create ClientHello with valid identity
        let mut hello = ClientHello::new(&valid_identity, create_quic_capabilities()).unwrap();

        // Tamper with DID (simulates identity theft attempt)
        hello.identity.did = "did:zhtp:attacker_fake_did_12345".to_string();

        // Verification MUST fail - signature won't match tampered DID
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);

        let result = hello.verify_signature(&ctx);
        assert!(result.is_err(), "CRITICAL: QUIC must reject peer with tampered DID");

        println!("✓ QUIC correctly rejects tampered DID");
    }

    /// Test: QUIC rejects ClientHello with zeroed signature
    ///
    /// CRITICAL SECURITY TEST
    /// If this fails, attackers can connect without valid Dilithium signatures.
    #[tokio::test]
    async fn test_quic_rejects_zeroed_signature() {
        let valid_identity = create_test_identity("quic-sig-test");

        // Create ClientHello with valid identity
        let mut hello = ClientHello::new(&valid_identity, create_quic_capabilities()).unwrap();

        // Zero out the signature (simulates no-auth attack)
        hello.signature.signature = vec![0u8; 64];

        // Verification MUST fail - signature is invalid
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);

        let result = hello.verify_signature(&ctx);
        assert!(result.is_err(), "CRITICAL: QUIC must reject peer with zeroed signature");

        println!("✓ QUIC correctly rejects zeroed signature");
    }

    /// Test: QUIC rejects ClientHello with random garbage signature
    ///
    /// CRITICAL SECURITY TEST
    /// If this fails, Dilithium signature verification is broken.
    #[tokio::test]
    async fn test_quic_rejects_random_signature() {
        let valid_identity = create_test_identity("quic-random-sig-test");

        // Create ClientHello with valid identity
        let mut hello = ClientHello::new(&valid_identity, create_quic_capabilities()).unwrap();

        // Replace with random garbage (simulates forged signature)
        let random_sig: Vec<u8> = (0..2420).map(|i| (i * 17 + 42) as u8).collect();
        hello.signature.signature = random_sig;

        // Verification MUST fail - signature is garbage
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);

        let result = hello.verify_signature(&ctx);
        assert!(result.is_err(), "CRITICAL: QUIC must reject peer with random garbage signature");

        println!("✓ QUIC correctly rejects random garbage signature");
    }

    /// Test: QUIC rejects ClientHello with wrong public key
    ///
    /// CRITICAL SECURITY TEST
    /// If this fails, attackers can substitute keys and impersonate identities.
    #[tokio::test]
    async fn test_quic_rejects_wrong_public_key() {
        let valid_identity = create_test_identity("quic-pk-test");
        let attacker_identity = create_test_identity("attacker-identity");

        // Create ClientHello with valid identity
        let mut hello = ClientHello::new(&valid_identity, create_quic_capabilities()).unwrap();

        // Substitute attacker's public key (signature won't match)
        hello.identity.public_key = attacker_identity.public_key.clone();

        // Verification MUST fail - signature was made with different key
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);

        let result = hello.verify_signature(&ctx);
        assert!(result.is_err(), "CRITICAL: QUIC must reject peer with wrong public key");

        println!("✓ QUIC correctly rejects wrong public key");
    }

    /// Test: Valid ClientHello passes verification (sanity check)
    ///
    /// Ensures the rejection tests aren't false positives.
    #[tokio::test]
    async fn test_quic_accepts_valid_client_hello() {
        let valid_identity = create_test_identity("quic-valid-test");

        // Create ClientHello with valid identity (no tampering)
        let hello = ClientHello::new(&valid_identity, create_quic_capabilities()).unwrap();

        // Verification MUST pass
        let nonce_cache = NonceCache::new_test(300, 1000);
        let ctx = HandshakeContext::new(nonce_cache);

        let result = hello.verify_signature(&ctx);
        assert!(result.is_ok(), "Valid ClientHello should pass verification: {:?}", result.err());

        println!("✓ QUIC correctly accepts valid ClientHello");
    }
}
