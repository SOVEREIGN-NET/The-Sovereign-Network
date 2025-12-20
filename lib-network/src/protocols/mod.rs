use serde::{Deserialize, Serialize};
use anyhow::Result;
use async_trait::async_trait;
use crate::types::mesh_message::MeshMessageEnvelope;
use std::net::SocketAddr;

// Bluetooth protocol suite (includes BLE mesh, Classic RFCOMM, platform-specific)
pub mod bluetooth;

// Other protocols
pub mod wifi_direct;
pub mod wifi_direct_handshake; // UHP handshake adapter for WiFi Direct
pub mod lorawan;
pub mod satellite;
pub mod zhtp_auth;
pub mod zhtp_encryption;
pub mod quic_mesh;           // QUIC transport with PQC encryption
pub mod quic_handshake;      // UHP handshake adapter for QUIC with Kyber binding
pub mod quic_api_dispatcher; // QUIC API request dispatcher for Web4 client


// Enhanced protocol implementations with platform-specific optimizations
// NOTE: enhanced_bluetooth functionality is in bluetooth/enhanced.rs, not a separate top-level module
// #[cfg(feature = "enhanced-bluetooth")]
// pub mod enhanced_bluetooth;

#[cfg(feature = "enhanced-wifi-direct")]
pub mod enhanced_wifi_direct;

/// Network protocol enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    /// Bluetooth Low Energy for device-to-device communication
    BluetoothLE,
    /// Bluetooth Classic (BR/EDR) for high-throughput mesh
    BluetoothClassic,
    /// WiFi Direct for medium-range peer connections
    WiFiDirect,
    /// LoRaWAN for long-range low-power communication
    LoRaWAN,
    /// Satellite for global coverage
    Satellite,
    /// TCP for internet bridging
    TCP,
    /// UDP for mesh networking
    UDP,
    /// QUIC for modern mesh transport (replaces TCP/UDP split)
    QUIC,
}

/// Protocol capabilities describing both performance characteristics and security posture
/// 
/// Includes traditional metrics (MTU, throughput, latency, range, power) and
/// security properties (authentication schemes, encryption ciphers, PQC support,
/// replay protection, identity binding, forward secrecy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCapabilities {
    /// Maximum Transmission Unit in bytes
    pub mtu: u16,
    /// Estimated throughput in Mbps
    pub throughput_mbps: f64,
    /// Estimated latency in milliseconds
    pub latency_ms: u32,
    /// Effective range in meters (None for global protocols like satellite)
    pub range_meters: Option<u32>,
    /// Power consumption profile
    pub power_profile: PowerProfile,
    /// Whether the protocol supports reliable delivery
    pub reliable: bool,
    /// Whether the protocol requires internet connectivity to function
    ///
    /// Semantics:
    /// - `true`: The protocol fundamentally depends on internet connectivity and cannot
    ///   operate in a purely local/offline environment (e.g., satellite backhaul or
    ///   cloud-routed services).
    /// - `false`: The protocol can operate without internet connectivity. This includes
    ///   strictly local protocols and hybrid protocols that support both local and
    ///   internet-connected operation (e.g., QUIC or TCP used on a local network).
    pub requires_internet: bool,
    
    // ============ Security Capabilities (PR #393 Review) ============
    /// Authentication schemes supported by this protocol
    pub auth_schemes: Vec<AuthScheme>,
    /// Encryption cipher suite (None if integrity-only or unauthenticated)
    pub encryption: Option<CipherSuite>,
    /// Post-quantum cryptography mode
    pub pqc_mode: PqcMode,
    /// Whether protocol provides replay protection
    pub replay_protection: bool,
    /// Whether messages are bound to authenticated peer/session
    pub identity_binding: bool,
    /// True if integrity-only (no confidentiality)
    pub integrity_only: bool,
    /// Whether protocol provides forward secrecy
    pub forward_secrecy: bool,
}

/// Power consumption profile for protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerProfile {
    /// Ultra-low power (< 10mW average)
    UltraLow,
    /// Low power (10-100mW)
    Low,
    /// Medium power (100mW-1W)
    Medium,
    /// High power (1W-10W)
    High,
    /// Very high power (> 10W)
    VeryHigh,
}

/// Authentication scheme supported by a protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthScheme {
    /// No authentication
    Unauthenticated,
    /// Pre-shared key authentication
    PreSharedKey,
    /// Mutual handshake with identity verification (e.g., UHP)
    MutualHandshake,
    /// Certificate-based authentication
    Certificate,
    /// Post-quantum resistant mutual authentication using a PQC signature scheme.
    ///
    /// The concrete post-quantum algorithm is implementation-defined and selected by
    /// the underlying transport/handshake layer (for example, an ML-DSA (Dilithium)
    /// or SLH-DSA (SPHINCS+) signature scheme), rather than being fixed by this enum.
    PostQuantumMutual,
}

/// Encryption cipher suite
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// No encryption (plaintext transport; integrity-only or fully unprotected)
    Plaintext,
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// Kyber-768 + AES-256-GCM (hybrid PQC)
    KyberAes256,
    /// Kyber-1024 + ChaCha20 (hybrid PQC)
    KyberChaCha20,
    /// Full post-quantum encryption (future)
    FullPostQuantum,
}

/// Post-quantum cryptography mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcMode {
    /// No post-quantum protection
    None,
    /// Hybrid classical + PQC (Kyber KEM + classical AEAD)
    Hybrid,
    /// Full post-quantum (future)
    FullPqc,
}

/// Peer address for protocol-agnostic addressing
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerAddress {
    /// Bluetooth MAC address (6 bytes)
    Bluetooth([u8; 6]),
    /// IP address and port
    IpSocket(SocketAddr),
    /// Device ID (DID or similar identifier)
    DeviceId(String),
    /// LoRaWAN device address
    LoRaDevAddr(u32),
    /// Satellite endpoint identifier
    SatelliteId(String),
    /// Custom protocol-specific address
    Custom(String),
}

/// Protocol session representing an authenticated/encrypted connection
/// 
/// Sessions bind messages to a specific peer identity with cryptographic keys,
/// replay protection, and protocol-specific state.
#[derive(Debug, Clone)]
pub struct ProtocolSession {
    /// Unique session identifier
    pub session_id: String,
    /// Peer address for this session
    pub peer_address: PeerAddress,
    /// Authenticated peer identity (DID, public key hash, etc.)
    pub peer_identity: Option<String>,
    /// Protocol type for this session
    pub protocol: NetworkProtocol,
    /// Session encryption keys (opaque, protocol-specific)
    pub session_keys: Option<Vec<u8>>,
    /// Replay protection state (sequence numbers, nonces, etc.)
    pub replay_state: Option<Vec<u8>>,
    /// Authentication scheme used for this session
    pub auth_scheme: AuthScheme,
    /// Cipher suite used for this session
    pub cipher_suite: CipherSuite,
    /// Session creation timestamp (Unix epoch seconds)
    pub created_at: u64,
    /// Last activity timestamp (Unix epoch seconds)
    pub last_activity: u64,
}

/// Unified protocol trait for all mesh network transports
/// 
/// All protocols (BLE, WiFi Direct, LoRaWAN, QUIC, Satellite, Bluetooth Classic)
/// implement this trait to provide a consistent interface for message transmission.
/// 
/// # Security Model (PR #393 Review)
/// 
/// Protocols now expose session-aware APIs with explicit authentication and encryption:
/// - `connect()` / `accept()` establish authenticated sessions with peer identity binding
/// - `send_message()` and `receive_message()` operate on sessions with cryptographic guarantees
/// - `capabilities()` includes security posture for transport selection
/// 
/// # Example
/// ```no_run
/// use lib_network::protocols::{Protocol, PeerAddress};
/// use lib_network::types::mesh_message::MeshMessageEnvelope;
/// 
/// async fn secure_send<P: Protocol>(
///     protocol: &mut P,
///     target: PeerAddress,
///     envelope: &MeshMessageEnvelope
/// ) -> anyhow::Result<()> {
///     // Establish authenticated session
///     let session = protocol.connect(&target).await?;
///     
///     // Send encrypted message bound to peer identity
///     protocol.send_message(&session, envelope).await?;
///     
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Initiate connection and perform handshake with a peer
    /// 
    /// Establishes an authenticated, encrypted session with the target peer.
    /// This includes:
    /// - Peer identity verification (mutual auth if supported)
    /// - Key exchange (PQC-hybrid or classical)
    /// - Replay protection initialization
    /// 
    /// # Arguments
    /// * `target` - Typed peer address (Bluetooth MAC, IP, device ID, etc.)
    /// 
    /// # Returns
    /// * `Ok(ProtocolSession)` with peer identity, session keys, and security state
    /// * `Err(...)` if connection/handshake failed
    async fn connect(&mut self, target: &PeerAddress) -> Result<ProtocolSession>;
    
    /// Accept incoming connection and perform handshake
    /// 
    /// Listens for and accepts an incoming connection request, performing
    /// authentication and key exchange.
    /// 
    /// # Returns
    /// * `Ok(ProtocolSession)` with authenticated peer identity and session keys
    /// * `Err(...)` if no connection available or handshake failed
    async fn accept(&mut self) -> Result<ProtocolSession>;
    
    /// Send a mesh message over an established session
    /// 
    /// Messages are encrypted and bound to the session's peer identity.
    /// Replay protection is enforced via session state.
    /// 
    /// # Arguments
    /// * `session` - Active session with peer identity and cryptographic keys
    /// * `envelope` - The message envelope containing routing and payload data
    /// 
    /// # Returns
    /// * `Ok(())` if message was successfully transmitted (or queued)
    /// * `Err(...)` if transmission failed or session is invalid
    async fn send_message(
        &self,
        session: &ProtocolSession,
        envelope: &MeshMessageEnvelope,
    ) -> Result<()>;
    
    /// Receive a mesh message from an established session
    /// 
    /// Blocks until a message is available or timeout occurs.
    /// Messages are decrypted and replay protection is verified.
    /// 
    /// # Arguments
    /// * `session` - Active session to receive from
    /// 
    /// # Returns
    /// * `Ok(MeshMessageEnvelope)` if message received and verified
    /// * `Err(...)` if receive failed, timeout, or replay attack detected
    async fn receive_message(&self, session: &ProtocolSession) -> Result<MeshMessageEnvelope>;

    /// Get the protocol's technical capabilities
    /// 
    /// Returns characteristics like MTU, throughput, latency, range, power consumption,
    /// and security posture (auth schemes, encryption, PQC mode, etc.).
    fn capabilities(&self) -> ProtocolCapabilities;

    /// Get the protocol type identifier
    fn protocol_type(&self) -> NetworkProtocol;

    /// Check if the protocol is currently available/enabled
    /// 
    /// Returns `false` if hardware is unavailable, disabled, or in error state.
    fn is_available(&self) -> bool {
        true // Default implementation - protocols can override
    }
}
