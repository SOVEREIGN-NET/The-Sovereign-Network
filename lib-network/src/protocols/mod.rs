//! Unified Protocol Trait for Mesh Network Transports
//!
//! This module defines the core `Protocol` trait and security-hardened types
//! for session management, peer addressing, and cryptographic state.
//!
//! # Security Model
//!
//! All sessions provide:
//! - Cryptographic key zeroization on drop
//! - Structured replay protection with sliding window
//! - Session lifecycle management (timeouts, rekeying)
//! - Validated peer addresses and identities
//! - Constant-time comparisons for sensitive data
//!
//! # Organization
//!
//! This module is organized as follows:
//! - `types/` - Type definitions (network, capabilities, security, peer, session)
//! - Protocol implementations for various transports (bluetooth, wifi_direct, quic_encryption, etc.)

use async_trait::async_trait;
use anyhow::Result;
use crate::types::mesh_message::MeshMessageEnvelope;

// ============================================================================
// Type Definitions (organized in sub-modules)
// ============================================================================

pub mod types;

// Re-export commonly used types for convenience
pub use types::{
    NetworkProtocol, ProtocolCapabilities, PowerProfile,
    AuthScheme, UnsafeAuthScheme, CipherSuite, UnsafeCipherSuite, PqcMode,
    BluetoothMac, ValidatedSocketAddr, ValidatedDeviceId, ValidatedSatelliteId,
    PeerAddress, VerifiedPeerIdentity,
    SessionId, SessionKeys, ReplayProtectionState, SessionLifecycle,
    SessionRenewalReason, ProtocolSession,
};

// ============================================================================
// Protocol Implementations
// ============================================================================

// Bluetooth protocol suite (includes BLE mesh, Classic RFCOMM, platform-specific)
pub mod bluetooth;
pub mod bluetooth_encryption; // Bluetooth encryption adapter with wire format & replay protection

// Encryption adapters for various protocols
pub mod zhtp_mesh_encryption;    // ZHTP mesh encryption adapter with domain separation
pub mod wifi_direct_encryption;  // WiFi Direct encryption adapter with fallback support
pub mod quic_encryption;         // QUIC application-level encryption adapter
pub mod lorawan_encryption;      // LoRaWAN encryption adapter with frame counter domain separation

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

// ============================================================================
// Protocol Trait (with session validation and rekeying)
// ============================================================================

/// Unified protocol trait for all mesh network transports
///
/// All protocols (BLE, WiFi Direct, LoRaWAN, QUIC, Satellite, Bluetooth Classic)
/// implement this trait to provide a consistent interface for message transmission.
///
/// # Security Model
///
/// Protocols expose session-aware APIs with explicit authentication and encryption:
/// - `connect()` / `accept()` establish authenticated sessions with peer identity binding
/// - `validate_session()` prevents session hijacking (CRITICAL-3)
/// - `send_message()` and `receive_message()` operate on validated sessions
/// - `rekey_session()` maintains forward secrecy (HIGH-4)
/// - `capabilities()` includes security posture for transport selection
///
/// # Security Events
///
/// Implementations MUST log the following security events:
/// - Authentication failures (with peer address, NOT credentials)
/// - Replay attack detection (sequence number, session ID)
/// - Session expiration/timeout
/// - Cryptographic errors (algorithm, error type)
///
/// # Example
/// ```ignore
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
///     // Validate session before use
///     protocol.validate_session(&session)?;
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

    /// Validate that a session is valid and belongs to this protocol instance
    ///
    /// CRITICAL: Call this before every send/receive operation to prevent
    /// session hijacking attacks.
    ///
    /// # Security
    /// - Validates session MAC (constant-time comparison)
    /// - Checks session lifecycle (expiration, idle timeout, message count)
    /// - Verifies session belongs to this protocol instance
    fn validate_session(&self, session: &ProtocolSession) -> Result<()>;

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
    ///
    /// # Security
    /// - Session is validated before sending
    /// - Message is encrypted with session keys
    /// - Sequence number is included for replay protection
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
    ///
    /// # Security
    /// - Session is validated before receiving
    /// - Message is decrypted with session keys
    /// - Sequence number is validated for replay protection
    async fn receive_message(&self, session: &ProtocolSession) -> Result<MeshMessageEnvelope>;

    /// Rekey an existing session (HIGH-4: Forward secrecy maintenance)
    ///
    /// Establishes new ephemeral keys while maintaining the session.
    /// Required for maintaining forward secrecy in long-lived sessions.
    ///
    /// # Arguments
    /// * `session` - Session to rekey (mutably borrowed)
    ///
    /// # Returns
    /// * `Ok(())` if rekeying succeeded
    /// * `Err(...)` if rekeying failed (session should be terminated)
    ///
    /// # Security
    /// - New ephemeral key exchange is performed
    /// - Old keys are zeroized
    /// - Replay state is reset
    /// - Rekey generation counter is incremented
    async fn rekey_session(&mut self, session: &mut ProtocolSession) -> Result<()>;

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

// ============================================================================
// Tests (moved from old mod.rs)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generation() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();

        assert!(!id1.ct_eq(&id2));
        assert!(!id1.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_session_id_constant_time_eq() {
        let id1 = SessionId::from_bytes([1u8; 32]);
        let id2 = SessionId::from_bytes([1u8; 32]);
        let id3 = SessionId::from_bytes([2u8; 32]);

        assert!(id1.ct_eq(&id2));
        assert!(!id1.ct_eq(&id3));
    }

    #[test]
    fn test_bluetooth_mac_validation() {
        assert!(BluetoothMac::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]).is_ok());
        assert!(BluetoothMac::new([0xFF; 6]).is_err());
        assert!(BluetoothMac::new([0x00; 6]).is_err());
    }

    #[test]
    fn test_validated_socket_addr() {
        use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

        let valid = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert!(ValidatedSocketAddr::new(valid).is_ok());

        let unspec = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
        assert!(ValidatedSocketAddr::new(unspec).is_err());

        let port0 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 0);
        assert!(ValidatedSocketAddr::new(port0).is_err());
    }

    #[test]
    fn test_device_id_validation() {
        assert!(ValidatedDeviceId::new("device-123".to_string()).is_ok());
        assert!(ValidatedDeviceId::new("AA:BB:CC:DD".to_string()).is_ok());
        assert!(ValidatedDeviceId::new("".to_string()).is_err());

        let long_id = "a".repeat(types::peer::MAX_IDENTIFIER_LENGTH + 1);
        assert!(ValidatedDeviceId::new(long_id).is_err());

        assert!(ValidatedDeviceId::new("device\ninjection".to_string()).is_err());
    }

    #[test]
    fn test_session_keys_validation() {
        let mut keys = SessionKeys::new(CipherSuite::ChaCha20Poly1305, true);
        assert!(keys.set_encryption_key([1u8; 32]).is_ok());

        let mut keys2 = SessionKeys::new(CipherSuite::Aes256Gcm, true);
        assert!(keys2.set_encryption_key([0u8; 32]).is_err());
    }

    #[test]
    fn test_replay_protection() {
        let state = ReplayProtectionState::new(64);

        assert!(state.validate_recv_sequence(0).is_ok());
        assert!(state.validate_recv_sequence(0).is_err());
        assert!(state.validate_recv_sequence(1).is_ok());
        assert!(state.validate_recv_sequence(100).is_ok());
        assert!(state.validate_recv_sequence(0).is_err());
    }

    #[test]
    fn test_session_lifecycle() {
        let lifecycle = SessionLifecycle::with_settings(60, 30, Some(100));

        assert_eq!(lifecycle.needs_renewal(), SessionRenewalReason::None);

        lifecycle.touch();
        assert_eq!(lifecycle.message_count(), 1);
    }

    #[test]
    fn test_cipher_suite_key_sizes() {
        assert_eq!(CipherSuite::Aes256Gcm.key_size(), 32);
        assert_eq!(CipherSuite::ChaCha20Poly1305.key_size(), 32);
        assert_eq!(CipherSuite::KyberChaCha20.key_size(), 32);
    }
}

use std::net::SocketAddr;
