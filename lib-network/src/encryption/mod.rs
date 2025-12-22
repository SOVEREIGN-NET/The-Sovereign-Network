//! Unified Protocol Encryption Module
//!
//! Provides consistent encryption across all mesh protocols (WiFi Direct, LoRaWAN, QUIC, Bluetooth, etc.)
//!
//! # Architecture
//!
//! All protocols use **ChaCha20Poly1305 AEAD** for symmetric encryption:
//! - **LoRaWAN**: ChaCha20Poly1305 (replaces insecure XOR)
//! - **WiFi Direct**: WPA2/3 + ChaCha20Poly1305 app-layer
//! - **QUIC**: TLS 1.3 + UHP + Kyber512 + ChaCha20Poly1305
//! - **Bluetooth**: ChaCha20Poly1305 over BLE
//! - **ZHTP Mesh**: Kyber512 + ChaCha20Poly1305
//!
//! # Security Properties
//!
//! - **AEAD (Authenticated Encryption with Associated Data)**: Provides both confidentiality and authenticity
//! - **Nonce Management**: 96-bit random nonces generated per message (collision probability ~2^-96)
//! - **Post-Quantum Ready**: Can be combined with Kyber KEM for PQC key exchange
//! - **Performance**: ChaCha20 is faster than AES on devices without hardware acceleration
//! - **Mobile-Optimized**: Efficient on ARM processors (phones, IoT devices)
//!
//! # Usage
//!
//! ```rust,ignore
//! use lib_network::encryption::{ProtocolEncryption, ChaCha20Poly1305Encryption, create_encryption};
//!
//! // Create encryption instance for a protocol
//! let mut enc = create_encryption("lorawan", &session_key)?;
//!
//! // Encrypt application data
//! let plaintext = b"Hello, mesh network!";
//! let ciphertext = enc.encrypt(plaintext)?;
//!
//! // Decrypt received data
//! let decrypted = enc.decrypt(&ciphertext)?;
//! assert_eq!(plaintext, &decrypted[..]);
//!
//! // Check encryption stats
//! println!("Encrypted {} messages", enc.stats().messages_encrypted);
//! ```
//!
//! # Protocol-Specific Considerations
//!
//! ## LoRaWAN
//! - Replaces insecure XOR "encryption" with ChaCha20Poly1305
//! - Maintains LoRaWAN frame format (MHDR, FHDR, encrypted payload, MIC)
//! - MIC derived from BLAKE3 hash (4-byte truncation) for frame authenticity
//! - Key derived from node_id (32 bytes) during OTAA join
//!
//! ## WiFi Direct
//! - **Link Layer**: WPA2/3 (PSK or Enterprise) - managed by OS
//! - **App Layer**: ChaCha20Poly1305 using session key from UHP handshake
//! - Dual-layer security: prevents rogue AP attacks and provides E2E encryption
//! - Falls back to WPA2/3-only if UHP handshake fails
//!
//! ## QUIC
//! - **Transport**: TLS 1.3 (built into Quinn QUIC implementation)
//! - **Authentication**: UHP (Unified Handshake Protocol) with Dilithium signatures
//! - **PQC Key Exchange**: Kyber512 KEM bound to UHP transcript
//! - **Master Key Derivation**: HKDF(uhp_session_key || kyber_shared_secret || transcript_hash || peer_node_id)
//! - NOT triple encryption - layered security with single derived master key
//!
//! ## Bluetooth LE
//! - BLE link encryption (AES-CCM) managed by Bluetooth stack
//! - ChaCha20Poly1305 app-layer for E2E security
//!
//! # Security Fixes
//!
//! **CRITICAL FIX**: LoRaWAN XOR Encryption Replacement
//! - **Previous**: Simple XOR with app_key (easily broken with known-plaintext)
//! - **Current**: ChaCha20Poly1305 AEAD (industry-standard, IND-CCA2 secure)
//! - **Impact**: Prevents eavesdropping on LoRaWAN mesh communications
//!
//! # Performance
//!
//! ChaCha20Poly1305 performance (typical ARM Cortex-A53):
//! - Encryption: ~200 MB/s
//! - Decryption: ~200 MB/s
//! - Latency: < 1ms for typical mesh messages (< 1KB)
//!
//! Suitable for all mesh protocols including low-power LoRaWAN devices.

use anyhow::{Result, Context as AnyhowContext};
use lib_crypto::symmetric::chacha20::{encrypt_data, decrypt_data};
use serde::{Serialize, Deserialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

// ============================================================================
// Unified Protocol Encryption Trait
// ============================================================================

/// Unified encryption interface for all mesh protocols
///
/// Provides consistent API across WiFi Direct, LoRaWAN, QUIC, Bluetooth, etc.
pub trait ProtocolEncryption: Send + Sync {
    /// Encrypt plaintext using protocol-specific encryption
    ///
    /// # Arguments
    /// - `plaintext`: Data to encrypt (arbitrary length)
    ///
    /// # Returns
    /// - Ciphertext with embedded nonce and authentication tag
    ///
    /// # Errors
    /// - Returns error if encryption fails (e.g., invalid key)
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using protocol-specific decryption
    ///
    /// # Arguments
    /// - `ciphertext`: Encrypted data (from `encrypt()`)
    ///
    /// # Returns
    /// - Original plaintext
    ///
    /// # Errors
    /// - Returns error if authentication fails or ciphertext is corrupted
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Get protocol name (e.g., "lorawan", "wifi_direct", "quic")
    fn protocol(&self) -> &str;

    /// Get encryption statistics
    fn stats(&self) -> EncryptionStats;

    /// Reset statistics (for testing/monitoring)
    fn reset_stats(&mut self);
}

// ============================================================================
// Encryption Statistics
// ============================================================================

/// Encryption statistics for monitoring and debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionStats {
    /// Protocol name
    pub protocol: String,
    /// Total messages encrypted
    pub messages_encrypted: u64,
    /// Total messages decrypted
    pub messages_decrypted: u64,
    /// Total bytes encrypted
    pub bytes_encrypted: u64,
    /// Total bytes decrypted
    pub bytes_decrypted: u64,
    /// Encryption failures (should be 0 in normal operation)
    pub encryption_failures: u64,
    /// Decryption failures (non-zero indicates potential attacks or corruption)
    pub decryption_failures: u64,
}

impl Default for EncryptionStats {
    fn default() -> Self {
        Self {
            protocol: String::new(),
            messages_encrypted: 0,
            messages_decrypted: 0,
            bytes_encrypted: 0,
            bytes_decrypted: 0,
            encryption_failures: 0,
            decryption_failures: 0,
        }
    }
}

// ============================================================================
// ChaCha20Poly1305 Implementation (Standard for All Protocols)
// ============================================================================

/// ChaCha20Poly1305 encryption implementation
///
/// Used by all protocols for consistent security and performance.
/// Wraps lib-crypto's ChaCha20Poly1305 with statistics and error handling.
pub struct ChaCha20Poly1305Encryption {
    /// Protocol identifier (e.g., "lorawan", "wifi_direct")
    protocol: String,
    /// Encryption key (32 bytes)
    key: [u8; 32],
    /// Statistics (atomic for thread-safety)
    stats: Arc<EncryptionStatsAtomic>,
}

/// Atomic statistics for thread-safe updates
struct EncryptionStatsAtomic {
    messages_encrypted: AtomicU64,
    messages_decrypted: AtomicU64,
    bytes_encrypted: AtomicU64,
    bytes_decrypted: AtomicU64,
    encryption_failures: AtomicU64,
    decryption_failures: AtomicU64,
}

impl EncryptionStatsAtomic {
    fn new() -> Self {
        Self {
            messages_encrypted: AtomicU64::new(0),
            messages_decrypted: AtomicU64::new(0),
            bytes_encrypted: AtomicU64::new(0),
            bytes_decrypted: AtomicU64::new(0),
            encryption_failures: AtomicU64::new(0),
            decryption_failures: AtomicU64::new(0),
        }
    }

    fn to_stats(&self, protocol: String) -> EncryptionStats {
        EncryptionStats {
            protocol,
            messages_encrypted: self.messages_encrypted.load(Ordering::Relaxed),
            messages_decrypted: self.messages_decrypted.load(Ordering::Relaxed),
            bytes_encrypted: self.bytes_encrypted.load(Ordering::Relaxed),
            bytes_decrypted: self.bytes_decrypted.load(Ordering::Relaxed),
            encryption_failures: self.encryption_failures.load(Ordering::Relaxed),
            decryption_failures: self.decryption_failures.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.messages_encrypted.store(0, Ordering::Relaxed);
        self.messages_decrypted.store(0, Ordering::Relaxed);
        self.bytes_encrypted.store(0, Ordering::Relaxed);
        self.bytes_decrypted.store(0, Ordering::Relaxed);
        self.encryption_failures.store(0, Ordering::Relaxed);
        self.decryption_failures.store(0, Ordering::Relaxed);
    }
}

impl ChaCha20Poly1305Encryption {
    /// Create new ChaCha20Poly1305 encryption instance
    ///
    /// # Arguments
    /// - `protocol`: Protocol name (e.g., "lorawan", "wifi_direct", "quic")
    /// - `key`: 32-byte encryption key (from key exchange or derivation)
    ///
    /// # Returns
    /// - New encryption instance
    ///
    /// # Errors
    /// - Returns error if key length is not 32 bytes
    pub fn new(protocol: impl Into<String>, key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!(
                "ChaCha20Poly1305 requires 32-byte key, got {} bytes",
                key.len()
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);

        Ok(Self {
            protocol: protocol.into(),
            key: key_array,
            stats: Arc::new(EncryptionStatsAtomic::new()),
        })
    }

    /// Get protocol name
    pub fn protocol_name(&self) -> &str {
        &self.protocol
    }
}

impl ProtocolEncryption for ChaCha20Poly1305Encryption {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        debug!(
            protocol = %self.protocol,
            plaintext_len = plaintext.len(),
            "Encrypting with ChaCha20Poly1305"
        );

        match encrypt_data(plaintext, &self.key) {
            Ok(ciphertext) => {
                // Update statistics
                self.stats.messages_encrypted.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_encrypted.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

                debug!(
                    protocol = %self.protocol,
                    ciphertext_len = ciphertext.len(),
                    "Encryption successful"
                );

                Ok(ciphertext)
            }
            Err(e) => {
                self.stats.encryption_failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    protocol = %self.protocol,
                    error = %e,
                    "Encryption failed"
                );
                Err(e).context("ChaCha20Poly1305 encryption failed")
            }
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        debug!(
            protocol = %self.protocol,
            ciphertext_len = ciphertext.len(),
            "Decrypting with ChaCha20Poly1305"
        );

        match decrypt_data(ciphertext, &self.key) {
            Ok(plaintext) => {
                // Update statistics
                self.stats.messages_decrypted.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_decrypted.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

                debug!(
                    protocol = %self.protocol,
                    plaintext_len = plaintext.len(),
                    "Decryption successful"
                );

                Ok(plaintext)
            }
            Err(e) => {
                self.stats.decryption_failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    protocol = %self.protocol,
                    error = %e,
                    "Decryption failed (possible attack or corruption)"
                );
                Err(e).context("ChaCha20Poly1305 decryption failed")
            }
        }
    }

    fn protocol(&self) -> &str {
        &self.protocol
    }

    fn stats(&self) -> EncryptionStats {
        self.stats.to_stats(self.protocol.clone())
    }

    fn reset_stats(&mut self) {
        self.stats.reset();
    }
}

// ============================================================================
// Factory Function
// ============================================================================

/// Create encryption instance for a protocol
///
/// # Arguments
/// - `protocol`: Protocol name ("lorawan", "wifi_direct", "quic", "bluetooth", "zhtp")
/// - `key`: 32-byte encryption key
///
/// # Returns
/// - Boxed encryption instance implementing ProtocolEncryption trait
///
/// # Example
///
/// ```rust,ignore
/// let key = [0u8; 32]; // In practice, use proper key derivation
/// let mut enc = create_encryption("lorawan", &key)?;
/// let ciphertext = enc.encrypt(b"test message")?;
/// ```
pub fn create_encryption(protocol: &str, key: &[u8]) -> Result<Box<dyn ProtocolEncryption>> {
    debug!(
        protocol = protocol,
        key_len = key.len(),
        "Creating encryption instance"
    );

    // All protocols use ChaCha20Poly1305 for consistency
    let encryption = ChaCha20Poly1305Encryption::new(protocol, key)?;
    Ok(Box::new(encryption))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key() -> [u8; 32] {
        // Deterministic key for testing
        [0x42u8; 32]
    }

    #[test]
    fn test_basic_encryption_decryption() {
        let key = create_test_key();
        let mut enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

        let plaintext = b"Hello, mesh network!";
        let ciphertext = enc.encrypt(plaintext).unwrap();

        // Ciphertext should be longer (includes nonce + tag)
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = enc.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_lorawan_encryption() {
        let key = create_test_key();
        let mut enc = create_encryption("lorawan", &key).unwrap();

        let payload = b"LoRaWAN mesh data";
        let encrypted = enc.encrypt(payload).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        assert_eq!(payload, &decrypted[..]);
        assert_eq!(enc.protocol(), "lorawan");
    }

    #[test]
    fn test_wifi_direct_encryption() {
        let key = create_test_key();
        let mut enc = create_encryption("wifi_direct", &key).unwrap();

        let message = b"WiFi Direct P2P message";
        let encrypted = enc.encrypt(message).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        assert_eq!(message, &decrypted[..]);
        assert_eq!(enc.protocol(), "wifi_direct");
    }

    #[test]
    fn test_quic_encryption() {
        let key = create_test_key();
        let mut enc = create_encryption("quic", &key).unwrap();

        let data = b"QUIC mesh transport data";
        let encrypted = enc.encrypt(data).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        assert_eq!(data, &decrypted[..]);
        assert_eq!(enc.protocol(), "quic");
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0u8; 16];
        let result = ChaCha20Poly1305Encryption::new("test", &short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decryption_with_wrong_key() {
        let key1 = create_test_key();
        let mut key2 = create_test_key();
        key2[0] ^= 0xFF; // Flip bits to create different key

        let mut enc1 = ChaCha20Poly1305Encryption::new("test", &key1).unwrap();
        let mut enc2 = ChaCha20Poly1305Encryption::new("test", &key2).unwrap();

        let plaintext = b"Secret message";
        let ciphertext = enc1.encrypt(plaintext).unwrap();

        // Decryption with wrong key should fail
        let result = enc2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_statistics() {
        let key = create_test_key();
        let mut enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

        // Initial stats should be zero
        let stats = enc.stats();
        assert_eq!(stats.messages_encrypted, 0);
        assert_eq!(stats.messages_decrypted, 0);

        // Encrypt some messages
        let plaintext = b"Test message";
        for _ in 0..5 {
            let ciphertext = enc.encrypt(plaintext).unwrap();
            enc.decrypt(&ciphertext).unwrap();
        }

        // Check stats updated
        let stats = enc.stats();
        assert_eq!(stats.messages_encrypted, 5);
        assert_eq!(stats.messages_decrypted, 5);
        assert_eq!(stats.bytes_encrypted, 5 * plaintext.len() as u64);
        assert_eq!(stats.bytes_decrypted, 5 * plaintext.len() as u64);
        assert_eq!(stats.encryption_failures, 0);
        assert_eq!(stats.decryption_failures, 0);

        // Reset stats
        enc.reset_stats();
        let stats = enc.stats();
        assert_eq!(stats.messages_encrypted, 0);
    }

    #[test]
    fn test_large_payload() {
        let key = create_test_key();
        let mut enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

        // Test with 1MB payload
        let large_payload = vec![0x55u8; 1024 * 1024];
        let encrypted = enc.encrypt(&large_payload).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        assert_eq!(large_payload, decrypted);
    }

    #[test]
    fn test_empty_payload() {
        let key = create_test_key();
        let mut enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

        let empty = b"";
        let encrypted = enc.encrypt(empty).unwrap();

        // Even empty payload gets nonce + tag
        assert!(encrypted.len() > 0);

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(empty, &decrypted[..]);
    }

    #[test]
    fn test_protocol_identifier() {
        let key = create_test_key();
        let enc = ChaCha20Poly1305Encryption::new("lorawan", &key).unwrap();
        assert_eq!(enc.protocol_name(), "lorawan");

        let enc = ChaCha20Poly1305Encryption::new("wifi_direct", &key).unwrap();
        assert_eq!(enc.protocol_name(), "wifi_direct");
    }

    #[test]
    fn test_different_nonces() {
        let key = create_test_key();
        let mut enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

        let plaintext = b"Same message";
        
        // Encrypt same plaintext multiple times
        let ciphertext1 = enc.encrypt(plaintext).unwrap();
        let ciphertext2 = enc.encrypt(plaintext).unwrap();
        let ciphertext3 = enc.encrypt(plaintext).unwrap();

        // Ciphertexts should be different (different nonces)
        assert_ne!(ciphertext1, ciphertext2);
        assert_ne!(ciphertext2, ciphertext3);
        assert_ne!(ciphertext1, ciphertext3);

        // But all should decrypt to same plaintext
        assert_eq!(enc.decrypt(&ciphertext1).unwrap(), plaintext);
        assert_eq!(enc.decrypt(&ciphertext2).unwrap(), plaintext);
        assert_eq!(enc.decrypt(&ciphertext3).unwrap(), plaintext);
    }
}
