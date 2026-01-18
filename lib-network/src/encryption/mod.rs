//! Unified Protocol Encryption Module
//!
//! Provides consistent encryption across all mesh protocols (WiFi Direct, LoRaWAN, QUIC, Bluetooth, etc.)
//!
//! # Architecture: Functional Core / Imperative Shell (FCIS)
//!
//! This module separates cryptographic concerns from operational concerns using sub-modules:
//!
//! ## Functional Core (`core` sub-module)
//!
//! Functions: `core::encrypt_core()`, `core::decrypt_core()`
//!
//! - **No side effects**: No logging, stats, I/O, or state mutation
//! - **Deterministic**: Same inputs always produce predictable results
//! - **Auditable**: Security-critical code path isolated and easy to review
//! - **Testable**: Can be tested in isolation without observability overhead
//! - **Composable**: Can be wrapped by different shells (logging, metrics, etc.)
//!
//! Security properties:
//! - **Confidentiality**: ChaCha20 stream cipher (256-bit key, 96-bit random nonce)
//! - **Authenticity**: Poly1305 AEAD tag (detects tampering and corruption)
//! - **Domain Separation**: Associated Authenticated Data (AAD) prevents cross-protocol attacks
//! - **Nonce**: Randomly generated per message (collision probability ~2^-96 for < 2^48 messages)
//!
//! ## Imperative Shell (`shell` sub-module)
//!
//! Trait impl: `shell::ProtocolEncryption for shell::ChaCha20Poly1305Encryption`
//!
//! Wraps the functional core with:
//! - **Logging**: Debug/warn logs for troubleshooting
//! - **Statistics**: Atomic counters for messages encrypted/decrypted, bytes, failures
//! - **Error Context**: Enhanced error messages with protocol name and details
//! - **Thread-Safety**: Uses atomic operations for stats (no locks needed)
//!
//! Test Structure:
//! - **Core tests** (4): Verify pure crypto without shell overhead
//! - **Shell tests** (11): Verify trait impl with stats and logging
//! - **Security tests** (4): Verify attack resistance and invariants
//!
//! ## Module Organization
//!
//! ```text
//! lib-network/src/encryption/
//!   mod.rs
//!     ├── [Trait definitions - public API]
//!     ├── [Statistics structures]
//!     ├── mod core
//!     │   ├── encrypt_core() - pure crypto
//!     │   ├── decrypt_core() - pure crypto
//!     │   └── tests
//!     └── mod shell
//!         ├── ChaCha20Poly1305Encryption struct
//!         ├── ProtocolEncryption impl
//!         ├── factory functions
//!         └── tests
//! ```
//!
//! Benefits of FCIS with sub-modules:
//! 1. **Auditability**: Crypto logic is pure and in one place (core sub-module)
//! 2. **Testability**: Core can be tested separately from observability
//! 3. **Maintainability**: Clear separation of concerns
//! 4. **Flexibility**: Easy to add new shells without changing core
//! 5. **Security**: Reduced surface area for bugs in security-critical code
//! 6. **Module Safety**: Can enforce `#![forbid(unsafe_code)]` on core module
//!
//! # Architecture
//!
//! All protocols use **ChaCha20Poly1305 AEAD** for symmetric encryption:
//! - **LoRaWAN**: ChaCha20Poly1305 (replaces insecure XOR)
//! - **WiFi Direct**: WPA2/3 + ChaCha20Poly1305 app-layer
//! - **QUIC**: TLS 1.3 + UHP v2 + ChaCha20Poly1305
//! - **Bluetooth**: ChaCha20Poly1305 over BLE
//! - **ZHTP Mesh**: Kyber1024 + ChaCha20Poly1305
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
//! let enc = create_encryption("lorawan", &session_key)?;
//!
//! // Encrypt application data with domain separation AAD
//! let plaintext = b"Hello, mesh network!";
//! let aad = b"lorawan||v1";
//! let ciphertext = enc.encrypt(plaintext, aad)?;
//!
//! // Decrypt received data
//! let decrypted = enc.decrypt(&ciphertext, aad)?;
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
//! - **PQC Key Exchange**: Kyber1024 KEM bound to UHP v2 transcript
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

use anyhow::{Result, Context};
use lib_crypto::symmetric::chacha20::{encrypt_data_with_ad, decrypt_data_with_ad};
use serde::{Serialize, Deserialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

// ============================================================================
// Unified Protocol Encryption Trait (Public API)
// ============================================================================

/// Unified encryption interface for all mesh protocols
///
/// Provides consistent API across WiFi Direct, LoRaWAN, QUIC, Bluetooth, etc.
///
/// # Design Notes
///
/// - **Stateless Design**: Uses `&self` (not `&mut self`) for thread-safe access without locks
/// - **AAD Support**: Includes Associated Authenticated Data for domain separation between protocols
/// - **Atomic Stats**: Statistics updated via atomic operations (thread-safe)
pub trait ProtocolEncryption: Send + Sync {
    /// Encrypt plaintext using protocol-specific encryption with domain separation
    ///
    /// # Arguments
    /// - `plaintext`: Data to encrypt (arbitrary length)
    /// - `aad`: Associated Authenticated Data for domain separation
    ///   (prevents cross-protocol ciphertext transplant attacks)
    ///
    /// # Returns
    /// - Ciphertext with embedded nonce and authentication tag
    ///
    /// # Errors
    /// - Returns error if encryption fails (e.g., invalid key)
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using protocol-specific decryption with domain separation
    ///
    /// # Arguments
    /// - `ciphertext`: Encrypted data (from `encrypt()`)
    /// - `aad`: Associated Authenticated Data (must match encryption AAD)
    ///
    /// # Returns
    /// - Original plaintext
    ///
    /// # Errors
    /// - Returns error if authentication fails, AAD mismatch, or ciphertext is corrupted
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Get protocol name (e.g., "lorawan", "wifi_direct", "quic")
    fn protocol(&self) -> &str;

    /// Get encryption statistics
    fn stats(&self) -> EncryptionStats;

    /// Reset statistics (for testing/monitoring)
    fn reset_stats(&mut self);
}

// ============================================================================
// Encryption Statistics (Public API)
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
// FUNCTIONAL CORE: Pure Cryptography (No Side Effects)
// ============================================================================
//
// This module contains security-critical cryptographic operations.
// It has no side effects (no logging, stats, or I/O), making it:
// - Auditable: Security logic is isolated
// - Testable: Can be tested without observability overhead
// - Verifiable: Can be formally verified
//
mod core {
    use super::*;

    /// Pure encryption without side effects
    ///
    /// FUNCTIONAL CORE: This is the security-critical code path.
    /// No logging, stats, or other side effects.
    ///
    /// # Arguments
    /// - `plaintext`: Data to encrypt
    /// - `key`: 32-byte encryption key
    /// - `aad`: Associated Authenticated Data for domain separation
    ///
    /// # Returns
    /// - Ciphertext with embedded nonce and authentication tag
    ///
    /// # Security Properties
    /// - **Confidentiality**: ChaCha20 stream cipher
    /// - **Authenticity**: Poly1305 AEAD tag
    /// - **Domain Separation**: AAD prevents cross-protocol attacks
    /// - **Nonce**: Randomly generated 96-bit nonce (no collision risk for < 2^48 messages)
    #[inline]
    pub fn encrypt_core(plaintext: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        encrypt_data_with_ad(plaintext, key, aad)
    }

    /// Pure decryption without side effects
    ///
    /// FUNCTIONAL CORE: This is the security-critical code path.
    /// No logging, stats, or other side effects.
    ///
    /// # Arguments
    /// - `ciphertext`: Encrypted data (including embedded nonce)
    /// - `key`: 32-byte encryption key
    /// - `aad`: Associated Authenticated Data (must match encryption AAD)
    ///
    /// # Returns
    /// - Plaintext
    ///
    /// # Errors
    /// - If authentication fails (AEAD tag verification failed)
    /// - If ciphertext is corrupted
    /// - If AAD doesn't match
    ///
    /// # Security Properties
    /// - **Authenticity**: Poly1305 tag verification detects tampering
    /// - **Domain Separation**: AAD mismatch causes decryption to fail
    #[inline]
    pub fn decrypt_core(ciphertext: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        decrypt_data_with_ad(ciphertext, key, aad)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn create_test_key() -> [u8; 32] {
            [0x42u8; 32]
        }

        // ========== FUNCTIONAL CORE TESTS (Pure Crypto) ==========
        //
        // These tests verify the security-critical functional core in isolation.
        // No side effects, no stats, no logging - just pure cryptography.
        //

        #[test]
        fn test_functional_core_encrypt_decrypt() {
            let key = create_test_key();
            let plaintext = b"Pure functional core test";
            let aad = b"test||v1";

            let ciphertext = encrypt_core(plaintext, &key, aad).unwrap();
            assert!(ciphertext.len() > plaintext.len()); // Includes nonce + tag

            let decrypted = decrypt_core(&ciphertext, &key, aad).unwrap();
            assert_eq!(plaintext, &decrypted[..]);
        }

        #[test]
        fn test_functional_core_deterministic() {
            let key = create_test_key();
            let plaintext = b"Same message";
            let aad = b"test||v1";

            // Note: ChaCha20 uses random nonces, so same plaintext != same ciphertext
            // But decryption should always work
            let ct1 = encrypt_core(plaintext, &key, aad).unwrap();
            let pt1 = decrypt_core(&ct1, &key, aad).unwrap();
            assert_eq!(plaintext, &pt1[..]);

            let ct2 = encrypt_core(plaintext, &key, aad).unwrap();
            let pt2 = decrypt_core(&ct2, &key, aad).unwrap();
            assert_eq!(plaintext, &pt2[..]);
        }

        #[test]
        fn test_functional_core_aad_validation() {
            let key = create_test_key();
            let plaintext = b"AAD validation test";
            let aad1 = b"protocol1||v1";
            let aad2 = b"protocol2||v1";

            let ciphertext = encrypt_core(plaintext, &key, aad1).unwrap();

            // Core decryption fails with different AAD
            let result = decrypt_core(&ciphertext, &key, aad2);
            assert!(result.is_err(), "SECURITY: AAD mismatch must fail");
        }

        #[test]
        fn test_functional_core_authentication() {
            let key = create_test_key();
            let plaintext = b"Authentication test";
            let aad = b"test||v1";

            let mut ciphertext = encrypt_core(plaintext, &key, aad).unwrap();

            // Tamper with a byte (anywhere except the nonce prefix)
            if ciphertext.len() > 12 {
                ciphertext[12] ^= 0xFF;
            }

            let result = decrypt_core(&ciphertext, &key, aad);
            assert!(result.is_err(), "SECURITY: Tampering must be detected");
        }
    }
}

// ============================================================================
// IMPERATIVE SHELL: I/O, logging, state management
// ============================================================================
//
// This module wraps the functional core with observability:
// - Debug/warn logging
// - Statistics tracking (via atomic operations)
// - Error context enhancement
//
// The imperative shell is responsible for operational concerns, while
// delegating all cryptographic operations to the functional core.
//
mod shell {
    use super::*;

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
        fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            // SHELL: Pre-encryption logging
            debug!(
                protocol = %self.protocol,
                plaintext_len = plaintext.len(),
                aad_len = aad.len(),
                "Encrypting with ChaCha20Poly1305 AEAD"
            );

            // CORE: Pure cryptographic operation (no side effects)
            match core::encrypt_core(plaintext, &self.key, aad) {
                Ok(ciphertext) => {
                    // SHELL: Post-encryption stats tracking (atomic, thread-safe)
                    self.stats.messages_encrypted.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_encrypted.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

                    // SHELL: Post-encryption logging
                    debug!(
                        protocol = %self.protocol,
                        ciphertext_len = ciphertext.len(),
                        "Encryption successful"
                    );

                    Ok(ciphertext)
                }
                Err(e) => {
                    // SHELL: Error stats tracking
                    self.stats.encryption_failures.fetch_add(1, Ordering::Relaxed);

                    // SHELL: Error logging
                    warn!(
                        protocol = %self.protocol,
                        error = %e,
                        "Encryption failed"
                    );

                    Err(e).context("ChaCha20Poly1305 AEAD encryption failed")
                }
            }
        }

        fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            // SHELL: Pre-decryption logging
            debug!(
                protocol = %self.protocol,
                ciphertext_len = ciphertext.len(),
                aad_len = aad.len(),
                "Decrypting with ChaCha20Poly1305 AEAD"
            );

            // CORE: Pure cryptographic operation (no side effects)
            match core::decrypt_core(ciphertext, &self.key, aad) {
                Ok(plaintext) => {
                    // SHELL: Post-decryption stats tracking (atomic, thread-safe)
                    self.stats.messages_decrypted.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_decrypted.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

                    // SHELL: Post-decryption logging
                    debug!(
                        protocol = %self.protocol,
                        plaintext_len = plaintext.len(),
                        "Decryption successful"
                    );

                    Ok(plaintext)
                }
                Err(e) => {
                    // SHELL: Error stats tracking
                    self.stats.decryption_failures.fetch_add(1, Ordering::Relaxed);

                    // SHELL: Error logging
                    warn!(
                        protocol = %self.protocol,
                        error = %e,
                        "Decryption failed (possible attack, corruption, or AAD mismatch)"
                    );

                    Err(e).context("ChaCha20Poly1305 AEAD decryption failed")
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

    #[cfg(test)]
    mod tests {
        use super::*;

        fn create_test_key() -> [u8; 32] {
            [0x42u8; 32]
        }

        // ========== IMPERATIVE SHELL TESTS (with Stats/Logging) ==========
        //
        // These tests verify the trait implementation (stats tracking, error handling).
        // They test the integration of the functional core with observability.
        //

        #[test]
        fn test_basic_encryption_decryption() {
            let key = create_test_key();
            let enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

            let plaintext = b"Hello, mesh network!";
            let aad = b"test-protocol||v1";
            let ciphertext = enc.encrypt(plaintext, aad).unwrap();

            // Ciphertext should be longer (includes nonce + tag)
            assert!(ciphertext.len() > plaintext.len());

            let decrypted = enc.decrypt(&ciphertext, aad).unwrap();
            assert_eq!(plaintext, &decrypted[..]);
        }

        #[test]
        fn test_lorawan_encryption() {
            let key = create_test_key();
            let enc = ChaCha20Poly1305Encryption::new("lorawan", &key).unwrap();

            let payload = b"LoRaWAN mesh data";
            let aad = b"lorawan||v1";
            let encrypted = enc.encrypt(payload, aad).unwrap();
            let decrypted = enc.decrypt(&encrypted, aad).unwrap();

            assert_eq!(payload, &decrypted[..]);
            assert_eq!(enc.protocol(), "lorawan");
        }

        #[test]
        fn test_wifi_direct_encryption() {
            let key = create_test_key();
            let enc = ChaCha20Poly1305Encryption::new("wifi_direct", &key).unwrap();

            let message = b"WiFi Direct P2P message";
            let aad = b"wifi-direct||v1";
            let encrypted = enc.encrypt(message, aad).unwrap();
            let decrypted = enc.decrypt(&encrypted, aad).unwrap();

            assert_eq!(message, &decrypted[..]);
            assert_eq!(enc.protocol(), "wifi_direct");
        }

        #[test]
        fn test_quic_encryption() {
            let key = create_test_key();
            let enc = ChaCha20Poly1305Encryption::new("quic", &key).unwrap();

            let data = b"QUIC mesh transport data";
            let aad = b"quic||v1";
            let encrypted = enc.encrypt(data, aad).unwrap();
            let decrypted = enc.decrypt(&encrypted, aad).unwrap();

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

            let enc1 = ChaCha20Poly1305Encryption::new("test", &key1).unwrap();
            let enc2 = ChaCha20Poly1305Encryption::new("test", &key2).unwrap();

            let plaintext = b"Secret message";
            let aad = b"test||v1";
            let ciphertext = enc1.encrypt(plaintext, aad).unwrap();

            // Decryption with wrong key should fail
            let result = enc2.decrypt(&ciphertext, aad);
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
            let aad = b"test||v1";
            for _ in 0..5 {
                let ciphertext = enc.encrypt(plaintext, aad).unwrap();
                enc.decrypt(&ciphertext, aad).unwrap();
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
            let enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

            // Test with 1MB payload
            let large_payload = vec![0x55u8; 1024 * 1024];
            let aad = b"test||v1";
            let encrypted = enc.encrypt(&large_payload, aad).unwrap();
            let decrypted = enc.decrypt(&encrypted, aad).unwrap();

            assert_eq!(large_payload, decrypted);
        }

        #[test]
        fn test_empty_payload() {
            let key = create_test_key();
            let enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

            let empty = b"";
            let aad = b"test||v1";
            let encrypted = enc.encrypt(empty, aad).unwrap();

            // Even empty payload gets nonce + tag
            assert!(encrypted.len() > 0);

            let decrypted = enc.decrypt(&encrypted, aad).unwrap();
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
            let enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

            let plaintext = b"Same message";
            let aad = b"test||v1";

            // Encrypt same plaintext multiple times
            let ciphertext1 = enc.encrypt(plaintext, aad).unwrap();
            let ciphertext2 = enc.encrypt(plaintext, aad).unwrap();
            let ciphertext3 = enc.encrypt(plaintext, aad).unwrap();

            // Ciphertexts should be different (different nonces)
            assert_ne!(ciphertext1, ciphertext2);
            assert_ne!(ciphertext2, ciphertext3);
            assert_ne!(ciphertext1, ciphertext3);

            // But all should decrypt to same plaintext
            assert_eq!(enc.decrypt(&ciphertext1, aad).unwrap(), plaintext);
            assert_eq!(enc.decrypt(&ciphertext2, aad).unwrap(), plaintext);
            assert_eq!(enc.decrypt(&ciphertext3, aad).unwrap(), plaintext);
        }

        // ========== SECURITY TESTS (Functional Core) ==========
        //
        // These tests verify security properties of the functional core.
        // They test domain separation, authentication, and attack detection.
        //

        #[test]
        fn test_aad_domain_separation() {
            let key = create_test_key();
            let enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

            let message = b"Secret message";
            let aad1 = b"protocol1||v1";
            let aad2 = b"protocol2||v1";

            // Encrypt with AAD1
            let ciphertext = enc.encrypt(message, aad1).unwrap();

            // Decryption with different AAD should fail
            let result = enc.decrypt(&ciphertext, aad2);
            assert!(result.is_err(), "❌ SECURITY FAILURE: AAD mismatch should cause decryption failure");
        }

        #[test]
        fn test_corrupted_ciphertext_detection() {
            let key = create_test_key();
            let enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

            let plaintext = b"Important data";
            let aad = b"test||v1";
            let mut ciphertext = enc.encrypt(plaintext, aad).unwrap();

            // Tamper with the ciphertext (flip bit in MAC tag - last bytes)
            let len = ciphertext.len();
            if len > 0 {
                ciphertext[len - 1] ^= 0x01;
            }

            // Decryption should fail due to authentication failure
            let result = enc.decrypt(&ciphertext, aad);
            assert!(result.is_err(), "❌ SECURITY FAILURE: Tampered ciphertext should be detected");
        }

        #[test]
        fn test_cross_protocol_ciphertext_rejection() {
            let key = create_test_key();
            let enc1 = ChaCha20Poly1305Encryption::new("protocol1", &key).unwrap();
            let enc2 = ChaCha20Poly1305Encryption::new("protocol2", &key).unwrap();

            let message = b"Cross-protocol test";
            let aad1 = b"protocol1||msg||v1";
            let aad2 = b"protocol2||msg||v1";

            // Encrypt with protocol1's encryption
            let ciphertext = enc1.encrypt(message, aad1).unwrap();

            // CRITICAL TEST: protocol2 MUST FAIL to decrypt protocol1's ciphertext
            // even if they share the same key
            let result = enc2.decrypt(&ciphertext, aad2);
            assert!(
                result.is_err(),
                "❌ SECURITY FAILURE: Cross-protocol decryption should FAIL (AAD domain separation violated)"
            );
        }

        #[test]
        fn test_empty_aad() {
            let key = create_test_key();
            let enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

            let plaintext = b"Message with no AAD";
            let empty_aad = b"";

            let ciphertext = enc.encrypt(plaintext, empty_aad).unwrap();
            let decrypted = enc.decrypt(&ciphertext, empty_aad).unwrap();

            assert_eq!(plaintext, &decrypted[..]);
        }
    }
}

// ============================================================================
// Public Re-exports
// ============================================================================

pub use shell::ChaCha20Poly1305Encryption;

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
/// let enc = create_encryption("lorawan", &key)?;
/// let aad = b"lorawan||v1";
/// let ciphertext = enc.encrypt(b"test message", aad)?;
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
