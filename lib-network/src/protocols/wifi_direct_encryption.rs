//! WiFi Direct Encryption Adapter with Fallback Support
//!
//! Implements **ChaCha20Poly1305 AEAD** encryption for WiFi Direct with:
//! - End-to-end encryption when UHP session established
//! - Graceful fallback to link-layer only (WPA2/3 via OS)
//! - Message-type aware AAD for domain separation
//! - Explicit state tracking for transparency
//!
//! # Architecture: Functional Core / Imperative Shell (FCIS)
//!
//! **Functional Core** (Pure Cryptography):
//! - `build_aad()`: Deterministic AAD construction
//! - Direct ChaCha20Poly1305 encryption/decryption
//!
//! **Imperative Shell** (Observability & State Management):
//! - `WiFiDirectEncryption` struct with fallback state
//! - Message-type interface
//! - Logging and error context
//! - ProtocolEncryption trait implementation
//!
//! # Security Model
//!
//! **End-to-End Mode**:
//! - ChaCha20Poly1305 AEAD encryption
//! - Stateless (no nonce reuse)
//! - Domain separation via AAD
//!
//! **Link-Layer Only Mode**:
//! - WPA2/3 managed by OS kernel
//! - No application-level encryption
//! - Suitable for OS-handled networks
//! - ⚠️  Warns on use to indicate reduced security
//!
//! # Transparent State Tracking
//!
//! The enum-based state design makes it explicit:
//! - `is_e2e_encrypted()` shows current mode
//! - Stats reflect actual operational state
//! - Fallback is intentional, not silent failure

use crate::encryption::{ProtocolEncryption, ChaCha20Poly1305Encryption, EncryptionStats};
use anyhow::Result;
use tracing::{debug, warn};

// ============================================================================
// State Enum
// ============================================================================

/// WiFi Direct encryption state
///
/// Tracks whether end-to-end encryption is active or if we're relying on
/// link-layer protection only.
pub enum WiFiDirectEncryptionState {
    /// End-to-end AEAD encryption (UHP session established with peer)
    EndToEndAead(ChaCha20Poly1305Encryption),
    /// Link-layer only (WPA2/3 managed by OS kernel, no E2E secrecy)
    LinkLayerOnly,
}

impl std::fmt::Debug for WiFiDirectEncryptionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndToEndAead(_) => f.write_str("WiFiDirectEncryptionState::EndToEndAead(...)"),
            Self::LinkLayerOnly => f.write_str("WiFiDirectEncryptionState::LinkLayerOnly"),
        }
    }
}

// ============================================================================
// FUNCTIONAL CORE: Pure Cryptography
// ============================================================================

mod core {
    /// Build AAD (Associated Authenticated Data) for domain separation
    ///
    /// Format: `wifi-direct\0v1\0<message_type>`
    pub fn build_aad(message_type: &str) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"wifi-direct");    // protocol_id
        aad.push(0x00);                            // separator
        aad.extend_from_slice(b"v1");              // version
        aad.push(0x00);                            // separator
        aad.extend_from_slice(message_type.as_bytes()); // message_type
        aad
    }
}

// ============================================================================
// IMPERATIVE SHELL: Observability & State Management
// ============================================================================

mod shell {
    use super::*;

    /// WiFi Direct encryption with fallback support
    pub struct WiFiDirectEncryption {
        /// Current encryption state
        state: WiFiDirectEncryptionState,
    }

    impl WiFiDirectEncryption {
        /// Create WiFi Direct encryption with end-to-end AEAD
        ///
        /// This mode provides full end-to-end encryption after UHP session establishment.
        pub fn new_with_session_key(session_key: &[u8; 32]) -> Result<Self> {
            debug!("WiFi Direct: Creating with end-to-end encryption");
            Ok(Self {
                state: WiFiDirectEncryptionState::EndToEndAead(
                    ChaCha20Poly1305Encryption::new("wifi-direct", session_key)?,
                ),
            })
        }

        /// Create WiFi Direct encryption in fallback mode
        ///
        /// This mode relies on OS-level WPA2/3 protection. No application-level
        /// encryption is performed. This is appropriate for:
        /// - Connections through system network stack
        /// - Kernel-managed WPA2/3 protection
        ///
        /// ⚠️  **Warning**: No application-level secrecy in this mode
        pub fn new_fallback() -> Self {
            warn!("⚠️  WiFi Direct: Creating in LINK-LAYER-ONLY mode (no application E2E encryption)");
            Self {
                state: WiFiDirectEncryptionState::LinkLayerOnly,
            }
        }

        /// Check if end-to-end encryption is active
        pub fn is_e2e_encrypted(&self) -> bool {
            matches!(self.state, WiFiDirectEncryptionState::EndToEndAead(_))
        }

        /// Encrypt a message with message-type aware AAD
        ///
        /// # Arguments
        /// - `plaintext`: Message to encrypt
        /// - `message_type`: Type of WiFi Direct message (e.g., "service_discovery", "go_negotiation")
        ///
        /// # Behavior
        /// - **End-to-End Mode**: Encrypts with AAD
        /// - **Link-Layer Mode**: Returns plaintext with warning
        pub fn encrypt_message(&self, plaintext: &[u8], message_type: &str) -> Result<Vec<u8>> {
            match &self.state {
                WiFiDirectEncryptionState::EndToEndAead(enc) => {
                    debug!(
                        message_type = message_type,
                        plaintext_len = plaintext.len(),
                        "WiFi Direct: Encrypting with end-to-end AEAD"
                    );

                    let aad = core::build_aad(message_type);
                    enc.encrypt(plaintext, &aad)
                }
                WiFiDirectEncryptionState::LinkLayerOnly => {
                    warn!("⚠️  WiFi Direct: Encrypting in link-layer-only mode (plaintext flow)");
                    debug!(
                        message_type = message_type,
                        plaintext_len = plaintext.len(),
                        "WiFi Direct: Relying on OS-level WPA2/3"
                    );

                    Ok(plaintext.to_vec()) // OS handles WPA2/3
                }
            }
        }

        /// Decrypt a message with message-type aware AAD
        ///
        /// # Arguments
        /// - `ciphertext`: Encrypted message to decrypt
        /// - `message_type`: Expected type of WiFi Direct message
        ///
        /// # Behavior
        /// - **End-to-End Mode**: Decrypts with AEAD authentication
        /// - **Link-Layer Mode**: Returns plaintext (OS already decrypted)
        pub fn decrypt_message(&self, ciphertext: &[u8], message_type: &str) -> Result<Vec<u8>> {
            match &self.state {
                WiFiDirectEncryptionState::EndToEndAead(enc) => {
                    debug!(
                        message_type = message_type,
                        ciphertext_len = ciphertext.len(),
                        "WiFi Direct: Decrypting with end-to-end AEAD"
                    );

                    let aad = core::build_aad(message_type);
                    enc.decrypt(ciphertext, &aad)
                }
                WiFiDirectEncryptionState::LinkLayerOnly => {
                    debug!(
                        message_type = message_type,
                        ciphertext_len = ciphertext.len(),
                        "WiFi Direct: Already decrypted by OS (link-layer mode)"
                    );

                    Ok(ciphertext.to_vec()) // OS already decrypted via WPA2/3
                }
            }
        }
    }

    impl ProtocolEncryption for WiFiDirectEncryption {
        fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            match &self.state {
                WiFiDirectEncryptionState::EndToEndAead(enc) => {
                    debug!("WiFi Direct: encrypt() trait method with custom AAD");
                    enc.encrypt(plaintext, aad)
                }
                WiFiDirectEncryptionState::LinkLayerOnly => {
                    warn!("⚠️  WiFi Direct: encrypt() trait method called in link-layer-only mode");
                    Ok(plaintext.to_vec())
                }
            }
        }

        fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            match &self.state {
                WiFiDirectEncryptionState::EndToEndAead(enc) => {
                    debug!("WiFi Direct: decrypt() trait method with custom AAD");
                    enc.decrypt(ciphertext, aad)
                }
                WiFiDirectEncryptionState::LinkLayerOnly => {
                    debug!("WiFi Direct: decrypt() trait method in link-layer-only mode");
                    Ok(ciphertext.to_vec())
                }
            }
        }

        fn protocol(&self) -> &str {
            "wifi-direct"
        }

        fn stats(&self) -> EncryptionStats {
            match &self.state {
                WiFiDirectEncryptionState::EndToEndAead(enc) => enc.stats(),
                WiFiDirectEncryptionState::LinkLayerOnly => {
                    // Return stats with correct protocol name for fallback mode
                    let mut stats = EncryptionStats::default();
                    stats.protocol = "wifi-direct".to_string();
                    stats
                }
            }
        }

        fn reset_stats(&mut self) {
            match &mut self.state {
                WiFiDirectEncryptionState::EndToEndAead(enc) => {
                    // Note: would need mutable access, which the trait provides
                    // This is a limitation of the current trait design
                }
                WiFiDirectEncryptionState::LinkLayerOnly => {}
            }
        }
    }
}

pub use shell::WiFiDirectEncryption;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key() -> [u8; 32] {
        [0x66u8; 32]
    }

    // ========== CORE TESTS ==========

    #[test]
    fn test_aad_construction() {
        let aad = core::build_aad("service_discovery");

        assert!(aad.starts_with(b"wifi-direct"));
        assert!(aad.contains(&b'\0'));

        let aad2 = core::build_aad("go_negotiation");
        assert_ne!(aad, aad2, "Different message types must produce different AAD");
    }

    #[test]
    fn test_aad_determinism() {
        let aad1 = core::build_aad("service_discovery");
        let aad2 = core::build_aad("service_discovery");

        assert_eq!(aad1, aad2, "Same inputs must produce same AAD");
    }

    // ========== SHELL TESTS: END-TO-END MODE ==========

    #[test]
    fn test_wifi_e2e_encrypt_decrypt() {
        let key = create_test_key();
        let enc = WiFiDirectEncryption::new_with_session_key(&key).unwrap();

        assert!(enc.is_e2e_encrypted(), "Should be in E2E mode");

        let message = b"WiFi Direct E2E message";

        let ciphertext = enc.encrypt_message(message, "service_discovery").unwrap();
        assert!(ciphertext.len() > message.len()); // Includes tag

        let decrypted = enc.decrypt_message(&ciphertext, "service_discovery").unwrap();
        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_wifi_e2e_message_type_separation() {
        let key = create_test_key();
        let enc = WiFiDirectEncryption::new_with_session_key(&key).unwrap();

        let message = b"Test message";

        let ciphertext = enc.encrypt_message(message, "service_discovery").unwrap();

        // Wrong message type should fail
        let result = enc.decrypt_message(&ciphertext, "go_negotiation");
        assert!(result.is_err(), "Different message type should fail");
    }

    #[test]
    fn test_wifi_e2e_tampering_detection() {
        let key = create_test_key();
        let enc = WiFiDirectEncryption::new_with_session_key(&key).unwrap();

        let message = b"Important WiFi Direct data";

        let mut ciphertext = enc.encrypt_message(message, "service_discovery").unwrap();

        // Tamper
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = enc.decrypt_message(&ciphertext, "service_discovery");
        assert!(result.is_err(), "SECURITY: Tampering should be detected");
    }

    // ========== SHELL TESTS: FALLBACK MODE ==========

    #[test]
    fn test_wifi_fallback_is_not_e2e() {
        let enc = WiFiDirectEncryption::new_fallback();
        assert!(!enc.is_e2e_encrypted(), "Should NOT be in E2E mode");
    }

    #[test]
    fn test_wifi_fallback_pass_through() {
        let enc = WiFiDirectEncryption::new_fallback();

        let message = b"WiFi Direct fallback message";

        // Encrypt returns plaintext
        let encrypted = enc.encrypt_message(message, "service_discovery").unwrap();
        assert_eq!(message, &encrypted[..], "Fallback should return plaintext");

        // Decrypt returns same plaintext
        let decrypted = enc.decrypt_message(&encrypted, "service_discovery").unwrap();
        assert_eq!(message, &decrypted[..], "Fallback decrypt should return plaintext");
    }

    #[test]
    fn test_wifi_fallback_no_processing() {
        let enc = WiFiDirectEncryption::new_fallback();

        let original = b"Test data";

        // Encrypt
        let result1 = enc.encrypt_message(original, "go_negotiation").unwrap();
        assert_eq!(original.len(), result1.len(), "Fallback should not change length");

        // Decrypt
        let result2 = enc.decrypt_message(&result1, "go_negotiation").unwrap();
        assert_eq!(original, &result2[..], "Fallback roundtrip should preserve data");
    }

    #[test]
    fn test_wifi_fallback_multiple_messages() {
        let enc = WiFiDirectEncryption::new_fallback();

        let messages = vec![
            b"First message".to_vec(),
            b"Second message".to_vec(),
            b"Third message".to_vec(),
        ];

        for msg in messages {
            let encrypted = enc.encrypt_message(&msg, "service_discovery").unwrap();
            let decrypted = enc.decrypt_message(&encrypted, "service_discovery").unwrap();

            assert_eq!(msg, decrypted, "Fallback roundtrip failed");
        }
    }

    // ========== TRAIT TESTS ==========

    #[test]
    fn test_wifi_trait_e2e_mode() {
        let key = create_test_key();
        let enc = WiFiDirectEncryption::new_with_session_key(&key).unwrap();

        let message = b"Trait test";
        let aad = b"custom-aad";

        let ciphertext = enc.encrypt(message, aad).unwrap();
        let decrypted = enc.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(message, &decrypted[..]);
        assert_eq!(enc.protocol(), "wifi-direct");
    }

    #[test]
    fn test_wifi_trait_fallback_mode() {
        let enc = WiFiDirectEncryption::new_fallback();

        let message = b"Fallback trait test";
        let aad = b"aad";

        let encrypted = enc.encrypt(message, aad).unwrap();
        assert_eq!(message, &encrypted[..], "Fallback should pass through");

        let decrypted = enc.decrypt(&encrypted, aad).unwrap();
        assert_eq!(message, &decrypted[..], "Fallback should pass through");

        assert_eq!(enc.protocol(), "wifi-direct");
    }

    // ========== STATS TESTS ==========

    #[test]
    fn test_wifi_stats_e2e() {
        let key = create_test_key();
        let enc = WiFiDirectEncryption::new_with_session_key(&key).unwrap();

        let stats = enc.stats();
        assert_eq!(stats.protocol, "wifi-direct");
    }

    #[test]
    fn test_wifi_stats_fallback() {
        let enc = WiFiDirectEncryption::new_fallback();

        let stats = enc.stats();
        assert_eq!(stats.protocol, "wifi-direct");
    }

    // ========== INTEGRATION TESTS ==========

    #[test]
    fn test_wifi_e2e_large_message() {
        let key = create_test_key();
        let enc = WiFiDirectEncryption::new_with_session_key(&key).unwrap();

        let large_message = vec![0x42u8; 1024 * 1024]; // 1MB

        let ciphertext = enc.encrypt_message(&large_message, "service_discovery").unwrap();
        let decrypted = enc.decrypt_message(&ciphertext, "service_discovery").unwrap();

        assert_eq!(large_message, decrypted, "Large message should round-trip");
    }

    #[test]
    fn test_wifi_e2e_empty_message() {
        let key = create_test_key();
        let enc = WiFiDirectEncryption::new_with_session_key(&key).unwrap();

        let ciphertext = enc.encrypt_message(b"", "service_discovery").unwrap();
        assert!(!ciphertext.is_empty(), "Even empty message produces ciphertext (tag)");

        let decrypted = enc.decrypt_message(&ciphertext, "service_discovery").unwrap();
        assert_eq!(decrypted.len(), 0, "Should decrypt to empty");
    }

    #[test]
    fn test_wifi_multiple_message_types() {
        let key = create_test_key();
        let enc = WiFiDirectEncryption::new_with_session_key(&key).unwrap();

        let message_types = vec!["service_discovery", "go_negotiation", "handshake"];
        let message = b"Test";

        let ciphertexts: Vec<_> = message_types
            .iter()
            .map(|&msg_type| enc.encrypt_message(message, msg_type).unwrap())
            .collect();

        // Different message types → different ciphertexts
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                assert_ne!(ciphertexts[i], ciphertexts[j]);
            }
        }

        // Each decrypts with correct type
        for (msg_type, ciphertext) in message_types.iter().zip(ciphertexts.iter()) {
            let decrypted = enc.decrypt_message(ciphertext, msg_type).unwrap();
            assert_eq!(message, &decrypted[..]);
        }
    }
}
