//! ZHTP Mesh Encryption Adapter with Domain Separation
//!
//! Implements **ChaCha20Poly1305 AEAD** encryption for ZHTP mesh with:
//! - Message-type aware AAD for domain separation
//! - Session-based key derivation
//! - Stateless encryption (no locks required)
//! - Comprehensive cryptographic domain separation
//!
//! # Architecture: Functional Core / Imperative Shell (FCIS)
//!
//! **Functional Core** (Pure Cryptography):
//! - `build_aad()`: Deterministic AAD construction
//! - Direct ChaCha20Poly1305 encryption/decryption
//!
//! **Imperative Shell** (Observability & Operations):
//! - `ZhtpMeshEncryption` struct with message-type interface
//! - Logging and error context
//! - ProtocolEncryption trait implementation
//!
//! # Security Properties
//!
//! - **Domain Separation**: AAD includes protocol, version, message_type, session_id
//! - **No Replay Protection**: ZHTP mesh relies on higher-layer mechanisms
//! - **Stateless**: No sequence tracking required
//! - **Cross-protocol Isolation**: Different message types can't be interchanged
//!
//! # AAD Format
//!
//! ```text
//! zhtp-mesh\0v1\0<message_type>\0<session_id>
//! ```
//!
//! Example for node discovery:
//! ```text
//! "zhtp-mesh\0v1\0node_discovery\0<32-byte session_id>"
//! ```

use crate::encryption::{ProtocolEncryption, ChaCha20Poly1305Encryption, EncryptionStats};
use anyhow::Result;
use tracing::debug;

// ============================================================================
// FUNCTIONAL CORE: Pure Cryptography
// ============================================================================

mod core {

    /// Build AAD (Associated Authenticated Data) for domain separation
    ///
    /// Format: `zhtp-mesh\0v1\0<message_type>\0<session_id>`
    /// This ensures different message types and sessions produce different AAD.
    pub fn build_aad(message_type: &str, session_id: &[u8]) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"zhtp-mesh");      // protocol_id
        aad.push(0x00);                            // separator
        aad.extend_from_slice(b"v1");              // version
        aad.push(0x00);                            // separator
        aad.extend_from_slice(message_type.as_bytes()); // message_type
        aad.push(0x00);                            // separator
        aad.extend_from_slice(session_id);         // session_id
        aad
    }
}

// ============================================================================
// IMPERATIVE SHELL: Observability & Message-Type Interface
// ============================================================================

mod shell {
    use super::*;

    /// ZHTP mesh encryption with message-type aware AAD
    pub struct ZhtpMeshEncryption {
        /// Core encryption (ChaCha20Poly1305)
        enc: ChaCha20Poly1305Encryption,
        /// Session identifier for domain separation
        session_id: [u8; 32],
    }

    impl ZhtpMeshEncryption {
        /// Create new ZHTP mesh encryption instance
        pub fn new(app_key: &[u8; 32], session_id: [u8; 32]) -> Result<Self> {
            Ok(Self {
                enc: ChaCha20Poly1305Encryption::new("zhtp-mesh", app_key)?,
                session_id,
            })
        }

        /// Encrypt a message with message-type aware AAD
        ///
        /// # Arguments
        /// - `plaintext`: Message to encrypt
        /// - `message_type`: Type of ZHTP message (e.g., "node_discovery", "route_update")
        ///   This ensures different message types can't be interchanged
        pub fn encrypt_message(&self, plaintext: &[u8], message_type: &str) -> Result<Vec<u8>> {
            debug!(
                session_id = hex::encode(&self.session_id),
                message_type = message_type,
                plaintext_len = plaintext.len(),
                "Encrypting ZHTP mesh message with domain separation"
            );

            let aad = core::build_aad(message_type, &self.session_id);

            // CORE: Pure encryption
            let ciphertext = self.enc.encrypt(plaintext, &aad)?;

            debug!(
                message_type = message_type,
                ciphertext_len = ciphertext.len(),
                "ZHTP mesh encryption successful"
            );

            Ok(ciphertext)
        }

        /// Decrypt a message with message-type aware AAD
        ///
        /// # Arguments
        /// - `ciphertext`: Encrypted message to decrypt
        /// - `message_type`: Expected type of ZHTP message
        ///   Must match the type used during encryption, or decryption fails
        pub fn decrypt_message(&self, ciphertext: &[u8], message_type: &str) -> Result<Vec<u8>> {
            debug!(
                session_id = hex::encode(&self.session_id),
                message_type = message_type,
                ciphertext_len = ciphertext.len(),
                "Decrypting ZHTP mesh message"
            );

            let aad = core::build_aad(message_type, &self.session_id);

            // CORE: Pure decryption
            let plaintext = self.enc.decrypt(ciphertext, &aad)?;

            debug!(
                message_type = message_type,
                plaintext_len = plaintext.len(),
                "ZHTP mesh decryption successful"
            );

            Ok(plaintext)
        }

        pub fn session_id(&self) -> [u8; 32] {
            self.session_id
        }
    }

    impl ProtocolEncryption for ZhtpMeshEncryption {
        fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            // Trait-level encryption: direct pass-through
            debug!("encrypt() called - using trait-level AAD");
            self.enc.encrypt(plaintext, aad)
        }

        fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            // Trait-level decryption: direct pass-through
            debug!("decrypt() called - using trait-level AAD");
            self.enc.decrypt(ciphertext, aad)
        }

        fn protocol(&self) -> &str {
            "zhtp-mesh"
        }

        fn stats(&self) -> EncryptionStats {
            self.enc.stats()
        }

        fn reset_stats(&mut self) {
            // Note: trait requires &mut but stats are atomic
            // This is a limitation of the current trait design
        }
    }
}

pub use shell::ZhtpMeshEncryption;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key() -> [u8; 32] {
        [0x77u8; 32]
    }

    fn create_test_session_id() -> [u8; 32] {
        [0x88u8; 32]
    }

    // ========== CORE TESTS ==========

    #[test]
    fn test_aad_construction() {
        let session_id = [0xAAu8; 32];
        let aad = core::build_aad("node_discovery", &session_id);

        // Verify structure
        assert!(aad.starts_with(b"zhtp-mesh"));
        assert!(aad.windows(2).any(|w| w == [b'\0', b'v']));
        assert!(aad.contains(&b'\0'));

        // Different message types should produce different AAD
        let aad2 = core::build_aad("route_update", &session_id);
        assert_ne!(aad, aad2, "Different message types must produce different AAD");
    }

    #[test]
    fn test_aad_session_separation() {
        let session_id1 = [0x11u8; 32];
        let session_id2 = [0x22u8; 32];

        let aad1 = core::build_aad("node_discovery", &session_id1);
        let aad2 = core::build_aad("node_discovery", &session_id2);

        assert_ne!(aad1, aad2, "Different sessions must produce different AAD");
    }

    #[test]
    fn test_aad_determinism() {
        let session_id = [0x99u8; 32];
        let aad1 = core::build_aad("node_discovery", &session_id);
        let aad2 = core::build_aad("node_discovery", &session_id);

        assert_eq!(aad1, aad2, "Same inputs must produce same AAD");
    }

    // ========== SHELL TESTS ==========

    #[test]
    fn test_zhtp_encrypt_decrypt() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = ZhtpMeshEncryption::new(&key, session_id).unwrap();
        let message = b"Test ZHTP mesh message";

        let ciphertext = enc.encrypt_message(message, "node_discovery").unwrap();
        assert!(ciphertext.len() > message.len()); // Includes tag

        let decrypted = enc.decrypt_message(&ciphertext, "node_discovery").unwrap();
        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_zhtp_message_type_separation() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = ZhtpMeshEncryption::new(&key, session_id).unwrap();
        let message = b"Test message";

        // Encrypt with one message type
        let ciphertext = enc.encrypt_message(message, "node_discovery").unwrap();

        // Try to decrypt with different message type (should fail)
        let result = enc.decrypt_message(&ciphertext, "route_update");
        assert!(result.is_err(), "Different message type should fail decryption");
    }

    #[test]
    fn test_zhtp_session_separation() {
        let key = create_test_key();
        let session_id1 = [0x11u8; 32];
        let session_id2 = [0x22u8; 32];

        let enc1 = ZhtpMeshEncryption::new(&key, session_id1).unwrap();
        let enc2 = ZhtpMeshEncryption::new(&key, session_id2).unwrap();

        let message = b"Test message";

        // Encrypt with session 1
        let ciphertext = enc1.encrypt_message(message, "node_discovery").unwrap();

        // Try to decrypt with session 2 (should fail due to different AAD)
        let result = enc2.decrypt_message(&ciphertext, "node_discovery");
        assert!(result.is_err(), "Different session should fail decryption");
    }

    #[test]
    fn test_zhtp_tampering_detection() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = ZhtpMeshEncryption::new(&key, session_id).unwrap();
        let message = b"Important ZHTP message";

        let mut ciphertext = enc.encrypt_message(message, "node_discovery").unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = enc.decrypt_message(&ciphertext, "node_discovery");
        assert!(result.is_err(), "SECURITY: Tampering should be detected");
    }

    #[test]
    fn test_zhtp_empty_message() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = ZhtpMeshEncryption::new(&key, session_id).unwrap();

        // Encrypt empty message
        let ciphertext = enc.encrypt_message(b"", "node_discovery").unwrap();
        assert!(!ciphertext.is_empty(), "Even empty message produces ciphertext (tag)");

        let decrypted = enc.decrypt_message(&ciphertext, "node_discovery").unwrap();
        assert_eq!(decrypted.len(), 0, "Empty message should decrypt to empty");
    }

    #[test]
    fn test_zhtp_large_message() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = ZhtpMeshEncryption::new(&key, session_id).unwrap();

        // Create 1MB message
        let large_message = vec![0x42u8; 1024 * 1024];

        let ciphertext = enc.encrypt_message(&large_message, "node_discovery").unwrap();
        let decrypted = enc.decrypt_message(&ciphertext, "node_discovery").unwrap();

        assert_eq!(large_message, decrypted, "Large message should round-trip correctly");
    }

    #[test]
    fn test_zhtp_protocol_encryption_trait() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = ZhtpMeshEncryption::new(&key, session_id).unwrap();

        // Test trait-level interface
        let message = b"Trait test";
        let aad = b"custom-aad";

        let ciphertext = enc.encrypt(message, aad).unwrap();
        let decrypted = enc.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(message, &decrypted[..]);
        assert_eq!(enc.protocol(), "zhtp-mesh");
    }

    #[test]
    fn test_zhtp_multiple_message_types() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = ZhtpMeshEncryption::new(&key, session_id).unwrap();

        // Encrypt different message types
        let types = vec!["node_discovery", "route_update", "key_exchange"];
        let message = b"Test";

        let ciphertexts: Vec<_> = types
            .iter()
            .map(|&msg_type| enc.encrypt_message(message, msg_type).unwrap())
            .collect();

        // All should produce different ciphertexts
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i], ciphertexts[j],
                    "Different message types should produce different ciphertexts"
                );
            }
        }

        // All should decrypt with correct message type
        for (msg_type, ciphertext) in types.iter().zip(ciphertexts.iter()) {
            let decrypted = enc.decrypt_message(ciphertext, msg_type).unwrap();
            assert_eq!(message, &decrypted[..]);
        }
    }

    #[test]
    fn test_zhtp_wrong_message_type_comprehensive() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = ZhtpMeshEncryption::new(&key, session_id).unwrap();
        let message = b"Critical data";

        // Encrypt as node_discovery
        let ciphertext = enc.encrypt_message(message, "node_discovery").unwrap();

        // Try all these wrong types
        let wrong_types = vec![
            "route_update",
            "key_exchange",
            "topology_update",
            "node_discoveryy", // typo
            "node_discover",   // prefix
            "",                // empty
        ];

        for wrong_type in wrong_types {
            let result = enc.decrypt_message(&ciphertext, wrong_type);
            assert!(
                result.is_err(),
                "Decryption with wrong message type '{}' should fail",
                wrong_type
            );
        }
    }
}
