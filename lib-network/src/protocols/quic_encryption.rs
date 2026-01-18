//! QUIC Application-Level Encryption Adapter
//!
//! Implements **ChaCha20Poly1305 AEAD** encryption for QUIC with:
//! - Application-level encryption on top of TLS 1.3
//! - Session-based key derivation
//! - Message-type aware domain separation
//! - Stateless operation (no locks required)
//!
//! # Architecture: Functional Core / Imperative Shell (FCIS)
//!
//! **Functional Core** (Pure Cryptography):
//! - `build_aad()`: Deterministic AAD construction
//! - Direct ChaCha20Poly1305 encryption/decryption
//!
//! **Imperative Shell** (Observability & Session Tracking):
//! - `QuicApplicationEncryption` struct with session context
//! - Message-type interface for QUIC streams
//! - Logging and error context
//! - ProtocolEncryption trait implementation
//!
//! # Security Model
//!
//! **Transport Security**: TLS 1.3 handled by QUIC layer
//! **Application Security**: Application-level encryption via this adapter
//!
//! This provides:
//! - Confidentiality: ChaCha20 stream cipher
//! - Authenticity: Poly1305 AEAD tag
//! - Domain Separation: AAD includes session context and message type
//! - Stateless: No nonce reuse risk from this layer
//!
//! # Use Cases
//!
//! - **Encrypted streams**: Per-stream encryption on top of QUIC TLS
//! - **Multi-tenant**: Session ID ensures per-tenant isolation
//! - **Application domains**: Message types prevent cross-domain attacks

use crate::encryption::{ProtocolEncryption, ChaCha20Poly1305Encryption, EncryptionStats};
use anyhow::Result;
use tracing::debug;

// ============================================================================
// FUNCTIONAL CORE: Pure Cryptography
// ============================================================================

mod core {
    /// Build AAD (Associated Authenticated Data) for domain separation
    ///
    /// Format: `quic\0v1\0<message_type>\0<session_id>`
    pub fn build_aad(message_type: &str, session_id: &[u8]) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"quic");              // protocol_id
        aad.push(0x00);                              // separator
        aad.extend_from_slice(b"v1");                // version
        aad.push(0x00);                              // separator
        aad.extend_from_slice(message_type.as_bytes()); // message_type
        aad.push(0x00);                              // separator
        aad.extend_from_slice(session_id);           // session_id
        aad
    }
}

// ============================================================================
// IMPERATIVE SHELL: Observability & Session Tracking
// ============================================================================

mod shell {
    use super::*;

    /// QUIC application-level encryption with session context
    pub struct QuicApplicationEncryption {
        /// Core encryption (ChaCha20Poly1305)
        enc: ChaCha20Poly1305Encryption,
        /// Session identifier for domain separation (UHP v2, 32 bytes)
        session_id: [u8; 32],
    }

    impl QuicApplicationEncryption {
        /// Create new QUIC application encryption instance
        ///
        /// # Arguments
        /// - `session_key`: 32-byte ChaCha20 session key
        /// - `session_id`: 32-byte session identifier for domain separation
        pub fn new(session_key: &[u8; 32], session_id: [u8; 32]) -> Result<Self> {
            Ok(Self {
                enc: ChaCha20Poly1305Encryption::new("quic", session_key)?,
                session_id,
            })
        }

        /// Get the session ID for context tracking
        pub fn session_id(&self) -> [u8; 32] {
            self.session_id
        }

        /// Encrypt a message with message-type aware AAD
        ///
        /// # Arguments
        /// - `plaintext`: Message to encrypt
        /// - `message_type`: Type of QUIC application message (e.g., "handshake", "data", "control")
        ///   This ensures different message types can't be interchanged
        pub fn encrypt_message(&self, plaintext: &[u8], message_type: &str) -> Result<Vec<u8>> {
            debug!(
                session_id = hex::encode(&self.session_id),
                message_type = message_type,
                plaintext_len = plaintext.len(),
                "Encrypting QUIC application message with domain separation"
            );

            let aad = core::build_aad(message_type, &self.session_id);

            // CORE: Pure encryption
            let ciphertext = self.enc.encrypt(plaintext, &aad)?;

            debug!(
                message_type = message_type,
                ciphertext_len = ciphertext.len(),
                "QUIC encryption successful"
            );

            Ok(ciphertext)
        }

        /// Decrypt a message with message-type aware AAD
        ///
        /// # Arguments
        /// - `ciphertext`: Encrypted message to decrypt
        /// - `message_type`: Expected type of QUIC application message
        ///   Must match the type used during encryption, or decryption fails
        pub fn decrypt_message(&self, ciphertext: &[u8], message_type: &str) -> Result<Vec<u8>> {
            debug!(
                session_id = hex::encode(&self.session_id),
                message_type = message_type,
                ciphertext_len = ciphertext.len(),
                "Decrypting QUIC application message"
            );

            let aad = core::build_aad(message_type, &self.session_id);

            // CORE: Pure decryption
            let plaintext = self.enc.decrypt(ciphertext, &aad)?;

            debug!(
                message_type = message_type,
                plaintext_len = plaintext.len(),
                "QUIC decryption successful"
            );

            Ok(plaintext)
        }
    }

    impl ProtocolEncryption for QuicApplicationEncryption {
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
            "quic"
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

pub use shell::QuicApplicationEncryption;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key() -> [u8; 32] {
        [0x55u8; 32]
    }

    fn create_test_session_id() -> [u8; 32] {
        [0x77u8; 32]
    }

    // ========== CORE TESTS ==========

    #[test]
    fn test_aad_construction() {
        let session_id = [0xAAu8; 32];
        let aad = core::build_aad("handshake", &session_id);

        assert!(aad.starts_with(b"quic"));
        assert!(aad.contains(&b'\0'));

        let aad2 = core::build_aad("data", &session_id);
        assert_ne!(aad, aad2, "Different message types must produce different AAD");
    }

    #[test]
    fn test_aad_session_separation() {
        let session_id1 = [0x11u8; 16];
        let session_id2 = [0x22u8; 16];

        let aad1 = core::build_aad("handshake", &session_id1);
        let aad2 = core::build_aad("handshake", &session_id2);

        assert_ne!(aad1, aad2, "Different sessions must produce different AAD");
    }

    #[test]
    fn test_aad_determinism() {
        let session_id = [0x99u8; 16];
        let aad1 = core::build_aad("handshake", &session_id);
        let aad2 = core::build_aad("handshake", &session_id);

        assert_eq!(aad1, aad2, "Same inputs must produce same AAD");
    }

    // ========== SHELL TESTS ==========

    #[test]
    fn test_quic_encrypt_decrypt() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();
        let message = b"QUIC application message";

        let ciphertext = enc.encrypt_message(message, "data").unwrap();
        assert!(ciphertext.len() > message.len()); // Includes tag

        let decrypted = enc.decrypt_message(&ciphertext, "data").unwrap();
        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_quic_message_type_separation() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();
        let message = b"Test message";

        let ciphertext = enc.encrypt_message(message, "handshake").unwrap();

        // Try to decrypt with different message type
        let result = enc.decrypt_message(&ciphertext, "data");
        assert!(result.is_err(), "Different message type should fail decryption");
    }

    #[test]
    fn test_quic_session_separation() {
        let key = create_test_key();
        let session_id1 = [0x11u8; 32];
        let session_id2 = [0x22u8; 32];

        let enc1 = QuicApplicationEncryption::new(&key, session_id1).unwrap();
        let enc2 = QuicApplicationEncryption::new(&key, session_id2).unwrap();

        let message = b"Test message";

        let ciphertext = enc1.encrypt_message(message, "data").unwrap();

        // Try to decrypt with different session
        let result = enc2.decrypt_message(&ciphertext, "data");
        assert!(result.is_err(), "Different session should fail decryption");
    }

    #[test]
    fn test_quic_tampering_detection() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();
        let message = b"Important QUIC data";

        let mut ciphertext = enc.encrypt_message(message, "data").unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = enc.decrypt_message(&ciphertext, "data");
        assert!(result.is_err(), "SECURITY: Tampering should be detected");
    }

    #[test]
    fn test_quic_empty_message() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();

        // Encrypt empty message
        let ciphertext = enc.encrypt_message(b"", "data").unwrap();
        assert!(!ciphertext.is_empty(), "Even empty message produces ciphertext (tag)");

        let decrypted = enc.decrypt_message(&ciphertext, "data").unwrap();
        assert_eq!(decrypted.len(), 0, "Empty message should decrypt to empty");
    }

    #[test]
    fn test_quic_large_message() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();

        // Create 10MB message (QUIC can handle large streams)
        let large_message = vec![0x42u8; 10 * 1024 * 1024];

        let ciphertext = enc.encrypt_message(&large_message, "data").unwrap();
        let decrypted = enc.decrypt_message(&ciphertext, "data").unwrap();

        assert_eq!(large_message, decrypted, "Large message should round-trip");
    }

    #[test]
    fn test_quic_protocol_encryption_trait() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();

        let message = b"Trait test";
        let aad = b"custom-aad";

        let ciphertext = enc.encrypt(message, aad).unwrap();
        let decrypted = enc.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(message, &decrypted[..]);
        assert_eq!(enc.protocol(), "quic");
        assert_eq!(enc.session_id(), session_id);
    }

    #[test]
    fn test_quic_multiple_message_types() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();

        // QUIC message types
        let types = vec!["handshake", "data", "ack", "control", "crypto"];
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
    fn test_quic_multiple_sessions() {
        let key = create_test_key();
        let message = b"Test message";

        // Create 5 sessions
        let sessions: Vec<_> = (0..5)
            .map(|i| {
                let mut sid = [0u8; 32];
                sid[0] = i as u8;
                QuicApplicationEncryption::new(&key, sid).unwrap()
            })
            .collect();

        // Encrypt same message with each session
        let ciphertexts: Vec<_> = sessions
            .iter()
            .map(|enc| enc.encrypt_message(message, "data").unwrap())
            .collect();

        // All ciphertexts should be different (different AAD)
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i], ciphertexts[j],
                    "Different sessions should produce different ciphertexts"
                );
            }
        }

        // Each session should only decrypt its own ciphertext
        for (i, (session, ciphertext)) in sessions.iter().zip(ciphertexts.iter()).enumerate() {
            let decrypted = session.decrypt_message(ciphertext, "data").unwrap();
            assert_eq!(message, &decrypted[..]);

            // Try to decrypt other ciphertexts with this session (should fail)
            for (j, other_ciphertext) in ciphertexts.iter().enumerate() {
                if i != j {
                    let result = session.decrypt_message(other_ciphertext, "data");
                    assert!(result.is_err(), "Session {} should not decrypt session {} ciphertext", i, j);
                }
            }
        }
    }

    #[test]
    fn test_quic_wrong_message_type_comprehensive() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();
        let message = b"Critical QUIC data";

        // Encrypt as "data"
        let ciphertext = enc.encrypt_message(message, "data").unwrap();

        // Try all these wrong types
        let wrong_types = vec![
            "handshake",
            "ack",
            "control",
            "crypto",
            "dataa",     // typo
            "dat",       // prefix
            "",          // empty
            "DATA",      // case-sensitive
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

    #[test]
    fn test_quic_stats() {
        let key = create_test_key();
        let session_id = create_test_session_id();

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();

        let stats = enc.stats();
        assert_eq!(stats.protocol, "quic");
    }

    #[test]
    fn test_quic_session_context_preserved() {
        let key = create_test_key();
        let session_id = [0xFFu8; 32];

        let enc = QuicApplicationEncryption::new(&key, session_id).unwrap();

        assert_eq!(enc.session_id(), session_id, "Session ID should be preserved");

        // Encrypt and decrypt
        let message = b"Test";
        let ciphertext = enc.encrypt_message(message, "data").unwrap();
        let decrypted = enc.decrypt_message(&ciphertext, "data").unwrap();

        assert_eq!(message, &decrypted[..]);
        assert_eq!(enc.session_id(), session_id, "Session ID should remain unchanged after operations");
    }
}
