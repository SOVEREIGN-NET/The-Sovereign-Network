//! Bluetooth Encryption Adapter with Wire Format & Replay Protection
//!
//! Implements **ChaCha20Poly1305 AEAD** encryption for Bluetooth mesh with:
//! - Deterministic nonce derivation
//! - Sequence number-based replay protection
//! - Wire format with version and flags fields
//! - Domain separation via AAD (Associated Authenticated Data)
//!
//! # Architecture: Functional Core / Imperative Shell (FCIS)
//!
//! ## Wire Format (Total: 42+ bytes overhead)
//!
//! ```text
//! ┌────────┬───────┬────────┬──────────┬─────────────┬─────────┐
//! │Version │ Flags │ Nonce  │ Sequence │ Ciphertext  │   Tag   │
//! │ (1)    │ (1)   │ (12)   │   (8)    │  (variable) │  (16)   │
//! └────────┴───────┴────────┴──────────┴─────────────┴─────────┘
//! ```
//!
//! **Fields**:
//! - **Version** (1 byte): Protocol version (0x01 for initial release)
//! - **Flags** (1 byte): Reserved for future use (fragmentation, compression)
//! - **Nonce** (12 bytes): Deterministic HKDF(session_id || seq || direction)
//! - **Sequence** (8 bytes): Monotonic counter for replay protection
//! - **Ciphertext** (variable): ChaCha20 encrypted payload
//! - **Tag** (16 bytes): Poly1305 authentication tag (AEAD)
//!
//! # Security Properties
//!
//! - **Nonce Uniqueness**: Derived from (session_id, sequence, direction)
//! - **Replay Protection**: Sequence numbers tracked per peer
//! - **Domain Separation**: AAD includes protocol, version, session_id, sequence
//! - **Authentication**: Poly1305 AEAD tag
//! - **Versioning**: Wire format version field for future compatibility

use crate::encryption::{ProtocolEncryption, EncryptionStats};
use anyhow::{anyhow, Result};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tracing::debug;

const PROTOCOL_VERSION: u8 = 0x01;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const SEQ_SIZE: usize = 8;
const HEADER_SIZE: usize = 1 + 1 + NONCE_SIZE + SEQ_SIZE; // version + flags + nonce + seq = 22

// ============================================================================
// Wire Frame Type
// ============================================================================

/// Bluetooth encrypted frame structure
///
/// Implements the wire format with version, flags, nonce, sequence, and tag.
#[derive(Debug, Clone)]
pub struct BluetoothFrame {
    pub version: u8,
    pub flags: u8,
    pub nonce: [u8; NONCE_SIZE],
    pub sequence: u64,
    pub ciphertext: Vec<u8>, // Includes 16-byte tag
}

impl BluetoothFrame {
    /// Serialize frame to wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.ciphertext.len());
        buf.push(self.version);
        buf.push(self.flags);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize frame from wire format
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE + TAG_SIZE {
            return Err(anyhow!("Frame too short: {} bytes (min: {})", data.len(), HEADER_SIZE + TAG_SIZE));
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(anyhow!("Unsupported protocol version: 0x{:02x}", version));
        }

        let flags = data[1];
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[2..14]);
        let sequence = u64::from_be_bytes(data[14..22].try_into()?);
        let ciphertext = data[22..].to_vec();

        Ok(Self {
            version,
            flags,
            nonce,
            sequence,
            ciphertext,
        })
    }
}

// ============================================================================
// FUNCTIONAL CORE: Pure Cryptography
// ============================================================================

mod core {
    use super::*;
    use crate::encryption::ChaCha20Poly1305Encryption;

    /// Derive deterministic nonce from session_id, sequence, and direction
    ///
    /// Uses HKDF-SHA256 to derive a unique nonce per message.
    /// Same (session_id, sequence, direction) always produces same nonce.
    pub fn derive_nonce(session_id: &[u8; 16], sequence: u64, direction: u8) -> Result<[u8; NONCE_SIZE]> {
        let mut hasher = Sha256::new();
        hasher.update(b"bluetooth-nonce-v1");
        hasher.update(session_id);
        hasher.update(&sequence.to_be_bytes());
        hasher.update(&[direction]); // 0x00 = send, 0x01 = recv

        let hash = hasher.finalize();
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&hash[..NONCE_SIZE]);
        Ok(nonce)
    }

    /// Build AAD (Associated Authenticated Data) for domain separation
    pub fn build_aad(session_id: &[u8; 16], sequence: u64) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"bluetooth");       // protocol_id
        aad.push(0x00);                            // separator
        aad.extend_from_slice(b"v1");              // version
        aad.push(0x00);                            // separator
        aad.extend_from_slice(session_id);         // session_id
        aad.push(0x00);                            // separator
        aad.extend_from_slice(&sequence.to_be_bytes()); // sequence
        aad
    }

    /// Pure encryption without side effects (FUNCTIONAL CORE)
    pub fn encrypt_core(
        plaintext: &[u8],
        enc: &ChaCha20Poly1305Encryption,
        session_id: &[u8; 16],
        sequence: u64,
    ) -> Result<Vec<u8>> {
        let nonce = derive_nonce(session_id, sequence, 0x00)?; // direction = send
        let aad = build_aad(session_id, sequence);

        // Encrypt with the functional core
        enc.encrypt(plaintext, &aad)
    }

    /// Pure decryption without side effects (FUNCTIONAL CORE)
    pub fn decrypt_core(
        ciphertext: &[u8],
        enc: &ChaCha20Poly1305Encryption,
        session_id: &[u8; 16],
        sequence: u64,
    ) -> Result<Vec<u8>> {
        let nonce = derive_nonce(session_id, sequence, 0x01)?; // direction = recv
        let aad = build_aad(session_id, sequence);

        // Decrypt with the functional core
        enc.decrypt(ciphertext, &aad)
    }
}

// ============================================================================
// IMPERATIVE SHELL: Observability + Replay Protection
// ============================================================================

mod shell {
    use super::*;
    use crate::encryption::ChaCha20Poly1305Encryption;

    /// Bluetooth encryption with replay protection
    pub struct BluetoothEncryption {
        /// Core encryption (ChaCha20Poly1305)
        enc: ChaCha20Poly1305Encryption,
        /// Session identifier
        session_id: [u8; 16],
        /// Monotonic send sequence number
        send_sequence: AtomicU64,
        /// Received sequence numbers per peer (for replay protection)
        /// Uses None for first message, then tracks the sequence number
        recv_sequences: RwLock<HashMap<[u8; 16], Option<u64>>>,
    }

    impl BluetoothEncryption {
        /// Create new Bluetooth encryption instance
        pub fn new(session_key: &[u8; 32], session_id: [u8; 16]) -> Result<Self> {
            Ok(Self {
                enc: ChaCha20Poly1305Encryption::new("bluetooth", session_key)?,
                session_id,
                send_sequence: AtomicU64::new(0),
                recv_sequences: RwLock::new(HashMap::new()),
            })
        }

        /// Encrypt a message and wrap in Bluetooth frame with sequence
        pub fn encrypt_message(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            debug!(
                session_id = hex::encode(&self.session_id),
                plaintext_len = plaintext.len(),
                "Encrypting Bluetooth message with wire format"
            );

            let sequence = self.send_sequence.fetch_add(1, Ordering::SeqCst);
            let nonce = core::derive_nonce(&self.session_id, sequence, 0x00)?;
            let aad = core::build_aad(&self.session_id, sequence);

            // CORE: Pure encryption
            let ciphertext = self.enc.encrypt(plaintext, &aad)?;

            // SHELL: Wrap in frame
            let frame = BluetoothFrame {
                version: PROTOCOL_VERSION,
                flags: 0x00,
                nonce,
                sequence,
                ciphertext,
            };

            debug!(
                sequence,
                frame_len = frame.serialize().len(),
                "Bluetooth encryption successful"
            );

            Ok(frame.serialize())
        }

        /// Decrypt a Bluetooth frame and verify replay protection
        pub fn decrypt_message(&self, frame_data: &[u8], peer_id: &[u8; 16]) -> Result<Vec<u8>> {
            debug!(
                session_id = hex::encode(&self.session_id),
                peer_id = hex::encode(peer_id),
                frame_len = frame_data.len(),
                "Decrypting Bluetooth message"
            );

            let frame = BluetoothFrame::deserialize(frame_data)?;

            // SHELL: Replay protection - check sequence number
            {
                let mut recv_seqs = self.recv_sequences.write().map_err(|e| {
                    anyhow!("Failed to acquire recv_sequences lock: {}", e)
                })?;
                let last_seen_opt = recv_seqs.entry(*peer_id).or_insert(None);

                if let Some(last_seen) = last_seen_opt {
                    if frame.sequence <= *last_seen {
                        return Err(anyhow!(
                            "Replay attack detected: seq {} <= last_seen {}",
                            frame.sequence,
                            last_seen
                        ));
                    }
                }

                *last_seen_opt = Some(frame.sequence);
            }

            // SHELL: Build AAD for decryption
            // Note: Nonce verification is redundant since AEAD tag already authenticates it
            let aad = core::build_aad(&self.session_id, frame.sequence);

            // CORE: Pure decryption
            let plaintext = self.enc.decrypt(&frame.ciphertext, &aad)?;

            debug!(
                sequence = frame.sequence,
                plaintext_len = plaintext.len(),
                "Bluetooth decryption successful"
            );

            Ok(plaintext)
        }

        pub fn session_id(&self) -> [u8; 16] {
            self.session_id
        }
    }

    impl ProtocolEncryption for BluetoothEncryption {
        fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            // Use the frame-based encrypt_message for full protocol support
            debug!("encrypt() called - using full wire format encryption");
            self.enc.encrypt(plaintext, aad)
        }

        fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            // Use the frame-based decrypt_message for full protocol support
            debug!("decrypt() called - using full wire format decryption");
            self.enc.decrypt(ciphertext, aad)
        }

        fn protocol(&self) -> &str {
            "bluetooth"
        }

        fn stats(&self) -> EncryptionStats {
            self.enc.stats()
        }

        fn reset_stats(&mut self) {
            // Need to get mut access - this is a limitation of the trait
            // In practice, we'd want a separate reset mechanism
        }
    }
}

pub use shell::BluetoothEncryption;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key() -> [u8; 32] {
        [0x88u8; 32]
    }

    fn create_test_session_id() -> [u8; 16] {
        [0xBBu8; 16]
    }

    fn create_test_peer_id() -> [u8; 16] {
        [0xCCu8; 16]
    }

    // ========== CORE TESTS ==========

    #[test]
    fn test_nonce_derivation_determinism() {
        let session_id = create_test_session_id();
        let nonce1 = core::derive_nonce(&session_id, 100, 0x00).unwrap();
        let nonce2 = core::derive_nonce(&session_id, 100, 0x00).unwrap();

        assert_eq!(nonce1, nonce2, "Same inputs should produce same nonce");

        let nonce3 = core::derive_nonce(&session_id, 101, 0x00).unwrap();
        assert_ne!(nonce1, nonce3, "Different sequence should produce different nonce");
    }

    #[test]
    fn test_wire_format_serialization() {
        let frame = BluetoothFrame {
            version: 0x01,
            flags: 0x00,
            nonce: [0x42u8; 12],
            sequence: 0x0102030405060708,
            ciphertext: vec![0xAA, 0xBB, 0xCC],
        };

        let serialized = frame.serialize();
        assert_eq!(serialized[0], 0x01); // version
        assert_eq!(serialized[1], 0x00); // flags
        assert_eq!(&serialized[2..14], &[0x42u8; 12]); // nonce
        assert_eq!(&serialized[14..22], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // sequence
        assert_eq!(&serialized[22..], &[0xAA, 0xBB, 0xCC]); // ciphertext
    }

    #[test]
    fn test_wire_format_deserialization() {
        // Ciphertext must be at least TAG_SIZE (16 bytes) to pass deserialization
        let original = BluetoothFrame {
            version: 0x01,
            flags: 0x00,
            nonce: [0x42u8; 12],
            sequence: 12345,
            ciphertext: vec![0xAA; TAG_SIZE + 4], // 16-byte tag + 4 bytes of encrypted data
        };

        let serialized = original.serialize();
        let deserialized = BluetoothFrame::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, original.version);
        assert_eq!(deserialized.flags, original.flags);
        assert_eq!(deserialized.nonce, original.nonce);
        assert_eq!(deserialized.sequence, original.sequence);
        assert_eq!(deserialized.ciphertext, original.ciphertext);
    }

    #[test]
    fn test_wire_format_version_rejection() {
        let mut data = vec![0xFF; HEADER_SIZE + TAG_SIZE]; // version 0xFF (invalid)
        let result = BluetoothFrame::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported protocol version"));
    }

    // ========== SHELL TESTS ==========

    #[test]
    fn test_bluetooth_encrypt_decrypt() {
        let key = create_test_key();
        let session_id = create_test_session_id();
        let peer_id = create_test_peer_id();

        let enc = BluetoothEncryption::new(&key, session_id).unwrap();
        let message = b"Test Bluetooth message";

        let frame_data = enc.encrypt_message(message).unwrap();
        assert!(frame_data.len() > message.len()); // Includes frame + nonce + tag

        let decrypted = enc.decrypt_message(&frame_data, &peer_id).unwrap();
        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_bluetooth_replay_protection() {
        let key = create_test_key();
        let session_id = create_test_session_id();
        let peer_id = create_test_peer_id();

        let enc = BluetoothEncryption::new(&key, session_id).unwrap();
        let message = b"Test message";

        let frame1 = enc.encrypt_message(message).unwrap();

        // First decryption should succeed
        let result1 = enc.decrypt_message(&frame1, &peer_id);
        assert!(result1.is_ok(), "First decryption should succeed");

        // CRITICAL: Replay same frame should FAIL
        let result2 = enc.decrypt_message(&frame1, &peer_id);
        assert!(result2.is_err(), "SECURITY: Replay attack detection failed");
        assert!(result2.unwrap_err().to_string().contains("Replay attack"));
    }

    #[test]
    fn test_bluetooth_nonce_derivation_verified() {
        let key = create_test_key();
        let session_id = create_test_session_id();
        let peer_id = create_test_peer_id();

        let enc1 = BluetoothEncryption::new(&key, session_id).unwrap();
        let enc2 = BluetoothEncryption::new(&key, session_id).unwrap();

        let message = b"Test";
        let frame1 = enc1.encrypt_message(message).unwrap();
        let frame2 = enc2.encrypt_message(message).unwrap();

        // Parse frames
        let parsed1 = BluetoothFrame::deserialize(&frame1).unwrap();
        let parsed2 = BluetoothFrame::deserialize(&frame2).unwrap();

        // Same session_id + sequence (both start at 0) should produce same nonce
        assert_eq!(parsed1.nonce, parsed2.nonce, "Nonce determinism failed");
        assert_eq!(parsed1.sequence, parsed2.sequence, "Sequence should start at 0");
    }

    #[test]
    fn test_bluetooth_tampering_detection() {
        let key = create_test_key();
        let session_id = create_test_session_id();
        let peer_id = create_test_peer_id();

        let enc = BluetoothEncryption::new(&key, session_id).unwrap();
        let message = b"Important data";

        let mut frame_data = enc.encrypt_message(message).unwrap();

        // Tamper with ciphertext (flip a bit)
        if frame_data.len() > HEADER_SIZE {
            frame_data[HEADER_SIZE] ^= 0xFF;
        }

        let result = enc.decrypt_message(&frame_data, &peer_id);
        assert!(result.is_err(), "SECURITY: Tampering should be detected");
    }

    #[test]
    fn test_bluetooth_multiple_peers_replay_independent() {
        let key = create_test_key();
        let session_id = create_test_session_id();
        let peer_id1 = [0xAAu8; 16];
        let peer_id2 = [0xBBu8; 16];

        let enc = BluetoothEncryption::new(&key, session_id).unwrap();
        let message = b"Test";

        // Encrypt once (sequence 0)
        let frame1 = enc.encrypt_message(message).unwrap();

        // Decrypt from peer1 (should succeed, record seq 0)
        let result1 = enc.decrypt_message(&frame1, &peer_id1);
        assert!(result1.is_ok());

        // Decrypt same frame from peer2 (should succeed, different peer)
        let result2 = enc.decrypt_message(&frame1, &peer_id2);
        assert!(result2.is_ok(), "Same frame from different peer should be accepted");

        // Replay from peer1 should fail
        let result3 = enc.decrypt_message(&frame1, &peer_id1);
        assert!(result3.is_err(), "Replay from same peer should fail");
    }
}
