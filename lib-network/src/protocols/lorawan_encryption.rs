//! LoRaWAN Encryption Adapter with Frame Counter Domain Separation
//!
//! Implements **ChaCha20Poly1305 AEAD** encryption for LoRaWAN with:
//! - Frame counter aware AAD for message sequencing
//! - Device EUI based isolation
//! - Stateless encryption (no locks required)
//! - Comprehensive cryptographic domain separation
//!
//! # Architecture: Functional Core / Imperative Shell (FCIS)
//!
//! **Functional Core** (Pure Cryptography):
//! - `build_aad()`: Deterministic AAD construction from frame counter and device EUI
//! - Direct ChaCha20Poly1305 encryption/decryption
//!
//! **Imperative Shell** (Observability & Operations):
//! - `LoRaWANEncryption` struct with frame counter aware interface
//! - Logging and error context
//! - ProtocolEncryption trait implementation
//!
//! # Security Properties
//!
//! - **Domain Separation**: AAD includes protocol, version, device_eui, frame_counter
//! - **Frame Counter Protection**: Different frame counters produce different AAD
//! - **Stateless**: No sequence tracking required (LoRaWAN provides frame counter)
//! - **Device Isolation**: Different LoRaWAN devices have different AAD
//! - **Cross-protocol Isolation**: Different protocols can't decrypt each other's messages
//!
//! # AAD Format
//!
//! ```text
//! lorawan\0v1\0<device_eui (8 bytes)>\0<frame_counter (2 bytes)>
//! ```
//!
//! Example for device EUI 70:B3:D5:7E:D0:02:00:00 with frame counter 42:
//! ```text
//! "lorawan\0v1\0\x70\xB3\xD5\x7E\xD0\x02\x00\x00\x00\x2A"
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use lib_network::protocols::lorawan_encryption::LoRaWANEncryption;
//!
//! let device_eui = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
//! let app_key = [0x11u8; 32];
//!
//! let enc = LoRaWANEncryption::new(&app_key, device_eui)?;
//!
//! // Encrypt with frame counter for domain separation
//! let ciphertext = enc.encrypt_payload(b"LoRaWAN payload", 42)?;
//!
//! // Decrypt (frame counter must match)
//! let plaintext = enc.decrypt_payload(&ciphertext, 42)?;
//! ```

use crate::encryption::{ProtocolEncryption, ChaCha20Poly1305Encryption, EncryptionStats};
use anyhow::Result;
use tracing::{debug, warn};

// ============================================================================
// FUNCTIONAL CORE: Pure Cryptography
// ============================================================================

mod core {
    /// Build AAD (Associated Authenticated Data) for domain separation
    ///
    /// Format: `lorawan\0v1\0<device_eui>\0<frame_counter>`
    /// This ensures:
    /// - Different LoRaWAN devices have different AAD (device_eui separation)
    /// - Different messages from same device have different AAD (frame_counter separation)
    /// - LoRaWAN protocol is isolated from other protocols (protocol_id separation)
    pub fn build_aad(device_eui: &[u8; 8], frame_counter: u16) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"lorawan");     // protocol_id
        aad.push(0x00);                         // separator
        aad.extend_from_slice(b"v1");           // version
        aad.push(0x00);                         // separator
        aad.extend_from_slice(device_eui);     // device_eui (8 bytes)
        aad.push(0x00);                         // separator
        aad.extend_from_slice(&frame_counter.to_be_bytes()); // frame_counter (2 bytes)
        aad
    }
}

// ============================================================================
// IMPERATIVE SHELL: Observability & Frame Counter Interface
// ============================================================================

mod shell {
    use super::*;

    /// LoRaWAN encryption with frame counter aware AAD
    pub struct LoRaWANEncryption {
        /// Core encryption (ChaCha20Poly1305)
        enc: ChaCha20Poly1305Encryption,
        /// Device EUI for LoRaWAN device identification
        device_eui: [u8; 8],
    }

    impl LoRaWANEncryption {
        /// Create new LoRaWAN encryption instance
        ///
        /// # Arguments
        /// - `app_key`: 32-byte ChaCha20Poly1305 key (derived from LoRaWAN AppKey)
        /// - `device_eui`: 8-byte device identifier for EUI isolation
        pub fn new(app_key: &[u8; 32], device_eui: [u8; 8]) -> Result<Self> {
            Ok(Self {
                enc: ChaCha20Poly1305Encryption::new("lorawan", app_key)?,
                device_eui,
            })
        }

        /// Encrypt a LoRaWAN payload with frame counter based AAD
        ///
        /// # Arguments
        /// - `plaintext`: Message payload to encrypt
        /// - `frame_counter`: LoRaWAN frame counter for domain separation
        ///   Different frame counters produce different AAD, preventing replay attacks
        pub fn encrypt_payload(&self, plaintext: &[u8], frame_counter: u16) -> Result<Vec<u8>> {
            debug!(
                device_eui = hex::encode(&self.device_eui),
                frame_counter = frame_counter,
                plaintext_len = plaintext.len(),
                "Encrypting LoRaWAN payload with frame counter domain separation"
            );

            let aad = core::build_aad(&self.device_eui, frame_counter);

            // CORE: Pure encryption
            let ciphertext = self.enc.encrypt(plaintext, &aad)?;

            debug!(
                device_eui = hex::encode(&self.device_eui),
                frame_counter = frame_counter,
                ciphertext_len = ciphertext.len(),
                "LoRaWAN encryption successful"
            );

            Ok(ciphertext)
        }

        /// Decrypt a LoRaWAN payload with frame counter based AAD
        ///
        /// # Arguments
        /// - `ciphertext`: Encrypted message to decrypt
        /// - `frame_counter`: LoRaWAN frame counter used during encryption
        ///   Must match the frame counter used for encryption, or decryption fails
        pub fn decrypt_payload(&self, ciphertext: &[u8], frame_counter: u16) -> Result<Vec<u8>> {
            debug!(
                device_eui = hex::encode(&self.device_eui),
                frame_counter = frame_counter,
                ciphertext_len = ciphertext.len(),
                "Decrypting LoRaWAN payload"
            );

            let aad = core::build_aad(&self.device_eui, frame_counter);

            // CORE: Pure decryption
            let plaintext = self.enc.decrypt(ciphertext, &aad)?;

            debug!(
                device_eui = hex::encode(&self.device_eui),
                frame_counter = frame_counter,
                plaintext_len = plaintext.len(),
                "LoRaWAN decryption successful"
            );

            Ok(plaintext)
        }

        /// Get the device EUI
        pub fn device_eui(&self) -> &[u8; 8] {
            &self.device_eui
        }
    }

    impl ProtocolEncryption for LoRaWANEncryption {
        fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            // Trait-level encryption: direct pass-through with provided AAD
            debug!("encrypt() called - using trait-level AAD");
            self.enc.encrypt(plaintext, aad)
        }

        fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
            // Trait-level decryption: direct pass-through with provided AAD
            debug!("decrypt() called - using trait-level AAD");
            self.enc.decrypt(ciphertext, aad)
        }

        fn protocol(&self) -> &str {
            "lorawan"
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

pub use shell::LoRaWANEncryption;

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aad_construction() {
        let device_eui = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
        let aad = core::build_aad(&device_eui, 42);

        // Verify structure: "lorawan\0v1\0<device_eui>\0<frame_counter>"
        assert!(aad.starts_with(b"lorawan"));
        assert!(aad.contains(&0x00)); // Contains separators
        assert_eq!(aad.len(), 7 + 1 + 2 + 1 + 8 + 1 + 2); // 22 bytes
    }

    #[test]
    fn test_aad_determinism() {
        let device_eui = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
        let aad1 = core::build_aad(&device_eui, 42);
        let aad2 = core::build_aad(&device_eui, 42);

        assert_eq!(aad1, aad2);
    }

    #[test]
    fn test_aad_device_eui_separation() {
        let device_eui1 = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
        let device_eui2 = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x01];

        let aad1 = core::build_aad(&device_eui1, 42);
        let aad2 = core::build_aad(&device_eui2, 42);

        assert_ne!(aad1, aad2);
    }

    #[test]
    fn test_aad_frame_counter_separation() {
        let device_eui = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
        let aad1 = core::build_aad(&device_eui, 41);
        let aad2 = core::build_aad(&device_eui, 42);

        assert_ne!(aad1, aad2);
    }

    #[test]
    fn test_lorawan_encrypt_decrypt() {
        let device_eui = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
        let app_key = [0x22u8; 32];

        let enc = LoRaWANEncryption::new(&app_key, device_eui).unwrap();

        let payload = b"LoRaWAN test payload";
        let frame_counter = 42u16;

        let ciphertext = enc.encrypt_payload(payload, frame_counter).unwrap();
        assert_ne!(&ciphertext[..], payload);

        let plaintext = enc.decrypt_payload(&ciphertext, frame_counter).unwrap();
        assert_eq!(&plaintext[..], payload);
    }

    #[test]
    fn test_lorawan_frame_counter_mismatch() {
        let device_eui = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
        let app_key = [0x33u8; 32];

        let enc = LoRaWANEncryption::new(&app_key, device_eui).unwrap();

        let payload = b"LoRaWAN test";
        let ciphertext = enc.encrypt_payload(payload, 42).unwrap();

        // Try to decrypt with different frame counter
        let result = enc.decrypt_payload(&ciphertext, 43);
        assert!(result.is_err(), "Decryption with wrong frame counter should fail");
    }

    #[test]
    fn test_lorawan_tampering_detection() {
        let device_eui = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
        let app_key = [0x44u8; 32];

        let enc = LoRaWANEncryption::new(&app_key, device_eui).unwrap();

        let payload = b"Important LoRaWAN data";
        let mut ciphertext = enc.encrypt_payload(payload, 42).unwrap();

        // Tamper with ciphertext (flip a bit in the middle)
        if ciphertext.len() > 5 {
            ciphertext[5] ^= 0x01;
        }

        // Decryption should fail due to AEAD tag verification
        let result = enc.decrypt_payload(&ciphertext, 42);
        assert!(result.is_err(), "Tampering should be detected by AEAD tag");
    }

    #[test]
    fn test_lorawan_multiple_devices() {
        let app_key = [0x55u8; 32];
        let device_eui1 = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x00];
        let device_eui2 = [0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x02, 0x00, 0x01];

        let enc1 = LoRaWANEncryption::new(&app_key, device_eui1).unwrap();
        let enc2 = LoRaWANEncryption::new(&app_key, device_eui2).unwrap();

        let payload = b"Device message";
        let frame_counter = 42u16;

        // Device 1 encrypts with its EUI
        let ct1 = enc1.encrypt_payload(payload, frame_counter).unwrap();

        // Device 2 cannot decrypt device 1's message (different AAD due to different device_eui)
        let result = enc2.decrypt_payload(&ct1, frame_counter);
        assert!(result.is_err(), "Different devices should not be able to decrypt each other's messages");
    }
}
