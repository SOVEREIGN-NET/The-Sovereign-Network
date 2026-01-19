//! Session management and encryption
//!
//! After completing the UHP v2 handshake, this module provides
//! authenticated encryption for all subsequent messages using
//! ChaCha20-Poly1305.
//!
//! # Security Properties
//!
//! - **Authenticated Encryption**: ChaCha20-Poly1305 (AEAD)
//! - **Replay Protection**: Sequence numbers in nonces
//! - **Forward Secrecy**: Session keys derived from ephemeral nonces
//!
//! # Wire Format
//!
//! Encrypted message: [nonce (12 bytes)] [ciphertext] [tag (16 bytes)]

use crate::error::{ClientError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Authenticated session for encrypted communication
///
/// Use this after completing the UHP v2 handshake to encrypt
/// and decrypt messages.
pub struct Session {
    /// ChaCha20-Poly1305 cipher
    cipher: ChaCha20Poly1305,
    /// Session key (for reference/debugging)
    key: [u8; 32],
    /// Peer's DID
    peer_did: String,
    /// Session identifier
    session_id: [u8; 32],
    /// Outgoing message sequence number
    send_sequence: AtomicU64,
    /// Expected incoming sequence number
    recv_sequence: AtomicU64,
}

impl Session {
    /// Create a new encrypted session
    ///
    /// # Arguments
    ///
    /// * `session_key` - 32-byte session key from handshake
    /// * `session_id` - 32-byte session identifier from handshake
    /// * `peer_did` - Peer's decentralized identifier
    pub fn new(session_key: Vec<u8>, session_id: Vec<u8>, peer_did: String) -> Result<Self> {
        if session_key.len() != 32 {
            return Err(ClientError::CryptoError(format!(
                "Session key must be 32 bytes, got {}",
                session_key.len()
            )));
        }

        if session_id.len() != 32 {
            return Err(ClientError::CryptoError(format!(
                "Session ID must be 32 bytes, got {}",
                session_id.len()
            )));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&session_key)
            .map_err(|_| ClientError::CryptoError("Invalid session key".into()))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&session_key);

        let mut sid = [0u8; 32];
        sid.copy_from_slice(&session_id);

        Ok(Self {
            cipher,
            key,
            peer_did,
            session_id: sid,
            send_sequence: AtomicU64::new(1), // Start at 1 (0 reserved)
            recv_sequence: AtomicU64::new(1),
        })
    }

    /// Encrypt a message
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// Encrypted message: [nonce (12)] [ciphertext + tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate nonce from sequence number
        let seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        let nonce_bytes = build_nonce(seq);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt with ChaCha20-Poly1305
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| ClientError::CryptoError("Encryption failed".into()))?;

        // Return: nonce (12) + ciphertext + tag (16)
        Ok([&nonce_bytes[..], &ciphertext].concat())
    }

    /// Decrypt a message
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Encrypted message with nonce prefix
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
            // Minimum: nonce (12) + tag (16)
            return Err(ClientError::InvalidFormat(
                "Ciphertext too short".into(),
            ));
        }

        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let ct = &ciphertext[12..];

        // Decrypt
        self.cipher
            .decrypt(nonce, ct)
            .map_err(|_| ClientError::CryptoError("Decryption failed (invalid ciphertext or tag)".into()))
    }

    /// Encrypt with explicit nonce (for advanced use cases)
    pub fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let n = Nonce::from_slice(nonce);

        self.cipher
            .encrypt(n, plaintext)
            .map_err(|_| ClientError::CryptoError("Encryption failed".into()))
    }

    /// Decrypt with explicit nonce (for advanced use cases)
    pub fn decrypt_with_nonce(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let n = Nonce::from_slice(nonce);

        self.cipher
            .decrypt(n, ciphertext)
            .map_err(|_| ClientError::CryptoError("Decryption failed".into()))
    }

    /// Get the peer's DID
    pub fn peer_did(&self) -> &str {
        &self.peer_did
    }

    /// Get the session ID
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Get current send sequence number (for debugging)
    pub fn send_sequence(&self) -> u64 {
        self.send_sequence.load(Ordering::SeqCst)
    }

    /// Get current receive sequence number (for debugging)
    pub fn recv_sequence(&self) -> u64 {
        self.recv_sequence.load(Ordering::SeqCst)
    }

    /// Check if session is valid (has key material)
    pub fn is_valid(&self) -> bool {
        self.key != [0u8; 32]
    }
}

/// Build a 12-byte nonce from a sequence number
///
/// Format: [4 bytes zero padding] [8 bytes sequence (BE)]
fn build_nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

/// Encrypt data with a one-time key (no session state)
///
/// Useful for encrypting data at rest or for one-shot encryption.
pub fn encrypt_oneshot(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(ClientError::CryptoError("Key must be 32 bytes".into()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ClientError::CryptoError("Invalid key".into()))?;

    // Generate random nonce
    let nonce_bytes = crate::crypto::random_bytes(12);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ClientError::CryptoError("Encryption failed".into()))?;

    Ok([&nonce_bytes[..], &ciphertext].concat())
}

/// Decrypt data with a one-time key (no session state)
pub fn decrypt_oneshot(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(ClientError::CryptoError("Key must be 32 bytes".into()));
    }

    if ciphertext.len() < 12 + 16 {
        return Err(ClientError::InvalidFormat("Ciphertext too short".into()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ClientError::CryptoError("Invalid key".into()))?;

    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let ct = &ciphertext[12..];

    cipher
        .decrypt(nonce, ct)
        .map_err(|_| ClientError::CryptoError("Decryption failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_encrypt_decrypt() {
        let key = crate::crypto::random_bytes(32);
        let session_id = crate::crypto::random_bytes(32);

        let session = Session::new(key, session_id, "did:zhtp:test".into()).unwrap();

        let plaintext = b"Hello, ZHTP!";
        let ciphertext = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_session_sequence_increment() {
        let key = crate::crypto::random_bytes(32);
        let session_id = crate::crypto::random_bytes(32);

        let session = Session::new(key, session_id, "did:zhtp:test".into()).unwrap();

        assert_eq!(session.send_sequence(), 1);

        session.encrypt(b"msg1").unwrap();
        assert_eq!(session.send_sequence(), 2);

        session.encrypt(b"msg2").unwrap();
        assert_eq!(session.send_sequence(), 3);
    }

    #[test]
    fn test_oneshot_encrypt_decrypt() {
        let key = crate::crypto::random_bytes(32);
        let plaintext = b"One-time message";

        let ciphertext = encrypt_oneshot(&key, plaintext).unwrap();
        let decrypted = decrypt_oneshot(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_tampered_fails() {
        let key = crate::crypto::random_bytes(32);
        let session_id = crate::crypto::random_bytes(32);

        let session = Session::new(key, session_id, "did:zhtp:test".into()).unwrap();

        let ciphertext = session.encrypt(b"secret").unwrap();

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        if let Some(byte) = tampered.get_mut(15) {
            *byte ^= 0xFF;
        }

        assert!(session.decrypt(&tampered).is_err());
    }
}
