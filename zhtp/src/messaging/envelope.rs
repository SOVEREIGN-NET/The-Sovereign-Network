//! Encrypted message envelope.
//!
//! The envelope is the wire format for all messages. Content is encrypted
//! with a ratcheted key (ChaCha20Poly1305). The envelope is signed with
//! the sender's Dilithium key for non-repudiation.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::ratchet::MessageKey;

/// Message content types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContentType {
    Text,
    Image,
    File,
    Voice,
    KeyExchange,
    KeyRatchet,
    ReadReceipt,
    GroupInvite,
}

/// Encrypted message envelope — the wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Protocol version
    pub version: u8,
    /// Sender DID
    pub sender_did: String,
    /// Recipient DID
    pub recipient_did: String,
    /// Unix timestamp
    pub timestamp: u64,
    /// Ratchet epoch
    pub epoch: u32,
    /// Message counter within epoch
    pub sequence: u64,
    /// Content type
    pub content_type: ContentType,
    /// Encrypted payload (ChaCha20Poly1305)
    pub ciphertext: Vec<u8>,
    /// Dilithium signature over hash(version || sender || recipient || timestamp || epoch || sequence || content_type || ciphertext)
    pub signature: Vec<u8>,
}

/// Plaintext message before encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContent {
    pub content_type: ContentType,
    pub body: Vec<u8>,
}

impl MessageEnvelope {
    /// Create an encrypted envelope from plaintext content.
    pub fn seal(
        sender_did: &str,
        recipient_did: &str,
        content: &MessageContent,
        message_key: &MessageKey,
    ) -> Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Serialize content
        let plaintext = bincode::serialize(content)
            .map_err(|e| anyhow!("Failed to serialize message content: {}", e))?;

        // Encrypt with ChaCha20Poly1305 using ratcheted key
        let ciphertext = lib_crypto::symmetric::chacha20::encrypt_data_with_ad_nonce(
            &plaintext,
            &message_key.key,
            &message_key.nonce,
            sender_did.as_bytes(),
        )
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok(Self {
            version: 1,
            sender_did: sender_did.to_string(),
            recipient_did: recipient_did.to_string(),
            timestamp: now,
            epoch: message_key.epoch,
            sequence: message_key.counter,
            content_type: content.content_type.clone(),
            ciphertext,
            signature: Vec::new(), // Signed by caller after construction
        })
    }

    /// Decrypt the envelope to recover plaintext content.
    pub fn open(&self, message_key: &MessageKey) -> Result<MessageContent> {
        let plaintext = lib_crypto::symmetric::chacha20::decrypt_data_with_ad_nonce(
            &self.ciphertext,
            &message_key.key,
            &message_key.nonce,
            self.sender_did.as_bytes(),
        )
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        bincode::deserialize(&plaintext)
            .map_err(|e| anyhow!("Failed to deserialize message content: {}", e))
    }

    /// Compute the signing hash for this envelope.
    pub fn signing_hash(&self) -> [u8; 32] {
        lib_crypto::hash_blake3(
            &[
                &[self.version],
                self.sender_did.as_bytes(),
                self.recipient_did.as_bytes(),
                &self.timestamp.to_le_bytes(),
                &self.epoch.to_le_bytes(),
                &self.sequence.to_le_bytes(),
                &bincode::serialize(&self.content_type).unwrap_or_default(),
                &self.ciphertext,
            ]
            .concat(),
        )
    }

    /// Sign the envelope with a Dilithium keypair.
    pub fn sign(&mut self, keypair: &lib_crypto::KeyPair) -> Result<()> {
        let hash = self.signing_hash();
        let sig = lib_crypto::sign_message(keypair, &hash)
            .map_err(|e| anyhow!("Failed to sign envelope: {}", e))?;
        self.signature = sig.signature;
        Ok(())
    }

    /// Verify the envelope signature against a Dilithium public key (raw bytes).
    pub fn verify_signature(&self, public_key_bytes: &[u8]) -> Result<bool> {
        let hash = self.signing_hash();
        lib_crypto::verify_signature(&hash, &self.signature, public_key_bytes)
    }

    /// Serialize to bytes for transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Failed to serialize envelope: {}", e))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Failed to deserialize envelope: {}", e))
    }
}
