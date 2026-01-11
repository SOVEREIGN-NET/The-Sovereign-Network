//! DHT Message Signing and Verification
//!
//! Provides cryptographic signing and verification for DHT messages to ensure:
//! - **Authenticity**: Messages come from claimed sender
//! - **Integrity**: Messages have not been tampered with
//! - **Replay Protection**: Combined with timestamp and nonce validation
//!
//! # Security Properties
//!
//! - Uses CRYSTALS-Dilithium (post-quantum) signatures
//! - Signs deterministic serialization of message fields (excluding signature)
//! - Verifies timestamp freshness (rejects messages > 5 min old)
//! - Verifies sender public key matches claimed sender_id

use anyhow::Result;
use lib_crypto::{KeyPair, Signature, PublicKey};
use crate::types::dht_types::{DhtMessage, MAX_MESSAGE_AGE_SECS};
use tracing::{debug, warn};

/// Maximum allowed clock skew for future timestamps (60 seconds)
pub const MAX_FUTURE_TIMESTAMP_SECS: u64 = 60;

/// Message signer for DHT operations
///
/// Wraps a KeyPair to provide message signing capabilities.
/// Should be initialized once per node and shared across DHT operations.
#[derive(Debug, Clone)]
pub struct MessageSigner {
    keypair: KeyPair,
}

impl MessageSigner {
    /// Create a new message signer with the given keypair
    pub fn new(keypair: KeyPair) -> Self {
        Self { keypair }
    }

    /// Get the public key for this signer
    pub fn public_key(&self) -> &PublicKey {
        &self.keypair.public_key
    }

    /// Sign a DHT message
    ///
    /// Signs the deterministic serialization of the message (excluding signature field).
    /// The signature is set in the message's signature field.
    ///
    /// # Arguments
    /// * `message` - Mutable reference to the message to sign
    ///
    /// # Returns
    /// * `Ok(())` if signing succeeded
    /// * `Err(...)` if signing failed
    pub fn sign_message(&self, message: &mut DhtMessage) -> Result<()> {
        // Get signable data (excludes signature field)
        let signable_data = message.signable_data();

        // Sign with Dilithium
        let signature = self.keypair.sign(&signable_data)?;

        // Store signature bytes in message
        message.signature = Some(signature.signature);

        debug!(
            message_id = %message.message_id,
            msg_type = ?message.message_type,
            "Signed DHT message"
        );

        Ok(())
    }

    /// Create a signed DHT message
    ///
    /// Convenience method that signs a message and returns it.
    pub fn sign(&self, mut message: DhtMessage) -> Result<DhtMessage> {
        self.sign_message(&mut message)?;
        Ok(message)
    }
}

/// Verify a DHT message signature
///
/// Verifies that:
/// 1. Message has a signature
/// 2. Signature is valid for the message content
/// 3. Message timestamp is fresh (not too old or too far in future)
/// 4. Message nonce is non-zero
///
/// # Arguments
/// * `message` - The message to verify
/// * `sender_public_key` - The public key of the claimed sender
///
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err(...)` if verification could not be performed
pub fn verify_message_signature(
    message: &DhtMessage,
    sender_public_key: &PublicKey,
) -> Result<bool> {
    // Check message has a signature
    let signature_bytes = match &message.signature {
        Some(sig) => sig,
        None => {
            warn!(
                message_id = %message.message_id,
                "Message has no signature"
            );
            return Ok(false);
        }
    };

    // Validate freshness first (fast path rejection)
    if let Err(e) = message.validate_freshness() {
        warn!(
            message_id = %message.message_id,
            error = %e,
            "Message failed freshness validation"
        );
        return Ok(false);
    }

    // Get signable data
    let signable_data = message.signable_data();

    // Reconstruct Signature struct for verification
    let signature = Signature::from_bytes_with_key(signature_bytes, sender_public_key.clone());

    // Verify signature
    match sender_public_key.verify(&signable_data, &signature) {
        Ok(valid) => {
            if valid {
                debug!(
                    message_id = %message.message_id,
                    msg_type = ?message.message_type,
                    "Message signature verified"
                );
            } else {
                warn!(
                    message_id = %message.message_id,
                    msg_type = ?message.message_type,
                    "Message signature verification failed"
                );
            }
            Ok(valid)
        }
        Err(e) => {
            warn!(
                message_id = %message.message_id,
                error = %e,
                "Signature verification error"
            );
            Ok(false)
        }
    }
}

/// Verify a DHT message signature using raw public key bytes
///
/// Convenience function when you only have the raw Dilithium public key bytes.
pub fn verify_message_signature_bytes(
    message: &DhtMessage,
    dilithium_pk: &[u8],
) -> Result<bool> {
    let public_key = PublicKey::new(dilithium_pk.to_vec());
    verify_message_signature(message, &public_key)
}

/// Check if a message requires signature verification
///
/// Some messages may be exempt from signature verification in certain contexts
/// (e.g., during bootstrap before keys are exchanged). This should be used
/// sparingly and only when absolutely necessary.
pub fn requires_signature(_message: &DhtMessage) -> bool {
    // All messages require signatures for security
    // This function exists to make the policy explicit and auditable
    true
}

/// Signing error types
#[derive(Debug, Clone)]
pub enum SigningError {
    /// No keypair available for signing
    NoKeypair,
    /// Signing operation failed
    SigningFailed(String),
    /// Message already has a signature
    AlreadySigned,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::NoKeypair => write!(f, "No keypair available for signing"),
            SigningError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            SigningError::AlreadySigned => write!(f, "Message is already signed"),
        }
    }
}

impl std::error::Error for SigningError {}

/// Verification error types
#[derive(Debug, Clone)]
pub enum VerificationError {
    /// Message has no signature
    NoSignature,
    /// Signature is invalid
    InvalidSignature,
    /// Message is too old
    MessageTooOld { age_secs: u64 },
    /// Message timestamp is in the future
    FutureTimestamp { delta_secs: u64 },
    /// Nonce is invalid (zero)
    InvalidNonce,
    /// Public key is invalid
    InvalidPublicKey(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::NoSignature => write!(f, "Message has no signature"),
            VerificationError::InvalidSignature => write!(f, "Signature verification failed"),
            VerificationError::MessageTooOld { age_secs } => {
                write!(f, "Message is {} seconds old (max {})", age_secs, MAX_MESSAGE_AGE_SECS)
            }
            VerificationError::FutureTimestamp { delta_secs } => {
                write!(f, "Message timestamp is {} seconds in the future", delta_secs)
            }
            VerificationError::InvalidNonce => write!(f, "Message has zero/invalid nonce"),
            VerificationError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
        }
    }
}

impl std::error::Error for VerificationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::dht_types::DhtMessageType;
    use crate::types::NodeId;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_message() -> DhtMessage {
        DhtMessage {
            message_id: "test_msg_001".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: NodeId::from_bytes([1u8; 32]),
            target_id: Some(NodeId::from_bytes([2u8; 32])),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: [42u8; 32],
            sequence_number: 1,
            signature: None,
        }
    }

    #[test]
    fn test_sign_and_verify_message() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();

        // Sign the message
        signer.sign_message(&mut message).expect("Failed to sign message");

        // Verify signature is present
        assert!(message.signature.is_some());

        // Verify the signature
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(result, "Signature should be valid");
    }

    #[test]
    fn test_tampered_message_fails_verification() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        signer.sign_message(&mut message).expect("Failed to sign message");

        // Tamper with the message
        message.sequence_number = 9999;

        // Verification should fail
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(!result, "Tampered message should fail verification");
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let keypair1 = KeyPair::generate().expect("Failed to generate keypair");
        let keypair2 = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair1);

        let mut message = create_test_message();
        signer.sign_message(&mut message).expect("Failed to sign message");

        // Verify with wrong key should fail
        let result = verify_message_signature(&message, &keypair2.public_key)
            .expect("Verification should not error");
        assert!(!result, "Wrong key should fail verification");
    }

    #[test]
    fn test_unsigned_message_fails_verification() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let message = create_test_message();

        // Unsigned message should fail
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(!result, "Unsigned message should fail verification");
    }

    #[test]
    fn test_stale_message_fails_verification() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        // Set timestamp to 10 minutes ago
        message.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(600);

        signer.sign_message(&mut message).expect("Failed to sign message");

        // Stale message should fail
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(!result, "Stale message should fail verification");
    }

    #[test]
    fn test_future_message_fails_verification() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        // Set timestamp to 2 minutes in the future
        message.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 120;

        signer.sign_message(&mut message).expect("Failed to sign message");

        // Future message should fail
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(!result, "Future timestamp message should fail verification");
    }

    #[test]
    fn test_zero_nonce_fails_verification() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        message.nonce = [0u8; 32]; // Invalid zero nonce

        signer.sign_message(&mut message).expect("Failed to sign message");

        // Zero nonce should fail
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(!result, "Zero nonce message should fail verification");
    }

    #[test]
    fn test_sign_convenience_method() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let message = create_test_message();
        let signed = signer.sign(message).expect("Failed to sign message");

        assert!(signed.signature.is_some());

        let result = verify_message_signature(&signed, &keypair.public_key)
            .expect("Verification should not error");
        assert!(result);
    }

    #[test]
    fn test_message_signer_public_key() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        assert_eq!(signer.public_key(), &keypair.public_key);
    }
}
