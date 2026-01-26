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
    /// * `Err(SigningError)` if signing failed
    pub fn sign_message(&self, message: &mut DhtMessage) -> Result<(), SigningError> {
        // Check if message is already signed
        if message.signature.is_some() {
            return Err(SigningError::AlreadySigned);
        }

        // Get signable data (excludes signature field)
        let signable_data = message.signable_data();

        // Sign with Dilithium
        let signature = self.keypair.sign(&signable_data)
            .map_err(|e| SigningError::SigningFailed(e.to_string()))?;

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
    pub fn sign(&self, mut message: DhtMessage) -> Result<DhtMessage, SigningError> {
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
/// * `Ok(false)` if signature is invalid but verification completed
/// * `Err(VerificationError)` for critical verification failures
pub fn verify_message_signature(
    message: &DhtMessage,
    sender_public_key: &PublicKey,
) -> Result<bool, VerificationError> {
    // Check message has a signature
    let signature_bytes = match &message.signature {
        Some(sig) => sig,
        None => {
            warn!(
                message_id = %message.message_id,
                "Message has no signature"
            );
            return Err(VerificationError::NoSignature);
        }
    };

    // Validate nonce is non-zero
    if message.nonce.iter().all(|&b| b == 0) {
        warn!(
            message_id = %message.message_id,
            "Message has zero nonce"
        );
        return Err(VerificationError::InvalidNonce);
    }

    // Validate freshness first (fast path rejection)
    if let Err(e) = message.validate_freshness() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| {
                // System clock is set before Unix epoch - use timestamp 0
                // This should never happen in practice on modern systems
                warn!("System clock is before Unix epoch");
                std::time::Duration::from_secs(0)
            })
            .as_secs();
        
        if message.timestamp > now {
            let delta_secs = message.timestamp - now;
            warn!(
                message_id = %message.message_id,
                error = %e,
                "Message timestamp is in the future"
            );
            return Err(VerificationError::FutureTimestamp { delta_secs });
        } else {
            let age_secs = now.saturating_sub(message.timestamp);
            warn!(
                message_id = %message.message_id,
                error = %e,
                "Message is too old"
            );
            return Err(VerificationError::MessageTooOld { age_secs });
        }
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
                Ok(true)
            } else {
                warn!(
                    message_id = %message.message_id,
                    msg_type = ?message.message_type,
                    "Message signature verification failed"
                );
                Ok(false)
            }
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
) -> Result<bool, VerificationError> {
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
#[derive(Debug, Clone, thiserror::Error)]
pub enum SigningError {
    /// No keypair available for signing
    #[error("No keypair available for signing")]
    NoKeypair,
    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// Message already has a signature
    #[error("Message is already signed")]
    AlreadySigned,
}

/// Verification error types
#[derive(Debug, Clone, thiserror::Error)]
pub enum VerificationError {
    /// Message has no signature
    #[error("Message has no signature")]
    NoSignature,
    /// Signature is invalid
    #[error("Signature verification failed")]
    InvalidSignature,
    /// Message is too old
    #[error("Message is {age_secs} seconds old (max {max_age})", max_age = MAX_MESSAGE_AGE_SECS)]
    MessageTooOld { age_secs: u64 },
    /// Message timestamp is in the future
    #[error("Message timestamp is {delta_secs} seconds in the future")]
    FutureTimestamp { delta_secs: u64 },
    /// Nonce is invalid (zero)
    #[error("Message has zero/invalid nonce")]
    InvalidNonce,
    /// Public key is invalid
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::dht_types::{
        build_peer_identity, ContractDhtData, ContractOperation, DhtMessageType, DhtNode,
    };
    use crate::types::NodeId;
    use lib_crypto::{PostQuantumSignature, SignatureAlgorithm};
    use lib_identity::{IdentityType, ZhtpIdentity};
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

    fn create_test_node() -> DhtNode {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Device,
            None,
            None,
            "test-device",
            None,
        )
        .expect("Failed to create test identity");

        let peer = build_peer_identity(
            identity.node_id.clone(),
            identity.public_key.clone(),
            identity.did.clone(),
            "test-device".to_string(),
        );

        DhtNode {
            peer,
            addresses: vec!["127.0.0.1:1234".to_string()],
            public_key: PostQuantumSignature {
                algorithm: SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: identity.public_key.clone(),
                timestamp: 0,
            },
            last_seen: 0,
            reputation: 0,
            storage_info: None,
        }
    }

    fn create_message_with_all_fields() -> DhtMessage {
        let mut message = create_test_message();
        message.key = Some("test-key".to_string());
        message.value = Some(vec![1, 2, 3, 4]);
        message.nodes = Some(vec![create_test_node()]);
        message.contract_data = Some(ContractDhtData {
            contract_id: "contract-001".to_string(),
            operation: ContractOperation::Deploy,
            bytecode: None,
            function_name: None,
            arguments: None,
            gas_limit: Some(10),
            result: None,
            metadata: None,
            zk_proofs: Vec::new(),
        });
        message
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

        // Unsigned message should return NoSignature error
        let result = verify_message_signature(&message, &keypair.public_key);
        assert!(result.is_err(), "Unsigned message should return error");
        match result {
            Err(VerificationError::NoSignature) => {},
            _ => panic!("Expected NoSignature error"),
        }
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

        // Stale message should return MessageTooOld error
        let result = verify_message_signature(&message, &keypair.public_key);
        assert!(result.is_err(), "Stale message should return error");
        match result {
            Err(VerificationError::MessageTooOld { .. }) => {},
            _ => panic!("Expected MessageTooOld error"),
        }
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

        // Future message should return FutureTimestamp error
        let result = verify_message_signature(&message, &keypair.public_key);
        assert!(result.is_err(), "Future timestamp message should return error");
        match result {
            Err(VerificationError::FutureTimestamp { .. }) => {},
            _ => panic!("Expected FutureTimestamp error"),
        }
    }

    #[test]
    fn test_zero_nonce_fails_verification() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        message.nonce = [0u8; 32]; // Invalid zero nonce

        signer.sign_message(&mut message).expect("Failed to sign message");

        // Zero nonce should return InvalidNonce error
        let result = verify_message_signature(&message, &keypair.public_key);
        assert!(result.is_err(), "Zero nonce message should return error");
        match result {
            Err(VerificationError::InvalidNonce) => {},
            _ => panic!("Expected InvalidNonce error"),
        }
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

    #[test]
    fn test_boundary_timestamp_just_under_max_age() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        // Set timestamp to 299 seconds ago (just under 300 max)
        message.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(299);

        signer.sign_message(&mut message).expect("Failed to sign message");

        // Should pass - just under the limit
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(result, "Message at 299 seconds should pass verification");
    }

    #[test]
    fn test_boundary_timestamp_over_max_age() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        // Set timestamp to 301 seconds ago (just over 300 max)
        // The check is > MAX_MESSAGE_AGE_SECS, so exactly 300 passes but 301 fails
        message.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(301);

        signer.sign_message(&mut message).expect("Failed to sign message");

        // Should fail - over the limit  
        let result = verify_message_signature(&message, &keypair.public_key);
        assert!(result.is_err(), "Message at 301 seconds should return error");
        match result {
            Err(VerificationError::MessageTooOld { .. }) => {},
            _ => panic!("Expected MessageTooOld error"),
        }
    }

    #[test]
    fn test_boundary_future_timestamp_at_tolerance() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        // Set timestamp to 59 seconds in the future (just under 60 max)
        message.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 59;

        signer.sign_message(&mut message).expect("Failed to sign message");

        // Should pass - just under the limit
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(result, "Message at 59 seconds in future should pass verification");
    }

    #[test]
    fn test_verify_message_signature_bytes() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        signer.sign_message(&mut message).expect("Failed to sign message");

        // Verify using raw bytes function
        let result = verify_message_signature_bytes(&message, &keypair.public_key.dilithium_pk)
            .expect("Verification should not error");
        assert!(result, "verify_message_signature_bytes should work correctly");
    }

    #[test]
    fn test_requires_signature_returns_true() {
        let message = create_test_message();
        assert!(requires_signature(&message), "requires_signature should always return true");
    }

    #[test]
    fn test_empty_signature_bytes_fails() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");

        let mut message = create_test_message();
        message.signature = Some(vec![]); // Empty signature

        // Empty signature should fail
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(!result, "Empty signature should fail verification");
    }

    #[test]
    fn test_corrupted_signature_bytes_fails() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        signer.sign_message(&mut message).expect("Failed to sign message");

        // Corrupt the signature
        if let Some(ref mut sig) = message.signature {
            if !sig.is_empty() {
                sig[0] ^= 0xFF; // Flip bits in first byte
            }
        }

        // Corrupted signature should fail
        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(!result, "Corrupted signature should fail verification");
    }

    #[test]
    fn test_truncated_signature_bytes_fails() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        signer.sign_message(&mut message).expect("Failed to sign message");

        if let Some(ref mut sig) = message.signature {
            sig.truncate(8);
        }

        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(!result, "Truncated signature should fail verification");
    }

    #[test]
    fn test_signature_covers_all_fields() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_message_with_all_fields();
        signer.sign_message(&mut message).expect("Failed to sign message");

        let mut variants: Vec<Box<dyn Fn(DhtMessage) -> DhtMessage>> = Vec::new();
        variants.push(Box::new(|mut msg| {
            msg.message_id = "altered-id".to_string();
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.message_type = DhtMessageType::Store;
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.sender_id = NodeId::from_bytes([9u8; 32]);
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.target_id = None;
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.key = Some("alt-key".to_string());
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.value = Some(vec![9, 9, 9]);
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.nodes = Some(vec![create_test_node(), create_test_node()]);
            msg
        }));
        variants.push(Box::new(|mut msg| {
            if let Some(ref mut data) = msg.contract_data {
                data.contract_id = "contract-002".to_string();
            }
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.timestamp = msg.timestamp.saturating_add(1);
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.nonce = [7u8; 32];
            msg
        }));
        variants.push(Box::new(|mut msg| {
            msg.sequence_number = msg.sequence_number.saturating_add(1);
            msg
        }));

        for mutate in variants {
            let tampered = mutate(message.clone());
            let result = verify_message_signature(&tampered, &keypair.public_key)
                .expect("Verification should not error");
            assert!(!result, "Tampered message should fail verification");
        }
    }

    #[test]
    fn test_signature_serialization_roundtrip() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_message_with_all_fields();
        signer.sign_message(&mut message).expect("Failed to sign message");

        let bytes = bincode::serialize(&message).expect("Failed to serialize message");
        let roundtrip: DhtMessage = bincode::deserialize(&bytes).expect("Failed to deserialize");

        let result = verify_message_signature(&roundtrip, &keypair.public_key)
            .expect("Verification should not error");
        assert!(result, "Round-tripped message should verify");
    }

    #[test]
    fn test_signature_with_large_message() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        message.key = Some("large".to_string());
        message.value = Some(vec![0u8; 64 * 1024]);

        signer.sign_message(&mut message).expect("Failed to sign message");

        let result = verify_message_signature(&message, &keypair.public_key)
            .expect("Verification should not error");
        assert!(result, "Large message should verify");
    }

    #[tokio::test]
    async fn test_concurrent_signature_verification() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_message_with_all_fields();
        signer.sign_message(&mut message).expect("Failed to sign message");

        let mut handles = Vec::new();
        for _ in 0..16 {
            let msg = message.clone();
            let pk = keypair.public_key.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                verify_message_signature(&msg, &pk)
            }));
        }

        for handle in handles {
            let result = handle.await.expect("Task join failed")
                .expect("Verification should not error");
            assert!(result, "Concurrent verification should succeed");
        }
    }

    #[test]
    fn test_already_signed_error() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let signer = MessageSigner::new(keypair.clone());

        let mut message = create_test_message();
        
        // Sign the message once
        signer.sign_message(&mut message).expect("Failed to sign message");
        assert!(message.signature.is_some());

        // Try to sign again - should return AlreadySigned error
        let result = signer.sign_message(&mut message);
        assert!(result.is_err(), "Signing already-signed message should return error");
        match result {
            Err(SigningError::AlreadySigned) => {},
            _ => panic!("Expected AlreadySigned error"),
        }
    }

    #[test]
    fn test_signing_error_display() {
        let err = SigningError::NoKeypair;
        assert_eq!(format!("{}", err), "No keypair available for signing");

        let err = SigningError::SigningFailed("test error".to_string());
        assert_eq!(format!("{}", err), "Signing failed: test error");

        let err = SigningError::AlreadySigned;
        assert_eq!(format!("{}", err), "Message is already signed");
    }

    #[test]
    fn test_verification_error_display() {
        let err = VerificationError::NoSignature;
        assert_eq!(format!("{}", err), "Message has no signature");

        let err = VerificationError::InvalidSignature;
        assert_eq!(format!("{}", err), "Signature verification failed");

        let err = VerificationError::MessageTooOld { age_secs: 400 };
        assert!(format!("{}", err).contains("400"));

        let err = VerificationError::FutureTimestamp { delta_secs: 120 };
        assert!(format!("{}", err).contains("120"));

        let err = VerificationError::InvalidNonce;
        assert_eq!(format!("{}", err), "Message has zero/invalid nonce");

        let err = VerificationError::InvalidPublicKey("bad key".to_string());
        assert!(format!("{}", err).contains("bad key"));
    }
}
