//! Shared Test Helpers for lib-identity Tests
//!
//! This module consolidates common test logic to eliminate code duplication.

use lib_identity::identity::ZhtpIdentity;
use lib_identity::types::IdentityType;
use lib_crypto::{PublicKey, PrivateKey};
use lib_proofs::ZeroKnowledgeProof;

/// Create a standard test identity with realistic Dilithium2 key sizes.
/// This is the single source of truth for creating mock identities in lib-identity tests.
///
/// Uses:
/// - Dilithium2: PK = 1312 bytes, SK = 2560 bytes
/// - Deterministic values for repeatability
/// - Human identity type with verified citizenship
/// - Reputation set to 1000 for testing
pub fn create_test_identity() -> ZhtpIdentity {
    let mut identity = create_test_identity_with_device("laptop", true);
    // Override reputation for testing (in real usage, this would be managed separately)
    identity.reputation = 1000u64;
    identity
}

/// Create a test identity with custom device name and verification status.
pub fn create_test_identity_with_device(device: &str, citizenship_verified: bool) -> ZhtpIdentity {
    let public_key = PublicKey {
        dilithium_pk: vec![42u8; 1312],
        kyber_pk: vec![],
        key_id: [42u8; 32],
    };
    let private_key = PrivateKey {
        dilithium_sk: vec![1u8; 2560],
        dilithium_pk: vec![42u8; 1312],
        kyber_sk: vec![],
        master_seed: vec![],
    };
    let ownership_proof = ZeroKnowledgeProof {
        proof_system: "test".to_string(),
        proof_data: vec![1, 2, 3, 4],
        public_inputs: vec![5, 6, 7, 8],
        verification_key: vec![9, 10, 11, 12],
        plonky2_proof: None,
        proof: vec![],
    };

    ZhtpIdentity::new(
        IdentityType::Human,
        public_key,
        private_key,
        device.to_string(),
        Some(30u64),
        Some("US".to_string()),
        citizenship_verified,
        ownership_proof,
    ).expect("Failed to create test identity")
}

/// Create a test identity for async contexts (same as sync version).
pub async fn create_test_identity_async() -> ZhtpIdentity {
    create_test_identity_with_device("test_device", false)
}
