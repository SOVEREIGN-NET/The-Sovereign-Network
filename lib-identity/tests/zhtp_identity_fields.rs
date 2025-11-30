// P1-5: Add new identity fields to ZhtpIdentity struct
// Acceptance Criteria Tests

use lib_identity::identity::ZhtpIdentity;
use lib_identity::types::{IdentityType, NodeId, IdentityId, AccessLevel};
use lib_identity::wallets::WalletManager;
use lib_crypto::{PublicKey, PrivateKey};
use lib_proofs::ZeroKnowledgeProof;
use blake3;
use std::collections::HashMap;

// AC1: New fields added to ZhtpIdentity
// Given: ZhtpIdentity struct in lib_identity.rs
// When: new fields are added
// Then: struct includes did, node_id, device_node_ids, primary_device,
//       zk_identity_secret, zk_credential_hash, wallet_master_seed,
//       dao_member_id, dao_voting_power, citizenship_verified, jurisdiction
#[test]
fn test_zhtp_identity_has_required_fields() {
    let identity = create_test_identity();

    // Verify all new fields are accessible and properly derived
    // DID should be derived from public key (not hardcoded)
    assert!(identity.did.starts_with("did:zhtp:"));
    assert_eq!(identity.did.len(), 73); // "did:zhtp:" + 64 hex chars

    assert_eq!(identity.primary_device, "laptop");

    // DAO voting power should be 10 for verified citizens (from new() logic)
    assert_eq!(identity.dao_voting_power, 10);
    assert_eq!(identity.citizenship_verified, true);
    assert_eq!(identity.jurisdiction, Some("US".to_string()));
    assert_eq!(identity.device_node_ids.len(), 1);

    // Secrets should be derived (non-zero) from private key
    assert_eq!(identity.zk_identity_secret.len(), 32);
    assert_ne!(identity.zk_identity_secret, [0u8; 32], "zk_identity_secret should not be zero");

    assert_eq!(identity.zk_credential_hash.len(), 32);
    assert_ne!(identity.zk_credential_hash, [0u8; 32], "zk_credential_hash should not be zero");

    assert_eq!(identity.wallet_master_seed.len(), 64);
    assert_ne!(identity.wallet_master_seed, [0u8; 64], "wallet_master_seed should not be zero");
}

// AC2: Correct types from lib-crypto
// Given: lib-crypto PublicKey/PrivateKey types
// When: fields are added
// Then: public_key is lib_crypto::PublicKey, private_key is Option<lib_crypto::PrivateKey>
#[test]
fn test_zhtp_identity_uses_lib_crypto_types() {
    let identity = create_test_identity();

    // Verify types at compile time - this test passes if it compiles
    let _pk: &PublicKey = &identity.public_key;
    let _sk: &Option<PrivateKey> = &identity.private_key;
}

// AC3: private_key uses serde(skip)
// Given: new fields with sensitive data
// When: Serialize trait is implemented
// Then: private_key uses serde(skip) to exclude private key
#[test]
fn test_private_key_not_serialized() {
    use serde_json;

    let mut identity = create_test_identity();
    // PrivateKey doesn't have Default, skip setting it for test

    let json = serde_json::to_string(&identity)
        .expect("Serialization should succeed");

    // Verify private_key is not in JSON
    assert!(!json.contains("private_key"),
            "private_key should be skipped in serialization");

    // Verify did IS in JSON (sanity check) - check for the prefix since DID is derived
    assert!(json.contains("did:zhtp:"),
            "did should be present in serialization");
}

// AC4: Type corrections for existing fields
// Given: existing type inconsistencies
// When: fields are corrected
// Then: age: Option<u8> → Option<u64>, reputation: u32 → u64
#[test]
fn test_field_type_corrections() {
    let identity = create_test_identity();

    // Verify age is Option<u64>
    let _age: Option<u64> = identity.age;
    assert_eq!(identity.age, Some(30u64));

    // Verify reputation is u64
    let _reputation: u64 = identity.reputation;
    assert_eq!(identity.reputation, 1000u64);
}

// AC5: HashMap for device_node_ids
// Given: multi-device support requirement
// When: device_node_ids field is added
// Then: it maps device names (String) to NodeId
#[test]
fn test_device_node_ids_mapping() {
    let laptop_id = NodeId::from_did_device("did:zhtp:test123", "laptop")
        .expect("Valid NodeId");
    let phone_id = NodeId::from_did_device("did:zhtp:test123", "phone")
        .expect("Valid NodeId");

    let mut device_node_ids = HashMap::new();
    device_node_ids.insert("laptop".to_string(), laptop_id);
    device_node_ids.insert("phone".to_string(), phone_id);

    let mut identity = create_test_identity();
    identity.device_node_ids = device_node_ids;
    identity.primary_device = "laptop".to_string();

    // Verify mapping
    assert_eq!(identity.device_node_ids.len(), 2);
    assert!(identity.device_node_ids.contains_key("laptop"));
    assert!(identity.device_node_ids.contains_key("phone"));
    assert_eq!(identity.primary_device, "laptop");
}

// AC6: Fixed-size arrays for secrets
// Given: cryptographic secret fields
// When: fields are added
// Then: zk_identity_secret is [u8; 32], zk_credential_hash is [u8; 32],
//       wallet_master_seed is [u8; 64]
#[test]
fn test_secret_fields_fixed_sizes() {
    let mut identity = create_test_identity();

    // Verify compile-time sizes
    let _zk_secret: [u8; 32] = identity.zk_identity_secret;
    let _zk_hash: [u8; 32] = identity.zk_credential_hash;
    let _wallet_seed: [u8; 64] = identity.wallet_master_seed;

    // Set some test values
    identity.zk_identity_secret = [1u8; 32];
    identity.zk_credential_hash = [2u8; 32];
    identity.wallet_master_seed = [3u8; 64];

    assert_eq!(identity.zk_identity_secret.len(), 32);
    assert_eq!(identity.zk_credential_hash.len(), 32);
    assert_eq!(identity.wallet_master_seed.len(), 64);
}

// AC7: DAO fields present and correct types
// Given: DAO integration requirements
// When: DAO fields are added
// Then: dao_member_id is String, dao_voting_power is u64
#[test]
fn test_dao_fields() {
    let mut identity = create_test_identity();
    identity.dao_member_id = "dao_member_xyz".to_string();
    identity.dao_voting_power = 5000u64;

    // Verify types
    let _member_id: String = identity.dao_member_id.clone();
    let _voting_power: u64 = identity.dao_voting_power;

    assert_eq!(identity.dao_member_id, "dao_member_xyz");
    assert_eq!(identity.dao_voting_power, 5000);
}

// AC8: Citizenship fields present
// Given: jurisdiction verification requirements
// When: citizenship fields are added
// Then: citizenship_verified is bool, jurisdiction is Option<String>
#[test]
fn test_citizenship_fields() {
    let mut identity = create_test_identity();

    // Test verified citizen with jurisdiction
    identity.citizenship_verified = true;
    identity.jurisdiction = Some("US".to_string());

    assert_eq!(identity.citizenship_verified, true);
    assert_eq!(identity.jurisdiction, Some("US".to_string()));

    // Test unverified citizen
    identity.citizenship_verified = false;
    identity.jurisdiction = None;

    assert_eq!(identity.citizenship_verified, false);
    assert_eq!(identity.jurisdiction, None);
}

// Helper function to create test identity using proper new() constructor
// This ensures all cryptographic fields are derived correctly per spec
fn create_test_identity() -> ZhtpIdentity {
    // Use realistic Dilithium2 key sizes for testing
    // Dilithium2: PK = 1312 bytes, SK = 2528 bytes
    // Using deterministic values for repeatability in tests
    let public_key = PublicKey {
        dilithium_pk: vec![42u8; 1312],  // Real Dilithium2 public key size
        kyber_pk: vec![],
        key_id: [42u8; 32],
    };
    let private_key = PrivateKey {
        dilithium_sk: vec![1u8; 2528],   // Real Dilithium2 secret key size
        kyber_sk: vec![],
        master_seed: vec![],
    };

    let ownership_proof = ZeroKnowledgeProof {
        proof_system: "test".to_string(),
        proof_data: vec![],
        public_inputs: vec![],
        verification_key: vec![],
        plonky2_proof: None,
        proof: vec![],
    };

    // Use new() to get proper derivation of all fields
    let mut identity = ZhtpIdentity::new(
        IdentityType::Human,
        public_key,
        private_key,
        "laptop".to_string(),
        Some(30u64),
        Some("US".to_string()),
        true,  // Verified citizen for testing
        ownership_proof,
    ).expect("Failed to create test identity");

    // Override reputation for testing (in real usage, this would be managed separately)
    identity.reputation = 1000u64;

    identity
}

// SECURITY TEST: Validate secrets are properly derived
#[test]
fn test_secrets_validation() {
    let identity = create_test_identity();

    // Secrets should be properly derived (non-zero)
    assert!(identity.is_secrets_derived(), "Secrets should be derived after new()");
    assert!(identity.validate_secrets_derived().is_ok(), "Validation should pass for derived secrets");
}

// SECURITY TEST: Direct deserialization is blocked, must use from_serialized
#[test]
fn test_deserialization_requires_rederive() {
    use serde_json;

    // Create identity with proper derivation
    let identity = create_test_identity();

    // Serialize
    let json = serde_json::to_string(&identity).expect("Serialization should succeed");

    // BLOCKED: Direct deserialization is now forbidden
    let deserialization_result: Result<ZhtpIdentity, _> = serde_json::from_str(&json);
    assert!(deserialization_result.is_err(),
        "Direct deserialization should be forbidden");
    assert!(deserialization_result.unwrap_err().to_string().contains("forbidden"),
        "Error message should indicate deserialization is forbidden");

    // SAFE PATH: Using from_serialized helper (enforces re-derivation)
    let private_key = PrivateKey {
        dilithium_sk: vec![1u8; 2528],
        kyber_sk: vec![],
        master_seed: vec![],
    };

    let deserialized = ZhtpIdentity::from_serialized(&json, &private_key)
        .expect("Safe deserialization should succeed");

    // Secrets should be properly derived via new()
    assert!(deserialized.is_secrets_derived(),
        "Secrets should be derived immediately with from_serialized()");
    assert!(deserialized.validate_secrets_derived().is_ok(),
        "Validation should pass for from_serialized()");

    // Verify derivation matches original
    assert_eq!(deserialized.did, identity.did,
        "DID should match original");
    assert_eq!(deserialized.zk_identity_secret, identity.zk_identity_secret,
        "ZK secret should match original");
    assert_eq!(deserialized.zk_credential_hash, identity.zk_credential_hash,
        "Credential hash should match original");
    assert_eq!(deserialized.wallet_master_seed, identity.wallet_master_seed,
        "Wallet seed should match original");
}

// GOLDEN VECTOR TEST: Validate deterministic derivation with expected outputs
#[test]
fn test_deterministic_derivation_golden_vector() {
    // Golden vector: Fixed key material with precomputed expected outputs
    // This validates that derivation algorithms produce expected results

    // Test vector 1: All zeros (simple case for validation)
    let public_key_zeros = PublicKey {
        dilithium_pk: vec![0u8; 1312],  // Real Dilithium2 PK size
        kyber_pk: vec![],
        key_id: [0u8; 32],
    };
    let private_key_zeros = PrivateKey {
        dilithium_sk: vec![0u8; 2528],  // Real Dilithium2 SK size
        kyber_sk: vec![],
        master_seed: vec![],
    };

    // Expected outputs for all-zero keys (computed per spec, not via derive functions)
    // Per Issue #9: DID uses key_id directly, not hash of dilithium_pk
    let expected_did_zeros = format!("did:zhtp:{}", hex::encode(public_key_zeros.key_id));

    let expected_zk_secret_zeros = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ZHTP_ZK_SECRET_V1:");
        hasher.update(&private_key_zeros.dilithium_sk);
        hasher.finalize()
    };

    let expected_zk_cred_hash_zeros = {
        let age_val: u64 = 30;
        let juris_code: u64 = 840; // US
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ZHTP_CREDENTIAL_V1:");
        hasher.update(expected_zk_secret_zeros.as_bytes());
        hasher.update(&age_val.to_le_bytes());
        hasher.update(&juris_code.to_le_bytes());
        hasher.finalize()
    };

    let expected_wallet_seed_zeros = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ZHTP_WALLET_SEED_V1:");
        hasher.update(&private_key_zeros.dilithium_sk);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 64];
        reader.fill(&mut out);
        out
    };

    let expected_dao_member_id_zeros = {
        let hash = blake3::hash(format!("DAO:{}", expected_did_zeros).as_bytes());
        hash.to_hex().to_string()
    };

    let ownership_proof = ZeroKnowledgeProof {
        proof_system: "test".to_string(),
        proof_data: vec![],
        public_inputs: vec![],
        verification_key: vec![],
        plonky2_proof: None,
        proof: vec![],
    };

    let identity_zeros = ZhtpIdentity::new(
        IdentityType::Human,
        public_key_zeros.clone(),
        private_key_zeros.clone(),
        "laptop".to_string(),
        Some(30u64),
        Some("US".to_string()),
        true,
        ownership_proof.clone(),
    ).expect("Failed to create identity with zero keys");

    // Validate DID derivation
    assert_eq!(identity_zeros.did, expected_did_zeros,
        "DID should match hex(key_id) for zero keys");
    assert_eq!(identity_zeros.did.len(), 73, "DID should be 73 chars (did:zhtp: + 64 hex)");

    // Validate ZK secret derivation
    assert_eq!(identity_zeros.zk_identity_secret, *expected_zk_secret_zeros.as_bytes(),
        "ZK secret should match expected hash for zero keys");
    assert_eq!(identity_zeros.zk_credential_hash, *expected_zk_cred_hash_zeros.as_bytes(),
        "ZK credential hash should match expected hash for zero keys");
    assert_eq!(identity_zeros.wallet_master_seed, expected_wallet_seed_zeros,
        "Wallet seed should match expected XOF output for zero keys");
    assert_eq!(identity_zeros.dao_member_id, expected_dao_member_id_zeros,
        "DAO member ID should match expected hash for zero keys");

    // Test vector 2: Non-zero pattern (validates different inputs produce different outputs)
    let public_key_pattern = PublicKey {
        dilithium_pk: vec![0xAB; 1312],  // Pattern: 0xAB repeated
        kyber_pk: vec![],
        key_id: [0xCD; 32],
    };
    let private_key_pattern = PrivateKey {
        dilithium_sk: vec![0xEF; 2528],  // Pattern: 0xEF repeated
        kyber_sk: vec![],
        master_seed: vec![],
    };

    let identity_pattern = ZhtpIdentity::new(
        IdentityType::Human,
        public_key_pattern.clone(),
        private_key_pattern.clone(),
        "laptop".to_string(),
        Some(30u64),
        Some("US".to_string()),
        true,
        ownership_proof.clone(),
    ).expect("Failed to create identity with pattern keys");

    // Different inputs should produce different outputs
    assert_ne!(identity_pattern.did, identity_zeros.did,
        "Different public keys should produce different DIDs");
    assert_ne!(identity_pattern.zk_identity_secret, identity_zeros.zk_identity_secret,
        "Different private keys should produce different ZK secrets");

    // Test vector 3: Determinism check - same inputs produce same outputs
    let identity_pattern_2 = ZhtpIdentity::new(
        IdentityType::Human,
        public_key_pattern.clone(),
        private_key_pattern.clone(),
        "laptop".to_string(),
        Some(30u64),
        Some("US".to_string()),
        true,
        ownership_proof.clone(),
    ).expect("Failed to create second identity with pattern keys");

    assert_eq!(identity_pattern.did, identity_pattern_2.did,
        "Same inputs should produce same DID (deterministic)");
    assert_eq!(identity_pattern.zk_identity_secret, identity_pattern_2.zk_identity_secret,
        "Same inputs should produce same ZK secret (deterministic)");
    assert_eq!(identity_pattern.zk_credential_hash, identity_pattern_2.zk_credential_hash,
        "Same inputs should produce same credential hash (deterministic)");
    assert_eq!(identity_pattern.wallet_master_seed, identity_pattern_2.wallet_master_seed,
        "Same inputs should produce same wallet seed (deterministic)");
    assert_eq!(identity_pattern.dao_member_id, identity_pattern_2.dao_member_id,
        "Same inputs should produce same DAO member ID (deterministic)");

    // Validate all secrets are non-zero for non-zero input
    assert_ne!(identity_pattern.zk_identity_secret, [0u8; 32],
        "ZK secret should be non-zero for non-zero input");
    assert_ne!(identity_pattern.zk_credential_hash, [0u8; 32],
        "Credential hash should be non-zero for non-zero input");
    assert_ne!(identity_pattern.wallet_master_seed, [0u8; 64],
        "Wallet seed should be non-zero for non-zero input");
}

// TEST: Voting power follows citizenship rules
#[test]
fn test_dao_voting_power_rules() {
    let public_key = PublicKey {
        dilithium_pk: vec![42u8; 1312],
        kyber_pk: vec![],
        key_id: [42u8; 32],
    };
    let private_key = PrivateKey {
        dilithium_sk: vec![1u8; 2528],
        kyber_sk: vec![],
        master_seed: vec![],
    };
    let ownership_proof = ZeroKnowledgeProof {
        proof_system: "test".to_string(),
        proof_data: vec![],
        public_inputs: vec![],
        verification_key: vec![],
        plonky2_proof: None,
        proof: vec![],
    };

    // Verified citizen: voting power = 10
    let verified_citizen = ZhtpIdentity::new(
        IdentityType::Human,
        public_key.clone(),
        private_key.clone(),
        "device1".to_string(),
        Some(30),
        Some("US".to_string()),
        true,  // verified
        ownership_proof.clone(),
    ).expect("Failed to create verified citizen");
    assert_eq!(verified_citizen.dao_voting_power, 10, "Verified citizen should have voting power 10");

    // Unverified human: voting power = 1
    let unverified_human = ZhtpIdentity::new(
        IdentityType::Human,
        public_key.clone(),
        private_key.clone(),
        "device2".to_string(),
        Some(30),
        Some("US".to_string()),
        false,  // not verified
        ownership_proof.clone(),
    ).expect("Failed to create unverified human");
    assert_eq!(unverified_human.dao_voting_power, 1, "Unverified human should have voting power 1");

    // Device type: voting power = 0
    let device = ZhtpIdentity::new(
        IdentityType::Device,
        public_key.clone(),
        private_key.clone(),
        "device3".to_string(),
        None,
        None,
        false,
        ownership_proof.clone(),
    ).expect("Failed to create device");
    assert_eq!(device.dao_voting_power, 0, "Device should have voting power 0");
}
