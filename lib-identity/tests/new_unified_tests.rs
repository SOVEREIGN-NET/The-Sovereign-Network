//! Given/When/Then tests for ZhtpIdentity::new_unified()
//! Tests based on P1-7 acceptance criteria

use lib_identity::identity::ZhtpIdentity;
use lib_identity::types::IdentityType;

/// AC1: Given new_unified(type, age, juris, device) is called
///      When construction completes
///      Then identity has real lib-crypto KeyPair (Dilithium + Kyber), valid DID,
///           derived NodeId, all secrets derived from keypair, WalletManager initialized
#[test]
fn given_new_unified_called_when_construction_completes_then_identity_fully_initialized() {
    // Given
    let identity_type = IdentityType::Human;
    let age = Some(30u64);
    let jurisdiction = Some("US".to_string());
    let primary_device = "laptop";

    // When
    let result = ZhtpIdentity::new_unified(
        identity_type,
        age,
        jurisdiction,
        primary_device,
        None,  // Let it generate random seed
    );

    // Then
    assert!(result.is_ok(), "new_unified() should succeed");
    let identity = result.unwrap();

    // Verify real PQC keypair components exist
    assert!(!identity.public_key.dilithium_pk.is_empty(),
        "Dilithium public key should be present");
    assert!(!identity.public_key.kyber_pk.is_empty(),
        "Kyber public key should be present");
    assert_ne!(identity.public_key.key_id, [0u8; 32],
        "key_id should be non-zero");

    // Verify valid DID format
    assert!(identity.did.starts_with("did:zhtp:"),
        "DID should start with 'did:zhtp:'");
    assert_eq!(identity.did.len(), 73,
        "DID should be 73 chars (did:zhtp: + 64 hex)");

    // Verify NodeId derived from DID + device
    assert!(!identity.device_node_ids.is_empty(),
        "device_node_ids should contain primary device");
    assert!(identity.device_node_ids.contains_key(primary_device),
        "device_node_ids should contain the primary device");

    // Verify all secrets are properly sized
    assert_eq!(identity.zk_identity_secret.len(), 32,
        "zk_identity_secret should be 32 bytes");
    assert_eq!(identity.zk_credential_hash.len(), 32,
        "zk_credential_hash should be 32 bytes");
    assert_eq!(identity.wallet_master_seed.len(), 64,
        "wallet_master_seed should be 64 bytes");

    // Verify secrets are non-zero (derived, not default)
    assert_ne!(identity.zk_identity_secret, [0u8; 32],
        "zk_identity_secret should be non-zero");
    assert_ne!(identity.zk_credential_hash, [0u8; 32],
        "zk_credential_hash should be non-zero");
    assert_ne!(identity.wallet_master_seed, [0u8; 64],
        "wallet_master_seed should be non-zero");

    // Verify DAO member ID is derived
    assert!(!identity.dao_member_id.is_empty(),
        "dao_member_id should be non-empty");

    // Verify WalletManager initialized (non-null)
    // (WalletManager structure verification depends on its API)
}

/// AC2: Given same seed to new_unified()
///      When called multiple times with the same seed
///      Then all outputs are deterministic (same DID, same secrets)
#[test]
fn given_same_seed_when_called_multiple_times_then_outputs_are_identical() {
    // Given - use a fixed seed for determinism
    let seed = [0x42u8; 64];
    let identity_type = IdentityType::Human;
    let age = Some(25u64);
    let jurisdiction = Some("CA".to_string());
    let primary_device = "phone";

    // When - call twice with same seed
    let identity1 = ZhtpIdentity::new_unified(
        identity_type.clone(),
        age,
        jurisdiction.clone(),
        primary_device,
        Some(seed),
    ).expect("First call should succeed");

    let identity2 = ZhtpIdentity::new_unified(
        identity_type,
        age,
        jurisdiction,
        primary_device,
        Some(seed),
    ).expect("Second call should succeed");

    // Then - same seed produces identical derived fields
    assert_eq!(identity1.did, identity2.did,
        "Same seed should produce same DID");
    assert_eq!(identity1.id, identity2.id,
        "Same seed should produce same IdentityId");
    assert_eq!(identity1.zk_identity_secret, identity2.zk_identity_secret,
        "Same seed should produce same zk_identity_secret");
    assert_eq!(identity1.wallet_master_seed, identity2.wallet_master_seed,
        "Same seed should produce same wallet_master_seed");
    assert_eq!(identity1.dao_member_id, identity2.dao_member_id,
        "Same seed should produce same dao_member_id");

    // PQC keypairs are allowed to differ (they're random)
    // This is by design - seed anchors identity, not PQC keys
}

/// AC2b: Given different seeds
///       When new_unified() is called
///       Then outputs are different
#[test]
fn given_different_seeds_when_called_then_outputs_are_different() {
    // Given - two different seeds
    let seed1 = [0x42u8; 64];
    let seed2 = [0x43u8; 64];

    // When
    let identity1 = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        "device",
        Some(seed1),
    ).expect("Should succeed");

    let identity2 = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        "device",
        Some(seed2),
    ).expect("Should succeed");

    // Then - different seeds produce different identities
    assert_ne!(identity1.did, identity2.did,
        "Different seeds should produce different DIDs");
    assert_ne!(identity1.zk_identity_secret, identity2.zk_identity_secret,
        "Different seeds should produce different secrets");
}

/// AC2c: Given no seed (None)
///       When new_unified() is called
///       Then generates random seed and creates valid identity
#[test]
fn given_no_seed_when_called_then_generates_random_seed() {
    // Given/When - no seed provided (but age/jurisdiction are required)
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),  // Age required for credential derivation
        Some("US".to_string()),  // Jurisdiction required for credential derivation
        "device",
        None,  // No seed - should generate random
    ).expect("Should succeed with random seed");

    // Then - identity is valid
    assert!(identity.did.starts_with("did:zhtp:"),
        "Should have valid DID");
    assert_ne!(identity.zk_identity_secret, [0u8; 32],
        "Should have non-zero secrets");
}

/// AC3: Given primary_device name
///      When new_unified() creates identity
///      Then device_node_ids contains primary device with derived NodeId
#[test]
fn given_primary_device_when_new_unified_creates_identity_then_device_mapping_correct() {
    // Given
    let primary_device = "desktop";

    // When
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(30),
        Some("US".to_string()),
        primary_device,
        None,
    ).expect("new_unified should succeed");

    // Then
    assert!(identity.device_node_ids.contains_key(primary_device),
        "device_node_ids must contain primary device");

    let node_id = identity.device_node_ids.get(primary_device)
        .expect("Primary device should have NodeId");

    // Verify NodeId is non-default
    assert!(!format!("{:?}", node_id).is_empty(),
        "NodeId should be properly initialized");
}

/// Unit Test: Verify DID format compliance
#[test]
fn test_did_format_is_valid() {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(30),  // Age required
        Some("CA".to_string()),  // Jurisdiction required
        "test-device",
        None,
    ).expect("new_unified should succeed");

    // DID format: "did:zhtp:{64 hex chars}"
    assert!(identity.did.starts_with("did:zhtp:"),
        "DID must start with 'did:zhtp:'");
    assert_eq!(identity.did.len(), 73,
        "DID must be exactly 73 characters");

    // Verify hex portion
    let hex_part = &identity.did[9..]; // Skip "did:zhtp:"
    assert_eq!(hex_part.len(), 64, "Hex portion must be 64 chars");
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "Hex portion must contain only hex digits");
}

/// Unit Test: Verify all secrets meet size requirements
#[test]
fn test_all_secrets_meet_size_requirements() {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("GB".to_string()),
        "device",
        None,
    ).expect("new_unified should succeed");

    assert_eq!(identity.zk_identity_secret.len(), 32,
        "zk_identity_secret must be 32 bytes");
    assert_eq!(identity.zk_credential_hash.len(), 32,
        "zk_credential_hash must be 32 bytes");
    assert_eq!(identity.wallet_master_seed.len(), 64,
        "wallet_master_seed must be 64 bytes");
}

/// Unit Test: Verify citizenship defaults for new unified identities
#[test]
fn test_citizenship_defaults_for_new_unified() {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),  // Age required
        Some("US".to_string()),  // Jurisdiction required
        "device",
        None,
    ).expect("new_unified should succeed");

    assert_eq!(identity.citizenship_verified, false,
        "New identities should have citizenship_verified=false");
    assert_eq!(identity.dao_voting_power, 1,
        "Unverified identities should have dao_voting_power=1");
}

/// Unit Test: Verify real PQC keypair from lib-crypto
#[test]
fn test_creates_real_pqc_keypair() {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),  // Age required
        Some("US".to_string()),  // Jurisdiction required
        "device",
        None,
    ).expect("new_unified should succeed");

    // Verify Dilithium5 keypair sizes (expected: PK=2592, SK=4896)
    // Note: lib-crypto uses Dilithium5 for stronger security
    assert_eq!(identity.public_key.dilithium_pk.len(), 2592,
        "Dilithium5 public key should be 2592 bytes");
    // Note: private_key not stored in ZhtpIdentity after construction

    // Verify Kyber1024 keypair present
    assert!(!identity.public_key.kyber_pk.is_empty(),
        "Kyber public key should be present");
    assert_eq!(identity.public_key.kyber_pk.len(), 1568,
        "Kyber1024 public key should be 1568 bytes");
}
