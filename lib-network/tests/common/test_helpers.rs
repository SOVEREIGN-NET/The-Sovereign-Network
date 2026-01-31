//! Shared Test Helpers for lib-network Tests
//!
//! This module consolidates ALL common test logic to eliminate code duplication.
//! All test files should import from here instead of duplicating logic.
//!
//! Usage:
//! ```ignore
//! mod common;
//! use common::test_helpers::*;
//! ```

use anyhow::Result;
use lib_crypto::kdf::hkdf::hkdf_sha3;
use lib_identity::{IdentityType, NodeId, ZhtpIdentity};
use std::time::Duration;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

pub const TEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const SHORT_WAIT: Duration = Duration::from_millis(100);

// ═══════════════════════════════════════════════════════════════════════════════
// IDENTITY CREATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Create a unified identity with seed.
/// This is the single source of truth for creating test identities in lib-network.
pub fn identity_with_seed(device: &str, seed: [u8; 64]) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        device,
        Some(seed),
    )
}

/// Convert NodeId to UUID for peer identification.
pub fn peer_id_from_node_id(node_id: &NodeId) -> Uuid {
    Uuid::from_slice(&node_id.as_bytes()[..16])
        .expect("NodeId::as_bytes() must return at least 16 bytes for UUID conversion")
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY DERIVATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Derive session key for test handshakes using v2 key derivation.
pub fn derive_session_key_for_test(
    uhp_session_key: &[u8; 32],
    pqc_shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
    peer_node_id: &[u8],
) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + peer_node_id.len());
    ikm.extend_from_slice(uhp_session_key);
    ikm.extend_from_slice(pqc_shared_secret);
    ikm.extend_from_slice(transcript_hash);
    ikm.extend_from_slice(peer_node_id);

    let extracted = hkdf_sha3(&ikm, b"zhtp-quic-mesh-v2", 32)?;
    let expanded = hkdf_sha3(&extracted, b"zhtp-quic-session-v2", 32)?;

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(&expanded);
    Ok(session_key)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ASSERTION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Assert two identities have the same DID (from same seed).
pub fn assert_same_did(a: &ZhtpIdentity, b: &ZhtpIdentity) {
    assert_eq!(
        a.did, b.did,
        "Same seed should produce same DID"
    );
}

/// Assert two identities have different DIDs (from different seeds).
pub fn assert_different_did(a: &ZhtpIdentity, b: &ZhtpIdentity) {
    assert_ne!(
        a.did, b.did,
        "Different seeds should produce different DIDs"
    );
}

/// Assert two identities have the same NodeId (stable across restart).
pub fn assert_same_node_id(a: &ZhtpIdentity, b: &ZhtpIdentity) {
    assert_eq!(
        a.node_id, b.node_id,
        "Same seed and device should produce same NodeId"
    );
}

/// Assert two identities have different NodeIds.
pub fn assert_different_node_id(a: &ZhtpIdentity, b: &ZhtpIdentity) {
    assert_ne!(
        a.node_id, b.node_id,
        "Different seeds or devices should produce different NodeIds"
    );
}

/// Assert NodeId matches DID + device derivation.
pub fn assert_node_id_matches_derivation(identity: &ZhtpIdentity, device: &str) -> Result<()> {
    let expected = NodeId::from_did_device(&identity.did, device)?;
    assert_eq!(
        expected, identity.node_id,
        "NodeId must match DID + device derivation"
    );
    Ok(())
}

/// Assert public key is present and non-empty.
pub fn assert_public_key_present(identity: &ZhtpIdentity) {
    assert!(
        !identity.public_key.as_bytes().is_empty(),
        "Public key should be present"
    );
}

/// Assert all identities in a collection have unique NodeIds.
pub fn assert_unique_node_ids(identities: &[ZhtpIdentity]) {
    use std::collections::HashSet;
    let ids: HashSet<_> = identities.iter().map(|i| &i.node_id).collect();
    assert_eq!(
        ids.len(),
        identities.len(),
        "All nodes must have unique NodeIds"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST SCENARIO RUNNERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Run a standard NodeId stability test (restart simulation).
pub fn run_node_id_stability_test(device: &str, seed: [u8; 64]) -> Result<()> {
    let first = identity_with_seed(device, seed)?;
    let second = identity_with_seed(device, seed)?;

    assert_same_did(&first, &second);
    assert_same_node_id(&first, &second);
    assert_public_key_present(&first);
    assert_public_key_present(&second);
    assert_node_id_matches_derivation(&first, device)?;

    Ok(())
}

/// Run a test verifying different seeds produce different identities.
pub fn run_different_seed_test(device: &str, seed_a: [u8; 64], seed_b: [u8; 64]) -> Result<()> {
    let a = identity_with_seed(device, seed_a)?;
    let b = identity_with_seed(device, seed_b)?;

    assert_different_did(&a, &b);
    assert_different_node_id(&a, &b);

    Ok(())
}

/// Run a test verifying different devices produce different NodeIds but same DID.
pub fn run_different_device_test(device_a: &str, device_b: &str, seed: [u8; 64]) -> Result<()> {
    let a = identity_with_seed(device_a, seed)?;
    let b = identity_with_seed(device_b, seed)?;

    assert_same_did(&a, &b);
    assert_different_node_id(&a, &b);

    Ok(())
}
