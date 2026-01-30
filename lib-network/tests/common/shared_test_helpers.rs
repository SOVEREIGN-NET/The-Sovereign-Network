//! Shared test utilities for zhtp and lib-network integration tests
//! Reduces code duplication across test suites (Issue #62)

use anyhow::Result;
use lib_crypto::kdf::hkdf::hkdf_sha3;
use lib_identity::{IdentityType, NodeId, ZhtpIdentity};
use uuid::Uuid;

/// Create a ZhtpIdentity with a specific seed and device
/// Used across multi-node network and DHT tests
pub fn create_test_identity(device: &str, seed: [u8; 64]) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        device,
        Some(seed),
    )
}

/// Derive PeerId (UUID) from NodeId for network operations
/// Extracts first 16 bytes of NodeId as UUID
pub fn peer_id_from_node_id(node_id: &NodeId) -> Uuid {
    Uuid::from_slice(&node_id.as_bytes()[..16])
        .expect("NodeId::as_bytes() must return at least 16 bytes for UUID conversion")
}

/// Derive session key for test scenarios
/// Combines multiple key material sources using HKDF-SHA3
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

    let extracted = hkdf_sha3(&ikm, b"zhtp-quic-mesh", 32)?;
    let expanded = hkdf_sha3(&extracted, b"zhtp-quic-session", 32)?;

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(&expanded);
    Ok(session_key)
}
