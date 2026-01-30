//! Test utilities for lib-identity.
//!
//! This module provides helper functions for creating test identities
//! with deterministic seeds. It is intended for use in integration tests
//! across multiple crates.
//!
//! # Example
//!
//! ```rust,ignore
//! use lib_identity::testing::{create_test_identity, peer_id_from_node_id};
//!
//! let identity = create_test_identity("my-device", [0u8; 64])?;
//! let peer_id = peer_id_from_node_id(&identity.node_id);
//! ```

use crate::{IdentityType, NodeId, ZhtpIdentity};
use anyhow::Result;
use uuid::Uuid;

/// Creates a Device ZhtpIdentity with a deterministic seed for testing.
///
/// # Arguments
/// * `device` - Device name for the identity
/// * `seed` - 64-byte seed for deterministic key generation
///
/// # Returns
/// A `ZhtpIdentity` created with the specified parameters.
pub fn create_test_identity(device: &str, seed: [u8; 64]) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        device,
        Some(seed),
    )
}

/// Creates a Human ZhtpIdentity with optional seed for handshake testing.
///
/// # Arguments
/// * `device` - Device name for the identity
/// * `seed` - Optional 64-byte seed for deterministic key generation
///
/// # Returns
/// A `ZhtpIdentity` of type Human created with the specified parameters.
pub fn create_human_identity(device: &str, seed: Option<[u8; 64]>) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        device,
        seed,
    )
}

/// Derives a UUID peer ID from a NodeId.
///
/// This is used for network peer identification in tests.
///
/// # Arguments
/// * `node_id` - The NodeId to derive the peer ID from
///
/// # Returns
/// A UUID derived from the first 16 bytes of the NodeId.
pub fn peer_id_from_node_id(node_id: &NodeId) -> Uuid {
    Uuid::from_slice(&node_id.as_bytes()[..16])
        .expect("NodeId::as_bytes() must return at least 16 bytes for UUID conversion")
}

/// Derives a session key for testing using HKDF-SHA3.
///
/// # Arguments
/// * `shared_secret` - Shared secret bytes
/// * `info` - Context info for key derivation
///
/// # Returns
/// A 32-byte derived session key.
pub fn derive_session_key_for_test(
    shared_secret: &[u8],
    info: &[u8],
) -> Result<[u8; 32]> {
    let derived = lib_crypto::kdf::hkdf_sha3(shared_secret, info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_identity() {
        let seed = [42u8; 64];
        let identity = create_test_identity("test-device", seed).unwrap();
        assert!(!identity.node_id.as_bytes().is_empty());
    }

    #[test]
    fn test_peer_id_from_node_id_deterministic() {
        let seed = [42u8; 64];
        let identity = create_test_identity("test-device", seed).unwrap();
        let peer_id1 = peer_id_from_node_id(&identity.node_id);
        let peer_id2 = peer_id_from_node_id(&identity.node_id);
        assert_eq!(peer_id1, peer_id2);
    }
}
