//! Identity seed generation and management
//!
//! Provides secure seed generation for deterministic identity derivation.

use anyhow::Result;
use rand::{RngCore, rngs::OsRng};

/// Generate a cryptographically secure 64-byte identity seed
///
/// This seed serves as the root of trust for all identity derivations:
/// - DID
/// - IdentityId
/// - zk_identity_secret
/// - wallet_master_seed
/// - dao_member_id
/// - NodeIds
///
/// Uses OS-provided CSPRNG for maximum entropy.
///
/// # Security
/// - The returned seed must be stored securely
/// - Losing the seed means losing the identity
/// - Seed should be backed up in secure storage
/// - Consider encrypting seed before storage
///
/// # Returns
/// 64-byte array suitable for use as identity root seed
pub fn generate_identity_seed() -> Result<[u8; 64]> {
    let mut seed = [0u8; 64];
    OsRng.fill_bytes(&mut seed);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity_seed_produces_64_bytes() {
        let seed = generate_identity_seed().expect("Should generate seed");
        assert_eq!(seed.len(), 64, "Seed must be 64 bytes");
    }

    #[test]
    fn test_generate_identity_seed_is_non_zero() {
        let seed = generate_identity_seed().expect("Should generate seed");
        assert_ne!(seed, [0u8; 64], "Seed must not be all zeros");
    }

    #[test]
    fn test_generate_identity_seed_produces_different_values() {
        let seed1 = generate_identity_seed().expect("Should generate seed");
        let seed2 = generate_identity_seed().expect("Should generate seed");
        assert_ne!(seed1, seed2, "Each seed must be unique");
    }
}
