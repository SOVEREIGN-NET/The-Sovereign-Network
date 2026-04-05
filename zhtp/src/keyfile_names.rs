//! Centralized file naming constants and types for keystore and identity files
//!
//! This module defines all standard filenames and data structures used in the keystore directory
//! to avoid naming inconsistencies and type duplication across the codebase.
//!
//! Usage:
//! ```ignore
//! use crate::keystore_names::*;
//! let path = keystore_path.join(NODE_IDENTITY_FILENAME);
//! ```

use serde::{Deserialize, Serialize};

/// Private key storage format for keystore files
///
/// This struct defines the JSON format used to persist private keys to disk.
/// It is shared across zhtp, zhtp-cli, and other components to ensure consistency.
/// Uses hex-encoded strings for JSON serialization of large fixed arrays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystorePrivateKey {
    /// Dilithium secret key bytes (hex-encoded for JSON)
    #[serde(with = "serialize_bytes")]
    pub dilithium_sk: [u8; 4864],
    /// Dilithium public key bytes (optional, hex-encoded)
    #[serde(default = "default_dilithium_pk", with = "serialize_bytes")]
    pub dilithium_pk: [u8; 2592],
    /// Kyber secret key bytes (hex-encoded)
    #[serde(with = "serialize_bytes")]
    pub kyber_sk: [u8; 3168],
    /// Master seed bytes (hex-encoded)
    #[serde(with = "serialize_bytes")]
    pub master_seed: [u8; 64],
}

fn default_dilithium_pk() -> [u8; 2592] {
    [0u8; 2592]
}

/// Custom serialization module for fixed-size byte arrays using hex encoding
mod serialize_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let len = bytes.len();
        bytes.try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {} bytes, got {}", N, len)))
    }
}

/// Node identity file (node's DID and identity metadata)
pub const NODE_IDENTITY_FILENAME: &str = "node_identity.json";

/// Node private key file (node's cryptographic private key)
pub const NODE_PRIVATE_KEY_FILENAME: &str = "node_private_key.json";

/// User identity file (user's DID and identity metadata)
pub const USER_IDENTITY_FILENAME: &str = "user_identity.json";

/// User private key file (user's cryptographic private key)
pub const USER_PRIVATE_KEY_FILENAME: &str = "user_private_key.json";

/// Wallet data file (wallet state and transaction history)
pub const WALLET_DATA_FILENAME: &str = "wallet_data.json";

/// Directory for encrypted seed storage (master seed)
pub const SEED_STORAGE_DIRNAME: &str = "seed_store";

// Legacy naming - for backward compatibility during migration
/// Deprecated: Use NODE_IDENTITY_FILENAME instead
#[deprecated(since = "0.2.0", note = "Use NODE_IDENTITY_FILENAME instead")]
pub const IDENTITY_FILENAME: &str = "identity.json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filenames_are_defined() {
        assert_eq!(NODE_IDENTITY_FILENAME, "node_identity.json");
        assert_eq!(NODE_PRIVATE_KEY_FILENAME, "node_private_key.json");
        assert_eq!(USER_IDENTITY_FILENAME, "user_identity.json");
        assert_eq!(USER_PRIVATE_KEY_FILENAME, "user_private_key.json");
        assert_eq!(WALLET_DATA_FILENAME, "wallet_data.json");
        assert_eq!(SEED_STORAGE_DIRNAME, "seed_store");
    }

    #[test]
    fn test_no_duplicate_filenames() {
        let filenames = [
            NODE_IDENTITY_FILENAME,
            NODE_PRIVATE_KEY_FILENAME,
            USER_IDENTITY_FILENAME,
            USER_PRIVATE_KEY_FILENAME,
            WALLET_DATA_FILENAME,
            SEED_STORAGE_DIRNAME,
        ];

        for i in 0..filenames.len() {
            for j in (i + 1)..filenames.len() {
                assert_ne!(
                    filenames[i], filenames[j],
                    "Duplicate filename: {}",
                    filenames[i]
                );
            }
        }
    }
}
