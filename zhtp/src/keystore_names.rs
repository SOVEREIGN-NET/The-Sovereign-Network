//! Centralized file naming constants for keystore and identity files
//!
//! This module defines all standard filenames used in the keystore directory
//! to avoid naming inconsistencies across the codebase.
//!
//! Usage:
//! ```ignore
//! use crate::keystore_names::*;
//! let path = keystore_path.join(NODE_IDENTITY_FILENAME);
//! ```

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
