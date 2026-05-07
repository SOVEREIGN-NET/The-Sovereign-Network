//! User credential registration for password-based public access.
//!
//! Credentials are registered on-chain so all nodes can validate username/password
//! logins without a centralized auth server. The password hash + salt are stored
//! directly — this is safe because argon2id hashes are designed to be public.
//!
//! Flow:
//! 1. User creates identity (DID + keys + wallets) via existing registration
//! 2. User sets username + password → RegisterCredential transaction
//! 3. Any node can validate login by reading the credential from chain state
//! 4. Password recovery: user provides seed phrase → proves DID → new SetPassword tx

use serde::{Deserialize, Serialize};

/// On-chain credential record indexed by username.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserCredential {
    /// Unique username (immutable after registration, lowercase alphanumeric + underscore)
    pub username: String,
    /// DID that owns this credential (did:zhtp:...)
    pub owner_did: String,
    /// Argon2id password hash (PHC string format: $argon2id$v=19$m=...$...)
    pub password_hash: String,
    /// Block height at registration
    pub registered_at_height: u64,
    /// Unix timestamp at registration
    pub registered_at: u64,
    /// Block height of last password change (0 = never changed)
    pub password_changed_at_height: u64,
}

/// Payload for RegisterCredential transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterCredentialData {
    /// Unique username (3-32 chars, lowercase alphanumeric + underscore, immutable)
    pub username: String,
    /// DID that owns this credential
    pub owner_did: String,
    /// Argon2id password hash (computed client-side, PHC string format)
    pub password_hash: String,
}

/// Payload for UpdateCredentialPassword transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCredentialPasswordData {
    /// Username whose password is being changed
    pub username: String,
    /// DID that owns this credential (must match registered owner)
    pub owner_did: String,
    /// New argon2id password hash
    pub new_password_hash: String,
}

/// Username validation rules.
pub fn validate_username(username: &str) -> Result<(), String> {
    if username.len() < 3 {
        return Err("Username must be at least 3 characters".to_string());
    }
    if username.len() > 32 {
        return Err("Username must be at most 32 characters".to_string());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(
            "Username must contain only lowercase letters, digits, and underscores".to_string(),
        );
    }
    if username.starts_with('_') || username.ends_with('_') {
        return Err("Username cannot start or end with underscore".to_string());
    }
    // Reserved names
    let reserved = [
        "admin", "root", "system", "node", "validator", "council", "treasury",
        "null", "undefined", "test", "zhtp", "sovereign",
    ];
    if reserved.contains(&username) {
        return Err(format!("Username '{}' is reserved", username));
    }
    Ok(())
}
