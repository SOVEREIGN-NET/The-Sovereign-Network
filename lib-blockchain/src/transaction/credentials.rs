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

/// How a credential authenticates the user.
///
/// `Argon2idPhc` is the legacy v1 method (client-side argon2id PHC string,
/// equality compared server-side). `Opaque` is the new OPAQUE-based method
/// (offline-attack-resistant, RFC 9497 / IETF CFRG draft).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AuthMethod {
    /// Legacy argon2id PHC string in `password_hash`. Deserializes by default
    /// so older blocks/sled records without the field load cleanly.
    #[default]
    Argon2idPhc,
    /// OPAQUE — `opaque_record` is the authoritative verifier; `password_hash`
    /// is ignored.
    Opaque,
}

/// On-chain credential record indexed by username.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserCredential {
    /// Unique username (immutable after registration, lowercase alphanumeric + underscore)
    pub username: String,
    /// DID that owns this credential (did:zhtp:...)
    pub owner_did: String,
    /// Argon2id password hash (PHC string format: $argon2id$v=19$m=...$...).
    /// Used only when `auth_method = Argon2idPhc`. Empty for Opaque entries.
    pub password_hash: String,
    /// Block height at registration
    pub registered_at_height: u64,
    /// Unix timestamp at registration
    pub registered_at: u64,
    /// Block height of last password change (0 = never changed)
    pub password_changed_at_height: u64,
    /// OPAQUE registration record bytes (per RFC 9497). Empty for legacy entries.
    /// Used only when `auth_method = Opaque`.
    #[serde(default)]
    pub opaque_record: Vec<u8>,
    /// Which auth primitive backs this credential.
    /// Defaults to `Argon2idPhc` for blocks/records that pre-date this field.
    #[serde(default)]
    pub auth_method: AuthMethod,
}

/// Payload for RegisterCredential transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterCredentialData {
    /// Unique username (3-32 chars, lowercase alphanumeric + underscore, immutable)
    pub username: String,
    /// DID that owns this credential
    pub owner_did: String,
    /// Argon2id password hash (computed client-side, PHC string format).
    /// Empty when `auth_method = Opaque`.
    pub password_hash: String,
    /// OPAQUE registration record bytes. Empty when `auth_method = Argon2idPhc`.
    #[serde(default)]
    pub opaque_record: Vec<u8>,
    /// Which auth primitive this credential uses.
    #[serde(default)]
    pub auth_method: AuthMethod,
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
