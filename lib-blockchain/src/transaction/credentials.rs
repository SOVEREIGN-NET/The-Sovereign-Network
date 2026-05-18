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
///
/// **Bincode wire-format note** (reviewer #2568): bincode is a
/// non-self-describing fixed-width format. `#[serde(default)]` does NOT
/// rescue appended fields when decoding previously-serialized bytes — the
/// decoder hits EOF before `default` ever runs. The additive schema change
/// in this PR is therefore safe **only because the current chain has issued
/// zero `RegisterCredential` transactions and holds no persisted
/// `UserCredential` snapshots that predate these fields**. Any future
/// schema change MUST introduce a new tagged `TransactionPayload` variant
/// (e.g. `RegisterCredentialDataV2`) rather than appending fields here.
/// See the `bincode_*` tests at the bottom of this module for the
/// roundtrip-and-pinned-layout coverage.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AuthMethod {
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
    ///
    /// `#[serde(default)]` is here for self-describing formats (JSON/CBOR
    /// APIs that expose this struct), NOT for bincode rescue — see the
    /// note on `AuthMethod`.
    #[serde(default)]
    pub opaque_record: Vec<u8>,
    /// Which auth primitive backs this credential. See note on `AuthMethod`.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user_credential() -> UserCredential {
        UserCredential {
            username: "alice".into(),
            owner_did: "did:zhtp:0011223344".into(),
            password_hash: String::new(),
            registered_at_height: 7,
            registered_at: 1_700_000_000,
            password_changed_at_height: 0,
            opaque_record: vec![1, 2, 3, 4],
            auth_method: AuthMethod::Opaque,
        }
    }

    fn sample_register_data() -> RegisterCredentialData {
        RegisterCredentialData {
            username: "bob".into(),
            owner_did: "did:zhtp:deadbeef".into(),
            password_hash: String::new(),
            opaque_record: vec![9; 32],
            auth_method: AuthMethod::Opaque,
        }
    }

    #[test]
    fn bincode_roundtrip_user_credential() {
        let v = sample_user_credential();
        let bytes = bincode::serialize(&v).expect("serialize");
        let back: UserCredential = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn bincode_roundtrip_register_credential_data() {
        let v = sample_register_data();
        let bytes = bincode::serialize(&v).expect("serialize");
        let back: RegisterCredentialData = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(v.username, back.username);
        assert_eq!(v.owner_did, back.owner_did);
        assert_eq!(v.password_hash, back.password_hash);
        assert_eq!(v.opaque_record, back.opaque_record);
        assert_eq!(v.auth_method, back.auth_method);
    }

    /// Pin the wire-format incompatibility to a test so any future
    /// developer who naively appends another field gets a red CI signal:
    /// bincode-encoded bytes of the OLD shape (without the trailing
    /// `opaque_record` + `auth_method` fields) MUST fail to decode as the
    /// current `UserCredential`. This documents and locks the rule that
    /// further schema changes need a new tagged variant.
    #[test]
    fn bincode_legacy_bytes_fail_to_decode() {
        // Hand-roll the bincode encoding of a pre-OPAQUE UserCredential —
        // i.e. one with neither `opaque_record` nor `auth_method`. Bincode
        // = field-order-sensitive, length-prefixed strings (u64-LE for
        // collection lengths by default).
        fn put_str(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u64).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        let mut legacy = Vec::new();
        put_str(&mut legacy, "alice");
        put_str(&mut legacy, "did:zhtp:0011223344");
        put_str(&mut legacy, "$argon2id$v=19$m=65536,t=3,p=4$abc$def");
        legacy.extend_from_slice(&7u64.to_le_bytes());
        legacy.extend_from_slice(&1_700_000_000u64.to_le_bytes());
        legacy.extend_from_slice(&0u64.to_le_bytes());

        let res: Result<UserCredential, _> = bincode::deserialize(&legacy);
        assert!(
            res.is_err(),
            "bincode #[serde(default)] does NOT rescue appended fields — \
             this MUST fail. If this test passes, schema migration assumptions \
             have changed and bincode_*.rs notes need re-review."
        );
    }
}
