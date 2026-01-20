//! Pure identity operation logic
//!
//! Handles identity validation, key generation parameters, and metadata.
//! No side effects - all functions are pure.

use crate::error::{CliError, CliResult};
use regex::Regex;
use lib_identity::IdentityType;

/// Identity key material (public view only)
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityKeys {
    pub dilithium_public_key: Vec<u8>,
    pub kyber_public_key: Vec<u8>,
    pub did: String,
}

/// Identity metadata for display
#[derive(Debug, Clone)]
pub struct IdentityMetadata {
    pub name: String,
    pub did: String,
    pub created_at: u64,
    pub last_used: u64,
    pub is_active: bool,
}

/// Parse identity type from string
///
/// Supported types: human, agent, contract, organization, device
/// Pure function - deterministic conversion
pub fn parse_identity_type(type_str: &str) -> CliResult<IdentityType> {
    match type_str.to_lowercase().as_str() {
        "human" => Ok(IdentityType::Human),
        "agent" => Ok(IdentityType::Agent),
        "contract" => Ok(IdentityType::Contract),
        "organization" => Ok(IdentityType::Organization),
        "device" => Ok(IdentityType::Device),
        other => Err(CliError::IdentityError(format!(
            "Unknown identity type: '{}'. Supported: human, agent, contract, organization, device",
            other
        ))),
    }
}

/// Validate identity name
///
/// Identity names must:
/// - Be 3-64 characters
/// - Start with alphanumeric
/// - Contain only alphanumeric, dash, underscore
pub fn validate_identity_name(name: &str) -> CliResult<()> {
    if name.is_empty() {
        return Err(CliError::IdentityError(
            "Identity name cannot be empty".to_string(),
        ));
    }

    if name.len() < 3 {
        return Err(CliError::IdentityError(
            "Identity name must be at least 3 characters".to_string(),
        ));
    }

    if name.len() > 64 {
        return Err(CliError::IdentityError(
            "Identity name must not exceed 64 characters".to_string(),
        ));
    }

    // Must start with alphanumeric
    if !name.chars().next().unwrap().is_alphanumeric() {
        return Err(CliError::IdentityError(
            "Identity name must start with alphanumeric character".to_string(),
        ));
    }

    // Only allow alphanumeric, dash, underscore
    let valid_pattern = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$").unwrap();
    if !valid_pattern.is_match(name) {
        return Err(CliError::IdentityError(
            "Identity name can only contain alphanumeric characters, dashes, and underscores"
                .to_string(),
        ));
    }

    Ok(())
}

/// Build DID string from identity name and public key hash
///
/// DID format: did:zhtp:{name}:{key_hash}
pub fn build_did(name: &str, key_hash: &str) -> CliResult<String> {
    validate_identity_name(name)?;

    if key_hash.is_empty() {
        return Err(CliError::IdentityError(
            "Key hash cannot be empty".to_string(),
        ));
    }

    Ok(format!("did:zhtp:{}:{}", name, key_hash))
}

/// Validate DID format
pub fn validate_did(did: &str) -> CliResult<()> {
    if !did.starts_with("did:zhtp:") {
        return Err(CliError::IdentityError(
            "Invalid DID format: must start with 'did:zhtp:'".to_string(),
        ));
    }

    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() != 4 {
        return Err(CliError::IdentityError(
            "Invalid DID format: expected did:zhtp:name:hash".to_string(),
        ));
    }

    let name = parts[2];
    validate_identity_name(name)?;

    Ok(())
}

/// Extract identity name from DID
pub fn extract_name_from_did(did: &str) -> CliResult<String> {
    validate_did(did)?;
    let parts: Vec<&str> = did.split(':').collect();
    Ok(parts[2].to_string())
}

/// Extract key hash from DID
pub fn extract_hash_from_did(did: &str) -> CliResult<String> {
    validate_did(did)?;
    let parts: Vec<&str> = did.split(':').collect();
    Ok(parts[3].to_string())
}

/// Validate Dilithium public key format
/// Accepts both Dilithium2 (1312 bytes) and Dilithium5 (2592 bytes)
pub fn validate_dilithium_public_key(key: &[u8]) -> CliResult<()> {
    const DILITHIUM2_PK_BYTES: usize = 1312;
    const DILITHIUM5_PK_BYTES: usize = 2592;

    if key.len() != DILITHIUM2_PK_BYTES && key.len() != DILITHIUM5_PK_BYTES {
        return Err(CliError::IdentityError(format!(
            "Invalid Dilithium public key size: expected {} (D2) or {} (D5) bytes, got {}",
            DILITHIUM2_PK_BYTES, DILITHIUM5_PK_BYTES, key.len()
        )));
    }
    Ok(())
}

/// Validate Kyber public key format
/// Only Kyber1024 (1568 bytes) is supported by ZHTP
pub fn validate_kyber_public_key(key: &[u8]) -> CliResult<()> {
    const KYBER1024_PK_BYTES: usize = 1568;

    if key.len() != KYBER1024_PK_BYTES {
        return Err(CliError::IdentityError(format!(
            "Invalid Kyber public key size: expected {} bytes (Kyber1024), got {}",
            KYBER1024_PK_BYTES, key.len()
        )));
    }
    Ok(())
}

/// Check if an identity is available (not already registered)
///
/// Note: This is a local check based on naming rules.
/// Server-side availability check happens during registration.
pub fn is_identity_name_available(name: &str) -> CliResult<bool> {
    validate_identity_name(name)?;
    // Local availability check - always returns true
    // Real availability is checked against server during registration
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_identity_name_valid() {
        assert!(validate_identity_name("alice").is_ok());
        assert!(validate_identity_name("bob-smith").is_ok());
        assert!(validate_identity_name("user_123").is_ok());
        assert!(validate_identity_name("A1b2C3").is_ok());
    }

    #[test]
    fn test_validate_identity_name_too_short() {
        let result = validate_identity_name("ab");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_identity_name_too_long() {
        let name = "a".repeat(65);
        let result = validate_identity_name(&name);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_identity_name_starts_with_dash() {
        let result = validate_identity_name("-invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_identity_name_special_chars() {
        assert!(validate_identity_name("user@email").is_err());
        assert!(validate_identity_name("user#123").is_err());
        assert!(validate_identity_name("user space").is_err());
    }

    #[test]
    fn test_build_did_valid() {
        let result = build_did("alice", "abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "did:zhtp:alice:abc123");
    }

    #[test]
    fn test_build_did_invalid_name() {
        let result = build_did("ab", "abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_did_empty_hash() {
        let result = build_did("alice", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_did_valid() {
        assert!(validate_did("did:zhtp:alice:abc123").is_ok());
    }

    #[test]
    fn test_validate_did_invalid_format() {
        assert!(validate_did("did:ethr:alice:abc123").is_err());
        assert!(validate_did("did:zhtp:ab:abc123").is_err());
        assert!(validate_did("did:zhtp:alice").is_err());
    }

    #[test]
    fn test_extract_name_from_did() {
        let result = extract_name_from_did("did:zhtp:alice:abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn test_extract_hash_from_did() {
        let result = extract_hash_from_did("did:zhtp:alice:abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc123");
    }

    #[test]
    fn test_validate_dilithium_key_correct_size_d2() {
        let key = vec![0u8; 1312]; // Dilithium2 public key
        assert!(validate_dilithium_public_key(&key).is_ok());
    }

    #[test]
    fn test_validate_dilithium_key_correct_size_d5() {
        let key = vec![0u8; 2592]; // Dilithium5 public key
        assert!(validate_dilithium_public_key(&key).is_ok());
    }

    #[test]
    fn test_validate_dilithium_key_wrong_size() {
        let key = vec![0u8; 1000];
        assert!(validate_dilithium_public_key(&key).is_err());
    }

    #[test]
    fn test_validate_kyber_key_correct_size() {
        let key = vec![0u8; 1568]; // Kyber1024 public key
        assert!(validate_kyber_public_key(&key).is_ok());
    }

    #[test]
    fn test_validate_kyber_key_wrong_size() {
        let key = vec![0u8; 1000];
        assert!(validate_kyber_public_key(&key).is_err());
    }

    #[test]
    fn test_is_identity_name_available() {
        assert!(is_identity_name_available("alice").is_ok());
        assert!(is_identity_name_available("valid_name").is_ok());
    }

    #[test]
    fn test_parse_identity_type_valid() {
        assert!(matches!(parse_identity_type("human"), Ok(IdentityType::Human)));
        assert!(matches!(parse_identity_type("agent"), Ok(IdentityType::Agent)));
        assert!(matches!(parse_identity_type("contract"), Ok(IdentityType::Contract)));
        assert!(matches!(parse_identity_type("organization"), Ok(IdentityType::Organization)));
        assert!(matches!(parse_identity_type("device"), Ok(IdentityType::Device)));
    }

    #[test]
    fn test_parse_identity_type_case_insensitive() {
        assert!(matches!(parse_identity_type("HUMAN"), Ok(IdentityType::Human)));
        assert!(matches!(parse_identity_type("Agent"), Ok(IdentityType::Agent)));
        assert!(matches!(parse_identity_type("CoNtRaCt"), Ok(IdentityType::Contract)));
    }

    #[test]
    fn test_parse_identity_type_invalid() {
        assert!(parse_identity_type("invalid").is_err());
        assert!(parse_identity_type("").is_err());
        assert!(parse_identity_type("robot").is_err());
    }
}
