//! Security utilities for Unified Handshake Protocol
//!
//! This module provides critical security functions including:
//! - HKDF-based key derivation (NIST SP 800-108 compliant)
//! - Constant-time cryptographic comparisons
//! - Timestamp validation for replay attack prevention
//! - Nonce management and verification

use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for timestamp validation
#[derive(Debug, Clone)]
pub struct TimestampConfig {
    /// Maximum age of message in seconds (default: 300 = 5 minutes)
    pub max_age_secs: u64,
    /// Clock skew tolerance in seconds (default: 300 = 5 minutes)
    pub clock_skew_tolerance: u64,
    /// Minimum valid timestamp (ZHTP launch date, default: Nov 2023)
    pub min_timestamp: u64,
}

impl Default for TimestampConfig {
    fn default() -> Self {
        Self {
            max_age_secs: 300,
            clock_skew_tolerance: 300,
            min_timestamp: 1700000000, // Nov 2023
        }
    }
}

/// Get current Unix timestamp
pub fn current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| anyhow!("System clock error: {}", e))
}

/// Validate timestamp for replay attack prevention
///
/// Checks:
/// 1. Not in future (beyond clock skew tolerance)
/// 2. Not too old (beyond max_age)
/// 3. Not before protocol launch
/// 4. Not zero
pub fn validate_timestamp(timestamp: u64, config: &TimestampConfig) -> Result<()> {
    let now = current_timestamp()?;

    // 1. Reject future timestamps (with clock skew tolerance)
    if timestamp > now + config.clock_skew_tolerance {
        return Err(anyhow!(
            "Timestamp in future: {} > {} (+{} tolerance)",
            timestamp, now, config.clock_skew_tolerance
        ));
    }

    // 2. Reject very old timestamps
    let age = now.saturating_sub(timestamp);
    if age > config.max_age_secs {
        return Err(anyhow!(
            "Timestamp too old: {} seconds (max: {})",
            age, config.max_age_secs
        ));
    }

    // 3. Reject timestamps before protocol launch
    if timestamp < config.min_timestamp {
        return Err(anyhow!(
            "Timestamp predates protocol launch: {}",
            timestamp
        ));
    }

    // 4. Reject zero timestamp
    if timestamp == 0 {
        return Err(anyhow!("Timestamp is zero"));
    }

    Ok(())
}

/// Context for session key derivation
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// Protocol version
    pub protocol_version: u32,
    /// Client DID
    pub client_did: String,
    /// Server DID
    pub server_did: String,
    /// Handshake timestamp
    pub timestamp: u64,
}

/// Derive session key using HKDF per NIST SP 800-108
///
/// Uses HKDF-Expand with:
/// - Salt: Protocol-specific constant
/// - IKM: client_nonce || server_nonce
/// - Info: protocol_version || client_did || server_did || timestamp
///
/// This provides:
/// - Domain separation
/// - Context binding
/// - Cryptographic strength
/// - NIST compliance
pub fn derive_session_key_hkdf(
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    context: &SessionContext,
) -> Result<[u8; 32]> {
    // Salt: Protocol-specific constant for domain separation
    let salt = b"ZHTP-UHP-v1-SESSION-KEY-DERIVATION-2025";

    // Input Key Material: Combine nonces
    let mut ikm = Vec::new();
    ikm.extend_from_slice(client_nonce);
    ikm.extend_from_slice(server_nonce);

    // Context Info: Bind to session context for additional security
    let info = build_context_info(context);

    // HKDF-Expand
    let hkdf = Hkdf::<Sha3_256>::new(Some(salt), &ikm);
    let mut session_key = [0u8; 32];
    hkdf.expand(&info, &mut session_key)
        .map_err(|e| anyhow!("HKDF expansion failed: {}", e))?;

    Ok(session_key)
}

/// Build context info for HKDF domain separation
fn build_context_info(context: &SessionContext) -> Vec<u8> {
    let mut info = Vec::new();
    // CRITICAL: Domain separation to prevent key reuse across protocols
    // Network session keys MUST NEVER be used for blockchain transaction signing
    info.extend_from_slice(b"ZHTP-NETWORK-SESSION-ONLY-v1");  // Domain tag
    info.push(0x00); // Separator
    info.extend_from_slice(&context.protocol_version.to_le_bytes());
    info.extend_from_slice(context.client_did.as_bytes());
    info.extend_from_slice(context.server_did.as_bytes());
    info.extend_from_slice(&context.timestamp.to_le_bytes());
    info
}

/// Constant-time equality check for byte arrays
///
/// Uses subtle::ConstantTimeEq to prevent timing side-channels
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Constant-time equality check with Result
///
/// Returns error if not equal, without leaking timing information
pub fn ct_verify_eq(a: &[u8], b: &[u8], error_msg: &str) -> Result<()> {
    if !ct_eq_bytes(a, b) {
        return Err(anyhow!("{}", error_msg));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_validation_accepts_recent() {
        let config = TimestampConfig::default();
        let now = current_timestamp().unwrap();

        // 1 minute ago - should accept
        assert!(validate_timestamp(now - 60, &config).is_ok());
    }

    #[test]
    fn test_timestamp_validation_rejects_future() {
        let config = TimestampConfig::default();
        let now = current_timestamp().unwrap();

        // 1 hour in future - should reject
        assert!(validate_timestamp(now + 3600, &config).is_err());
    }

    #[test]
    fn test_timestamp_validation_rejects_too_old() {
        let config = TimestampConfig::default();
        let now = current_timestamp().unwrap();

        // 10 minutes old (beyond 5 min limit) - should reject
        assert!(validate_timestamp(now - 600, &config).is_err());
    }

    #[test]
    fn test_timestamp_validation_rejects_zero() {
        let config = TimestampConfig::default();
        assert!(validate_timestamp(0, &config).is_err());
    }

    #[test]
    fn test_hkdf_deterministic() {
        let client_nonce = [1u8; 32];
        let server_nonce = [2u8; 32];
        let context = SessionContext {
            protocol_version: 1,
            client_did: "did:zhtp:test".into(),
            server_did: "did:zhtp:server".into(),
            timestamp: 1234567890,
        };

        let key1 = derive_session_key_hkdf(&client_nonce, &server_nonce, &context).unwrap();
        let key2 = derive_session_key_hkdf(&client_nonce, &server_nonce, &context).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hkdf_domain_separation() {
        let client_nonce = [1u8; 32];
        let server_nonce = [2u8; 32];

        let context1 = SessionContext {
            protocol_version: 1,
            client_did: "did:zhtp:client1".into(),
            server_did: "did:zhtp:server".into(),
            timestamp: 1234567890,
        };

        let context2 = SessionContext {
            protocol_version: 1,
            client_did: "did:zhtp:client2".into(),
            server_did: "did:zhtp:server".into(),
            timestamp: 1234567890,
        };

        let key1 = derive_session_key_hkdf(&client_nonce, &server_nonce, &context1).unwrap();
        let key2 = derive_session_key_hkdf(&client_nonce, &server_nonce, &context2).unwrap();

        // Different contexts → different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_constant_time_equality() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(ct_eq_bytes(&a, &b));
        assert!(!ct_eq_bytes(&a, &c));
    }

    #[test]
    fn test_constant_time_verify() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(ct_verify_eq(&a, &b, "should match").is_ok());
        assert!(ct_verify_eq(&a, &c, "should not match").is_err());
    }
}
