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
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    /// Network identifier for domain separation
    pub network_id: String,
    /// Protocol identifier for domain separation
    pub protocol_id: String,
    /// Purpose string for domain separation
    pub purpose: String,
    /// Declared client role (u8)
    pub client_role: u8,
    /// Declared server role (u8)
    pub server_role: u8,
    /// Channel binding token (raw bytes)
    pub channel_binding: Vec<u8>,
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
    let salt = b"ZHTP-UHP-v2-SESSION-KEY-DERIVATION-2025";

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
    info.extend_from_slice(b"ZHTP-NETWORK-SESSION-ONLY-v2");  // Domain tag
    info.push(0x00); // Separator
    info.extend_from_slice(&context.protocol_version.to_le_bytes());
    info.extend_from_slice(context.client_did.as_bytes());
    info.push(0x00);
    info.extend_from_slice(context.server_did.as_bytes());
    info.push(0x00);
    info.extend_from_slice(context.network_id.as_bytes());
    info.push(0x00);
    info.extend_from_slice(context.protocol_id.as_bytes());
    info.push(0x00);
    info.extend_from_slice(context.purpose.as_bytes());
    info.push(0x00);
    info.push(context.client_role);
    info.push(context.server_role);
    info.push(0x00);
    info.extend_from_slice(context.channel_binding.as_slice());
    info.extend_from_slice(&context.timestamp.to_le_bytes());
    info
}

// ============================================================================
// UHP v2 Key Schedule
// ============================================================================

/// v2 HKDF labels for key derivation
/// INVARIANT: Labels are constant and versioned to prevent cross-protocol attacks
pub mod v2_labels {
    pub const APP_KEY_C2S: &[u8] = b"zhtp/v2/app_key_c2s";
    pub const APP_KEY_S2C: &[u8] = b"zhtp/v2/app_key_s2c";
    pub const MAC_KEY: &[u8] = b"zhtp/v2/mac_key";
    pub const REKEY_KEY: &[u8] = b"zhtp/v2/rekey_key";
}

/// Derived keys from v2 key schedule
///
/// SECURITY: Uses Zeroize and ZeroizeOnDrop to ensure all key material
/// is securely wiped from memory when dropped, including cloned copies.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct V2SessionKeys {
    /// Client-to-server application encryption key
    pub app_key_c2s: [u8; 32],
    /// Server-to-client application encryption key
    pub app_key_s2c: [u8; 32],
    /// MAC key for request authentication
    pub mac_key: [u8; 32],
    /// Key for session rekeying
    pub rekey_key: [u8; 32],
}

impl std::fmt::Debug for V2SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2SessionKeys")
            .field("app_key_c2s", &"[REDACTED]")
            .field("app_key_s2c", &"[REDACTED]")
            .field("mac_key", &"[REDACTED]")
            .field("rekey_key", &"[REDACTED]")
            .finish()
    }
}

/// Derive v2 session keys from session_key using handshake_hash as salt
///
/// Key schedule (HKDF-SHA3-256):
/// - IKM: session_key (32 bytes from Kyber KEM or classical derivation)
/// - Salt: handshake_hash (32 bytes, preferred) or session_id
/// - Info: versioned labels for domain separation
///
/// INVARIANT: Keys are direction-scoped (c2s vs s2c) to prevent reflection attacks.
pub fn derive_v2_session_keys(
    session_key: &[u8; 32],
    handshake_hash: &[u8; 32],
) -> Result<V2SessionKeys> {
    use hkdf::Hkdf;
    use sha3::Sha3_256;

    let hkdf = Hkdf::<Sha3_256>::new(Some(handshake_hash), session_key);

    let mut app_key_c2s = [0u8; 32];
    let mut app_key_s2c = [0u8; 32];
    let mut mac_key = [0u8; 32];
    let mut rekey_key = [0u8; 32];

    hkdf.expand(v2_labels::APP_KEY_C2S, &mut app_key_c2s)
        .map_err(|e| anyhow!("HKDF expand app_key_c2s failed: {}", e))?;

    hkdf.expand(v2_labels::APP_KEY_S2C, &mut app_key_s2c)
        .map_err(|e| anyhow!("HKDF expand app_key_s2c failed: {}", e))?;

    hkdf.expand(v2_labels::MAC_KEY, &mut mac_key)
        .map_err(|e| anyhow!("HKDF expand mac_key failed: {}", e))?;

    hkdf.expand(v2_labels::REKEY_KEY, &mut rekey_key)
        .map_err(|e| anyhow!("HKDF expand rekey_key failed: {}", e))?;

    Ok(V2SessionKeys {
        app_key_c2s,
        app_key_s2c,
        mac_key,
        rekey_key,
    })
}

/// Derive a single key with custom label (for flexibility)
pub fn derive_v2_key(
    session_key: &[u8; 32],
    handshake_hash: &[u8; 32],
    label: &[u8],
) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha3::Sha3_256;

    let hkdf = Hkdf::<Sha3_256>::new(Some(handshake_hash), session_key);
    let mut key = [0u8; 32];
    hkdf.expand(label, &mut key)
        .map_err(|e| anyhow!("HKDF expand failed for label {:?}: {}", label, e))?;
    Ok(key)
}

// ============================================================================
// v2 MAC Computation
// ============================================================================

/// Canonical request representation for v2 MAC computation
///
/// Wire format:
/// - method: 1 byte (0=GET, 1=POST, 2=PUT, 3=DELETE)
/// - path_len: u16 BE
/// - path: UTF-8 bytes
/// - body_len: u32 BE
/// - body: raw bytes
#[derive(Debug, Clone)]
pub struct CanonicalRequest {
    pub method: u8,
    pub path: String,
    pub body: Vec<u8>,
}

impl CanonicalRequest {
    pub const METHOD_GET: u8 = 0;
    pub const METHOD_POST: u8 = 1;
    pub const METHOD_PUT: u8 = 2;
    pub const METHOD_DELETE: u8 = 3;

    /// Serialize to canonical bytes for MAC computation
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Method (1 byte)
        bytes.push(self.method);

        // Path length (u16 BE) + path bytes
        let path_bytes = self.path.as_bytes();
        let path_len_u16 = u16::try_from(path_bytes.len())
            .expect("CanonicalRequest path length exceeds u16::MAX");
        bytes.extend_from_slice(&path_len_u16.to_be_bytes());
        bytes.extend_from_slice(path_bytes);

        // Body length (u32 BE) + body bytes
        let body_len_u32 = u32::try_from(self.body.len())
            .expect("CanonicalRequest body length exceeds u32::MAX");
        bytes.extend_from_slice(&body_len_u32.to_be_bytes());
        bytes.extend_from_slice(&self.body);

        bytes
    }
}

/// Compute v2 MAC for an authenticated request
///
/// MAC = HMAC-SHA3-256(mac_key, canonical_bytes(request) || counter || session_id)
///
/// INVARIANT: Counter is included to prevent replay attacks.
pub fn compute_v2_mac(
    mac_key: &[u8; 32],
    request: &CanonicalRequest,
    counter: u64,
    session_id: &[u8; 32],
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_256;

    type HmacSha3 = Hmac<Sha3_256>;

    let mut mac = HmacSha3::new_from_slice(mac_key)
        .expect("HMAC can take key of any size");

    // canonical_bytes(request)
    mac.update(&request.to_bytes());

    // counter (u64 BE)
    mac.update(&counter.to_be_bytes());

    // session_id (32 bytes)
    mac.update(session_id);

    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// Verify v2 MAC (constant-time comparison)
pub fn verify_v2_mac(
    mac_key: &[u8; 32],
    request: &CanonicalRequest,
    counter: u64,
    session_id: &[u8; 32],
    expected_mac: &[u8; 32],
) -> bool {
    let computed = compute_v2_mac(mac_key, request, counter, session_id);
    ct_eq_bytes(&computed, expected_mac)
}

// ============================================================================
// Constant-time utilities
// ============================================================================

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
            protocol_version: 2,
            client_did: "did:zhtp:test".into(),
            server_did: "did:zhtp:server".into(),
            timestamp: 1234567890,
            network_id: "zhtp-mainnet".into(),
            protocol_id: "uhp".into(),
            purpose: "zhtp-node-handshake".into(),
            client_role: 0,
            server_role: 1,
            channel_binding: vec![0u8; 32],
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
            protocol_version: 2,
            client_did: "did:zhtp:client1".into(),
            server_did: "did:zhtp:server".into(),
            timestamp: 1234567890,
            network_id: "zhtp-mainnet".into(),
            protocol_id: "uhp".into(),
            purpose: "zhtp-node-handshake".into(),
            client_role: 0,
            server_role: 1,
            channel_binding: vec![0u8; 32],
        };

        let context2 = SessionContext {
            protocol_version: 2,
            client_did: "did:zhtp:client2".into(),
            server_did: "did:zhtp:server".into(),
            timestamp: 1234567890,
            network_id: "zhtp-mainnet".into(),
            protocol_id: "uhp".into(),
            purpose: "zhtp-node-handshake".into(),
            client_role: 0,
            server_role: 1,
            channel_binding: vec![0u8; 32],
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
