//! Lobby-auth OPAQUE server-setup bytes loaded from genesis.
//!
//! `lib-blockchain` only knows the *bytes* of the OPAQUE server setup — the
//! typed `ServerSetup<CipherSuite>` lives in the server crate (zhtp) where
//! the OPAQUE protocol state machines are instantiated.
//!
//! The cipher suite is locked network-wide and documented here as constants.
//! Changing any of these parameters is a hard breaking change requiring a
//! network-wide re-registration of all credentials.
//!
//! Locked ciphersuite:
//! - OPRF group: Ristretto255
//! - Key-exchange group: Ristretto255
//! - Hash: SHA-512
//! - KDF: HKDF-SHA-512
//! - MAC: HMAC-SHA-512
//! - Key-stretching function: Argon2id (m=64MiB, t=3, p=4)
//!
//! Single source of truth for the cipher suite identity. The server crate
//! pulls these constants when configuring `opaque-ke`.

use anyhow::{anyhow, Context, Result};

/// Argon2id parameters used by the lobby-auth Key Stretching Function.
pub const ARGON2_M_COST_KIB: u32 = 65_536; // 64 MiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;

/// Stable identifier of the network-wide OPAQUE cipher suite. Logged on every
/// validator boot so divergent suites are easy to spot.
pub const CIPHERSUITE_ID: &str = "ristretto255-sha512-argon2id-v1";

/// Raw bytes of an OPAQUE server setup, as serialized by `opaque-ke`'s
/// `ServerSetup::serialize`. Treated as opaque by lib-blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueServerSetupBytes(pub Vec<u8>);

impl OpaqueServerSetupBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Short fingerprint for log lines — confirms every validator loaded the
    /// same bytes. NOT a security primitive.
    pub fn fingerprint(&self) -> String {
        hex::encode(&blake3::hash(&self.0).as_bytes()[..8])
    }
}

/// Decode a base64-encoded `ServerSetup` blob from `genesis.toml`.
///
/// Strips whitespace before decode (TOML triple-quoted strings often carry
/// newlines). Returns a typed wrapper to avoid mixing this with arbitrary
/// `Vec<u8>` blobs elsewhere.
pub fn parse_server_setup_b64(s: &str) -> Result<OpaqueServerSetupBytes> {
    use base64::Engine;
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(anyhow!("opaque.server_setup_b64 is empty"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .context("opaque.server_setup_b64 is not valid base64")?;
    if bytes.len() < 32 || bytes.len() > 2048 {
        return Err(anyhow!(
            "opaque.server_setup_b64 has implausible length: {} bytes",
            bytes.len()
        ));
    }
    Ok(OpaqueServerSetupBytes(bytes))
}

/// Encode raw bytes to base64 (used by the genesis-keygen helper tool).
pub fn server_setup_to_b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_b64() {
        // Synthetic bytes — at v1 the genesis-keygen tool produces ~64-byte
        // setups; we accept anywhere in the 32-2048 range.
        let raw = vec![7u8; 64];
        let s = server_setup_to_b64(&raw);
        let back = parse_server_setup_b64(&s).unwrap();
        assert_eq!(back.as_slice(), raw.as_slice());
    }

    #[test]
    fn fingerprint_stable() {
        let raw = vec![7u8; 64];
        let bytes = OpaqueServerSetupBytes(raw);
        assert_eq!(bytes.fingerprint(), bytes.fingerprint());
    }

    #[test]
    fn empty_rejected() {
        assert!(parse_server_setup_b64("").is_err());
        assert!(parse_server_setup_b64("   \n").is_err());
    }

    #[test]
    fn malformed_b64_rejected() {
        assert!(parse_server_setup_b64("!!!").is_err());
        assert!(parse_server_setup_b64("AAAA").is_err()); // too short after decode
    }

    #[test]
    fn whitespace_in_b64_ok() {
        let raw = vec![7u8; 64];
        let s = server_setup_to_b64(&raw);
        let with_ws = format!("{}\n   {}\n", &s[..16], &s[16..]);
        let back = parse_server_setup_b64(&with_ws).unwrap();
        assert_eq!(back.as_slice(), raw.as_slice());
    }
}
