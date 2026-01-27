//! SPKI pin parsing utilities for bootstrap peer TLS certificate pinning (Issue #922)

use anyhow::{anyhow, Result};

/// Parse a hex-encoded SPKI SHA-256 pin into a 32-byte array.
///
/// # Arguments
/// * `hex_str` - A 64-character hex string representing a SHA-256 hash
///
/// # Errors
/// Returns an error if:
/// - The string is not exactly 64 hex characters
/// - The string contains non-hex characters
pub fn parse_spki_hex(hex_str: &str) -> Result<[u8; 32]> {
    let hex_str = hex_str.trim();
    if hex_str.len() != 64 {
        return Err(anyhow!(
            "SPKI pin must be exactly 64 hex characters (32 bytes SHA-256), got {} characters",
            hex_str.len()
        ));
    }

    let bytes = hex::decode(hex_str).map_err(|e| {
        anyhow!("SPKI pin contains invalid hex characters: {}", e)
    })?;

    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spki_hex_valid() {
        let hex = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8";
        let result = parse_spki_hex(hex);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(hash[0], 0xa1);
        assert_eq!(hash[1], 0xb2);
        assert_eq!(hash[31], 0xb8);
    }

    #[test]
    fn test_parse_spki_hex_too_short() {
        let hex = "a1b2c3d4";
        let result = parse_spki_hex(hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64 hex characters"));
    }

    #[test]
    fn test_parse_spki_hex_too_long() {
        let hex = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8ff";
        let result = parse_spki_hex(hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64 hex characters"));
    }

    #[test]
    fn test_parse_spki_hex_invalid_chars() {
        let hex = "g1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8";
        let result = parse_spki_hex(hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid hex"));
    }

    #[test]
    fn test_parse_spki_hex_all_zeros() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = parse_spki_hex(hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_parse_spki_hex_trimmed() {
        let hex = "  a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8  ";
        let result = parse_spki_hex(hex);
        assert!(result.is_ok());
    }
}
