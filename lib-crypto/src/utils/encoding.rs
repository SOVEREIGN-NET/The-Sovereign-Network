//! Encoding utility functions for post-quantum cryptographic keys
//!
//! These functions handle hex encoding/decoding for large fixed-size arrays
//! used in validator consensus keys and genesis configuration.

/// Convert a hex-encoded Dilithium5 public key string to a fixed array.
///
/// Called only at genesis bootstrap and validator registration tooling.
/// Panics on malformed input — genesis config errors must fail at startup.
///
/// # Arguments
/// * `hex_str` - Hex string without 0x prefix, exactly 5184 hex characters (2592 bytes × 2)
///
/// # Panics
/// Panics if the hex string is malformed or not exactly 2592 bytes after decoding.
pub fn dilithium5_pk_from_hex(hex_str: &str) -> [u8; 2592] {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_clean)
        .expect("genesis consensus_key: invalid hex encoding");
    bytes
        .as_slice()
        .try_into()
        .expect("genesis consensus_key: must be exactly 2592 bytes (Dilithium5 public key)")
}

/// Convert raw bytes to a Dilithium5 public key fixed array.
///
/// Called for paths that already have raw bytes and need the fixed array form.
/// Panics on malformed input — deployment errors must fail at startup.
///
/// # Arguments
/// * `bytes` - Byte slice that must be exactly 2592 bytes
///
/// # Panics
/// Panics if the byte slice is not exactly 2592 bytes.
pub fn dilithium5_pk_from_bytes(bytes: &[u8]) -> [u8; 2592] {
    bytes
        .try_into()
        .expect("consensus_key: must be exactly 2592 bytes (Dilithium5 public key)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium5_pk_from_hex_valid() {
        let valid_hex = "aa".repeat(2592);
        let result = dilithium5_pk_from_hex(&valid_hex);
        assert_eq!(result.len(), 2592);
        assert_eq!(result[0], 0xaa);
        assert_eq!(result[2591], 0xaa);
    }

    #[test]
    fn test_dilithium5_pk_from_hex_with_prefix() {
        let valid_hex = format!("0x{}", "bb".repeat(2592));
        let result = dilithium5_pk_from_hex(&valid_hex);
        assert_eq!(result.len(), 2592);
        assert_eq!(result[0], 0xbb);
    }

    #[test]
    #[should_panic(expected = "genesis consensus_key: must be exactly 2592 bytes")]
    fn test_dilithium5_pk_from_hex_wrong_length() {
        let wrong_hex = "cc".repeat(1000); // Too short
        let _result = dilithium5_pk_from_hex(&wrong_hex);
    }

    #[test]
    #[should_panic(expected = "genesis consensus_key: invalid hex encoding")]
    fn test_dilithium5_pk_from_hex_invalid_hex() {
        let invalid_hex = "not_valid_hex!!!".to_string();
        let _result = dilithium5_pk_from_hex(&invalid_hex);
    }

    #[test]
    fn test_dilithium5_pk_from_bytes_valid() {
        let valid_bytes = vec![0xddu8; 2592];
        let result = dilithium5_pk_from_bytes(&valid_bytes);
        assert_eq!(result.len(), 2592);
        assert_eq!(result[0], 0xdd);
    }

    #[test]
    #[should_panic(expected = "consensus_key: must be exactly 2592 bytes")]
    fn test_dilithium5_pk_from_bytes_wrong_length() {
        let wrong_bytes = vec![0xeeu8; 1000];
        let _result = dilithium5_pk_from_bytes(&wrong_bytes);
    }
}
