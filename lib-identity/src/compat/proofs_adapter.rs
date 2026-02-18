//! ProofsSecretAdapter - Compatibility adapter for lib-proofs secret conversions
//!
//! This module provides conversions between [u8; 32] cryptographic secrets
//! and u64 values used by lib-proofs for ZK circuit inputs.
//!
//! # Security Warning
//!
//! **IMPORTANT**: Converting from [u8; 32] to u64 reduces entropy from 256 bits
//! to 64 bits. This is acceptable for ZK circuit inputs where the secret is
//! used as a blinding factor or commitment, but should NOT be used for:
//!
//! - Key derivation
//! - Seed material for RNG
//! - Any security-critical randomness
//!
//! The u64 representation provides only 64 bits of entropy versus the full
//! 256 bits of the original secret.
//!
//! # Usage
//!
//! ```rust
//! use lib_identity::compat::ProofsSecretAdapter;
//!
//! let secret: [u8; 32] = [
//!     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
//!     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
//!     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
//!     0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
//! ];
//!
//! // Convert to u64 for lib-proofs compatibility
//! let legacy_secret = ProofsSecretAdapter::to_u64(&secret);
//!
//! // Convert back to [u8; 32]
//! let restored = ProofsSecretAdapter::from_u64(legacy_secret);
//! ```

/// Adapter for converting between [u8; 32] secrets and u64 values.
///
/// This is a unit struct as it provides only pure conversion functions
/// with no internal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofsSecretAdapter;

impl ProofsSecretAdapter {
    /// Converts a 32-byte secret to u64 by extracting the first 8 bytes.
    ///
    /// Uses little-endian byte order for compatibility with existing
    /// lib-proofs implementations.
    ///
    /// # Arguments
    ///
    /// * `secret` - A 32-byte array containing the cryptographic secret
    ///
    /// # Returns
    ///
    /// A u64 value representing the first 8 bytes of the secret in little-endian order.
    ///
    /// # Security Note
    ///
    /// This reduces entropy from 256 bits to 64 bits. See module-level documentation.
    ///
    /// # Examples
    ///
    /// ```
    /// use lib_identity::compat::ProofsSecretAdapter;
    ///
    /// let secret: [u8; 32] = [
    ///     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /// ];
    ///
    /// let value = ProofsSecretAdapter::to_u64(&secret);
    /// // Little-endian: 0x0807060504030201
    /// assert_eq!(value, 0x0807060504030201);
    /// ```
    #[inline]
    pub const fn to_u64(secret: &[u8; 32]) -> u64 {
        // Extract first 8 bytes and convert from little-endian
        u64::from_le_bytes([
            secret[0], secret[1], secret[2], secret[3],
            secret[4], secret[5], secret[6], secret[7],
        ])
    }

    /// Converts a u64 value to a 32-byte secret.
    ///
    /// The u64 value is placed in the first 8 bytes using little-endian order,
    /// and the remaining 24 bytes are zero-padded.
    ///
    /// # Arguments
    ///
    /// * `val` - The u64 value to convert
    ///
    /// # Returns
    ///
    /// A 32-byte array with the u64 value in the first 8 bytes (little-endian),
    /// and zeros in the remaining 24 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use lib_identity::compat::ProofsSecretAdapter;
    ///
    /// let value: u64 = 0x0807060504030201;
    /// let secret = ProofsSecretAdapter::from_u64(value);
    ///
    /// // First 8 bytes in little-endian
    /// assert_eq!(secret[0], 0x01);
    /// assert_eq!(secret[1], 0x02);
    /// assert_eq!(secret[2], 0x03);
    /// assert_eq!(secret[3], 0x04);
    /// assert_eq!(secret[4], 0x05);
    /// assert_eq!(secret[5], 0x06);
    /// assert_eq!(secret[6], 0x07);
    /// assert_eq!(secret[7], 0x08);
    ///
    /// // Remaining bytes are zero
    /// assert_eq!(secret[8..], [0u8; 24]);
    /// ```
    #[inline]
    pub const fn from_u64(val: u64) -> [u8; 32] {
        let bytes = val.to_le_bytes();
        [
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            // Zero-pad the remaining 24 bytes
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }

    /// Performs a round-trip conversion to verify correctness.
    ///
    /// Converts a u64 to [u8; 32] and back, returning true if the
    /// original value is recovered.
    ///
    /// # Arguments
    ///
    /// * `val` - The u64 value to test
    ///
    /// # Returns
    ///
    /// `true` if round-trip conversion succeeds, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use lib_identity::compat::ProofsSecretAdapter;
    ///
    /// assert!(ProofsSecretAdapter::verify_round_trip(0x1234567890ABCDEF));
    /// assert!(ProofsSecretAdapter::verify_round_trip(0));
    /// assert!(ProofsSecretAdapter::verify_round_trip(u64::MAX));
    /// ```
    pub const fn verify_round_trip(val: u64) -> bool {
        let secret = Self::from_u64(val);
        let recovered = Self::to_u64(&secret);
        recovered == val
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_u64_basic() {
        let secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        
        let result = ProofsSecretAdapter::to_u64(&secret);
        // Little-endian: bytes are interpreted as 0x0807060504030201
        assert_eq!(result, 0x0807060504030201);
    }

    #[test]
    fn test_to_u64_zero() {
        let secret: [u8; 32] = [0u8; 32];
        let result = ProofsSecretAdapter::to_u64(&secret);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_to_u64_max() {
        let secret: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = ProofsSecretAdapter::to_u64(&secret);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn test_from_u64_basic() {
        let val: u64 = 0x0807060504030201;
        let result = ProofsSecretAdapter::from_u64(val);
        
        // First 8 bytes in little-endian
        assert_eq!(result[0], 0x01);
        assert_eq!(result[1], 0x02);
        assert_eq!(result[2], 0x03);
        assert_eq!(result[3], 0x04);
        assert_eq!(result[4], 0x05);
        assert_eq!(result[5], 0x06);
        assert_eq!(result[6], 0x07);
        assert_eq!(result[7], 0x08);
        
        // Rest should be zero
        assert_eq!(result[8..], [0u8; 24]);
    }

    #[test]
    fn test_from_u64_zero() {
        let result = ProofsSecretAdapter::from_u64(0);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_from_u64_max() {
        let result = ProofsSecretAdapter::from_u64(u64::MAX);
        let expected: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_round_trip_various_values() {
        let test_values = [
            0u64,
            1u64,
            0x1234567890ABCDEF,
            0xABCDEF1234567890,
            u64::MAX,
            u64::MAX / 2,
            0x0102030405060708,
            0x0807060504030201,
        ];
        
        for &val in &test_values {
            let secret = ProofsSecretAdapter::from_u64(val);
            let recovered = ProofsSecretAdapter::to_u64(&secret);
            assert_eq!(
                recovered, val,
                "Round-trip failed for value: 0x{:016X}",
                val
            );
        }
    }

    #[test]
    fn test_verify_round_trip() {
        assert!(ProofsSecretAdapter::verify_round_trip(0));
        assert!(ProofsSecretAdapter::verify_round_trip(1));
        assert!(ProofsSecretAdapter::verify_round_trip(0x1234567890ABCDEF));
        assert!(ProofsSecretAdapter::verify_round_trip(u64::MAX));
    }

    #[test]
    fn test_little_endian_byte_order() {
        // Verify that we're using little-endian, not big-endian
        let val: u64 = 0x0102030405060708;
        let secret = ProofsSecretAdapter::from_u64(val);
        
        // In little-endian, the least significant byte comes first
        assert_eq!(secret[0], 0x08);
        assert_eq!(secret[1], 0x07);
        assert_eq!(secret[2], 0x06);
        assert_eq!(secret[3], 0x05);
        assert_eq!(secret[4], 0x04);
        assert_eq!(secret[5], 0x03);
        assert_eq!(secret[6], 0x02);
        assert_eq!(secret[7], 0x01);
        
        // Verify round-trip
        let recovered = ProofsSecretAdapter::to_u64(&secret);
        assert_eq!(recovered, val);
    }

    #[test]
    fn test_zero_padding() {
        let val: u64 = 0x0102030405060708;
        let secret = ProofsSecretAdapter::from_u64(val);
        
        // All bytes from index 8 onwards should be zero
        for i in 8..32 {
            assert_eq!(secret[i], 0, "Byte at index {} should be zero", i);
        }
    }

    #[test]
    fn test_to_u64_ignores_trailing_bytes() {
        // Create a secret where trailing bytes are non-zero
        let mut secret: [u8; 32] = [0u8; 32];
        secret[0] = 0x01;
        secret[8] = 0xFF; // This should be ignored
        secret[31] = 0xFF; // This should be ignored
        
        let result = ProofsSecretAdapter::to_u64(&secret);
        assert_eq!(result, 0x0000000000000001);
    }

    #[test]
    fn test_const_compatibility() {
        // Test that functions can be used in const contexts
        const TEST_VAL: u64 = 0x1234567890ABCDEF;
        const SECRET: [u8; 32] = ProofsSecretAdapter::from_u64(TEST_VAL);
        const RECOVERED: u64 = ProofsSecretAdapter::to_u64(&SECRET);
        const VERIFIED: bool = ProofsSecretAdapter::verify_round_trip(TEST_VAL);
        
        assert_eq!(RECOVERED, TEST_VAL);
        assert!(VERIFIED);
    }
}
