//! Post-quantum cryptography constants - CRYSTALS key sizes
//!
//! ZHTP uses only Kyber1024 (NIST Level 5) and Dilithium5 (highest security).
//! Kyber512 is NOT supported - do not add it.
//!
//! This is the SINGLE SOURCE OF TRUTH for all PQ constants used in this workspace.
//! Numeric values are copied from, and expected to match: pqc_kyber, pqcrypto_dilithium, crystals-dilithium.

/// CRYSTALS-Kyber1024 constants (NIST post-quantum standard - Level 5, highest security)
/// This is the ONLY Kyber variant supported by ZHTP.
/// Values are copied from the pqc_kyber crate and MUST remain in sync with its definitions.
pub const KYBER1024_CIPHERTEXT_BYTES: usize = 1568;
pub const KYBER1024_PUBLICKEY_BYTES: usize = 1568;
pub const KYBER1024_SECRETKEY_BYTES: usize = 3168;

/// CRYSTALS-Dilithium2 constants (NIST post-quantum standard)
/// NOTE: pqcrypto_dilithium uses 2560 bytes for D2 secret key
pub const DILITHIUM2_PUBLICKEY_BYTES: usize = 1312;
pub const DILITHIUM2_SECRETKEY_BYTES: usize = 2560;

/// CRYSTALS-Dilithium5 constants (highest security level)
pub const DILITHIUM5_PUBLICKEY_BYTES: usize = 2592;
pub const DILITHIUM5_SIGNATURE_BYTES: usize = 4595;
/// pqcrypto-dilithium format (random keygen)
pub const DILITHIUM5_SECRETKEY_BYTES_PQCRYPTO: usize = 4896;
/// crystals-dilithium format (seed-derived keys)
pub const DILITHIUM5_SECRETKEY_BYTES_CRYSTALS: usize = 4864;
/// Legacy alias for backward compatibility (defaults to pqcrypto format)
pub const DILITHIUM5_SECRETKEY_BYTES: usize = DILITHIUM5_SECRETKEY_BYTES_PQCRYPTO;

// Re-export canonical consensus-level sizes.
pub use DILITHIUM5_PUBLICKEY_BYTES as DILITHIUM_PUBLIC_KEY_SIZE;
pub use DILITHIUM5_SECRETKEY_BYTES as DILITHIUM_PRIVATE_KEY_SIZE;
pub use KYBER1024_PUBLICKEY_BYTES as KYBER_PUBLIC_KEY_SIZE;
pub use KYBER1024_SECRETKEY_BYTES as KYBER_PRIVATE_KEY_SIZE;
