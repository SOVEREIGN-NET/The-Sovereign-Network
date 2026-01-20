//! Post-quantum cryptography constants - CRYSTALS key sizes
//!
//! ZHTP uses only Kyber1024 (NIST Level 5) and Dilithium5 (highest security).
//! Kyber512 is NOT supported - do not add it.

/// CRYSTALS-Kyber1024 constants (NIST post-quantum standard - Level 5, highest security)
/// This is the ONLY Kyber variant supported by ZHTP.
pub const KYBER1024_CIPHERTEXT_BYTES: usize = 1568;
pub const KYBER1024_PUBLICKEY_BYTES: usize = 1568;
pub const KYBER1024_SECRETKEY_BYTES: usize = 3168;

/// CRYSTALS-Dilithium2 constants (NIST post-quantum standard)
/// NOTE: pqcrypto_dilithium uses 2560 bytes for D2 secret key
pub const DILITHIUM2_PUBLICKEY_BYTES: usize = 1312;
pub const DILITHIUM2_SECRETKEY_BYTES: usize = 2560;

/// CRYSTALS-Dilithium5 constants (highest security level)
pub const DILITHIUM5_PUBLICKEY_BYTES: usize = 2592;
pub const DILITHIUM5_SECRETKEY_BYTES: usize = 4896;

// Re-export for backward compatibility
pub use DILITHIUM2_PUBLICKEY_BYTES as DILITHIUM_PUBLIC_KEY_SIZE;
pub use DILITHIUM2_SECRETKEY_BYTES as DILITHIUM_PRIVATE_KEY_SIZE;
pub use KYBER1024_PUBLICKEY_BYTES as KYBER_PUBLIC_KEY_SIZE;
pub use KYBER1024_SECRETKEY_BYTES as KYBER_PRIVATE_KEY_SIZE;
