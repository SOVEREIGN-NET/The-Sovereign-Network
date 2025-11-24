//! Post-quantum cryptography constants - preserving CRYSTALS key sizes
//! 
//! constants from crypto.rs, lines 69-75

/// CRYSTALS-Kyber512 constants (NIST post-quantum standard)
pub const KYBER512_CIPHERTEXT_BYTES: usize = 768;
pub const KYBER512_PUBLICKEY_BYTES: usize = 800;
pub const KYBER512_SECRETKEY_BYTES: usize = 1632;

/// CRYSTALS-Dilithium2 constants (NIST post-quantum standard)
pub const DILITHIUM2_PUBLICKEY_BYTES: usize = 1312;
pub const DILITHIUM2_SECRETKEY_BYTES: usize = 2528;

/// CRYSTALS-Dilithium5 constants (highest security level)
pub const DILITHIUM5_PUBLICKEY_BYTES: usize = 2592;
pub const DILITHIUM5_SECRETKEY_BYTES: usize = 4864;

// Re-export for backward compatibility
pub use DILITHIUM2_PUBLICKEY_BYTES as DILITHIUM_PUBLIC_KEY_SIZE;
pub use DILITHIUM2_SECRETKEY_BYTES as DILITHIUM_PRIVATE_KEY_SIZE;
pub use KYBER512_PUBLICKEY_BYTES as KYBER_PUBLIC_KEY_SIZE;
pub use KYBER512_SECRETKEY_BYTES as KYBER_PRIVATE_KEY_SIZE;
