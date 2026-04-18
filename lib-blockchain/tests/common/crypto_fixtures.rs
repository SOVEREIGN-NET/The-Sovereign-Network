//! Shared cryptographic test fixtures for lib-blockchain integration tests.
//!
//! Centralises PublicKey and Signature construction so every test file uses
//! identical byte layouts rather than copying the same four lines.

use lib_crypto::types::keys::PublicKey;
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

/// A 2592-byte all-zeros Dilithium public key.
pub fn dummy_public_key() -> PublicKey {
    PublicKey::new([0u8; 2592])
}

/// A seeded Dilithium public key — first byte set to `seed`.
pub fn seeded_public_key(seed: u8) -> PublicKey {
    let mut pk = [0u8; 2592];
    pk[0] = seed;
    PublicKey::new(pk)
}

/// A zero-value signature over `dummy_public_key()` with timestamp 0.
pub fn dummy_signature() -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: dummy_public_key(),
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: 0,
    }
}

/// A seeded signature — `seed` byte repeated through signature bytes and pk.
pub fn seeded_signature(seed: u8) -> Signature {
    Signature {
        signature: vec![seed; 64],
        public_key: seeded_public_key(seed),
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: 1,
    }
}
