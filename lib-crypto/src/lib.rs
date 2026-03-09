//! ZHTP Cryptography Foundation Module
//!
//! cryptography implementations from crypto.rs preserving functionality

// Core modules
pub mod advanced;
pub mod classical;
pub mod kdf;
pub mod keypair;
pub mod post_quantum;
pub mod symmetric;
pub mod traits; // Cryptographic security traits
pub mod types;
pub mod utils;
pub mod verification;

// New modules for missing functionality
pub mod hashing;
pub mod random;
pub mod seed;
// Note: password module moved to lib-identity/src/auth/password.rs

// Re-export commonly used types and functions
pub use types::{
    hash::Hash,
    keys::{PrivateKey, PublicKey},
    signatures::{PostQuantumSignature, Signature, SignatureAlgorithm},
};
pub use verification::{
    validate_consensus_vote_signature_scheme, verify_consensus_vote_signature, verify_signature,
};

// Re-export security traits for zeroization enforcement
pub use traits::{SecureKey, ZeroizingKey};

// Re-export hashing functionality
pub use hashing::{hash_blake3, hash_sha3_256};

// Re-export random functionality
pub use random::{generate_nonce, SecureRng};

// Re-export seed functionality
pub use seed::generate_identity_seed;

// Re-export keypair functionality
pub use keypair::operations::encrypt_with_public_key;
pub use keypair::{
    generation::KeyPair, validate_consensus_signature_scheme, CONSENSUS_SIGNATURE_SCHEME,
};

// Re-export symmetric encryption
pub use symmetric::{
    chacha20::{decrypt_data, encrypt_data},
    hybrid::{hybrid_decrypt, hybrid_encrypt},
};

// Re-export key derivation
pub use kdf::hkdf::derive_keys;

// Note: ZK integration moved to lib-proofs for proper architectural separation

// Re-export utility functions
pub use utils::compatibility::{generate_keypair, sign_message};
