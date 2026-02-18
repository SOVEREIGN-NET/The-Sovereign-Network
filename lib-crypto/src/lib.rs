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
pub mod traits;  // Cryptographic security traits
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
    keys::{PublicKey, PrivateKey},
    signatures::{Signature, SignatureAlgorithm, PostQuantumSignature}
};
pub use verification::{verify_signature, validate_consensus_vote_signature_scheme, verify_consensus_vote_signature};

// Re-export security traits for zeroization enforcement
pub use traits::{ZeroizingKey, SecureKey};

// Re-export hashing functionality
pub use hashing::{hash_blake3, hash_sha3_256};

// Re-export random functionality
pub use random::{SecureRng, generate_nonce};

// Re-export seed functionality
pub use seed::generate_identity_seed;

// Re-export keypair functionality
pub use keypair::{
    generation::KeyPair,
    CONSENSUS_SIGNATURE_SCHEME,
    validate_consensus_signature_scheme,
};
pub use keypair::operations::encrypt_with_public_key;

// Re-export symmetric encryption
pub use symmetric::{
    hybrid::{hybrid_encrypt, hybrid_decrypt},
    chacha20::{encrypt_data, decrypt_data}
};

// Re-export key derivation
pub use kdf::hkdf::derive_keys;

// Note: ZK integration moved to lib-proofs for proper architectural separation

// Re-export utility functions
pub use utils::compatibility::{generate_keypair, sign_message};
