//! Crypto Integration Module
//! Re-exports from lib-crypto for blockchain use

pub use lib_crypto::{
    types::{
        keys::{PublicKey, PrivateKey},
        signatures::{Signature, SignatureAlgorithm},
    },
    hashing::hash_blake3 as hash_data,
    KeyPair,
    symmetric::{hybrid_encrypt, hybrid_decrypt},
};

// Helper functions
pub fn public_key_bytes(key: &PublicKey) -> Vec<u8> {
    key.as_bytes().to_vec()
}

pub fn encrypt_data_hybrid(data: &[u8], public_key: &PublicKey) -> Result<Vec<u8>, String> {
    // Use lib-crypto's encryption functionality
    hybrid_encrypt(data, public_key)
        .map_err(|e| format!("Encryption failed: {:?}", e))
}
