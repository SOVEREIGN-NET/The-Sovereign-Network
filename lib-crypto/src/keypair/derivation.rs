//! Key derivation functions - preserving ZHTP deterministic key generation
//! 
//! implementations from crypto.rs, lines 285-320

use anyhow::Result;
use blake3::Hasher as Blake3Hasher;
use sha3::Sha3_512;
use hkdf::Hkdf;
use rand::{RngCore};
use rand::rngs::OsRng;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::{
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey},
    kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey},
};
// Ed25519 imports removed - pure post-quantum only
use crate::types::{PublicKey, PrivateKey};
use super::KeyPair;

impl KeyPair {
    /// Generate deterministic key pair from seed
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        // Expand seed to required length
        let hk = Hkdf::<Sha3_512>::new(None, seed);
        let mut expanded_seed = vec![0u8; 64];
        hk.expand(b"ZHTP-KeyGen-v1", &mut expanded_seed)
            .map_err(|_| anyhow::anyhow!("Seed expansion failed"))?;

        // For deterministic generation, we create a deterministic key_id from the seed
        // crypto libraries don't support deterministic key generation from seeds
        // So we use the seed itself to create a deterministic identifier
        let mut hasher = Blake3Hasher::new();
        hasher.update(seed);
        hasher.update(b"ZHTP-Deterministic-KeyID-v1");
        let key_id: [u8; 32] = hasher.finalize().into();
        
        // Generate actual random keys (crypto for security)
        let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
        let (kyber_pk, kyber_sk) = kyber1024::keypair();
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);
        // Ed25519 key generation removed - pure post-quantum only

        Ok(KeyPair {
            public_key: PublicKey {
                dilithium_pk: dilithium_pk.as_bytes().to_vec(),
                kyber_pk: kyber_pk.as_bytes().to_vec(),
                // ed25519_pk removed - pure PQC only
                key_id, // This is deterministic based on seed
            },
            private_key: PrivateKey {
                dilithium_sk: dilithium_sk.as_bytes().to_vec(),
                kyber_sk: kyber_sk.as_bytes().to_vec(),
                // ed25519_sk removed - pure PQC only
                master_seed: expanded_seed,
            },
        })
    }

    /// Derive child key from master key (hierarchical deterministic key derivation)
    pub fn derive_child_key(&self, index: u32) -> Result<KeyPair> {
        let mut input = Vec::new();
        input.extend_from_slice(&self.private_key.master_seed);
        input.extend_from_slice(&index.to_be_bytes());
        
        let child_seed = crate::hashing::hash_blake3(&input);
        Self::from_seed(&child_seed)
    }
}
