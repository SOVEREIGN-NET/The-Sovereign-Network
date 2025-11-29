//! Key type definitions - preserving ZHTP key structures
//! 
//! implementations from crypto.rs, lines 78-150

use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use anyhow::Result;
use crate::types::Signature;
use crate::hashing::hash_blake3;
use crate::verification::verify_signature;

/// Pure post-quantum public key with CRYSTALS implementations only
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// CRYSTALS-Dilithium public key for post-quantum signatures
    pub dilithium_pk: Vec<u8>,
    /// CRYSTALS-Kyber public key for post-quantum key encapsulation
    pub kyber_pk: Vec<u8>,
    /// Key identifier for fast lookups
    pub key_id: [u8; 32],
}

impl PublicKey {
    /// Create a new public key from raw bytes (assumes Dilithium)
    pub fn new(dilithium_pk: Vec<u8>) -> Self {
        let key_id = hash_blake3(&dilithium_pk);
        PublicKey {
            dilithium_pk,
            kyber_pk: Vec::new(),
            // ed25519_pk removed - pure PQC only
            key_id,
        }
    }

    /// Get the size of this public key in bytes (pure PQC only)
    pub fn size(&self) -> usize {
        self.dilithium_pk.len() + self.kyber_pk.len() + 32 // key_id
    }

    /// Convert public key to bytes for signature verification (pure PQC only)
    pub fn as_bytes(&self) -> Vec<u8> {
        // Always use CRYSTALS-Dilithium public key for pure post-quantum security
        if !self.dilithium_pk.is_empty() {
            return self.dilithium_pk.clone();
        }
        
        // Fallback to key_id only if Dilithium key not available
        self.key_id.to_vec()
    }

    /// Verify a signature against this public key using pure post-quantum cryptography
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        // Always use CRYSTALS-Dilithium verification - no fallbacks
        if self.dilithium_pk.is_empty() {
            return Err(anyhow::anyhow!("No Dilithium public key available for pure PQC verification"));
        }
        
        // Pure post-quantum signature verification
        verify_signature(message, &signature.signature, &self.dilithium_pk)
    }
}

/// Pure post-quantum private key (zeroized on drop for security)
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// CRYSTALS-Dilithium secret key
    pub dilithium_sk: Vec<u8>,
    /// CRYSTALS-Kyber secret key  
    pub kyber_sk: Vec<u8>,
    /// Master seed for key derivation
    pub master_seed: Vec<u8>,
}

impl PrivateKey {
    /// Get the size of this private key in bytes (pure PQC only)
    pub fn size(&self) -> usize {
        self.dilithium_sk.len() + self.kyber_sk.len() + self.master_seed.len()
    }
}
