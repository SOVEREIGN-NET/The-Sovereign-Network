//! Private identity data from the original identity.rs

use lib_crypto::Hash;

/// Private identity data (never transmitted) - based on original identity.rs
#[derive(Debug, Clone)]
pub struct PrivateIdentityData {
    /// Private signing key
    pub private_key: Vec<u8>,
    /// Identity seed for key derivation (64 bytes - expanded via HKDF)
    pub seed: [u8; 64],
    /// Recovery phrases
    pub recovery_phrases: Vec<String>,
    /// Biometric templates (hashed)
    pub biometric_hashes: Vec<Hash>,
    /// Quantum keypair for post-quantum signatures
    pub quantum_keypair: QuantumKeypair,
}

/// Quantum-resistant keypair
#[derive(Debug, Clone)]
pub struct QuantumKeypair {
    /// Private signing key
    pub private_key: Vec<u8>,
    /// Public verification key
    pub public_key: Vec<u8>,
}

impl PrivateIdentityData {
    /// Create new private identity data
    pub fn new(private_key: Vec<u8>, public_key: Vec<u8>, seed: [u8; 64], recovery_phrases: Vec<String>) -> Self {
        Self {
            private_key: private_key.clone(),
            seed,
            recovery_phrases,
            biometric_hashes: vec![],
            quantum_keypair: QuantumKeypair {
                private_key,
                public_key,
            },
        }
    }
    
    /// Get private key reference
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
    
    /// Get public key reference
    pub fn public_key(&self) -> &[u8] {
        &self.quantum_keypair.public_key
    }
    
    /// Get seed reference
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }
}

impl QuantumKeypair {
    /// Create new quantum keypair
    pub fn new(private_key: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}
