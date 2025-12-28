//! Identity recovery data - used only for account recovery
//!
//! Per identity architecture (docs/identity.md):
//! - Cryptographic root is ZhtpIdentity.wallet_master_seed [u8; 64]
//! - This struct contains only recovery material (UX data, not crypto root)
//! - No "seed" field is allowed to exist (it created collisions)

use lib_crypto::Hash;
use crate::guardian::GuardianConfig;

/// Identity recovery data (never transmitted, never used for signing)
///
/// This struct exists ONLY to store recovery phrases for account recovery.
/// It must never contain:
/// - Any field named "seed" (creates ambiguity with root)
/// - Signing material
/// - Any value used for crypto operations
#[derive(Debug, Clone)]
pub struct PrivateIdentityData {
    /// Private signing key (stored for keystore export only)
    pub private_key: Vec<u8>,
    /// Recovery phrases (for recovery flow only)
    pub recovery_phrases: Vec<String>,
    /// Biometric templates (hashed)
    pub biometric_hashes: Vec<Hash>,
    /// Quantum keypair for post-quantum signatures
    pub quantum_keypair: QuantumKeypair,
    /// Guardian configuration for social recovery
    pub guardian_config: Option<GuardianConfig>,
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
    /// Create new recovery data (for keystore export only)
    ///
    /// CRITICAL: This must be created from data that is ALREADY properly derived.
    /// The seed parameter has been removed - it was causing collisions.
    pub fn new(private_key: Vec<u8>, public_key: Vec<u8>, recovery_phrases: Vec<String>) -> Self {
        Self {
            private_key: private_key.clone(),
            recovery_phrases,
            biometric_hashes: vec![],
            quantum_keypair: QuantumKeypair {
                private_key,
                public_key,
            },
            guardian_config: None,
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
