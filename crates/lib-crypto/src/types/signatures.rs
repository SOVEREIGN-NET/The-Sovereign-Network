//! Signature type definitions - preserving ZHTP signature structures
//! 
//! implementations from crypto.rs, lines 162-192

use serde::{Serialize, Deserialize};
use crate::types::PublicKey;

/// Digital signature with quantum-resistant security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// The actual signature bytes
    pub signature: Vec<u8>,
    /// Public key used for verification
    pub public_key: PublicKey,
    /// Signature algorithm identifier
    pub algorithm: SignatureAlgorithm,
    /// Timestamp of signature creation
    pub timestamp: u64,
}

/// Supported signature algorithms (pure post-quantum only)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// CRYSTALS-Dilithium Level 2 (post-quantum)
    Dilithium2,
    /// CRYSTALS-Dilithium Level 5 (post-quantum, highest security)
    Dilithium5,
    /// Ring signature for anonymity (post-quantum)
    RingSignature,
}

/// Type alias for compatibility with other modules
pub type PostQuantumSignature = Signature;

impl Default for Signature {
    fn default() -> Self {
        use crate::types::keys::PublicKey;
        Signature {
            signature: Vec::new(),
            public_key: PublicKey {
                dilithium_pk: Vec::new(),
                kyber_pk: Vec::new(),
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        }
    }
}
