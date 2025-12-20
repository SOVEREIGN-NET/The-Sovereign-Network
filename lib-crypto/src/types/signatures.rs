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

impl Signature {
    /// Create a Signature from raw bytes with a known public key
    ///
    /// This is used when reconstructing a signature from serialized form
    /// where the public key is known from the message context.
    ///
    /// # Arguments
    /// * `signature_bytes` - The raw signature bytes
    /// * `public_key` - The public key that created this signature
    ///
    /// # Note
    /// Assumes Dilithium2 algorithm. For other algorithms, use `from_bytes_with_algorithm`.
    pub fn from_bytes_with_key(signature_bytes: &[u8], public_key: PublicKey) -> Self {
        Signature {
            signature: signature_bytes.to_vec(),
            public_key,
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create a Signature from raw bytes (for backward compatibility)
    ///
    /// # Warning
    /// This creates a signature with an empty public key. You should use
    /// `from_bytes_with_key` when the public key is available.
    #[deprecated(note = "Use from_bytes_with_key instead when public key is available")]
    pub fn from_bytes(signature_bytes: &[u8]) -> Self {
        Signature {
            signature: signature_bytes.to_vec(),
            public_key: PublicKey {
                dilithium_pk: Vec::new(),
                kyber_pk: Vec::new(),
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Get the raw signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }
}

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
