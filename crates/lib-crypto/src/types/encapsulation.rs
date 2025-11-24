//! Key encapsulation type definitions - preserving ZHTP encapsulation
//! 
//! implementations from crypto.rs, lines 194-202

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key encapsulation result with quantum-resistant security
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Encapsulation {
    /// CRYSTALS-Kyber ciphertext
    pub ciphertext: Vec<u8>,
    /// Derived shared secret
    #[zeroize(skip)]
    pub shared_secret: [u8; 32],
    /// Key derivation info
    pub kdf_info: Vec<u8>,
}
