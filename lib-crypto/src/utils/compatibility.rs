//! Compatibility utility functions - preserving ZHTP convenience functions
//! 
//! implementation from crypto.rs, lines 657-665

use anyhow::Result;
use crate::keypair::KeyPair;
use crate::types::Signature;

/// Generate a new quantum-resistant keypair
pub fn generate_keypair() -> Result<KeyPair> {
    KeyPair::generate()
}

/// Sign a message with a keypair (convenience function)
pub fn sign_message(keypair: &KeyPair, message: &[u8]) -> Result<Signature> {
    keypair.sign(message)
}
