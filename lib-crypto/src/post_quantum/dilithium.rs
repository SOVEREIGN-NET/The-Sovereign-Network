//! CRYSTALS-Dilithium wrapper functions - preserving post-quantum signatures
//! 
//! implementation wrappers from crypto.rs for CRYSTALS-Dilithium

use anyhow::Result;
use pqcrypto_dilithium::{dilithium2, dilithium5};
use pqcrypto_traits::{
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, SignedMessage},
};

/// Generate Dilithium2 keypair (Level 2 security)
pub fn dilithium2_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium2::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Generate Dilithium5 keypair (Level 5 security - highest)
pub fn dilithium5_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium5::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Sign message with Dilithium2
pub fn dilithium2_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sk = dilithium2::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium2 secret key"))?;
    
    let signature = dilithium2::sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

/// Sign message with Dilithium5
pub fn dilithium5_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sk = dilithium5::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium5 secret key"))?;
    
    let signature = dilithium5::sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

/// Verify Dilithium2 signature
pub fn dilithium2_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let pk = dilithium2::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium2 public key"))?;
    let sig = dilithium2::SignedMessage::from_bytes(signature)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium2 signature"))?;
    
    match dilithium2::open(&sig, &pk) {
        Ok(verified_message) => Ok(verified_message == message),
        Err(_) => Ok(false),
    }
}

/// Verify Dilithium5 signature
pub fn dilithium5_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let pk = dilithium5::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium5 public key"))?;
    let sig = dilithium5::SignedMessage::from_bytes(signature)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium5 signature"))?;
    
    match dilithium5::open(&sig, &pk) {
        Ok(verified_message) => Ok(verified_message == message),
        Err(_) => Ok(false),
    }
}
