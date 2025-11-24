//! Ed25519 classical cryptography for compatibility
//! 
//! Ed25519 implementation from crypto.rs for legacy support

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature as Ed25519Signature, Signer, Verifier};
use rand::{RngCore, rngs::OsRng};

/// Generate Ed25519 keypair
pub fn ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();
    
    (verifying_key.as_bytes().to_vec(), signing_key.as_bytes().to_vec())
}

/// Generate Ed25519 keypair from seed
pub fn ed25519_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    
    (verifying_key.as_bytes().to_vec(), signing_key.as_bytes().to_vec())
}

/// Sign message with Ed25519
pub fn ed25519_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    if secret_key.len() != 32 {
        return Err(anyhow::anyhow!("Invalid Ed25519 secret key length"));
    }
    
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&secret_key[..32]);
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify Ed25519 signature
pub fn ed25519_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    if signature.len() != 64 {
        return Ok(false);
    }
    
    if public_key.len() != 32 {
        return Ok(false);
    }
    
    let sig = match Ed25519Signature::try_from(&signature[..64]) {
        Ok(sig) => sig,
        Err(_) => return Ok(false),
    };
    
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&public_key[..32]);
    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    
    Ok(verifying_key.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_operations() -> Result<()> {
        let (pk, sk) = ed25519_keypair();
        let message = b"ZHTP Ed25519 test message";
        
        // Sign and verify
        let signature = ed25519_sign(message, &sk)?;
        assert!(ed25519_verify(message, &signature, &pk)?);
        
        // Wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(!ed25519_verify(wrong_message, &signature, &pk)?);
        
        Ok(())
    }

    #[test]
    fn test_ed25519_deterministic() -> Result<()> {
        let seed = [42u8; 32];
        let (pk1, sk1) = ed25519_keypair_from_seed(&seed);
        let (pk2, sk2) = ed25519_keypair_from_seed(&seed);
        
        // Same seed should produce same keys
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
        
        Ok(())
    }
}
