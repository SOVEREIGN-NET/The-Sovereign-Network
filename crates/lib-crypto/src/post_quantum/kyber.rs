//! CRYSTALS-Kyber wrapper functions - preserving post-quantum KEM
//! 
//! implementation wrappers from crypto.rs for CRYSTALS-Kyber

use anyhow::Result;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, Ciphertext, SharedSecret},
};
use sha3::Sha3_256;
use hkdf::Hkdf;

/// Generate Kyber512 keypair (balanced security/performance)
pub fn kyber512_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kyber512::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Encapsulate shared secret with Kyber512
pub fn kyber512_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let pk = kyber512::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber512 public key"))?;
    
    let (shared_secret_bytes, ciphertext) = kyber512::encapsulate(&pk);
    
    // Derive a 32-byte key using HKDF-SHA3
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret_bytes.as_bytes());
    let mut shared_secret = [0u8; 32];
    let kdf_info = b"ZHTP-KEM-v1.0";
    hk.expand(kdf_info, &mut shared_secret)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
    
    Ok((ciphertext.as_bytes().to_vec(), shared_secret))
}

/// Decapsulate shared secret with Kyber512
pub fn kyber512_decapsulate(ciphertext: &[u8], secret_key: &[u8], kdf_info: &[u8]) -> Result<[u8; 32]> {
    let sk = kyber512::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber512 secret key"))?;
    let ct = kyber512::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber512 ciphertext"))?;
    
    let shared_secret_bytes = kyber512::decapsulate(&ct, &sk);
    
    // Derive the same 32-byte key using HKDF-SHA3
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret_bytes.as_bytes());
    let mut shared_secret = [0u8; 32];
    hk.expand(kdf_info, &mut shared_secret)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
    
    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber512_kem() -> Result<()> {
        let (pk, sk) = kyber512_keypair();
        
        // Encapsulate
        let (ciphertext, shared_secret1) = kyber512_encapsulate(&pk)?;
        
        // Decapsulate
        let kdf_info = b"ZHTP-KEM-v1.0";
        let shared_secret2 = kyber512_decapsulate(&ciphertext, &sk, kdf_info)?;
        
        // Should match
        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32);
        
        Ok(())
    }
}
