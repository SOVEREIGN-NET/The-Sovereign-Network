//! CRYSTALS-Kyber wrapper functions - preserving post-quantum KEM
//! 
//! implementation wrappers from crypto.rs for CRYSTALS-Kyber

use anyhow::Result;
use pqcrypto_kyber::{kyber512, kyber1024};
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
///
/// Note: kdf_info must match the info used in kyber512_decapsulate for the
/// shared secrets to be identical on both sides.
pub fn kyber512_encapsulate(public_key: &[u8], kdf_info: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let pk = kyber512::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber512 public key"))?;

    let (shared_secret_bytes, ciphertext) = kyber512::encapsulate(&pk);

    // Derive a 32-byte key using HKDF-SHA3
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret_bytes.as_bytes());
    let mut shared_secret = [0u8; 32];
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

// ============================================================================
// Kyber1024 - Highest security level (NIST Level 5)
// ============================================================================

/// Generate Kyber1024 keypair (highest security, larger keys)
pub fn kyber1024_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kyber1024::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// ✅ FIX: Encapsulate shared secret with Kyber1024 with consistent KDF info
///
/// Note: kdf_info must match the info used in kyber1024_decapsulate for the
/// shared secrets to be identical on both sides. Consistency is enforced by using
/// the same KDF info constant.
pub fn kyber1024_encapsulate(public_key: &[u8], kdf_info: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let pk = kyber1024::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber1024 public key"))?;

    let (shared_secret_bytes, ciphertext) = kyber1024::encapsulate(&pk);

    // Derive a 32-byte key using HKDF-SHA3
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret_bytes.as_bytes());
    let mut shared_secret = [0u8; 32];
    hk.expand(kdf_info, &mut shared_secret)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    Ok((ciphertext.as_bytes().to_vec(), shared_secret))
}

/// ✅ FIX: Decapsulate shared secret with Kyber1024 with consistent KDF info
pub fn kyber1024_decapsulate(ciphertext: &[u8], secret_key: &[u8], kdf_info: &[u8]) -> Result<[u8; 32]> {
    let sk = kyber1024::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber1024 secret key"))?;
    let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber1024 ciphertext"))?;

    let shared_secret_bytes = kyber1024::decapsulate(&ct, &sk);

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

        // Both sides must use the same kdf_info
        let kdf_info = b"ZHTP-QUIC-KEM-v1.0";

        // Encapsulate
        let (ciphertext, shared_secret1) = kyber512_encapsulate(&pk, kdf_info)?;

        // Decapsulate
        let shared_secret2 = kyber512_decapsulate(&ciphertext, &sk, kdf_info)?;

        // Should match
        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32);

        Ok(())
    }

    #[test]
    fn test_kyber1024_kem() -> Result<()> {
        let (pk, sk) = kyber1024_keypair();

        // Both sides must use the same kdf_info
        let kdf_info = b"ZHTP-KEM-v1.0";

        // Encapsulate
        let (ciphertext, shared_secret1) = kyber1024_encapsulate(&pk, kdf_info)?;

        // Decapsulate
        let shared_secret2 = kyber1024_decapsulate(&ciphertext, &sk, kdf_info)?;

        // Should match
        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32);

        Ok(())
    }
}
