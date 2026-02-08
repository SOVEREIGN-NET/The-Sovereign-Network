//! CRYSTALS-Kyber wrapper functions - preserving post-quantum KEM
//! 
//! implementation wrappers from crypto.rs for CRYSTALS-Kyber

use anyhow::Result;
use pqc_kyber::{self, KYBER_CIPHERTEXTBYTES, KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES};
use sha3::Sha3_256;
use hkdf::Hkdf;
use rand::rngs::OsRng;

/// Generate Kyber1024 keypair (highest security, larger keys)
pub fn kyber1024_keypair() -> (Vec<u8>, Vec<u8>) {
    let keys = pqc_kyber::keypair(&mut OsRng)
        .expect("Kyber1024 keypair generation failed");
    (keys.public.to_vec(), keys.secret.to_vec())
}

/// ✅ FIX: Encapsulate shared secret with Kyber1024 with consistent KDF info
///
/// Note: kdf_info must match the info used in kyber1024_decapsulate for the
/// shared secrets to be identical on both sides. Consistency is enforced by using
/// the same KDF info constant.
pub fn kyber1024_encapsulate(public_key: &[u8], kdf_info: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let pk: [u8; KYBER_PUBLICKEYBYTES] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid Kyber1024 public key (len={})", public_key.len()))?;

    let (ciphertext, shared_secret_bytes) = pqc_kyber::encapsulate(&pk, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("Kyber1024 encapsulate failed: {:?}", e))?;

    // Derive a 32-byte key using HKDF-SHA3
    let hk = Hkdf::<Sha3_256>::new(None, &shared_secret_bytes);
    let mut shared_secret = [0u8; 32];
    hk.expand(kdf_info, &mut shared_secret)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    Ok((ciphertext.to_vec(), shared_secret))
}

/// ✅ FIX: Decapsulate shared secret with Kyber1024 with consistent KDF info
pub fn kyber1024_decapsulate(ciphertext: &[u8], secret_key: &[u8], kdf_info: &[u8]) -> Result<[u8; 32]> {
    let sk: [u8; KYBER_SECRETKEYBYTES] = secret_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid Kyber1024 secret key (len={})", secret_key.len()))?;

    let ct: [u8; KYBER_CIPHERTEXTBYTES] = ciphertext
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid Kyber1024 ciphertext (len={})", ciphertext.len()))?;

    let shared_secret_bytes = pqc_kyber::decapsulate(&ct, &sk)
        .map_err(|e| anyhow::anyhow!("Kyber1024 decapsulate failed: {:?}", e))?;

    // Derive the same 32-byte key using HKDF-SHA3
    let hk = Hkdf::<Sha3_256>::new(None, &shared_secret_bytes);
    let mut shared_secret = [0u8; 32];
    hk.expand(kdf_info, &mut shared_secret)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber1024_kem() -> Result<()> {
        let (pk, sk) = kyber1024_keypair();

        // Both sides must use the same kdf_info
        let kdf_info = b"ZHTP-KEM-v2.0";

        // Encapsulate
        let (ciphertext, shared_secret1) = kyber1024_encapsulate(&pk, kdf_info)?;

        // Decapsulate
        let shared_secret2 = kyber1024_decapsulate(&ciphertext, &sk, kdf_info)?;

        // Should match
        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32);

        Ok(())
    }

    #[test]
    fn test_kyber1024_sizes_match_expected() {
        let (pk, sk) = kyber1024_keypair();
        assert_eq!(pk.len(), KYBER_PUBLICKEYBYTES);
        assert_eq!(sk.len(), KYBER_SECRETKEYBYTES);
    }
}
