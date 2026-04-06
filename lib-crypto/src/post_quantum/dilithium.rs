//! CRYSTALS-Dilithium5 wrapper functions — pure crystals-dilithium implementation
//!
//! All Dilithium operations use the `crystals-dilithium` crate exclusively.
//! Signatures are 4595-byte detached format; secret keys are 4864 bytes.

use anyhow::Result;
use crystals_dilithium::dilithium5::{
    Keypair, PublicKey as CrystalsPublicKey, SecretKey as CrystalsSecretKey, SIGNBYTES,
};

use super::constants::{
    DILITHIUM5_PUBLICKEY_BYTES, DILITHIUM5_SECRETKEY_BYTES, DILITHIUM5_SECRETKEY_STORAGE_BYTES,
};

/// Generate a random Dilithium5 keypair.
/// Returns (public_key: 2592 bytes, secret_key: 4864 bytes).
pub fn dilithium5_keypair() -> (Vec<u8>, Vec<u8>) {
    let keypair = Keypair::generate(None);
    (
        keypair.public.to_bytes().to_vec(),
        keypair.secret.to_bytes().to_vec(),
    )
}

/// Generate a deterministic Dilithium5 keypair from caller-provided entropy.
///
/// Uses blake3 to derive a 32-byte seed, then feeds it to crystals-dilithium's
/// deterministic keygen. Consensus/bootstrap code uses this to derive reproducible
/// public keys from protocol constants.
pub fn dilithium5_keypair_from_entropy(entropy: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let seed = crate::hashing::hash_blake3(entropy);
    let keypair = Keypair::generate(Some(&seed));
    (
        keypair.public.to_bytes().to_vec(),
        keypair.secret.to_bytes().to_vec(),
    )
}

/// Sign message with Dilithium5.
///
/// Accepts both 4864-byte (native crystals) and 4896-byte (zero-padded storage
/// format) secret keys. Produces a 4595-byte detached signature.
pub fn dilithium5_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sk_bytes = match secret_key.len() {
        DILITHIUM5_SECRETKEY_BYTES => secret_key,
        DILITHIUM5_SECRETKEY_STORAGE_BYTES => &secret_key[..DILITHIUM5_SECRETKEY_BYTES],
        n => {
            return Err(anyhow::anyhow!(
                "Invalid Dilithium5 secret key size: {} bytes (expected {} or {})",
                n,
                DILITHIUM5_SECRETKEY_BYTES,
                DILITHIUM5_SECRETKEY_STORAGE_BYTES
            ))
        }
    };

    let sk = CrystalsSecretKey::from_bytes(sk_bytes);
    let signature = sk.sign(message);
    Ok(signature.to_vec())
}

/// Verify a Dilithium5 detached signature (4595 bytes).
pub fn dilithium5_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    if public_key.len() != DILITHIUM5_PUBLICKEY_BYTES {
        return Err(anyhow::anyhow!(
            "Invalid Dilithium5 public key length: {} (expected {})",
            public_key.len(),
            DILITHIUM5_PUBLICKEY_BYTES
        ));
    }
    if signature.len() != SIGNBYTES {
        return Err(anyhow::anyhow!(
            "Invalid Dilithium5 signature length: {} (expected {})",
            signature.len(),
            SIGNBYTES
        ));
    }

    let pk = CrystalsPublicKey::from_bytes(public_key);
    let mut sig_arr = [0u8; SIGNBYTES];
    sig_arr.copy_from_slice(signature);
    Ok(pk.verify(message, &sig_arr))
}

/// Alias for dilithium5_verify (crystals-dilithium is now the only implementation).
pub fn dilithium5_verify_crystals(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    dilithium5_verify(message, signature, public_key)
}

/// Auto-detecting Dilithium signing (Dilithium5 only).
///
/// Accepts 4864-byte or 4896-byte (zero-padded) secret keys.
pub fn dilithium_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    dilithium5_sign(message, secret_key)
}

/// Auto-detecting Dilithium verification (Dilithium5 only).
pub fn dilithium_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    dilithium5_verify(message, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium5_key_sizes() {
        let (pk, sk) = dilithium5_keypair();
        assert_eq!(pk.len(), DILITHIUM5_PUBLICKEY_BYTES);
        assert_eq!(sk.len(), DILITHIUM5_SECRETKEY_BYTES);
    }

    #[test]
    fn test_dilithium5_sign_verify_roundtrip() {
        let (pk, sk) = dilithium5_keypair();
        let message = b"Test message for Dilithium5 signing";

        let signature = dilithium5_sign(message, &sk).expect("signing should succeed");
        assert_eq!(signature.len(), SIGNBYTES, "signature should be 4595 bytes");

        let valid = dilithium5_verify(message, &signature, &pk).expect("verification should succeed");
        assert!(valid, "signature should be valid");
    }

    #[test]
    fn test_dilithium5_wrong_message_fails() {
        let (pk, sk) = dilithium5_keypair();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = dilithium5_sign(message, &sk).unwrap();
        let valid = dilithium5_verify(wrong_message, &signature, &pk).unwrap();
        assert!(!valid, "signature should be invalid for wrong message");
    }

    #[test]
    fn test_dilithium5_wrong_key_fails() {
        let (_, sk) = dilithium5_keypair();
        let (wrong_pk, _) = dilithium5_keypair();
        let message = b"Test message";

        let signature = dilithium5_sign(message, &sk).unwrap();
        let valid = dilithium5_verify(message, &signature, &wrong_pk).unwrap();
        assert!(!valid, "signature should be invalid for wrong public key");
    }

    #[test]
    fn test_zero_padded_sk_signs_correctly() {
        let (pk, sk) = dilithium5_keypair();
        assert_eq!(sk.len(), 4864);

        // Zero-pad to 4896 (storage format)
        let mut padded_sk = vec![0u8; 4896];
        padded_sk[..4864].copy_from_slice(&sk);

        let message = b"Test with padded key";
        let sig = dilithium5_sign(message, &padded_sk).expect("padded key should sign");
        let valid = dilithium5_verify(message, &sig, &pk).expect("should verify");
        assert!(valid, "signature from padded key should verify");
    }

    #[test]
    fn test_deterministic_keypair_from_entropy() {
        let entropy = b"deterministic seed material";
        let (pk1, sk1) = dilithium5_keypair_from_entropy(entropy);
        let (pk2, sk2) = dilithium5_keypair_from_entropy(entropy);

        assert_eq!(pk1, pk2, "same entropy should produce same PK");
        assert_eq!(sk1, sk2, "same entropy should produce same SK");

        // Sign/verify roundtrip
        let message = b"Deterministic key test";
        let sig = dilithium5_sign(message, &sk1).unwrap();
        let valid = dilithium5_verify(message, &sig, &pk1).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_auto_sign_rejects_invalid_key_size() {
        let invalid_sk = vec![0u8; 1000];
        let result = dilithium_sign(b"Test", &invalid_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_verify_rejects_invalid_key_size() {
        let invalid_pk = vec![0u8; 1000];
        let result = dilithium_verify(b"Test", &[0u8; 4595], &invalid_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_full_auto_roundtrip() {
        let (pk, sk) = dilithium5_keypair();
        let message = b"Full auto roundtrip test";

        let signature = dilithium_sign(message, &sk).unwrap();
        let valid = dilithium_verify(message, &signature, &pk).unwrap();
        assert!(valid);
    }
}
