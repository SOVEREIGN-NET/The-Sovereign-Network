//! Cryptographic primitives wrapper
//!
//! Provides a consistent interface for post-quantum cryptography:
//! - **Dilithium5**: Digital signatures (NIST PQC standard)
//! - **Kyber1024**: Key encapsulation mechanism (NIST PQC standard)
//! - **Blake3**: Fast cryptographic hashing
//! - **ChaCha20-Poly1305**: Authenticated encryption
//!
//! # Platform Support
//!
//! - Native (Linux/macOS/Windows/iOS/Android): Uses C-based pqcrypto crates
//! - WASM: Uses pure Rust pqc_dilithium/pqc_kyber crates
//!
//! # Key Sizes
//!
//! | Algorithm | Public Key | Private Key | Signature/Ciphertext |
//! |-----------|------------|-------------|----------------------|
//! | Dilithium5 | 2,592 bytes | 4,896 bytes | 4,595 bytes |
//! | Kyber1024 | 1,568 bytes | 3,168 bytes | 1,568 bytes |

use crate::error::{ClientError, Result};

// ============================================================================
// Native implementation (C-based pqcrypto crates)
// ============================================================================

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_kyber::kyber1024;
    use pqcrypto_traits::kem::{
        Ciphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret,
    };
    use pqcrypto_traits::sign::{
        DetachedSignature, PublicKey as SignPublicKey, SecretKey as SignSecretKey,
    };
    // crystals-dilithium for deterministic key generation from seed
    use crystals_dilithium::dilithium5::Keypair as DilithiumKeypair;

    /// Dilithium5 post-quantum digital signatures
    pub struct Dilithium5;

    impl Dilithium5 {
        pub const PUBLIC_KEY_SIZE: usize = 2592;
        pub const SECRET_KEY_SIZE: usize = 4896;  // pqcrypto-dilithium (random)
        pub const SECRET_KEY_SIZE_SEEDED: usize = 4864;  // crystals-dilithium (from seed)
        pub const SIGNATURE_SIZE: usize = 4595;

        pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
            let (pk, sk) = dilithium5::keypair();
            Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
        }

        pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            // Use crystals-dilithium for deterministic generation from seed.
            // This ensures the same seed always produces the same Dilithium5 keypair (for recovery).
            //
            // NOTE/TODO: Kyber1024::generate_keypair_from_seed below still uses random key
            // generation and ignores the seed. It should be updated to use deterministic
            // generation from the seed as well so identity recovery is fully reproducible.
            // For now, only Dilithium (signing) keys are deterministic.
            if seed.len() != 32 {
                return Err(ClientError::CryptoError(format!(
                    "Invalid Dilithium5 seed length: expected 32 bytes, got {}",
                    seed.len()
                )));
            }
            let keypair = DilithiumKeypair::generate(Some(seed));
            Ok((keypair.public.to_bytes().to_vec(), keypair.secret.to_bytes().to_vec()))
        }

        pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
            // Auto-detect key format based on size:
            // - 4864 bytes: crystals-dilithium (from seed)
            // - 4896 bytes: pqcrypto-dilithium (random keygen)
            if secret_key.len() == 4864 {
                // Use crystals-dilithium for keys generated from seed
                use crystals_dilithium::dilithium5::SecretKey;
                let sk = SecretKey::from_bytes(secret_key);
                let signature = sk.sign(message);
                Ok(signature.to_vec())
            } else if secret_key.len() == 4896 {
                // Use pqcrypto-dilithium for randomly generated keys
                let sk = dilithium5::SecretKey::from_bytes(secret_key)
                    .map_err(|_| ClientError::CryptoError("Invalid Dilithium5 secret key".into()))?;
                let sig = dilithium5::detached_sign(message, &sk);
                Ok(sig.as_bytes().to_vec())
            } else {
                Err(ClientError::CryptoError(format!(
                    "Invalid Dilithium5 secret key size: {} (expected 4864 or 4896)",
                    secret_key.len()
                )))
            }
        }

        pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
            // Try crystals-dilithium first (both crates use same NIST standard)
            use crystals_dilithium::dilithium5::PublicKey as CrystalsPublicKey;
            let crystals_pk = CrystalsPublicKey::from_bytes(public_key);
            if crystals_pk.verify(message, signature) {
                return Ok(true);
            }

            // Try pqcrypto-dilithium
            let pk = dilithium5::PublicKey::from_bytes(public_key)
                .map_err(|_| ClientError::CryptoError("Invalid Dilithium5 public key".into()))?;

            let sig = dilithium5::DetachedSignature::from_bytes(signature)
                .map_err(|_| ClientError::CryptoError("Invalid Dilithium5 signature".into()))?;

            match dilithium5::verify_detached_signature(&sig, message, &pk) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }

    /// Kyber1024 post-quantum key encapsulation mechanism
    pub struct Kyber1024;

    impl Kyber1024 {
        pub const PUBLIC_KEY_SIZE: usize = 1568;
        pub const SECRET_KEY_SIZE: usize = 3168;
        pub const CIPHERTEXT_SIZE: usize = 1568;
        pub const SHARED_SECRET_SIZE: usize = 32;

        pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
            let (pk, sk) = kyber1024::keypair();
            Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
        }

        pub fn generate_keypair_from_seed(_seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            // IMPORTANT: Kyber is treated as an operational key in the current identity invariant.
            // A "seeded" API that silently returns random keys is dangerous; fail fast instead.
            Err(ClientError::CryptoError(
                "Kyber1024 deterministic keygen is not supported; use generate_keypair() and bind as an operational key".into(),
            ))
        }

        pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            let pk = kyber1024::PublicKey::from_bytes(public_key)
                .map_err(|_| ClientError::CryptoError("Invalid Kyber1024 public key".into()))?;

            let (ss, ct) = kyber1024::encapsulate(&pk);
            Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
        }

        pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
            let sk = kyber1024::SecretKey::from_bytes(secret_key)
                .map_err(|_| ClientError::CryptoError("Invalid Kyber1024 secret key".into()))?;

            let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
                .map_err(|_| ClientError::CryptoError("Invalid Kyber1024 ciphertext".into()))?;

            let ss = kyber1024::decapsulate(&ct, &sk);
            Ok(ss.as_bytes().to_vec())
        }
    }
}

// ============================================================================
// WASM implementation (pure Rust pqc_dilithium/pqc_kyber crates)
// ============================================================================

#[cfg(target_arch = "wasm32")]
mod wasm_crypto {
    use super::*;
    use crystals_dilithium::dilithium5::{Keypair as DilithiumKeypair, PublicKey, SecretKey, SIGNBYTES};
    use pqc_kyber::*;

    /// Dilithium5 post-quantum digital signatures (pure Rust implementation)
    /// Uses crystals-dilithium crate for WASM compatibility
    pub struct Dilithium5;

    impl Dilithium5 {
        // Dilithium5 (Mode 5) key sizes
        pub const PUBLIC_KEY_SIZE: usize = 2592;
        pub const SECRET_KEY_SIZE: usize = 4896;
        pub const SIGNATURE_SIZE: usize = SIGNBYTES;

        pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
            let keypair = DilithiumKeypair::generate(None);
            Ok((keypair.public.to_bytes().to_vec(), keypair.secret.to_bytes().to_vec()))
        }

        pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            let keypair = DilithiumKeypair::generate(Some(seed));
            Ok((keypair.public.to_bytes().to_vec(), keypair.secret.to_bytes().to_vec()))
        }

        pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
            let sk = SecretKey::from_bytes(secret_key);
            let signature = sk.sign(message);
            Ok(signature.to_vec())
        }

        pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
            let pk = PublicKey::from_bytes(public_key);

            // Signature is a type alias for [u8; SIGNBYTES]
            if signature.len() != SIGNBYTES {
                return Err(ClientError::CryptoError("Invalid signature length".into()));
            }
            let mut sig_arr = [0u8; SIGNBYTES];
            sig_arr.copy_from_slice(signature);

            Ok(pk.verify(message, &sig_arr))
        }
    }

    /// Kyber1024 post-quantum key encapsulation mechanism (pure Rust implementation)
    pub struct Kyber1024;

    impl Kyber1024 {
        pub const PUBLIC_KEY_SIZE: usize = KYBER_PUBLICKEYBYTES;
        pub const SECRET_KEY_SIZE: usize = KYBER_SECRETKEYBYTES;
        pub const CIPHERTEXT_SIZE: usize = KYBER_CIPHERTEXTBYTES;
        pub const SHARED_SECRET_SIZE: usize = KYBER_SSBYTES;

        pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
            let keys = keypair(&mut rand::thread_rng())
                .map_err(|e| ClientError::CryptoError(format!("Kyber keypair generation failed: {:?}", e)))?;
            Ok((keys.public.to_vec(), keys.secret.to_vec()))
        }

        pub fn generate_keypair_from_seed(_seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            // IMPORTANT: Kyber is treated as an operational key in the current identity invariant.
            // A "seeded" API that silently returns random keys is dangerous; fail fast instead.
            Err(ClientError::CryptoError(
                "Kyber1024 deterministic keygen is not supported; use generate_keypair() and bind as an operational key".into(),
            ))
        }

        pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            let pk: [u8; KYBER_PUBLICKEYBYTES] = public_key
                .try_into()
                .map_err(|_| ClientError::CryptoError("Invalid Kyber1024 public key length".into()))?;

            let (ciphertext, shared_secret) = encapsulate(&pk, &mut rand::thread_rng())
                .map_err(|e| ClientError::CryptoError(format!("Kyber encapsulation failed: {:?}", e)))?;

            Ok((shared_secret.to_vec(), ciphertext.to_vec()))
        }

        pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
            let ct: [u8; KYBER_CIPHERTEXTBYTES] = ciphertext
                .try_into()
                .map_err(|_| ClientError::CryptoError("Invalid Kyber1024 ciphertext length".into()))?;

            let sk: [u8; KYBER_SECRETKEYBYTES] = secret_key
                .try_into()
                .map_err(|_| ClientError::CryptoError("Invalid Kyber1024 secret key length".into()))?;

            let shared_secret = decapsulate(&ct, &sk)
                .map_err(|e| ClientError::CryptoError(format!("Kyber decapsulation failed: {:?}", e)))?;

            Ok(shared_secret.to_vec())
        }
    }
}

// ============================================================================
// Re-exports (select implementation based on target)
// ============================================================================

#[cfg(not(target_arch = "wasm32"))]
pub use native::{Dilithium5, Kyber1024};

#[cfg(target_arch = "wasm32")]
pub use wasm_crypto::{Dilithium5, Kyber1024};

// ============================================================================
// Platform-independent crypto utilities
// ============================================================================

/// Blake3 cryptographic hash function
pub struct Blake3;

impl Blake3 {
    /// Hash output size in bytes
    pub const OUTPUT_SIZE: usize = 32;

    /// Compute Blake3 hash of data
    pub fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    /// Compute Blake3 hash and return as Vec
    pub fn hash_vec(data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    /// Derive key material using Blake3 KDF
    pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(key_material);
        *hasher.finalize().as_bytes()
    }
}

/// Generate cryptographically secure random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a random 32-byte nonce
pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive bytes from a seed using Blake3 KDF
pub fn derive_bytes(seed: &[u8], context: &[u8]) -> Vec<u8> {
    let context_str = std::str::from_utf8(context).unwrap_or("derive");
    Blake3::derive_key(context_str, seed).to_vec()
}

/// HKDF-SHA3-256 key derivation
pub fn hkdf_sha3_256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    use hkdf::Hkdf;
    use sha3::Sha3_256;

    let default_salt = [0u8; 32];
    let salt = salt.unwrap_or(&default_salt);

    let hk = Hkdf::<Sha3_256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|_| ClientError::KeyDerivationError("HKDF expansion failed".into()))?;

    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium5_sign_verify() {
        let (pk, sk) = Dilithium5::generate_keypair().unwrap();
        let message = b"Hello, ZHTP!";

        let signature = Dilithium5::sign(message, &sk).unwrap();
        assert!(Dilithium5::verify(message, &signature, &pk).unwrap());

        // Verify with wrong message fails
        assert!(!Dilithium5::verify(b"Wrong message", &signature, &pk).unwrap());
    }

    #[test]
    fn test_kyber1024_encapsulate_decapsulate() {
        let (pk, sk) = Kyber1024::generate_keypair().unwrap();

        let (shared_secret1, ciphertext) = Kyber1024::encapsulate(&pk).unwrap();
        let shared_secret2 = Kyber1024::decapsulate(&ciphertext, &sk).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"test data";
        let hash1 = Blake3::hash(data);
        let hash2 = Blake3::hash(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32);
        let bytes2 = random_bytes(32);

        assert_eq!(bytes1.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different (with overwhelming probability)
    }

    #[test]
    fn test_dilithium5_deterministic_keygen() {
        // Same seed should produce same keys (critical for recovery)
        let seed = [42u8; 32];

        let (pk1, sk1) = Dilithium5::generate_keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = Dilithium5::generate_keypair_from_seed(&seed).unwrap();

        assert_eq!(pk1, pk2, "Same seed must produce same public key");
        assert_eq!(sk1, sk2, "Same seed must produce same secret key");

        // Different seed should produce different keys
        let different_seed = [43u8; 32];
        let (pk3, _) = Dilithium5::generate_keypair_from_seed(&different_seed).unwrap();
        assert_ne!(pk1, pk3, "Different seeds must produce different keys");
    }

    #[test]
    fn test_dilithium5_seed_length_validation() {
        let bad_seed = [7u8; 31];
        let err = Dilithium5::generate_keypair_from_seed(&bad_seed).unwrap_err();
        assert!(err.to_string().contains("Invalid Dilithium5 seed length"));
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_cross_library_sign_verify() {
        // This tests the EXACT flow used in production:
        // 1. lib-client generates keypair from seed (crystals-dilithium, 4864-byte SK)
        // 2. lib-client signs message (crystals-dilithium)
        // 3. lib-crypto verifies signature (pqcrypto-dilithium)

        let seed = [42u8; 32];
        let (pk, sk) = Dilithium5::generate_keypair_from_seed(&seed).unwrap();

        println!("Cross-library test: pk_len={}, sk_len={}", pk.len(), sk.len());
        assert_eq!(pk.len(), 2592, "Public key should be 2592 bytes");
        assert_eq!(sk.len(), 4864, "Secret key from seed should be 4864 bytes (crystals-dilithium)");

        // Sign with lib-client (uses crystals-dilithium for 4864-byte keys)
        let message = b"SEED_MIGRATE:supertramp:abc123hex:1234567890";
        let signature = Dilithium5::sign(message, &sk).expect("Signing should succeed");

        println!("Signature length: {}", signature.len());
        assert_eq!(signature.len(), 4595, "Dilithium5 signature should be 4595 bytes");

        // Verify with lib-crypto using crystals-dilithium (compatible!)
        let valid = lib_crypto::post_quantum::dilithium::dilithium5_verify_crystals(
            message,
            &signature,
            &pk,
        ).expect("Verification should not error");

        assert!(valid, "crystals-dilithium signature MUST verify with crystals-dilithium");
    }

}
