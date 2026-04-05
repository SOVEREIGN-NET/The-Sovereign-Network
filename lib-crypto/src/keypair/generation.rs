//! KeyPair generation - preserving ZHTP post-quantum key generation
//!
//! implementations from crypto.rs, lines 204-250, 260-310
//!
//! # Key Rotation Policy (BFT-I, Issue #1011)
//!
//! **Key rotation is NOT supported in the current protocol.**
//!
//! Validator identity is permanently bound to the public key used at
//! registration.  To use a different key, de-register and create a new
//! validator identity.  Key rotation without a new identity is prohibited
//! because it enables equivocation attacks.
//!
//! See [`KEY_ROTATION_POLICY`] and [`validate_key_rotation_prohibited`].

// ============================================================================
// KEY ROTATION POLICY (BFT-I, Issue #1011)
// ============================================================================

/// Key rotation policy: rotation is not supported in the current protocol.
///
/// Validator identity is permanently bound to the key at registration.
pub const KEY_ROTATION_POLICY: &str = "no_rotation";

/// Returns an error explaining that key rotation is prohibited.
///
/// Call this from any code path that would attempt to replace a validator's
/// key without creating a new validator identity.
pub fn validate_key_rotation_prohibited() -> Result<()> {
    Err(anyhow::anyhow!(
        "key rotation is not supported (policy=no_rotation): \
         register a new validator identity for a new key"
    ))
}

#[cfg(test)]
mod key_rotation_policy_tests {
    use super::*;

    #[test]
    fn test_key_rotation_is_prohibited() {
        assert!(validate_key_rotation_prohibited().is_err());
    }

    #[test]
    fn test_key_rotation_policy_constant() {
        assert_eq!(KEY_ROTATION_POLICY, "no_rotation");
    }
}

use crate::types::{PrivateKey, PublicKey};
use anyhow::Result;
use blake3::Hasher as Blake3Hasher;
use pqc_kyber;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use rand::rngs::OsRng;
use rand::RngCore;

/// quantum-resistant key pair with secure memory management
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Generate a new quantum-resistant key pair using CRYSTALS implementations
    /// This is production-ready cryptography with proper entropy sources
    pub fn generate() -> Result<Self> {
        let mut rng = OsRng;

        // Generate cryptographically secure master seed
        let mut master_seed = vec![0u8; 64];
        rng.fill_bytes(&mut master_seed);

        // Generate CRYSTALS-Dilithium5 key pair (NIST post-quantum standard, highest security)
        let (dilithium_pk, dilithium_sk) = dilithium5::keypair();

        // Generate CRYSTALS-Kyber key pair (NIST post-quantum standard)
        let kyber_keys = pqc_kyber::keypair(&mut rng)
            .map_err(|e| anyhow::anyhow!("Kyber1024 keypair generation failed: {:?}", e))?;

        // Calculate unique key ID from post-quantum public keys only
        let mut hasher = Blake3Hasher::new();
        hasher.update(dilithium_pk.as_bytes());
        hasher.update(&kyber_keys.public);
        let key_id: [u8; 32] = hasher.finalize().into();

        // Convert to fixed-size arrays
        let dilithium_pk_array: [u8; 2592] = dilithium_pk.as_bytes().try_into()
            .map_err(|_| anyhow::anyhow!("Dilithium5 public key must be 2592 bytes"))?;
        let kyber_pk_array: [u8; 1568] = kyber_keys.public.try_into()
            .map_err(|_| anyhow::anyhow!("Kyber1024 public key must be 1568 bytes"))?;
        
        // pqcrypto-dilithium produces 4896-byte secret keys
        let dilithium_sk_vec = dilithium_sk.as_bytes();
        let dilithium_sk_array: [u8; 4896] = dilithium_sk_vec.try_into()
            .map_err(|_| anyhow::anyhow!("Dilithium5 secret key must be 4896 bytes"))?;
        
        let kyber_sk_array: [u8; 3168] = kyber_keys.secret.try_into()
            .map_err(|_| anyhow::anyhow!("Kyber1024 secret key must be 3168 bytes"))?;
        
        let keypair = KeyPair {
            public_key: PublicKey {
                dilithium_pk: dilithium_pk_array,
                kyber_pk: kyber_pk_array,
                key_id,
            },
            private_key: PrivateKey {
                dilithium_sk: dilithium_sk_array,
                dilithium_pk: dilithium_pk_array,
                kyber_sk: kyber_sk_array,
                master_seed: master_seed.try_into()
                    .map_err(|_| anyhow::anyhow!("Master seed must be 64 bytes"))?,
            },
        };

        // Validate the generated keypair
        keypair.validate()?;

        Ok(keypair)
    }

    /// Validate that the keypair is properly formed and secure
    pub fn validate(&self) -> Result<()> {
        // Check that keys are not all zeros (weak keys)
        if self.private_key.dilithium_sk.iter().all(|&x| x == 0) {
            return Err(anyhow::anyhow!("Weak Dilithium private key detected"));
        }

        if self.private_key.kyber_sk.iter().all(|&x| x == 0) {
            return Err(anyhow::anyhow!("Weak Kyber private key detected"));
        }

        // Ed25519 validation removed - pure post-quantum only

        // Verify that public key matches private key by doing a test signature
        let test_message = b"ZHTP-KeyPair-Validation-Test";
        let signature = self.sign(test_message)?;
        let verification_result = self.public_key.verify(test_message, &signature)?;

        if !verification_result {
            return Err(anyhow::anyhow!(
                "Keypair validation failed: signature verification failed"
            ));
        }

        Ok(())
    }
}
