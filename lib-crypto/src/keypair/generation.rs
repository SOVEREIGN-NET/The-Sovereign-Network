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

    #[test]
    fn from_private_key_signs_with_stored_material() -> Result<()> {
        let keypair = KeyPair::generate()?;
        let derived = KeyPair::from_private_key(&keypair.private_key)?;
        let message = b"caller-key-bind-test";
        let signature = derived.sign(message)?;
        assert!(derived.public_key.verify(message, &signature)?);

        let other = KeyPair::generate()?;
        assert!(!other.public_key.verify(message, &signature)?);
        Ok(())
    }
}

use crate::types::{PrivateKey, PublicKey};
use anyhow::Result;
use blake3::Hasher as Blake3Hasher;
use crystals_dilithium::dilithium5::Keypair as DilithiumKeypair;
use pqc_kyber_edit as pqc_kyber;
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
        let dilithium_kp = DilithiumKeypair::generate(None);
        let dilithium_pk_bytes = dilithium_kp.public.to_bytes();
        let dilithium_sk_bytes = dilithium_kp.secret.to_bytes(); // 4864 bytes

        // Generate CRYSTALS-Kyber key pair (NIST post-quantum standard)
        let kyber_keys = pqc_kyber::keypair(&mut rng)
            .map_err(|e| anyhow::anyhow!("Kyber1024 keypair generation failed: {:?}", e))?;

        // Calculate unique key ID from post-quantum public keys only
        let mut hasher = Blake3Hasher::new();
        hasher.update(&dilithium_pk_bytes);
        hasher.update(&kyber_keys.public);
        let key_id: [u8; 32] = hasher.finalize().into();

        // Convert to fixed-size arrays
        let dilithium_pk_array: [u8; 2592] = dilithium_pk_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Dilithium5 public key must be 2592 bytes"))?;
        let kyber_pk_array: [u8; 1568] = kyber_keys.public.try_into()
            .map_err(|_| anyhow::anyhow!("Kyber1024 public key must be 1568 bytes"))?;

        // crystals-dilithium produces 4864-byte secret keys; zero-pad to [u8; 4896] for storage compat
        let mut dilithium_sk_array = [0u8; 4896];
        dilithium_sk_array[..dilithium_sk_bytes.len()].copy_from_slice(&dilithium_sk_bytes);

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

    /// Build a signing keypair from stored Dilithium private key material.
    ///
    /// Used when the caller already holds a `PrivateKey` (keystore, identity store)
    /// and must sign with that key — not a freshly generated one.
    pub fn from_private_key(private_key: &PrivateKey) -> Result<Self> {
        if private_key.dilithium_sk.iter().all(|&x| x == 0) {
            return Err(anyhow::anyhow!("Invalid Dilithium private key: all zeros"));
        }

        let dilithium_pk = private_key.dilithium_pk;
        let key_id = crate::hash_blake3(&dilithium_pk);

        Ok(Self {
            private_key: private_key.clone(),
            public_key: PublicKey {
                dilithium_pk,
                kyber_pk: [0u8; 1568],
                key_id,
            },
        })
    }

    /// Build a signing keypair from raw Dilithium key byte slices (identity store layout).
    pub fn from_dilithium_bytes(secret_key: &[u8], public_key: &[u8]) -> Result<Self> {
        if secret_key.is_empty() || secret_key.iter().all(|&x| x == 0) {
            return Err(anyhow::anyhow!("Invalid Dilithium secret key"));
        }
        if public_key.is_empty() {
            return Err(anyhow::anyhow!("Invalid Dilithium public key"));
        }

        let mut dilithium_sk = [0u8; 4896];
        let sk_len = secret_key.len().min(4896);
        dilithium_sk[..sk_len].copy_from_slice(&secret_key[..sk_len]);

        let mut dilithium_pk = [0u8; 2592];
        let pk_len = public_key.len().min(2592);
        dilithium_pk[..pk_len].copy_from_slice(&public_key[..pk_len]);

        Self::from_private_key(&PrivateKey {
            dilithium_sk,
            dilithium_pk,
            kyber_sk: [0u8; 3168],
            master_seed: [0u8; 64],
        })
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
