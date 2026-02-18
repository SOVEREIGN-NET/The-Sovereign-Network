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
pub fn validate_key_rotation_prohibited() -> Result<(), String> {
    Err(
        "key rotation is not supported (policy=no_rotation): \
         register a new validator identity for a new key"
            .to_string(),
    )
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

use anyhow::Result;
use blake3::Hasher as Blake3Hasher;
use rand::{RngCore};
use rand::rngs::OsRng;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::{
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey},
};
use crate::types::{PublicKey, PrivateKey};
use pqc_kyber as kyber1024;

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
        let kyber_keys = kyber1024::keypair(&mut rng)
            .map_err(|e| anyhow::anyhow!("Kyber1024 keypair generation failed: {:?}", e))?;
        
        // Calculate unique key ID from post-quantum public keys only
        let mut hasher = Blake3Hasher::new();
        hasher.update(dilithium_pk.as_bytes());
        hasher.update(&kyber_keys.public);
        let key_id: [u8; 32] = hasher.finalize().into();

        let dilithium_pk_bytes = dilithium_pk.as_bytes().to_vec();
        let keypair = KeyPair {
            public_key: PublicKey {
                dilithium_pk: dilithium_pk_bytes.clone(),
                kyber_pk: kyber_keys.public.to_vec(),
                key_id,
            },
            private_key: PrivateKey {
                dilithium_sk: dilithium_sk.as_bytes().to_vec(),
                dilithium_pk: dilithium_pk_bytes,
                kyber_sk: kyber_keys.secret.to_vec(),
                master_seed,
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
            return Err(anyhow::anyhow!("Keypair validation failed: signature verification failed"));
        }
        
        Ok(())
    }
}
