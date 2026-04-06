// packages/lib-identity/src/cryptography/key_generation.rs
// Quantum-resistant key generation using CRYSTALS-Dilithium
// IMPLEMENTATIONS using lib-crypto

use anyhow::Result;
use lib_crypto::post_quantum::dilithium5_keypair;
use lib_crypto::KeyPair as CryptoKeyPair;
use serde::{Deserialize, Serialize};

/// DEPRECATED: Use `lib_crypto::KeyPair` directly.
/// 
/// This struct is kept for backward compatibility but will be removed in a future version.
/// All new code should use `lib_crypto::KeyPair` which provides the same functionality
/// with proper fixed-size array types for security.
#[deprecated(
    since = "0.1.0",
    note = "Use lib_crypto::KeyPair directly instead"
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostQuantumKeypair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub algorithm: String,
    pub security_level: u32,
    pub key_id: String,
}

/// Key generation parameters
#[derive(Debug, Clone, Default)]
pub struct KeyGenParams {
    pub algorithm: String,
    pub security_level: u32,
}

/// DEPRECATED: Use `lib_crypto::KeyPair::generate()` directly.
/// 
/// This function is kept for backward compatibility but will be removed in a future version.
/// All new code should use `lib_crypto::KeyPair::generate()` which provides the same
/// functionality with proper fixed-size array types for security.
#[deprecated(
    since = "0.1.0",
    note = "Use lib_crypto::KeyPair::generate() directly instead"
)]
pub fn generate_pq_keypair(params: Option<KeyGenParams>) -> Result<PostQuantumKeypair, String> {
    let params = params.unwrap_or_default();

    // Determine public key and derive key_id from the actual key material
    let (public_key, private_key, algorithm, key_id) = match params.security_level {
        2 | 5 => {
            // Use Dilithium5 for all explicit security levels
            let (pk, sk) = dilithium5_keypair();
            let kid = generate_key_id_from_public_key(&pk);
            (pk, sk, "CRYSTALS-Dilithium5".to_string(), kid)
        }
        _ => {
            // Default to the pure post-quantum lib-crypto keypair (Dilithium5 + Kyber1024)
            let crypto_keypair = CryptoKeyPair::generate()
                .map_err(|e| format!("Failed to generate crypto keypair: {}", e))?;
            // Convert fixed arrays to Vec for PostQuantumKeypair API compatibility
            let pk = crypto_keypair.public_key.dilithium_pk.to_vec();
            let sk = crypto_keypair.private_key.dilithium_sk.to_vec();
            let kid = hex::encode(&crypto_keypair.public_key.key_id);
            (pk, sk, "CRYSTALS-Dilithium-PureQuantum".to_string(), kid)
        }
    };

    Ok(PostQuantumKeypair {
        public_key,
        private_key,
        algorithm,
        security_level: params.security_level,
        key_id,
    })
}

/// Generate unique key ID from public key using lib-crypto's blake3 hashing
pub fn generate_key_id_from_public_key(public_key: &[u8]) -> String {
    use lib_crypto::hash_blake3;

    let hash = hash_blake3(public_key);
    hex::encode(&hash[..16]) // Use first 16 bytes of blake3 hash for key ID
}

/// Validate post-quantum keypair using lib-crypto operations
pub fn validate_keypair(keypair: &PostQuantumKeypair) -> Result<bool, String> {
    use lib_crypto::post_quantum::{dilithium5_sign, dilithium5_verify};

    // Validate that keys are not empty
    if keypair.public_key.is_empty() || keypair.private_key.is_empty() {
        return Err("Empty keys detected".to_string());
    }

    // Test signature to validate keypair consistency using cryptography
    let test_message = b"ZHTP-Identity-KeyPair-Validation-Test";

    let signature_result = match keypair.security_level {
        2 | 5 => {
            // Use Dilithium5 for all security levels
            dilithium5_sign(test_message, &keypair.private_key)
                .map_err(|e| format!("Dilithium5 signing failed: {}", e))
        }
        _ => {
            return Err("Unsupported security level for validation".to_string());
        }
    };

    let signature = signature_result?;

    let verification_result = match keypair.security_level {
        2 | 5 => dilithium5_verify(test_message, &signature, &keypair.public_key)
            .map_err(|e| format!("Dilithium5 verification failed: {}", e)),
        _ => {
            return Err("Unsupported security level for verification".to_string());
        }
    };

    verification_result
}
