// packages/lib-identity/src/cryptography/signatures.rs
// Post-quantum signature generation and verification
// IMPLEMENTATIONS using lib-crypto

use anyhow::Result;
use lib_crypto::post_quantum::{
    dilithium2_sign, dilithium2_verify, dilithium5_sign, dilithium5_verify,
};
use serde::{Deserialize, Serialize};

// Re-export for backward compatibility (deprecated)
#[allow(deprecated)]
pub use crate::cryptography::key_generation::PostQuantumKeypair;

/// Post-quantum signature using CRYSTALS-Dilithium
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostQuantumSignature {
    pub signature: Vec<u8>,
    pub algorithm: String,
    pub security_level: u32,
    pub signature_type: String,
    pub timestamp: u64,
}

/// Signature parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureParams {
    pub context: Option<String>,
    pub domain_separation: Option<String>,
    pub randomization: bool,
}

/// Sign with a lib-crypto KeyPair using post-quantum cryptography.
/// 
/// This is the canonical signing function that should be used for all new code.
/// It uses the Dilithium5 secret key from the KeyPair for signing.
pub fn sign_with_keypair(
    keypair: &lib_crypto::KeyPair,
    message: &[u8],
    params: Option<SignatureParams>,
) -> Result<PostQuantumSignature, String> {
    let params = params.unwrap_or_default();

    // Add context and domain separation if specified
    let mut signing_input = Vec::new();

    if let Some(context) = &params.context {
        signing_input.extend_from_slice(context.as_bytes());
        signing_input.push(0x00); // Separator
    }

    if let Some(domain) = &params.domain_separation {
        signing_input.extend_from_slice(domain.as_bytes());
        signing_input.push(0x01); // Separator
    }

    signing_input.extend_from_slice(message);

    // Generate signature using Dilithium5 (always use level 5 for KeyPair)
    let signature = dilithium5_sign(&signing_input, &keypair.private_key.dilithium_sk)
        .map_err(|e| format!("Dilithium5 signing failed: {}", e))?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(PostQuantumSignature {
        signature,
        algorithm: "CRYSTALS-Dilithium5".to_string(),
        security_level: 5,
        signature_type: "PostQuantumSignature2024".to_string(),
        timestamp,
    })
}

/// DEPRECATED: Use `sign_with_keypair()` instead.
/// 
/// This function is kept for backward compatibility but will be removed in a future version.
#[deprecated(
    since = "0.1.0",
    note = "Use sign_with_keypair() with lib_crypto::KeyPair instead"
)]
#[allow(deprecated)]
pub fn sign_with_identity(
    keypair: &PostQuantumKeypair,
    message: &[u8],
    params: Option<SignatureParams>,
) -> Result<PostQuantumSignature, String> {
    let params = params.unwrap_or_default();

    // Add context and domain separation if specified
    let mut signing_input = Vec::new();

    if let Some(context) = &params.context {
        signing_input.extend_from_slice(context.as_bytes());
        signing_input.push(0x00); // Separator
    }

    if let Some(domain) = &params.domain_separation {
        signing_input.extend_from_slice(domain.as_bytes());
        signing_input.push(0x01); // Separator
    }

    signing_input.extend_from_slice(message);

    // Generate signature using lib-crypto implementations
    let signature = match keypair.security_level {
        2 => dilithium2_sign(&signing_input, &keypair.private_key)
            .map_err(|e| format!("Dilithium2 signing failed: {}", e))?,
        5 => dilithium5_sign(&signing_input, &keypair.private_key)
            .map_err(|e| format!("Dilithium5 signing failed: {}", e))?,
        _ => return Err("Unsupported security level (supported: 2, 5)".to_string()),
    };

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(PostQuantumSignature {
        signature,
        algorithm: keypair.algorithm.clone(),
        security_level: keypair.security_level,
        signature_type: "PostQuantumSignature2024".to_string(),
        timestamp,
    })
}

/// Verify post-quantum signature
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &PostQuantumSignature,
    params: Option<SignatureParams>,
) -> Result<bool, String> {
    let params = params.unwrap_or_default();

    // Reconstruct signing input
    let mut signing_input = Vec::new();

    if let Some(context) = &params.context {
        signing_input.extend_from_slice(context.as_bytes());
        signing_input.push(0x00);
    }

    if let Some(domain) = &params.domain_separation {
        signing_input.extend_from_slice(domain.as_bytes());
        signing_input.push(0x01);
    }

    signing_input.extend_from_slice(message);

    // Verify signature using lib-crypto implementations
    match signature.security_level {
        2 => dilithium2_verify(&signing_input, &signature.signature, public_key)
            .map_err(|e| format!("Dilithium2 verification failed: {}", e)),
        5 => dilithium5_verify(&signing_input, &signature.signature, public_key)
            .map_err(|e| format!("Dilithium5 verification failed: {}", e)),
        _ => Err("Unsupported security level (supported: 2, 5)".to_string()),
    }
}

// Removed fake Dilithium implementations - now using lib-crypto functions

/// Batch verify multiple signatures efficiently
pub fn batch_verify_signatures(
    verifications: &[(Vec<u8>, Vec<u8>, PostQuantumSignature)], // (public_key, message, signature)
    params: Option<SignatureParams>,
) -> Result<Vec<bool>, String> {
    let mut results = Vec::with_capacity(verifications.len());

    for (public_key, message, signature) in verifications {
        let result = verify_signature(public_key, message, signature, params.clone())?;
        results.push(result);
    }

    Ok(results)
}

/// Create detached signature (signature separate from message) using lib-crypto KeyPair.
/// 
/// This is the canonical function for creating detached signatures.
pub fn create_detached_signature(
    keypair: &lib_crypto::KeyPair,
    message: &[u8],
    params: Option<SignatureParams>,
) -> Result<Vec<u8>, String> {
    let signature = sign_with_keypair(keypair, message, params)?;
    Ok(signature.signature)
}

/// DEPRECATED: Use `create_detached_signature()` with `lib_crypto::KeyPair` instead.
#[deprecated(
    since = "0.1.0",
    note = "Use create_detached_signature() with lib_crypto::KeyPair instead"
)]
#[allow(deprecated)]
pub fn create_detached_signature_with_keypair(
    keypair: &PostQuantumKeypair,
    message: &[u8],
    params: Option<SignatureParams>,
) -> Result<Vec<u8>, String> {
    let signature = sign_with_identity(keypair, message, params)?;
    Ok(signature.signature)
}

/// Verify detached signature
pub fn verify_detached_signature(
    public_key: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    security_level: u32,
    params: Option<SignatureParams>,
) -> Result<bool, String> {
    let signature = PostQuantumSignature {
        signature: signature_bytes.to_vec(),
        algorithm: "CRYSTALS-Dilithium".to_string(),
        security_level,
        signature_type: "PostQuantumSignature2024".to_string(),
        timestamp: 0, // Not used in verification
    };

    verify_signature(public_key, message, &signature, params)
}

impl Default for SignatureParams {
    fn default() -> Self {
        Self {
            context: None,
            domain_separation: None,
            randomization: true,
        }
    }
}
