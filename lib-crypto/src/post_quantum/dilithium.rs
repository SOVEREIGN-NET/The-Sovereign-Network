//! CRYSTALS-Dilithium wrapper functions - preserving post-quantum signatures
//! 
//! implementation wrappers from crypto.rs for CRYSTALS-Dilithium

use anyhow::Result;
use pqcrypto_dilithium::{dilithium2, dilithium5};
use pqcrypto_traits::{
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, SignedMessage},
};

/// Generate Dilithium2 keypair (Level 2 security)
pub fn dilithium2_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium2::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Generate Dilithium5 keypair (Level 5 security - highest)
pub fn dilithium5_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium5::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Sign message with Dilithium2
pub fn dilithium2_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sk = dilithium2::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium2 secret key"))?;
    
    let signature = dilithium2::sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

/// Sign message with Dilithium5
pub fn dilithium5_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sk = dilithium5::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium5 secret key"))?;
    
    let signature = dilithium5::sign(message, &sk);
    Ok(signature.as_bytes().to_vec())
}

/// Verify Dilithium2 signature
pub fn dilithium2_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let pk = dilithium2::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium2 public key"))?;
    let sig = dilithium2::SignedMessage::from_bytes(signature)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium2 signature"))?;
    
    match dilithium2::open(&sig, &pk) {
        Ok(verified_message) => Ok(verified_message == message),
        Err(_) => Ok(false),
    }
}

/// Verify Dilithium5 signature
pub fn dilithium5_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let pk = dilithium5::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium5 public key"))?;
    let sig = dilithium5::SignedMessage::from_bytes(signature)
        .map_err(|_| anyhow::anyhow!("Invalid Dilithium5 signature"))?;

    match dilithium5::open(&sig, &pk) {
        Ok(verified_message) => Ok(verified_message == message),
        Err(_) => Ok(false),
    }
}

// Key size constants for auto-detection
// These values come from pqcrypto_dilithium library
const DILITHIUM2_PUBLICKEY_BYTES: usize = 1312;
const DILITHIUM5_PUBLICKEY_BYTES: usize = 2592;
const DILITHIUM2_SECRETKEY_BYTES: usize = 2560; // pqcrypto_dilithium uses 2560, not 2528
const DILITHIUM5_SECRETKEY_BYTES: usize = 4896;

/// Auto-detecting Dilithium signing
/// Chooses Dilithium2 or Dilithium5 based on secret key size
pub fn dilithium_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    if secret_key.len() == DILITHIUM2_SECRETKEY_BYTES {
        dilithium2_sign(message, secret_key)
    } else if secret_key.len() == DILITHIUM5_SECRETKEY_BYTES {
        dilithium5_sign(message, secret_key)
    } else {
        Err(anyhow::anyhow!(
            "Unknown Dilithium secret key size: {} (expected {} for D2 or {} for D5)",
            secret_key.len(), DILITHIUM2_SECRETKEY_BYTES, DILITHIUM5_SECRETKEY_BYTES
        ))
    }
}

/// Auto-detecting Dilithium signature verification
/// Chooses Dilithium2 or Dilithium5 based on public key size
pub fn dilithium_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    if public_key.len() == DILITHIUM2_PUBLICKEY_BYTES {
        dilithium2_verify(message, signature, public_key)
    } else if public_key.len() == DILITHIUM5_PUBLICKEY_BYTES {
        dilithium5_verify(message, signature, public_key)
    } else {
        Err(anyhow::anyhow!(
            "Unknown Dilithium public key size: {} (expected {} for D2 or {} for D5)",
            public_key.len(), DILITHIUM2_PUBLICKEY_BYTES, DILITHIUM5_PUBLICKEY_BYTES
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== KEY SIZE CONSTANTS TESTS ====================

    #[test]
    fn test_dilithium2_key_sizes() {
        let (pk, sk) = dilithium2_keypair();
        assert_eq!(pk.len(), DILITHIUM2_PUBLICKEY_BYTES, "D2 public key should be {} bytes", DILITHIUM2_PUBLICKEY_BYTES);
        assert_eq!(sk.len(), DILITHIUM2_SECRETKEY_BYTES, "D2 secret key should be {} bytes", DILITHIUM2_SECRETKEY_BYTES);
    }

    #[test]
    fn test_dilithium5_key_sizes() {
        let (pk, sk) = dilithium5_keypair();
        assert_eq!(pk.len(), DILITHIUM5_PUBLICKEY_BYTES, "D5 public key should be {} bytes", DILITHIUM5_PUBLICKEY_BYTES);
        assert_eq!(sk.len(), DILITHIUM5_SECRETKEY_BYTES, "D5 secret key should be {} bytes", DILITHIUM5_SECRETKEY_BYTES);
    }

    // ==================== DILITHIUM2 SIGN/VERIFY TESTS ====================

    #[test]
    fn test_dilithium2_sign_verify_roundtrip() {
        let (pk, sk) = dilithium2_keypair();
        let message = b"Test message for Dilithium2 signing";

        let signature = dilithium2_sign(message, &sk).expect("D2 signing should succeed");
        let valid = dilithium2_verify(message, &signature, &pk).expect("D2 verification should succeed");

        assert!(valid, "D2 signature should be valid");
    }

    #[test]
    fn test_dilithium2_wrong_message_fails() {
        let (pk, sk) = dilithium2_keypair();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = dilithium2_sign(message, &sk).expect("D2 signing should succeed");
        let valid = dilithium2_verify(wrong_message, &signature, &pk).expect("D2 verification should succeed");

        assert!(!valid, "D2 signature should be invalid for wrong message");
    }

    #[test]
    fn test_dilithium2_wrong_key_fails() {
        let (_, sk) = dilithium2_keypair();
        let (wrong_pk, _) = dilithium2_keypair();
        let message = b"Test message";

        let signature = dilithium2_sign(message, &sk).expect("D2 signing should succeed");
        let valid = dilithium2_verify(message, &signature, &wrong_pk).expect("D2 verification should succeed");

        assert!(!valid, "D2 signature should be invalid for wrong public key");
    }

    // ==================== DILITHIUM5 SIGN/VERIFY TESTS ====================

    #[test]
    fn test_dilithium5_sign_verify_roundtrip() {
        let (pk, sk) = dilithium5_keypair();
        let message = b"Test message for Dilithium5 signing";

        let signature = dilithium5_sign(message, &sk).expect("D5 signing should succeed");
        let valid = dilithium5_verify(message, &signature, &pk).expect("D5 verification should succeed");

        assert!(valid, "D5 signature should be valid");
    }

    #[test]
    fn test_dilithium5_wrong_message_fails() {
        let (pk, sk) = dilithium5_keypair();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = dilithium5_sign(message, &sk).expect("D5 signing should succeed");
        let valid = dilithium5_verify(wrong_message, &signature, &pk).expect("D5 verification should succeed");

        assert!(!valid, "D5 signature should be invalid for wrong message");
    }

    // ==================== AUTO-DETECT SIGN TESTS ====================

    #[test]
    fn test_auto_sign_detects_dilithium2() {
        let (pk, sk) = dilithium2_keypair();
        let message = b"Auto-detect D2 signing test";

        // Use auto-detecting sign
        let signature = dilithium_sign(message, &sk).expect("Auto-sign should detect D2 and succeed");

        // Verify with explicit D2 verify
        let valid = dilithium2_verify(message, &signature, &pk).expect("D2 verification should succeed");
        assert!(valid, "Auto-signed D2 signature should be valid");
    }

    #[test]
    fn test_auto_sign_detects_dilithium5() {
        let (pk, sk) = dilithium5_keypair();
        let message = b"Auto-detect D5 signing test";

        // Use auto-detecting sign
        let signature = dilithium_sign(message, &sk).expect("Auto-sign should detect D5 and succeed");

        // Verify with explicit D5 verify
        let valid = dilithium5_verify(message, &signature, &pk).expect("D5 verification should succeed");
        assert!(valid, "Auto-signed D5 signature should be valid");
    }

    #[test]
    fn test_auto_sign_rejects_invalid_key_size() {
        let invalid_sk = vec![0u8; 1000]; // Wrong size
        let message = b"Test message";

        let result = dilithium_sign(message, &invalid_sk);
        assert!(result.is_err(), "Auto-sign should reject invalid key size");

        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown Dilithium secret key size"), "Error should mention key size");
    }

    // ==================== AUTO-DETECT VERIFY TESTS ====================

    #[test]
    fn test_auto_verify_detects_dilithium2() {
        let (pk, sk) = dilithium2_keypair();
        let message = b"Auto-detect D2 verification test";

        // Sign with explicit D2
        let signature = dilithium2_sign(message, &sk).expect("D2 signing should succeed");

        // Verify with auto-detecting verify
        let valid = dilithium_verify(message, &signature, &pk).expect("Auto-verify should detect D2 and succeed");
        assert!(valid, "Auto-verified D2 signature should be valid");
    }

    #[test]
    fn test_auto_verify_detects_dilithium5() {
        let (pk, sk) = dilithium5_keypair();
        let message = b"Auto-detect D5 verification test";

        // Sign with explicit D5
        let signature = dilithium5_sign(message, &sk).expect("D5 signing should succeed");

        // Verify with auto-detecting verify
        let valid = dilithium_verify(message, &signature, &pk).expect("Auto-verify should detect D5 and succeed");
        assert!(valid, "Auto-verified D5 signature should be valid");
    }

    #[test]
    fn test_auto_verify_rejects_invalid_key_size() {
        let invalid_pk = vec![0u8; 1000]; // Wrong size
        let signature = vec![0u8; 100];
        let message = b"Test message";

        let result = dilithium_verify(message, &signature, &invalid_pk);
        assert!(result.is_err(), "Auto-verify should reject invalid key size");

        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown Dilithium public key size"), "Error should mention key size");
    }

    // ==================== FULL AUTO-DETECT ROUNDTRIP TESTS ====================

    #[test]
    fn test_full_auto_roundtrip_dilithium2() {
        let (pk, sk) = dilithium2_keypair();
        let message = b"Full auto roundtrip D2 test";

        // Both sign and verify use auto-detection
        let signature = dilithium_sign(message, &sk).expect("Auto-sign should succeed");
        let valid = dilithium_verify(message, &signature, &pk).expect("Auto-verify should succeed");

        assert!(valid, "Full auto roundtrip D2 should work");
    }

    #[test]
    fn test_full_auto_roundtrip_dilithium5() {
        let (pk, sk) = dilithium5_keypair();
        let message = b"Full auto roundtrip D5 test";

        // Both sign and verify use auto-detection
        let signature = dilithium_sign(message, &sk).expect("Auto-sign should succeed");
        let valid = dilithium_verify(message, &signature, &pk).expect("Auto-verify should succeed");

        assert!(valid, "Full auto roundtrip D5 should work");
    }

    // ==================== CROSS-VERSION REJECTION TESTS ====================

    #[test]
    fn test_d2_signature_rejected_by_d5_key() {
        let (_, sk_d2) = dilithium2_keypair();
        let (pk_d5, _) = dilithium5_keypair();
        let message = b"Cross-version test";

        let signature = dilithium2_sign(message, &sk_d2).expect("D2 signing should succeed");

        // D5 verify should fail (signature format incompatible)
        let result = dilithium5_verify(message, &signature, &pk_d5);
        // This should either error or return false
        match result {
            Ok(valid) => assert!(!valid, "D2 signature should not verify with D5 key"),
            Err(_) => {} // Error is also acceptable
        }
    }

    #[test]
    fn test_d5_signature_rejected_by_d2_key() {
        let (_, sk_d5) = dilithium5_keypair();
        let (pk_d2, _) = dilithium2_keypair();
        let message = b"Cross-version test";

        let signature = dilithium5_sign(message, &sk_d5).expect("D5 signing should succeed");

        // D2 verify should fail (signature format incompatible)
        let result = dilithium2_verify(message, &signature, &pk_d2);
        // This should either error or return false
        match result {
            Ok(valid) => assert!(!valid, "D5 signature should not verify with D2 key"),
            Err(_) => {} // Error is also acceptable
        }
    }

    // ==================== INTEROP: iOS (D5) <-> Server (auto-detect) ====================

    #[test]
    fn test_ios_d5_signature_verified_by_auto_detect() {
        // Simulate iOS client using D5
        let (ios_pk, ios_sk) = dilithium5_keypair();
        let message = b"iOS client hello message";

        // iOS signs with D5
        let signature = dilithium5_sign(message, &ios_sk).expect("iOS D5 signing should succeed");

        // Server verifies with auto-detect (should detect D5 from pk size)
        let valid = dilithium_verify(message, &signature, &ios_pk)
            .expect("Server auto-detect should handle iOS D5 signature");

        assert!(valid, "iOS D5 signature should be verified by server auto-detect");
    }

    // ==================== INTEROP: CLI (D2) <-> Server (auto-detect) ====================

    #[test]
    fn test_cli_d2_signature_verified_by_auto_detect() {
        // Simulate CLI client using D2
        let (cli_pk, cli_sk) = dilithium2_keypair();
        let message = b"CLI client hello message";

        // CLI signs with D2
        let signature = dilithium2_sign(message, &cli_sk).expect("CLI D2 signing should succeed");

        // Server verifies with auto-detect (should detect D2 from pk size)
        let valid = dilithium_verify(message, &signature, &cli_pk)
            .expect("Server auto-detect should handle CLI D2 signature");

        assert!(valid, "CLI D2 signature should be verified by server auto-detect");
    }

    // ==================== SIGNATURE SIZE TESTS ====================

    #[test]
    fn test_dilithium2_signature_size() {
        let (_, sk) = dilithium2_keypair();
        let message = b"Test message";
        let signature = dilithium2_sign(message, &sk).expect("D2 signing should succeed");

        // D2 SignedMessage = message + 2420 bytes
        let expected_size = message.len() + 2420;
        assert_eq!(signature.len(), expected_size,
            "D2 signature size should be message_len + 2420 = {}", expected_size);
    }

    #[test]
    fn test_dilithium5_signature_size() {
        let (_, sk) = dilithium5_keypair();
        let message = b"Test message";
        let signature = dilithium5_sign(message, &sk).expect("D5 signing should succeed");

        // D5 SignedMessage = message + 4627 bytes
        let expected_size = message.len() + 4627;
        assert_eq!(signature.len(), expected_size,
            "D5 signature size should be message_len + 4627 = {}", expected_size);
    }
}
