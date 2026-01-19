//! Signature verification - preserving ZHTP verification with development mode
//! 
//! implementation from crypto.rs, lines 960-1087 including browser compatibility

use anyhow::Result;
use pqcrypto_dilithium::{dilithium2, dilithium5};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as SignPublicKey, SignedMessage};

// Constants for CRYSTALS key sizes
const DILITHIUM2_PUBLICKEY_BYTES: usize = 1312;
const DILITHIUM5_PUBLICKEY_BYTES: usize = 2592;

/// Verify a signature against a message and public key
pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Only log verification for non-test messages to reduce spam
    let message_str = String::from_utf8_lossy(message);
    if !message_str.contains("ZHTP-KeyPair-Validation-Test") {
        // Removed debug output to prevent spam - enable only for debugging specific issues
        // println!("verify_signature: message len={}, sig len={}, pk len={}", message.len(), signature.len(), public_key.len());
    }
    
    //  PRODUCTION MODE: Strict signature verification only
    // NO DEVELOPMENT BYPASSES - All signatures must be valid CRYSTALS-Dilithium
    
    // Pure post-quantum verification - CRYSTALS-Dilithium only (no Ed25519 fallback)
    {
        let message_str = String::from_utf8_lossy(message);
        if !message_str.contains("ZHTP-KeyPair-Validation-Test") {
            // Only log for debugging non-test messages
            // println!("Attempting Dilithium verification...");
        }
        
        // Try Dilithium2 verification first
        if public_key.len() == DILITHIUM2_PUBLICKEY_BYTES {
            if !message_str.contains("ZHTP-KeyPair-Validation-Test") {
                // Only log for debugging non-test messages
                // println!("Public key length matches Dilithium2 ({})", DILITHIUM2_PUBLICKEY_BYTES);
            }
            match dilithium2::PublicKey::from_bytes(public_key) {
                Ok(pk) => {
                    if !message_str.contains("ZHTP-KeyPair-Validation-Test") {
                        // Only log for debugging non-test messages
                        // println!("Successfully parsed Dilithium2 public key");
                    }
                    // For Dilithium, the signature is the signed message format
                    // Try to verify directly using the signature as signed message
                    match dilithium2::SignedMessage::from_bytes(signature) {
                        Ok(signed_msg) => {
                            if !message_str.contains("ZHTP-KeyPair-Validation-Test") {
                                // Only log for debugging non-test messages
                                // println!("Successfully parsed signed message");
                            }
                            match dilithium2::open(&signed_msg, &pk) {
                                Ok(verified_message) => {
                                    // Only log details for non-test messages
                                    let message_str = String::from_utf8_lossy(message);
                                    if !message_str.contains("ZHTP-KeyPair-Validation-Test") {
                                        // Removed debug output to prevent spam
                                        // println!("Successfully opened signed message, verified len={}", verified_message.len());
                                    }
                                    // Verify the extracted message matches original
                                    let matches = verified_message == message;
                                    if !message_str.contains("ZHTP-KeyPair-Validation-Test") {
                                        // Removed debug output to prevent spam
                                        // println!("Message match result: {}", matches);
                                    }
                                    Ok(matches)
                                },
                                Err(e) => {
                                    println!("Failed to open signed message: {:?}", e);
                                    Ok(false)
                                }
                            }
                        },
                        Err(e) => {
                            println!("Failed to parse signed message: {:?}", e);
                            // SECURITY: Do not fallback to weak hash comparison
                            // Invalid signature format = invalid signature
                            Ok(false)
                        }
                    }
                },
                Err(_) => Ok(false)
            }
        }
        // Try Dilithium5 verification (NIST Level 5 - highest security)
        else if public_key.len() == DILITHIUM5_PUBLICKEY_BYTES {
            match dilithium5::PublicKey::from_bytes(public_key) {
                Ok(pk) => {
                    // Try detached signature first (what lib-client produces)
                    if let Ok(detached_sig) = dilithium5::DetachedSignature::from_bytes(signature) {
                        match dilithium5::verify_detached_signature(&detached_sig, message, &pk) {
                            Ok(()) => return Ok(true),
                            Err(_) => {}
                        }
                    }
                    // Fall back to SignedMessage format
                    match dilithium5::SignedMessage::from_bytes(signature) {
                        Ok(signed_msg) => {
                            match dilithium5::open(&signed_msg, &pk) {
                                Ok(verified_message) => Ok(verified_message == message),
                                Err(_) => Ok(false)
                            }
                        },
                        Err(_) => Ok(false)
                    }
                },
                Err(_) => Ok(false)
            }
        }
        else {
            // Invalid key/signature sizes for Dilithium
            Ok(false)
        }
    }
}
