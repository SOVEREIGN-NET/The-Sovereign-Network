//! ChaCha20-Poly1305 AEAD encryption - preserving symmetric crypto
//!
//! implementation from crypto.rs, lines 910-945
//!
//! ✅ SECURITY FIX (CRITICAL-3): Nonce collision mitigation
//!
//! ChaCha20Poly1305 requires unique nonces per key to maintain security.
//! Nonce collision would allow an attacker to break confidentiality.
//!
//! # Nonce Strategies Available
//!
//! ## 1. Random nonces (encrypt_data_with_ad)
//! - 96-bit random nonce per message from OS RNG
//! - Birthday bound: ~2^48 messages before 50% collision probability
//! - Suitable for per-connection encryption (typical session < 1M messages)
//! - Recommended for short-lived connections or where key rotation is in place
//!
//! ## 2. Counter-based nonces (encrypt_data_with_ad_nonce) ✅ PREFERRED FOR LONG-LIVED
//! - Explicit nonce control: caller provides 96-bit nonce
//! - Pattern: [4-byte prefix || 8-byte counter] for session-spanning uniqueness
//! - Guarantees no collisions within a session (no birthday bound)
//! - Used by: lib-network consensus encryption (Counter starts at 0, increments per message)
//! - Recommended for: validator-to-validator communication, high-traffic streams
//!
//! ## 3. Key rotation (fallback)
//! - Rotate keys after ~1M messages (safety margin below birthday bound)
//! - Implemented in lib-network/src/protocols/quic_mesh.rs
//! - Keys rotated every 1 million messages or 24 hours
//!
//! # Function Reference
//!
//! **Random nonce functions (legacy):**
//! - `encrypt_data()` / `decrypt_data()` - basic encryption
//! - `encrypt_data_with_ad()` / `decrypt_data_with_ad()` - with associated data
//!
//! **Explicit nonce functions (preferred for stateful nonce counters):**
//! - `encrypt_data_with_ad_nonce()` - caller provides 12-byte nonce
//! - `decrypt_data_with_ad_nonce()` - caller provides 12-byte nonce
//!
//! **CRITICAL:** When using nonce functions, nonce MUST be unique per key.
//! Reusing (key, nonce) breaks ChaCha20Poly1305 completely.

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce, Key,
};
use crate::random::generate_nonce;

/// ✅ SECURITY FIX: Encrypt data with unique nonce per message
///
/// CRITICAL: Each message uses a random 96-bit nonce.
/// The nonce is embedded in the ciphertext (first 12 bytes).
///
/// Security guarantee: Different messages have different nonces,
/// preventing nonce reuse attacks (as long as total messages < 2^48).
pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Key must be 32 bytes"));
    }
    
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    
    // Prepend nonce to ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data with a key using ChaCha20-Poly1305
pub fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Key must be 32 bytes"));
    }
    
    if encrypted_data.len() < 12 {
        return Err(anyhow::anyhow!("Encrypted data too short"));
    }
    
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    
    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    
    Ok(plaintext)
}

/// Encrypt data with associated data (AEAD)
pub fn encrypt_data_with_ad(data: &[u8], key: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Key must be 32 bytes"));
    }
    
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Create payload with associated data
    let payload = chacha20poly1305::aead::Payload {
        msg: data,
        aad: associated_data,
    };
    
    let ciphertext = cipher.encrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    
    // Prepend nonce to ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data with associated data (AEAD)
pub fn decrypt_data_with_ad(encrypted_data: &[u8], key: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Key must be 32 bytes"));
    }

    if encrypted_data.len() < 12 {
        return Err(anyhow::anyhow!("Encrypted data too short"));
    }

    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];

    // Create payload with associated data
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    let plaintext = cipher.decrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

/// Encrypt data with associated data (AEAD) using explicit nonce
///
/// CRITICAL: The nonce MUST be unique for every message encrypted with the same key.
/// Reusing a nonce breaks ChaCha20Poly1305 security completely.
///
/// Use this variant when you need to control nonce generation (e.g., counter-based nonces).
/// For random nonces, use `encrypt_data_with_ad()` instead.
pub fn encrypt_data_with_ad_nonce(
    data: &[u8],
    key: &[u8],
    nonce: &[u8; 12],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Key must be 32 bytes"));
    }

    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce_obj = Nonce::from_slice(nonce);

    // Create payload with associated data
    let payload = chacha20poly1305::aead::Payload {
        msg: data,
        aad: associated_data,
    };

    let ciphertext = cipher.encrypt(nonce_obj, payload)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext (matching format of encrypt_data_with_ad)
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with associated data (AEAD) using explicit nonce
///
/// Use this when decryption nonce comes from the ciphertext envelope
/// (e.g., stateless decryption where nonce is transmitted with the message).
pub fn decrypt_data_with_ad_nonce(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8; 12],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Key must be 32 bytes"));
    }

    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce_obj = Nonce::from_slice(nonce);

    // Create payload with associated data
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    let plaintext = cipher.decrypt(nonce_obj, payload)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, rngs::OsRng};

    #[test]
    fn test_symmetric_encryption() -> Result<()> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        
        let plaintext = b"ZHTP symmetric encryption test data";
        
        // Encrypt and decrypt
        let ciphertext = encrypt_data(plaintext, &key)?;
        let decrypted = decrypt_data(&ciphertext, &key)?;
        
        assert_eq!(plaintext.as_slice(), decrypted);
        assert_ne!(plaintext.as_slice(), &ciphertext[12..]); // Should be different (encrypted)
        
        Ok(())
    }

    #[test]
    fn test_aead_encryption() -> Result<()> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let plaintext = b"ZHTP AEAD test data";
        let associated_data = b"ZHTP-v1.0";

        // Encrypt and decrypt with AD
        let ciphertext = encrypt_data_with_ad(plaintext, &key, associated_data)?;
        let decrypted = decrypt_data_with_ad(&ciphertext, &key, associated_data)?;

        assert_eq!(plaintext.as_slice(), decrypted);

        // Wrong associated data should fail
        let wrong_ad = b"wrong-data";
        let result = decrypt_data_with_ad(&ciphertext, &key, wrong_ad);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_aead_encryption_with_explicit_nonce() -> Result<()> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let plaintext = b"ZHTP AEAD with explicit nonce";
        let associated_data = b"ZHTP-v1.0";
        let nonce = [0x42u8; 12];  // Fixed nonce

        // Encrypt with explicit nonce
        let encrypted = encrypt_data_with_ad_nonce(plaintext, &key, &nonce, associated_data)?;

        // Extract nonce and ciphertext parts
        let nonce_part = &encrypted[..12];
        let ciphertext_part = &encrypted[12..];

        // Nonce should be exactly what we provided
        assert_eq!(nonce_part, nonce);

        // Decrypt using explicit nonce (extract from envelope)
        let decrypted = decrypt_data_with_ad_nonce(ciphertext_part, &key, &nonce, associated_data)?;
        assert_eq!(plaintext.as_slice(), decrypted);

        Ok(())
    }

    #[test]
    fn test_nonce_uniqueness_with_explicit_nonce() -> Result<()> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let plaintext = b"same data";
        let associated_data = b"ZHTP-v1.0";

        // Encrypt same plaintext with different nonces
        let nonce1 = [0x01u8; 12];
        let nonce2 = [0x02u8; 12];

        let encrypted1 = encrypt_data_with_ad_nonce(plaintext, &key, &nonce1, associated_data)?;
        let encrypted2 = encrypt_data_with_ad_nonce(plaintext, &key, &nonce2, associated_data)?;

        // Ciphertexts must differ (different nonces)
        assert_ne!(encrypted1, encrypted2, "Different nonces must produce different ciphertexts");

        // But both must decrypt to same plaintext
        let decrypted1 = decrypt_data_with_ad_nonce(&encrypted1[12..], &key, &nonce1, associated_data)?;
        let decrypted2 = decrypt_data_with_ad_nonce(&encrypted2[12..], &key, &nonce2, associated_data)?;

        assert_eq!(plaintext.as_slice(), decrypted1);
        assert_eq!(plaintext.as_slice(), decrypted2);

        Ok(())
    }
}
