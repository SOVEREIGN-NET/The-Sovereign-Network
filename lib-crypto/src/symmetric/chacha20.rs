//! ChaCha20-Poly1305 AEAD encryption - preserving symmetric crypto
//! 
//! implementation from crypto.rs, lines 910-945

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce, Key,
};
use crate::random::generate_nonce;

/// Encrypt data with a key using ChaCha20-Poly1305
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
}
