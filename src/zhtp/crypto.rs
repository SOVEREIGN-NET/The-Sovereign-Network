use anyhow::{Result, anyhow};
use pqcrypto_dilithium::dilithium5::{
    detached_sign, keypair as dilithium_keypair, verify_detached_signature, 
    DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::{
    sign::{DetachedSignature as _, PublicKey as PublicKeyTrait},
    kem::{PublicKey as _, SharedSecret as _, Ciphertext as _},
};
use serde::{Deserialize, Serialize};
use base64::Engine as _;
use std::time::{SystemTime, UNIX_EPOCH};

const KEY_ROTATION_INTERVAL: u64 = 24 * 60 * 60; // 24 hours in seconds

/// Secure wrapper for secret key material that automatically zeroizes on drop
struct SecureSecretKey {
    // Store raw key bytes instead of the library types for better security control
    dilithium_secret_bytes: Vec<u8>,
    kyber_secret_bytes: Vec<u8>,
}

impl SecureSecretKey {
    fn new(dilithium_secret: SecretKey, kyber_secret: kyber768::SecretKey) -> Self {
        use pqcrypto_traits::sign::SecretKey as _;
        use pqcrypto_traits::kem::SecretKey as _;
        
        Self {
            dilithium_secret_bytes: dilithium_secret.as_bytes().to_vec(),
            kyber_secret_bytes: kyber_secret.as_bytes().to_vec(),
        }
    }
    
    fn get_dilithium(&self) -> Result<SecretKey> {
        use pqcrypto_traits::sign::SecretKey as _;
        SecretKey::from_bytes(&self.dilithium_secret_bytes)
            .map_err(|_| anyhow!("Failed to reconstruct Dilithium secret key"))
    }
    
    fn get_kyber(&self) -> Result<kyber768::SecretKey> {
        use pqcrypto_traits::kem::SecretKey as _;
        kyber768::SecretKey::from_bytes(&self.kyber_secret_bytes)
            .map_err(|_| anyhow!("Failed to reconstruct Kyber secret key"))
    }
}

impl Drop for SecureSecretKey {
    fn drop(&mut self) {
        // Manually zeroize the secret key bytes
        for byte in self.dilithium_secret_bytes.iter_mut() {
            *byte = 0;
        }
        for byte in self.kyber_secret_bytes.iter_mut() {
            *byte = 0;
        }
        
        // Additional security: overwrite with random data then zero again
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut self.dilithium_secret_bytes);
        rand::thread_rng().fill_bytes(&mut self.kyber_secret_bytes);
        
        for byte in self.dilithium_secret_bytes.iter_mut() {
            *byte = 0;
        }
        for byte in self.kyber_secret_bytes.iter_mut() {
            *byte = 0;
        }
    }
}

/// Secure wrapper for key bytes that automatically zeroizes on drop
pub struct SecureKeyBytes(Vec<u8>);

impl SecureKeyBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Convert to Vec<u8>, consuming the wrapper
    /// WARNING: The returned Vec will NOT be automatically zeroized
    pub fn into_vec(mut self) -> Vec<u8> {
        // Create a copy before we drop (and zeroize) the original
        let result = self.0.clone();
        // Manually zeroize the original before dropping
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
        result
    }
}

impl Drop for SecureKeyBytes {
    fn drop(&mut self) {
        // Zeroize the key bytes when dropped
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
        
        // Additional security: overwrite with random data then zero again
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut self.0);
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

/// Combined post-quantum keypair with secure key storage
pub struct Keypair {
    // Dilithium public key (safe to store normally)
    pub public: PublicKey,
    
    // Kyber public key (safe to store normally)
    kyber_public: kyber768::PublicKey,
    
    // Secure storage for secret keys (auto-zeroized on drop)
    secure_secrets: SecureSecretKey,
    
    // Key management
    pub(crate) created_at: u64,
    pub(crate) rotation_due: u64,
}

/// Exportable representation of a keypair (raw secrets encrypted at rest by caller)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeypairExport {
    /// Base64 Dilithium public key
    pub dilithium_public_b64: String,
    /// Base64 Kyber public key
    pub kyber_public_b64: String,
    /// Base64 Dilithium secret key (UNENCRYPTED – encrypt before persisting)
    pub dilithium_secret_b64: String,
    /// Base64 Kyber secret key (UNENCRYPTED – encrypt before persisting)
    pub kyber_secret_b64: String,
    pub created_at: u64,
    pub rotation_due: u64,
    pub version: u32,
}

impl Clone for Keypair {
    fn clone(&self) -> Self {
        // WARNING: Cloning keypairs should be done sparingly for security
        // Each clone creates additional copies of secret key material in memory
        Self {
            public: self.public,
            kyber_public: self.kyber_public,
            secure_secrets: SecureSecretKey {
                dilithium_secret_bytes: self.secure_secrets.dilithium_secret_bytes.clone(),
                kyber_secret_bytes: self.secure_secrets.kyber_secret_bytes.clone(),
            },
            created_at: self.created_at,
            rotation_due: self.rotation_due,
        }
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("created_at", &self.created_at)
            .field("rotation_due", &self.rotation_due)
            .field("public_key_len", &self.public.as_bytes().len())
            .field("kyber_public_len", &self.kyber_public.as_bytes().len())
            .finish_non_exhaustive()
    }
}

/// Key status information
#[derive(Debug, Clone)]
pub struct KeyStatus {
    pub created_at: u64,
    pub rotation_due: u64,
    pub needs_rotation: bool,
}

/// Serializable signature wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature(Vec<u8>);

/// Encapsulated key package
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    kyber_ciphertext: Vec<u8>,
    timestamp: u64,
}

impl Signature {
    pub fn empty() -> Self {
        Signature(Vec::new())
    }

    pub fn new(bytes: Vec<u8>) -> Self {
        Signature(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Get the length of the signature
    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    /// Check if signature is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    
    /// Get signature as mutable slice (for testing purposes)
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
    
    /// Get signature as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Keypair {
    /// Generate a new post-quantum keypair
    pub fn generate() -> Self {
        // Generate Dilithium keypair for signatures
        let (pk, sk) = dilithium_keypair();
        
        // Generate Kyber keypair for key encapsulation
        let (kyber_pk, kyber_sk) = kyber768::keypair();
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Keypair {
            public: pk,
            kyber_public: kyber_pk,
            secure_secrets: SecureSecretKey::new(sk, kyber_sk),
            created_at: now,
            rotation_due: now + KEY_ROTATION_INTERVAL,
        }
    }

    /// Sign a message using Dilithium with secure key handling
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        self.check_rotation()?;
        let secret_key = self.secure_secrets.get_dilithium()?;
        let sig = detached_sign(message, &secret_key);
        Ok(Signature(sig.as_bytes().to_vec()))
    }

    /// Verify a Dilithium signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        let sig = DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| anyhow!("Invalid signature format"))?;

        Ok(verify_detached_signature(&sig, message, &self.public).is_ok())
    }

    /// Encapsulate a shared secret using Kyber
    pub fn encapsulate_key(&self) -> Result<(Vec<u8>, KeyPackage)> {
        self.check_rotation()?;

        // Perform key encapsulation
        let (shared_secret, ciphertext) = kyber768::encapsulate(&self.kyber_public);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok((
            Vec::from(shared_secret.as_bytes()),
            KeyPackage {
                kyber_ciphertext: Vec::from(ciphertext.as_bytes()),
                timestamp: now,
            }
        ))
    }

    /// Decapsulate a shared secret using Kyber
    pub fn decapsulate_key(&self, package: &KeyPackage) -> Result<Vec<u8>> {
        self.check_rotation()?;

        // Convert bytes back to ciphertext
        let ct = kyber768::Ciphertext::from_bytes(&package.kyber_ciphertext)
            .map_err(|_| anyhow!("Invalid Kyber ciphertext"))?;

        // Perform decapsulation and get shared secret
        let kyber_secret = self.secure_secrets.get_kyber()?;
        let shared_secret = kyber768::decapsulate(&ct, &kyber_secret);
        Ok(Vec::from(shared_secret.as_bytes()))
    }

    /// Get current key status
    pub fn get_status(&self) -> KeyStatus {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        KeyStatus {
            created_at: self.created_at,
            rotation_due: self.rotation_due,
            needs_rotation: now > self.rotation_due,
        }
    }

    /// Check if key rotation is needed
    pub fn check_rotation(&self) -> Result<()> {
        let status = self.get_status();
        if status.needs_rotation {
            Err(anyhow!("Key rotation required"))
        } else {
            Ok(())
        }
    }

    /// Create a new keypair for rotation
    pub fn rotate() -> Self {
        Self::generate()
    }

    /// Force key rotation by setting due time to now
    pub fn needs_immediate_rotation(&mut self) {
        self.rotation_due = 0;
    }

    /// Get the public key bytes for this keypair
    pub fn public_key(&self) -> Vec<u8> {
        PublicKeyTrait::as_bytes(&self.public).to_vec()
    }

    /// Get the Kyber public key for key exchange  
    pub fn get_kyber_public(&self) -> &kyber768::PublicKey {
        &self.kyber_public
    }

    /// Derive shared secret from another party's Kyber public key using encapsulation
    pub fn derive_shared_secret(&self, other_public: &kyber768::PublicKey) -> Result<[u8; 32]> {
        self.check_rotation()?;
        
        // Perform key encapsulation with the other party's public key
        let (shared_secret, _ciphertext) = kyber768::encapsulate(other_public);
        
        // Return first 32 bytes as standardized shared secret
        let mut result = [0u8; 32];
        result.copy_from_slice(&shared_secret.as_bytes()[..32]);
        Ok(result)
    }

    /// Perform proper ECDH-style key exchange using Kyber KEM
    pub fn key_exchange_with(&self, other_keypair: &Keypair) -> Result<([u8; 32], Vec<u8>)> {
        self.check_rotation()?;
        
        // Alice (self) encapsulates for Bob (other)
        let (shared_secret, ciphertext) = kyber768::encapsulate(&other_keypair.kyber_public);
        
        // Return shared secret and ciphertext that other party can decapsulate
        let mut result = [0u8; 32];
        result.copy_from_slice(&shared_secret.as_bytes()[..32]);
        Ok((result, ciphertext.as_bytes().to_vec()))
    }

    /// Decapsulate shared secret from ciphertext
    pub fn decapsulate_shared_secret(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        self.check_rotation()?;
        
        // Convert bytes back to ciphertext
        let ct = kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| anyhow::anyhow!("Invalid Kyber ciphertext"))?;
        
        // Perform decapsulation
        let kyber_secret = self.secure_secrets.get_kyber()?;
        let shared_secret = kyber768::decapsulate(&ct, &kyber_secret);
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&shared_secret.as_bytes()[..32]);
        Ok(result)
    }

    /// Rotate keys and return new keypair
    pub fn rotate_keys(&self) -> Result<Self> {
        Ok(Self::generate())
    }

    /// Hash a message using post-quantum secure hash (BLAKE3)
    pub fn hash_message(&self, message: &[u8]) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(message);
        hasher.finalize().into()
    }

    /// Encrypt data using ChaCha20-Poly1305 with a shared secret
    pub fn encrypt_data(&self, data: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce};
        use rand::RngCore;
        
        // Derive key from shared secret using BLAKE3
        let key_hash = self.hash_message(shared_secret);
        let cipher = ChaCha20Poly1305::new_from_slice(&key_hash)
            .map_err(|_| anyhow!("Failed to create cipher"))?;
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Prepare data for encryption
        let mut buffer = data.to_vec();
        
        // Encrypt in place
        cipher.encrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|_| anyhow!("Encryption failed"))?;
        
        // Prepend nonce to encrypted data
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&buffer);
        
        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305 with a shared secret
    pub fn decrypt_data(&self, encrypted_data: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce};
        
        if encrypted_data.len() < 12 {
            return Err(anyhow!("Encrypted data too short"));
        }
        
        // Derive key from shared secret using BLAKE3
        let key_hash = self.hash_message(shared_secret);
        let cipher = ChaCha20Poly1305::new_from_slice(&key_hash)
            .map_err(|_| anyhow!("Failed to create cipher"))?;
        
        // Extract nonce and encrypted data
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let mut buffer = encrypted_data[12..].to_vec();
        
        // Decrypt in place
        cipher.decrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|_| anyhow!("Decryption failed"))?;
        
        Ok(buffer)
    }

    /// Get the secret key bytes for this keypair (RESTRICTED - only for blockchain integration)
    /// WARNING: This method exposes raw key material and should be used sparingly
    /// Returns SecureKeyBytes that automatically zeroizes when dropped
    pub fn secret_key_bytes(&self) -> SecureKeyBytes {
        // Return secure wrapper that will be zeroized when dropped
        SecureKeyBytes(self.secure_secrets.dilithium_secret_bytes.clone())
    }
    
    /// Secure method to verify if this keypair can sign for a given public key
    /// This avoids exposing the raw secret key bytes in most cases
    pub fn can_sign_for(&self, public_key_bytes: &[u8]) -> bool {
        self.public_key() == public_key_bytes
    }

    /// Export keypair into a serializable struct. Secrets are returned UNENCRYPTED.
    /// Caller MUST encrypt before writing to persistent storage.
    pub fn export_unencrypted(&self) -> KeypairExport {
        use pqcrypto_traits::sign::PublicKey as _;
        use pqcrypto_traits::kem::PublicKey as _;

        let engine = base64::prelude::BASE64_STANDARD;
        // Reconstruct secret keys from stored bytes
        let dilithium_secret_b64 = engine.encode(&self.secure_secrets.dilithium_secret_bytes);
        let kyber_secret_b64 = engine.encode(&self.secure_secrets.kyber_secret_bytes);

        KeypairExport {
            dilithium_public_b64: engine.encode(self.public.as_bytes()),
            kyber_public_b64: engine.encode(self.kyber_public.as_bytes()),
            dilithium_secret_b64,
            kyber_secret_b64,
            created_at: self.created_at,
            rotation_due: self.rotation_due,
            version: 1,
        }
    }

    /// Import keypair from export struct (expects UNENCRYPTED secrets already decrypted in memory)
    pub fn import_unencrypted(export: &KeypairExport) -> Result<Self> {
        use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
        let engine = base64::prelude::BASE64_STANDARD;
        let dilithium_pk_bytes = engine.decode(export.dilithium_public_b64.as_bytes())
            .map_err(|_| anyhow!("Invalid base64 dilithium public"))?;
        let kyber_pk_bytes = engine.decode(export.kyber_public_b64.as_bytes())
            .map_err(|_| anyhow!("Invalid base64 kyber public"))?;
        let dilithium_sk_bytes = engine.decode(export.dilithium_secret_b64.as_bytes())
            .map_err(|_| anyhow!("Invalid base64 dilithium secret"))?;
        let kyber_sk_bytes = engine.decode(export.kyber_secret_b64.as_bytes())
            .map_err(|_| anyhow!("Invalid base64 kyber secret"))?;

        let public = pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(&dilithium_pk_bytes)
            .map_err(|_| anyhow!("Failed to parse dilithium public"))?;
        let kyber_public = kyber768::PublicKey::from_bytes(&kyber_pk_bytes)
            .map_err(|_| anyhow!("Failed to parse kyber public"))?;
        let dilithium_secret = pqcrypto_dilithium::dilithium5::SecretKey::from_bytes(&dilithium_sk_bytes)
            .map_err(|_| anyhow!("Failed to parse dilithium secret"))?;
        let kyber_secret = kyber768::SecretKey::from_bytes(&kyber_sk_bytes)
            .map_err(|_| anyhow!("Failed to parse kyber secret"))?;

        Ok(Keypair {
            public,
            kyber_public,
            secure_secrets: SecureSecretKey::new(dilithium_secret, kyber_secret),
            created_at: export.created_at,
            rotation_due: export.rotation_due,
        })
    }
}

/// Verify a signature given only public key bytes, message and signature bytes (Dilithium5)
/// Returns true if verification succeeds, false otherwise.
pub fn verify_signature_bytes(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    use pqcrypto_dilithium::dilithium5::{verify_detached_signature, DetachedSignature, PublicKey};
    use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};

    // Basic format sanity checks to avoid panics / excessive allocations
    if public_key_bytes.is_empty() || signature_bytes.is_empty() { return false; }

    // Construct types from bytes; any failure means invalid input
    let pk = match PublicKey::from_bytes(public_key_bytes) { Ok(pk) => pk, Err(_) => return false };
    let sig = match DetachedSignature::from_bytes(signature_bytes) { Ok(sig) => sig, Err(_) => return false };

    verify_detached_signature(&sig, message, &pk).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_lifecycle() -> Result<()> {
        let keypair = Keypair::generate();
        let message = b"Hello, quantum-resistant world!";

        let signature = keypair.sign(message)?;
        assert!(keypair.verify(message, &signature)?);

        let wrong_message = b"Hello, quantum-vulnerable world!";
        assert!(!keypair.verify(wrong_message, &signature)?);

        Ok(())
    }

    #[test]
    fn test_key_encapsulation() -> Result<()> {
        let bob_keypair = Keypair::generate();

        // Alice encapsulates a secret for Bob
        let (secret1, package) = bob_keypair.encapsulate_key()?;

        // Bob decapsulates the secret
        let secret2 = bob_keypair.decapsulate_key(&package)?;

        // The secrets should match
        assert_eq!(secret1, secret2);
        
        Ok(())
    }

    #[test]
    fn test_different_keypairs() -> Result<()> {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let message = b"Test message";

        let signature = keypair1.sign(message)?;
        assert!(keypair1.verify(message, &signature)?);
        assert!(!keypair2.verify(message, &signature)?);

        Ok(())
    }

    #[test]
    fn test_key_rotation() -> Result<()> {
        let mut keypair = Keypair::generate();
        keypair.needs_immediate_rotation();
        
        let message = b"Test message";
        assert!(keypair.sign(message).is_err());
        
        Ok(())
    }
}
