//! Encrypted Seed Storage Module
//!
//! Provides secure storage and retrieval of cryptographic seeds using:
//! - ChaCha20-Poly1305 for authenticated encryption
//! - Argon2id for key derivation from passphrases
//! - Base64 encoding for JSON persistence
//!
//! This module ensures that node seeds can be stored on disk with strong password-based
//! encryption, enabling secure multi-device node identity recovery.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use lib_crypto::symmetric::chacha20::{decrypt_data, encrypt_data};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_writer_pretty};
use std::fs::{read_to_string, File};
use std::path::Path;
use tracing::{debug, info};

/// File format version for encrypted seed records.
/// Increment this when making incompatible changes to the storage format.
pub const FILE_FORMAT_VERSION: u8 = 1;

/// Key derivation function name for seed encryption.
pub const KDF_NAME: &str = "argon2id";

/// Size of the random salt for key derivation in bytes.
const SALT_SIZE: usize = 16;

/// Size of the derived key in bytes.
const KEY_SIZE: usize = 32;

/// Encrypted seed storage record with metadata.
///
/// This structure is JSON-serialized to disk and contains:
/// - `version`: File format version for compatibility checking
/// - `kdf`: Name of the key derivation function used
/// - `salt_b64`: Base64-encoded random salt (16 bytes)
/// - `ciphertext_b64`: Base64-encoded encrypted seed data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSeedRecord {
    /// File format version (currently 1)
    pub version: u8,
    /// KDF algorithm name (e.g., "argon2id")
    pub kdf: String,
    /// Base64-encoded salt used in key derivation
    pub salt_b64: String,
    /// Base64-encoded ciphertext from ChaCha20-Poly1305
    pub ciphertext_b64: String,
}

/// Encrypts a seed value using a passphrase.
///
/// # Arguments
///
/// * `seed` - The raw seed bytes to encrypt
/// * `passphrase` - The passphrase used for key derivation
///
/// # Returns
///
/// An `EncryptedSeedRecord` containing the encrypted seed and metadata,
/// ready for JSON serialization.
///
/// # Process
///
/// 1. Generates a random 16-byte salt
/// 2. Derives a 32-byte key using Argon2id
/// 3. Encrypts the seed using ChaCha20-Poly1305
/// 4. Base64-encodes salt and ciphertext for storage
///
/// # Example
///
/// ```ignore
/// let seed = [42u8; 64];
/// let record = encrypt_seed(&seed, "my-passphrase")?;
/// ```
pub fn encrypt_seed(seed: &[u8], passphrase: &str) -> Result<EncryptedSeedRecord> {
    debug!("Starting seed encryption with Argon2id + ChaCha20");

    // Generate random salt
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    debug!("Generated random salt: {} bytes", SALT_SIZE);

    // Derive encryption key from passphrase
    let key = derive_key(passphrase, &salt)
        .map_err(|e| anyhow!("Failed to derive encryption key: {}", e))?;
    debug!("Derived encryption key from passphrase");

    // Encrypt the seed data
    let ciphertext = encrypt_data(seed, &key)
        .map_err(|e| anyhow!("ChaCha20-Poly1305 encryption failed: {}", e))?;
    debug!("Encrypted seed: {} bytes -> {} bytes", seed.len(), ciphertext.len());

    // Encode to Base64 for storage
    let salt_b64 = general_purpose::STANDARD.encode(&salt);
    let ciphertext_b64 = general_purpose::STANDARD.encode(&ciphertext);

    info!(
        "Seed encrypted successfully: ciphertext_len={}, salt_len={}",
        ciphertext_b64.len(),
        salt_b64.len()
    );

    Ok(EncryptedSeedRecord {
        version: FILE_FORMAT_VERSION,
        kdf: KDF_NAME.to_string(),
        salt_b64,
        ciphertext_b64,
    })
}

/// Decrypts a seed from an encrypted record using a passphrase.
///
/// # Arguments
///
/// * `record` - The encrypted seed record (typically loaded from JSON)
/// * `passphrase` - The passphrase used during encryption
///
/// # Returns
///
/// The decrypted seed bytes, or an error if decryption fails.
///
/// # Validation
///
/// - Checks that the record version matches FILE_FORMAT_VERSION
/// - Checks that the KDF matches KDF_NAME
/// - Validates Base64 encoding of salt and ciphertext
///
/// # Example
///
/// ```ignore
/// let record = load_encrypted_record("seed.json")?;
/// let seed = decrypt_seed(&record, "my-passphrase")?;
/// ```
pub fn decrypt_seed(record: &EncryptedSeedRecord, passphrase: &str) -> Result<Vec<u8>> {
    debug!("Starting seed decryption");

    // Validate version
    if record.version != FILE_FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported encrypted seed record version: {} (expected {})",
            record.version,
            FILE_FORMAT_VERSION
        ));
    }
    debug!("Seed record version validated: {}", record.version);

    // Validate KDF
    if record.kdf != KDF_NAME {
        return Err(anyhow!(
            "Unsupported seed KDF: {} (expected {})",
            record.kdf,
            KDF_NAME
        ));
    }
    debug!("Seed record KDF validated: {}", record.kdf);

    // Decode Base64 salt
    let salt = general_purpose::STANDARD
        .decode(&record.salt_b64)
        .map_err(|e| anyhow!("Failed to decode salt from Base64: {}", e))?;
    if salt.len() != SALT_SIZE {
        return Err(anyhow!(
            "Invalid salt size: {} (expected {})",
            salt.len(),
            SALT_SIZE
        ));
    }
    debug!("Salt decoded: {} bytes", salt.len());

    // Decode Base64 ciphertext
    let ciphertext = general_purpose::STANDARD
        .decode(&record.ciphertext_b64)
        .map_err(|e| anyhow!("Failed to decode ciphertext from Base64: {}", e))?;
    debug!("Ciphertext decoded: {} bytes", ciphertext.len());

    // Derive decryption key
    let key = derive_key(passphrase, &salt)
        .map_err(|e| anyhow!("Failed to derive decryption key: {}", e))?;
    debug!("Derived decryption key from passphrase");

    // Decrypt the seed
    let seed = decrypt_data(&ciphertext, &key)
        .map_err(|e| anyhow!("ChaCha20-Poly1305 decryption failed: {}", e))?;
    debug!("Decrypted seed: {} bytes", seed.len());

    info!("Seed decrypted successfully: {} bytes", seed.len());
    Ok(seed)
}

/// Persists a seed to disk in encrypted form.
///
/// # Arguments
///
/// * `path` - File path for storage (parent directories will be created)
/// * `seed` - The seed bytes to encrypt and store
/// * `passphrase` - The passphrase for encryption
///
/// # Returns
///
/// Ok(()) on success, or an error if encryption/IO fails.
///
/// # Behavior
///
/// - Creates parent directories if they don't exist
/// - Encrypts the seed using `encrypt_seed()`
/// - Writes JSON to the specified path
///
/// # Example
///
/// ```ignore
/// let seed = [42u8; 64];
/// store_seed(Path::new("./seed_store/node.json"), &seed, "passphrase")?;
/// ```
pub fn store_seed(path: &Path, seed: &[u8], passphrase: &str) -> Result<()> {
    debug!("Starting seed storage to: {:?}", path);

    // Encrypt the seed
    let record = encrypt_seed(seed, passphrase)?;
    debug!("Seed encrypted for storage");

    // Create parent directories if necessary
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow!(
                "Failed to create seed storage directory {:?}: {}",
                parent,
                e
            )
        })?;
        debug!("Created parent directories: {:?}", parent);
    }

    // Write JSON to file
    let file = File::create(path).map_err(|e| {
        anyhow!("Failed to create seed storage file {:?}: {}", path, e)
    })?;
    to_writer_pretty(file, &record).map_err(|e| {
        anyhow!("Failed to serialize encrypted seed to JSON: {}", e)
    })?;

    info!("Seed stored successfully to: {:?}", path);
    Ok(())
}

/// Loads and decrypts a seed from disk.
///
/// # Arguments
///
/// * `path` - File path to the encrypted seed record
/// * `passphrase` - The passphrase for decryption
///
/// # Returns
///
/// The decrypted seed bytes, or an error if loading/decryption fails.
///
/// # Behavior
///
/// - Reads JSON from the specified path
/// - Deserializes to `EncryptedSeedRecord`
/// - Decrypts using `decrypt_seed()`
///
/// # Example
///
/// ```ignore
/// let seed = load_seed(Path::new("./seed_store/node.json"), "passphrase")?;
/// ```
pub fn load_seed(path: &Path, passphrase: &str) -> Result<Vec<u8>> {
    debug!("Loading encrypted seed from: {:?}", path);

    // Read JSON from file
    let contents = read_to_string(path)
        .map_err(|e| anyhow!("Failed to read seed storage file {:?}: {}", path, e))?;
    debug!("Read {} bytes from seed file", contents.len());

    // Deserialize JSON
    let record: EncryptedSeedRecord = from_str(&contents).map_err(|e| {
        anyhow!("Failed to deserialize encrypted seed from JSON: {}", e)
    })?;
    debug!("Deserialized encrypted seed record");

    // Decrypt and return
    let seed = decrypt_seed(&record, passphrase)?;
    info!("Seed loaded and decrypted from: {:?}", path);
    Ok(seed)
}

/// Derives a key from a passphrase using Argon2id.
///
/// # Arguments
///
/// * `passphrase` - The passphrase to derive from
/// * `salt` - The salt bytes (typically 16 bytes)
///
/// # Returns
///
/// A 32-byte key suitable for ChaCha20 encryption.
///
/// # Argon2id Parameters
///
/// Uses Argon2 library defaults, which provide strong security
/// against both GPU and side-channel attacks while remaining practical
/// for interactive use.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
    debug!(
        "Deriving Argon2id key from passphrase with salt: {} bytes",
        salt.len()
    );

    let mut key = [0u8; KEY_SIZE];
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

    debug!("Successfully derived {} byte key", KEY_SIZE);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() -> Result<()> {
        let seed = [42u8; 64];
        let passphrase = "test-passphrase";

        let record = encrypt_seed(&seed, passphrase)?;
        assert_eq!(record.version, FILE_FORMAT_VERSION);
        assert_eq!(record.kdf, KDF_NAME);

        let decrypted = decrypt_seed(&record, passphrase)?;
        assert_eq!(decrypted, seed.to_vec());

        Ok(())
    }

    #[test]
    fn test_wrong_passphrase_fails() -> Result<()> {
        let seed = [42u8; 64];
        let record = encrypt_seed(&seed, "correct-passphrase")?;

        let result = decrypt_seed(&record, "wrong-passphrase");
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_corrupted_ciphertext_fails() -> Result<()> {
        let seed = [42u8; 64];
        let mut record = encrypt_seed(&seed, "passphrase")?;

        // Corrupt the ciphertext
        record.ciphertext_b64 = general_purpose::STANDARD.encode(b"corrupted");

        let result = decrypt_seed(&record, "passphrase");
        assert!(result.is_err());

        Ok(())
    }
}
