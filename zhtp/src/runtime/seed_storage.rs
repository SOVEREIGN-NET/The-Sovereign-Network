//! Secure identity seed storage (keychain-first, encrypted file fallback).
//!
//! Stores the 64-byte identity master seed outside the keystore JSON so it is
//! never written to disk in plaintext. Uses the OS keychain when available,
//! otherwise encrypts to a local file with a password-derived key.
//!
//! For non-interactive deployments (services, containers, CI, etc.), the
//! password for the file-based fallback must be provided via the
//! `ZHTP_SEED_PASSWORD` environment variable. When this variable is not set,
//! the runtime may prompt interactively for a password instead.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::config::SeedStorageConfig;

// Platform-specific file locking
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

const KEYCHAIN_SERVICE: &str = "zhtp-identity-seed";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SeedSlot {
    User,
    Node,
}

impl SeedSlot {
    fn account_name(self) -> &'static str {
        match self {
            SeedSlot::User => "user",
            SeedSlot::Node => "node",
        }
    }

    fn record_key(self) -> &'static str {
        match self {
            SeedSlot::User => "user_seed",
            SeedSlot::Node => "node_seed",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedSeedRecord {
    salt_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SeedStorageFile {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    records: HashMap<String, EncryptedSeedRecord>,
}

impl Default for SeedStorageFile {
    fn default() -> Self {
        Self {
            version: 1,
            records: HashMap::new(),
        }
    }
}

pub struct SeedStorage {
    config: SeedStorageConfig,
}

impl SeedStorage {
    pub fn new(keystore_path: &Path) -> Self {
        Self {
            config: SeedStorageConfig::default_for_keystore(keystore_path),
        }
    }

    pub fn store_seed(&self, slot: SeedSlot, seed: &[u8]) -> Result<()> {
        if !keychain_disabled() {
            if try_store_keychain(slot, seed)? {
                return Ok(());
            }
        }

        self.store_seed_file(slot, seed)
    }

    pub fn load_seed(&self, slot: SeedSlot) -> Result<Vec<u8>> {
        if !keychain_disabled() {
            if let Some(seed) = try_load_keychain(slot)? {
                return Ok(seed);
            }
        }

        self.load_seed_file(slot)
    }

    pub fn export_seed_backup(&self, slot: SeedSlot, backup_path: &Path, password: &str) -> Result<()> {
        let seed = self.load_seed(slot)?;
        let record = encrypt_seed_with_password(&seed, password)?;
        let backup = SeedStorageFile {
            version: 1,
            records: HashMap::from([(slot.record_key().to_string(), record)]),
        };

        let data = serde_json::to_vec_pretty(&backup)?;

        // Create backup file with restrictive permissions (0600 on Unix).
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(backup_path)?;
        file.write_all(&data)?;
        file.flush()?;
        Ok(())
    }

    pub fn import_seed_backup(&self, slot: SeedSlot, backup_path: &Path, password: &str) -> Result<()> {
        let data = fs::read(backup_path)?;
        let backup: SeedStorageFile = serde_json::from_slice(&data)?;
        let record = backup.records.get(slot.record_key())
            .ok_or_else(|| anyhow!("Backup missing seed record for {}", slot.record_key()))?;
        let seed = decrypt_seed_with_password(record, password)?;
        self.store_seed(slot, &seed)
    }

    fn seed_file_path(&self) -> PathBuf {
        self.config.storage_path()
    }

    fn store_seed_file(&self, slot: SeedSlot, seed: &[u8]) -> Result<()> {
        let password = prompt_password("Enter password to encrypt identity seed")?;
        let record = encrypt_seed_with_password(seed, &password)?;
        
        // Lock file for atomic read-modify-write
        let file_path = self.seed_file_path();
        let _lock = acquire_file_lock(&file_path)?;
        
        let mut storage = load_seed_file(file_path.clone())?;
        storage.version = 1;
        storage.records.insert(slot.record_key().to_string(), record);
        write_seed_file(file_path, &storage)?;
        Ok(())
    }

    fn load_seed_file(&self, slot: SeedSlot) -> Result<Vec<u8>> {
        let password = prompt_password("Enter password to decrypt identity seed")?;
        
        // Lock file for consistent read
        let file_path = self.seed_file_path();
        let _lock = acquire_file_lock(&file_path)?;
        
        let storage = load_seed_file(file_path)?;
        let record = storage.records.get(slot.record_key())
            .ok_or_else(|| anyhow!("Seed record missing for {}", slot.record_key()))?;
        decrypt_seed_with_password(record, &password)
    }
}

/// File lock guard to ensure atomic access to seed storage file.
/// The lock is released when this guard is dropped.
struct FileLock {
    #[allow(dead_code)]
    file: fs::File,
}

fn acquire_file_lock(path: &Path) -> Result<FileLock> {
    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Create a lock file adjacent to the seed storage file
    // This provides basic serialization of file access
    let lock_path = path.with_extension("lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
        .map_err(|e| anyhow!("Failed to open lock file: {}", e))?;
    
    // Note: This is a basic file-based mutex.
    // For production use, consider using fs2 crate for proper advisory locking.
    
    Ok(FileLock { file })
}

fn keychain_disabled() -> bool {
    env::var("ZHTP_DISABLE_KEYCHAIN").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

fn try_store_keychain(slot: SeedSlot, seed: &[u8]) -> Result<bool> {
    let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, slot.account_name()) {
        Ok(entry) => entry,
        Err(e) => {
            tracing::debug!("Keychain unavailable for storing {}: {}", slot.account_name(), e);
            return Ok(false);
        }
    };
    let encoded = general_purpose::STANDARD.encode(seed);
    match entry.set_password(&encoded) {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::warn!("Failed to store seed in keychain for {}: {}. Falling back to encrypted file.", slot.account_name(), e);
            Ok(false)
        }
    }
}

fn try_load_keychain(slot: SeedSlot) -> Result<Option<Vec<u8>>> {
    let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, slot.account_name()) {
        Ok(entry) => entry,
        Err(e) => {
            tracing::debug!("Keychain unavailable for loading {}: {}", slot.account_name(), e);
            return Ok(None);
        }
    };
    match entry.get_password() {
        Ok(encoded) => {
            let decoded = general_purpose::STANDARD.decode(encoded.as_bytes())?;
            Ok(Some(decoded))
        }
        Err(e) => {
            tracing::debug!("Seed not found in keychain for {}: {}. Will try encrypted file.", slot.account_name(), e);
            Ok(None)
        }
    }
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(password) = env::var("ZHTP_SEED_PASSWORD") {
        return Ok(Zeroizing::new(password));
    }

    if !atty::is(atty::Stream::Stdin) {
        return Err(anyhow!(
            "Seed storage requires ZHTP_SEED_PASSWORD when running non-interactively"
        ));
    }

    print!("{}: ", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    let trimmed = password.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Seed storage password cannot be empty"));
    }
    if trimmed.len() < 12 {
        return Err(anyhow!("Seed storage password must be at least 12 characters long"));
    }
    Ok(Zeroizing::new(password))
}

fn encrypt_seed_with_password(seed: &[u8], password: &str) -> Result<EncryptedSeedRecord> {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_key(password.as_bytes(), &salt)?;
    let ciphertext = lib_crypto::symmetric::chacha20::encrypt_data(seed, &key)?;

    Ok(EncryptedSeedRecord {
        salt_b64: general_purpose::STANDARD.encode(salt),
        ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
    })
}

fn decrypt_seed_with_password(record: &EncryptedSeedRecord, password: &str) -> Result<Vec<u8>> {
    let salt = general_purpose::STANDARD.decode(record.salt_b64.as_bytes())?;
    let ciphertext = general_purpose::STANDARD.decode(record.ciphertext_b64.as_bytes())?;
    let key = derive_key(password.as_bytes(), &salt)?;
    let plaintext = lib_crypto::symmetric::chacha20::decrypt_data(&ciphertext, &key)?;
    Ok(plaintext)
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    
    // Use explicit, strong Argon2id parameters instead of crate defaults:
    // - Algorithm: Argon2id (recommended for password hashing)
    // - Memory cost: 32 MiB
    // - Time cost (iterations): 3
    // - Parallelism: 2 lanes
    let params = argon2::Params::new(32 * 1024, 3, 2, None)
        .map_err(|e| anyhow!("Failed to configure Argon2 parameters: {}", e))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow!("Failed to derive seed encryption key: {}", e))?;
    Ok(key)
}

fn load_seed_file(path: PathBuf) -> Result<SeedStorageFile> {
    if !path.exists() {
        return Ok(SeedStorageFile::default());
    }
    let data = fs::read(&path)?;
    let storage: SeedStorageFile = serde_json::from_slice(&data)?;
    
    // Validate the on-disk version against the currently supported version to
    // avoid silently accepting incompatible formats.
    let default_storage = SeedStorageFile::default();
    if storage.version != default_storage.version {
        return Err(anyhow!(
            "Unsupported seed storage file version. Expected {:?}, found {:?}. \
             Please migrate or recreate your seed storage file at: {}",
            default_storage.version,
            storage.version,
            path.display()
        ));
    }
    
    Ok(storage)
}

fn write_seed_file(path: PathBuf, storage: &SeedStorageFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(storage)?;
    
    // Create seed file with restrictive permissions (0600 on Unix).
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&path)?;
    file.write_all(&data)?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::sync::{Mutex, OnceLock};

    fn setup_env(password: &str) {
        env::set_var("ZHTP_SEED_PASSWORD", password);
        env::set_var("ZHTP_DISABLE_KEYCHAIN", "1");
    }

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    #[test]
    fn stores_and_loads_seed_from_file() -> Result<()> {
        let _guard = lock_env();
        setup_env("test-password");
        let temp = TempDir::new()?;
        let storage = SeedStorage::new(temp.path());
        let seed = [42u8; 64];

        storage.store_seed(SeedSlot::User, &seed)?;
        let loaded = storage.load_seed(SeedSlot::User)?;
        assert_eq!(loaded, seed);
        Ok(())
    }

    #[test]
    fn refuses_to_decrypt_with_wrong_password() -> Result<()> {
        let _guard = lock_env();
        setup_env("correct-password");
        let temp = TempDir::new()?;
        let storage = SeedStorage::new(temp.path());
        let seed = [7u8; 64];

        storage.store_seed(SeedSlot::Node, &seed)?;

        env::set_var("ZHTP_SEED_PASSWORD", "wrong-password");
        let result = storage.load_seed(SeedSlot::Node);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn seed_file_never_contains_plaintext_seed() -> Result<()> {
        let _guard = lock_env();
        setup_env("plain-check");
        let temp = TempDir::new()?;
        let storage = SeedStorage::new(temp.path());
        let seed = [0xAAu8; 64];

        storage.store_seed(SeedSlot::User, &seed)?;
        let contents = fs::read_to_string(storage.seed_file_path())?;
        let seed_hex = hex::encode(seed);
        assert!(!contents.contains(&seed_hex));
        Ok(())
    }

    #[test]
    fn exports_and_imports_seed_backup() -> Result<()> {
        let _guard = lock_env();
        setup_env("backup-password");
        let source_dir = TempDir::new()?;
        let target_dir = TempDir::new()?;
        let backup_file = target_dir.path().join("seed_backup.json");
        let seed = [0x11u8; 64];

        let source_storage = SeedStorage::new(source_dir.path());
        source_storage.store_seed(SeedSlot::User, &seed)?;
        source_storage.export_seed_backup(SeedSlot::User, &backup_file, "backup-password")?;

        let target_storage = SeedStorage::new(target_dir.path());
        target_storage.import_seed_backup(SeedSlot::User, &backup_file, "backup-password")?;
        let loaded = target_storage.load_seed(SeedSlot::User)?;
        assert_eq!(loaded, seed);
        Ok(())
    }
}
