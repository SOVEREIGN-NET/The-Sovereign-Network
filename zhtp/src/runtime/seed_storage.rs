//! Secure identity seed storage (keychain-first, encrypted file fallback).
//!
//! Stores the 64-byte identity master seed outside the keystore JSON so it is
//! never written to disk in plaintext. Uses the OS keychain when available,
//! otherwise encrypts to a local file with a password-derived key.

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

#[derive(Debug, Default, Serialize, Deserialize)]
struct SeedStorageFile {
    version: u8,
    records: HashMap<String, EncryptedSeedRecord>,
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
        fs::write(backup_path, data)?;
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
        let mut storage = load_seed_file(self.seed_file_path())?;
        storage.version = 1;
        storage.records.insert(slot.record_key().to_string(), record);
        write_seed_file(self.seed_file_path(), &storage)?;
        Ok(())
    }

    fn load_seed_file(&self, slot: SeedSlot) -> Result<Vec<u8>> {
        let password = prompt_password("Enter password to decrypt identity seed")?;
        let storage = load_seed_file(self.seed_file_path())?;
        let record = storage.records.get(slot.record_key())
            .ok_or_else(|| anyhow!("Seed record missing for {}", slot.record_key()))?;
        decrypt_seed_with_password(record, &password)
    }
}

fn keychain_disabled() -> bool {
    env::var("ZHTP_DISABLE_KEYCHAIN").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

fn try_store_keychain(slot: SeedSlot, seed: &[u8]) -> Result<bool> {
    let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, slot.account_name()) {
        Ok(entry) => entry,
        Err(_) => return Ok(false),
    };
    let encoded = general_purpose::STANDARD.encode(seed);
    match entry.set_password(&encoded) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn try_load_keychain(slot: SeedSlot) -> Result<Option<Vec<u8>>> {
    let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, slot.account_name()) {
        Ok(entry) => entry,
        Err(_) => return Ok(None),
    };
    match entry.get_password() {
        Ok(encoded) => {
            let decoded = general_purpose::STANDARD.decode(encoded.as_bytes())?;
            Ok(Some(decoded))
        }
        Err(_) => Ok(None),
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
    if password.trim().is_empty() {
        return Err(anyhow!("Seed storage password cannot be empty"));
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
    let argon2 = argon2::Argon2::default();
    argon2.hash_password_into(password, salt, &mut key)?;
    Ok(key)
}

fn load_seed_file(path: PathBuf) -> Result<SeedStorageFile> {
    if !path.exists() {
        return Ok(SeedStorageFile::default());
    }
    let data = fs::read(&path)?;
    let storage = serde_json::from_slice(&data)?;
    Ok(storage)
}

fn write_seed_file(path: PathBuf, storage: &SeedStorageFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(storage)?;
    fs::write(path, data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_env(password: &str) {
        env::set_var("ZHTP_SEED_PASSWORD", password);
        env::set_var("ZHTP_DISABLE_KEYCHAIN", "1");
    }

    #[test]
    fn stores_and_loads_seed_from_file() -> Result<()> {
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
