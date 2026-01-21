//! Encrypted seed storage for identity master seeds.
//!
//! Uses system keyring when available, with an encrypted file fallback.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Write;
use zeroize::{Zeroize, Zeroizing};

use crate::config::SeedStorageConfig;
use crate::keystore_names::SEED_STORAGE_DIRNAME;
use lib_crypto::symmetric::chacha20::{decrypt_data, encrypt_data};
use lib_crypto::Hash;

const FILE_FORMAT_VERSION: u8 = 1;
const KDF_NAME: &str = "argon2id";
const PASS_ENV: &str = "ZHTP_SEED_PASSPHRASE";

#[derive(Debug, Clone, Copy)]
pub enum SeedKind {
    User,
    Node,
}

impl SeedKind {
    fn label(self) -> &'static str {
        match self {
            SeedKind::User => "user",
            SeedKind::Node => "node",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeedStorage {
    config: SeedStorageConfig,
}

impl SeedStorage {
    pub fn new(config: SeedStorageConfig) -> Self {
        Self { config }
    }

    pub fn store_seed(&self, identity_id: &Hash, kind: SeedKind, seed: &[u8]) -> Result<()> {
        if self.config.prefer_keyring {
            match self.store_seed_keyring(identity_id, kind, seed) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    tracing::warn!("Keyring store failed ({}); falling back to file", err);
                }
            }
        }

        let passphrase = self.resolve_passphrase(kind)?;
        self.store_seed_file(identity_id, kind, seed, &passphrase)
    }

    pub fn store_seed_with_passphrase(
        &self,
        identity_id: &Hash,
        kind: SeedKind,
        seed: &[u8],
        passphrase: &str,
    ) -> Result<()> {
        self.store_seed_file(identity_id, kind, seed, &Zeroizing::new(passphrase.to_string()))
    }

    pub fn load_seed(&self, identity_id: &Hash, kind: SeedKind) -> Result<Option<Vec<u8>>> {
        if self.config.prefer_keyring {
            match self.load_seed_keyring(identity_id, kind) {
                Ok(Some(seed)) => return Ok(Some(seed)),
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!("Keyring load failed ({}); falling back to file", err);
                }
            }
        }

        let passphrase = self.resolve_passphrase(kind)?;
        self.load_seed_file(identity_id, kind, &passphrase)
    }

    pub fn load_seed_with_passphrase(
        &self,
        identity_id: &Hash,
        kind: SeedKind,
        passphrase: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.load_seed_file(identity_id, kind, &Zeroizing::new(passphrase.to_string()))
    }

    pub fn export_seed_backup(
        &self,
        identity_id: &Hash,
        kind: SeedKind,
        passphrase: &str,
    ) -> Result<String> {
        let seed = self
            .load_seed_with_passphrase(identity_id, kind, passphrase)?
            .ok_or_else(|| anyhow!("Seed not found for backup"))?;
        let record = encrypt_seed(&seed, passphrase)?;
        let payload = serde_json::to_vec(&record)
            .map_err(|e| anyhow!("Failed to serialize seed backup: {}", e))?;
        Ok(general_purpose::STANDARD.encode(payload))
    }

    pub fn import_seed_backup(
        &self,
        identity_id: &Hash,
        kind: SeedKind,
        passphrase: &str,
        backup_payload: &str,
    ) -> Result<()> {
        let decoded = general_purpose::STANDARD
            .decode(backup_payload)
            .map_err(|e| anyhow!("Invalid seed backup encoding: {}", e))?;
        let record: EncryptedSeedRecord = serde_json::from_slice(&decoded)
            .map_err(|e| anyhow!("Invalid seed backup format: {}", e))?;
        let seed = decrypt_seed(&record, passphrase)?;
        self.store_seed_with_passphrase(identity_id, kind, &seed, passphrase)?;
        Ok(())
    }

    pub fn identity_id_from_json(identity_json: &str) -> Result<Hash> {
        let raw: serde_json::Value = serde_json::from_str(identity_json)
            .map_err(|e| anyhow!("Failed to parse identity JSON: {}", e))?;
        let id_value = raw
            .get("id")
            .cloned()
            .ok_or_else(|| anyhow!("Identity JSON missing id"))?;
        let id: Hash = serde_json::from_value(id_value)
            .map_err(|e| anyhow!("Invalid identity id: {}", e))?;
        Ok(id)
    }

    pub fn scrub_seed_from_key_file(path: &std::path::Path, key: &KeystoreSeedlessKey) -> Result<()> {
        let json = serde_json::to_string_pretty(key)
            .map_err(|e| anyhow!("Failed to serialize sanitized key: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| anyhow!("Failed to write sanitized key file: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow!("Failed to set key file permissions: {}", e))?;
        }
        Ok(())
    }

    fn resolve_passphrase(&self, kind: SeedKind) -> Result<Zeroizing<String>> {
        if let Ok(value) = std::env::var(PASS_ENV) {
            if !value.trim().is_empty() {
                return Ok(Zeroizing::new(value));
            }
        }

        if atty::is(atty::Stream::Stdin) {
            let prompt = format!("Enter passphrase for {} seed storage: ", kind.label());
            print!("{}", prompt);
            std::io::stdout().flush().map_err(|e| anyhow!("Failed to write prompt: {}", e))?;
            let passphrase = rpassword::read_password()
                .map_err(|e| anyhow!("Failed to read passphrase: {}", e))?;
            if passphrase.trim().is_empty() {
                return Err(anyhow!("Passphrase cannot be empty"));
            }
            return Ok(Zeroizing::new(passphrase));
        }

        Err(anyhow!(
            "Passphrase required for seed storage. Set {} or run interactively.",
            PASS_ENV
        ))
    }

    fn store_seed_keyring(&self, identity_id: &Hash, kind: SeedKind, seed: &[u8]) -> Result<()> {
        let entry = self.keyring_entry(identity_id, kind)?;
        let encoded = general_purpose::STANDARD.encode(seed);
        entry
            .set_password(&encoded)
            .map_err(|e| anyhow!("Keyring store failed: {}", e))?;
        Ok(())
    }

    fn load_seed_keyring(&self, identity_id: &Hash, kind: SeedKind) -> Result<Option<Vec<u8>>> {
        let entry = self.keyring_entry(identity_id, kind)?;
        match entry.get_password() {
            Ok(encoded) => {
                let decoded = general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|e| anyhow!("Keyring data decode failed: {}", e))?;
                Ok(Some(decoded))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(anyhow!("Keyring read failed: {}", err)),
        }
    }

    fn keyring_entry(&self, identity_id: &Hash, kind: SeedKind) -> Result<keyring::Entry> {
        let username = format!("{}:{}", kind.label(), hex::encode(identity_id.as_bytes()));
        keyring::Entry::new(&self.config.keyring_service, &username)
            .map_err(|e| anyhow!("Keyring entry creation failed: {}", e))
    }

    fn store_seed_file(
        &self,
        identity_id: &Hash,
        kind: SeedKind,
        seed: &[u8],
        passphrase: &Zeroizing<String>,
    ) -> Result<()> {
        let record = encrypt_seed(seed, passphrase)?;
        let payload = serde_json::to_vec(&record)
            .map_err(|e| anyhow!("Failed to serialize seed file: {}", e))?;
        let path = self.seed_file_path(identity_id, kind);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| anyhow!("Failed to create seed storage dir {:?}: {}", dir, e))?;
        }
        std::fs::write(&path, payload)
            .map_err(|e| anyhow!("Failed to write seed file {:?}: {}", path, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow!("Failed to set seed file permissions: {}", e))?;
        }
        Ok(())
    }

    fn load_seed_file(
        &self,
        identity_id: &Hash,
        kind: SeedKind,
        passphrase: &Zeroizing<String>,
    ) -> Result<Option<Vec<u8>>> {
        let path = self.seed_file_path(identity_id, kind);
        if !path.exists() {
            return Ok(None);
        }
        let payload = std::fs::read(&path)
            .map_err(|e| anyhow!("Failed to read seed file {:?}: {}", path, e))?;
        let record: EncryptedSeedRecord = serde_json::from_slice(&payload)
            .map_err(|e| anyhow!("Failed to parse seed file {:?}: {}", path, e))?;
        let seed = decrypt_seed(&record, passphrase)?;
        Ok(Some(seed))
    }

    fn seed_file_path(&self, identity_id: &Hash, kind: SeedKind) -> std::path::PathBuf {
        let name = format!("{}_{}.json", kind.label(), hex::encode(identity_id.as_bytes()));
        let base = if self.config.storage_dir.ends_with(SEED_STORAGE_DIRNAME) {
            self.config.storage_dir.clone()
        } else {
            self.config.storage_dir.join(SEED_STORAGE_DIRNAME)
        };
        base.join(name)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeystoreSeedlessKey {
    pub dilithium_sk: Vec<u8>,
    pub kyber_sk: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedSeedRecord {
    version: u8,
    kdf: String,
    salt_b64: String,
    ciphertext_b64: String,
}

fn encrypt_seed(seed: &[u8], passphrase: &str) -> Result<EncryptedSeedRecord> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut key = derive_key(passphrase, &salt)?;
    let ciphertext = encrypt_data(seed, &key)?;
    key.zeroize();

    Ok(EncryptedSeedRecord {
        version: FILE_FORMAT_VERSION,
        kdf: KDF_NAME.to_string(),
        salt_b64: general_purpose::STANDARD.encode(salt),
        ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
    })
}

fn decrypt_seed(record: &EncryptedSeedRecord, passphrase: &str) -> Result<Vec<u8>> {
    if record.version != FILE_FORMAT_VERSION {
        return Err(anyhow!("Unsupported seed file version: {}", record.version));
    }
    if record.kdf != KDF_NAME {
        return Err(anyhow!("Unsupported seed KDF: {}", record.kdf));
    }
    let salt = general_purpose::STANDARD
        .decode(&record.salt_b64)
        .map_err(|e| anyhow!("Invalid seed salt encoding: {}", e))?;
    let ciphertext = general_purpose::STANDARD
        .decode(&record.ciphertext_b64)
        .map_err(|e| anyhow!("Invalid seed ciphertext encoding: {}", e))?;
    let mut key = derive_key(passphrase, &salt)?;
    let plaintext = decrypt_data(&ciphertext, &key)?;
    key.zeroize();
    Ok(plaintext)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon2 = argon2::Argon2::default();
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_file_round_trip() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let config = SeedStorageConfig {
            storage_dir: temp.path().to_path_buf(),
            keyring_service: "zhtp-seed-test".to_string(),
            prefer_keyring: false,
        };
        let storage = SeedStorage::new(config);
        let identity_id = Hash::from_bytes(&lib_crypto::hash_blake3(b"seed-test").to_vec());
        let seed = vec![42u8; 64];

        storage.store_seed_with_passphrase(&identity_id, SeedKind::User, &seed, "test-passphrase")?;
        let loaded = storage
            .load_seed_with_passphrase(&identity_id, SeedKind::User, "test-passphrase")?
            .ok_or_else(|| anyhow!("Seed missing"))?;

        assert_eq!(loaded, seed);
        Ok(())
    }

    #[test]
    fn seed_backup_round_trip() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let config = SeedStorageConfig {
            storage_dir: temp.path().to_path_buf(),
            keyring_service: "zhtp-seed-test".to_string(),
            prefer_keyring: false,
        };
        let storage = SeedStorage::new(config);
        let identity_id = Hash::from_bytes(&lib_crypto::hash_blake3(b"seed-backup").to_vec());
        let seed = vec![7u8; 64];
        let passphrase = "backup-passphrase";

        storage.store_seed_with_passphrase(&identity_id, SeedKind::Node, &seed, passphrase)?;
        let backup = storage.export_seed_backup(&identity_id, SeedKind::Node, passphrase)?;

        let temp2 = tempfile::tempdir()?;
        let config2 = SeedStorageConfig {
            storage_dir: temp2.path().to_path_buf(),
            keyring_service: "zhtp-seed-test".to_string(),
            prefer_keyring: false,
        };
        let storage2 = SeedStorage::new(config2);
        storage2.import_seed_backup(&identity_id, SeedKind::Node, passphrase, &backup)?;
        let loaded = storage2
            .load_seed_with_passphrase(&identity_id, SeedKind::Node, passphrase)?
            .ok_or_else(|| anyhow!("Seed missing after restore"))?;

        assert_eq!(loaded, seed);
        Ok(())
    }
}
