use anyhow::{Context, Result};
use lib_crypto::types::PrivateKey;
use lib_identity::{IdentityType, ZhtpIdentity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KEYSTORE_DIR: &str = "keystore";
const IDENTITY_FILE: &str = "daemon_identity.json";
const PRIVATE_KEY_FILE: &str = "daemon_private_key.json";
const DEFAULT_DEVICE_NAME: &str = "zhtp-browser-daemon";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPrivateKey {
    dilithium_sk_hex: String,
    dilithium_pk_hex: String,
    kyber_sk_hex: String,
    master_seed_hex: String,
}

impl From<&PrivateKey> for StoredPrivateKey {
    fn from(value: &PrivateKey) -> Self {
        Self {
            dilithium_sk_hex: hex::encode(value.dilithium_sk),
            dilithium_pk_hex: hex::encode(value.dilithium_pk),
            kyber_sk_hex: hex::encode(value.kyber_sk),
            master_seed_hex: hex::encode(value.master_seed),
        }
    }
}

impl TryFrom<StoredPrivateKey> for PrivateKey {
    type Error = anyhow::Error;

    fn try_from(value: StoredPrivateKey) -> Result<Self> {
        Ok(Self {
            dilithium_sk: decode_fixed_hex("dilithium_sk_hex", &value.dilithium_sk_hex)?,
            dilithium_pk: decode_fixed_hex("dilithium_pk_hex", &value.dilithium_pk_hex)?,
            kyber_sk: decode_fixed_hex("kyber_sk_hex", &value.kyber_sk_hex)?,
            master_seed: decode_fixed_hex("master_seed_hex", &value.master_seed_hex)?,
        })
    }
}

pub fn keystore_dir(root_dir: &Path) -> PathBuf {
    root_dir.join(KEYSTORE_DIR)
}

pub fn load_or_create(root_dir: &Path) -> Result<ZhtpIdentity> {
    let keystore_dir = keystore_dir(root_dir);
    let identity_path = keystore_dir.join(IDENTITY_FILE);
    let private_key_path = keystore_dir.join(PRIVATE_KEY_FILE);

    if identity_path.exists() && private_key_path.exists() {
        return load_from_files(&identity_path, &private_key_path);
    }

    std::fs::create_dir_all(&keystore_dir)
        .with_context(|| format!("Failed to create {}", keystore_dir.display()))?;

    let identity =
        ZhtpIdentity::new_unified(IdentityType::Device, None, None, DEFAULT_DEVICE_NAME, None)
            .context("Failed to generate daemon identity")?;
    save_identity(&identity, &identity_path, &private_key_path)?;
    Ok(identity)
}

fn load_from_files(identity_path: &Path, private_key_path: &Path) -> Result<ZhtpIdentity> {
    let identity_json = std::fs::read_to_string(identity_path)
        .with_context(|| format!("Failed to read {}", identity_path.display()))?;
    let key_json = std::fs::read_to_string(private_key_path)
        .with_context(|| format!("Failed to read {}", private_key_path.display()))?;
    let stored_key: StoredPrivateKey = serde_json::from_str(&key_json)
        .with_context(|| format!("Failed to parse {}", private_key_path.display()))?;
    let private_key = PrivateKey::try_from(stored_key)
        .context("Failed to decode daemon private key")?;

    ZhtpIdentity::from_serialized(&identity_json, &private_key)
        .context("Failed to restore daemon identity from keystore")
}

fn save_identity(identity: &ZhtpIdentity, identity_path: &Path, private_key_path: &Path) -> Result<()> {
    let private_key = identity
        .private_key
        .as_ref()
        .context("Generated identity missing private key")?;
    let identity_json =
        serde_json::to_string_pretty(identity).context("Failed to serialize identity")?;
    let key_json = serde_json::to_string_pretty(&StoredPrivateKey::from(private_key))
        .context("Failed to serialize daemon private key")?;

    write_secure_file(identity_path, identity_json.as_bytes())?;
    write_secure_file(private_key_path, key_json.as_bytes())?;
    Ok(())
}

fn write_secure_file(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("Failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set permissions on {}", path.display()))?;
    }

    Ok(())
}

fn decode_fixed_hex<const N: usize>(field: &str, encoded: &str) -> Result<[u8; N]> {
    let decoded = hex::decode(encoded).with_context(|| format!("Invalid hex in {}", field))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} has invalid length: expected {} bytes", field, N))
}
