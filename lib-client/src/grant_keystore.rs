//! # Why this exists
//!
//! Without these custody rules, a grant secret can end up re-co-stored next to the DID root key and unlocked by the same passphrase/biometric gate,
//! collapsing what is supposed to be dual-auth (DID session *and* independent grant proof) into a single factor with extra JSON around it.
//!
//! Made with <3 by AvadaKedavra6

use crate::crypto::Dilithium5;
use crate::error::{ClientError, Result};
use lib_access_control::grant_auth::grant_exercise_message;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const RESERVED_DID_KEYSTORE_FILENAMES: &[&str] =
    &["user_private_key.json", "node_private_key.json"];
pub const GRANT_KEYSTORE_DIRNAME: &str = "grant_store";

pub fn forbid_default_keystore_path(path: &Path) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| ClientError::InvalidFormat("grant key path has no filename".into()))?;

    if RESERVED_DID_KEYSTORE_FILENAMES
        .iter()
        .any(|reserved| *reserved == file_name)
    {
        return Err(ClientError::IdentityError(format!(
            "refusing to use '{file_name}' for grant key material: that filename is reserved for \
            the DID keystore and must never hold a grant secret key (ADR §4)"
        )));
    }
    Ok(())
}

/// A standalone Dilithium5 keypair for dual-auth grant material.
///
/// This is **not** a DID/wallet key. It must be generated independently of [`crate::identity::Identity`] and stored outside the DID keystore.
#[derive(Clone)]
pub struct GrantKeyMaterial {
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl std::fmt::Debug for GrantKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantKeyMaterial")
            .field("public_key", &hex::encode(&self.public_key))
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl Drop for GrantKeyMaterial {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.secret_key);
    }
}

impl GrantKeyMaterial {
    pub fn generate() -> Result<Self> {
        let (public_key, secret_key) = Dilithium5::generate_keypair()
            .map_err(|e| ClientError::CryptoError(format!("grant keygen failed: {e}")))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    pub fn from_raw(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn sign_exercise_proof(
        &self,
        grant_id: &str,
        grantee_did: &str,
        session_binding: &str,
        signed_at_unix: u64,
    ) -> Result<Vec<u8>> {
        let message =
            grant_exercise_message(grant_id, grantee_did, session_binding, signed_at_unix);
        Dilithium5::sign(&message, &self.secret_key)
            .map_err(|e| ClientError::CryptoError(format!("grant proof signing failed: {e}")))
    }
}

#[derive(Serialize, Deserialize)]
struct GrantKeystoreFile {
    format: String,
    grant_public_key_hex: String,
    grant_secret_key_hex: String,
}

const GRANT_KEYSTORE_FORMAT_TAG: &str = "zhtp-grant-keystore-v1";

pub fn import_ephemeral(path: &Path) -> Result<GrantKeyMaterial> {
    forbid_default_keystore_path(path)?;
    let raw = std::fs::read_to_string(path)?;
    let file: GrantKeystoreFile = serde_json::from_str(&raw)?;

    if file.format != GRANT_KEYSTORE_FORMAT_TAG {
        return Err(ClientError::InvalidFormat(format!(
            "unrecognized grant keystore format: {}",
            file.format
        )));
    }

    let public_key = hex::decode(&file.grant_public_key_hex)
        .map_err(|e| ClientError::InvalidFormat(format!("bad grant public key hex: {e}")))?;
    let secret_key = hex::decode(&file.grant_secret_key_hex)
        .map_err(|e| ClientError::InvalidFormat(format!("bad grant secret key hex: {e}")))?;

    Ok(GrantKeyMaterial::from_raw(public_key, secret_key))
}

pub fn unlock_from_disk(path: &Path) -> Result<GrantKeyMaterial> {
    import_ephemeral(path)
}

pub fn lock_to_disk(material: &GrantKeyMaterial, dir: &Path, grant_id: &str) -> Result<PathBuf> {
    let store_dir = dir.join(GRANT_KEYSTORE_DIRNAME);
    std::fs::create_dir_all(&store_dir)?;

    let file_name = format!("{grant_id}_grant_private_key.json");
    let path = store_dir.join(&file_name);
    forbid_default_keystore_path(&path)?;

    let file = GrantKeystoreFile {
        format: GRANT_KEYSTORE_FORMAT_TAG.to_string(),
        grant_public_key_hex: hex::encode(&material.public_key),
        grant_secret_key_hex: hex::encode(&material.secret_key),
    };
    let json = serde_json::to_string_pretty(&file)?;

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(json.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, json)?;
    }

    Ok(path)
}

fn zeroize_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub struct ColdGrant {
    material: Option<GrantKeyMaterial>,
}

impl ColdGrant {
    pub fn new(material: GrantKeyMaterial) -> Self {
        Self {
            material: Some(material),
        }
    }

    pub fn sign_once(
        &mut self,
        grant_id: &str,
        grantee_did: &str,
        session_binding: &str,
        signed_at_unix: u64,
    ) -> Result<Vec<u8>> {
        let material = self.material.take().ok_or_else(|| {
            ClientError::IdentityError(
                "cold-grant key already used or dropped; a new ceremony is required".into(),
            )
        })?;
        material.sign_exercise_proof(grant_id, grantee_did, session_binding, signed_at_unix)
    }

    pub fn drop_now(mut self) {
        self.material = None;
    }

    pub fn is_live(&self) -> bool {
        self.material.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn refuses_reserved_did_filename() {
        let p = Path::new("/tmp/whatever/user_private_key.json");
        let err = forbid_default_keystore_path(p).unwrap_err();
        assert!(matches!(err, ClientError::IdentityError(_)));

        let p2 = Path::new("/tmp/whatever/node_private_key.json");
        assert!(forbid_default_keystore_path(p2).is_err());
    }

    #[test]
    fn allows_dedicated_grant_filename() {
        let p = Path::new("/tmp/whatever/grant_store/g-1_grant_private_key.json");
        assert!(forbid_default_keystore_path(p).is_ok());
    }

    #[test]
    fn default_identity_json_does_not_parse_as_grant_keystore() {
        // Shape of an Identity-style JSON blob (DID keystore), missing the  `format` / `grant_*_hex` fields a GrantKeystoreFile requires.
        let did_shaped_json = serde_json::json!({
            "did": "did:zhtp:deadbeef",
            "public_key": [1, 2, 3],
            "private_key": [4, 5, 6],
            "kyber_public_key": [7, 8, 9],
            "kyber_secret_key": [10, 11, 12],
            "node_id": [13, 14, 15],
            "device_id": "device-1",
            "recovery_entropy": [16, 17, 18],
            "created_at": 0
        })
        .to_string();

        let parsed: std::result::Result<GrantKeystoreFile, _> =
            serde_json::from_str(&did_shaped_json);
        assert!(
            parsed.is_err(),
            "a DID identity JSON blob must not parse as a grant keystore file"
        );
    }

    #[test]
    fn lock_then_unlock_round_trips_and_signs() {
        let dir = TempDir::new().unwrap();
        let material = GrantKeyMaterial::generate().unwrap();
        let pk_before = material.public_key.clone();

        let path = lock_to_disk(&material, dir.path(), "g-1").unwrap();
        assert!(path.to_str().unwrap().contains(GRANT_KEYSTORE_DIRNAME));

        let unlocked = unlock_from_disk(&path).unwrap();
        assert_eq!(unlocked.public_key, pk_before);

        let sig = unlocked
            .sign_exercise_proof("g-1", "did:zhtp:alice", "sess-1", 1_000)
            .unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn lock_to_disk_refuses_reserved_filename_via_dir_trick() {
        let dir = TempDir::new().unwrap();
        let material = GrantKeyMaterial::generate().unwrap();
        let path = lock_to_disk(&material, dir.path(), "user_private_key").unwrap();
        let file_name = path.file_name().unwrap().to_str().unwrap();
        assert_ne!(file_name, "user_private_key.json");
        assert_ne!(file_name, "node_private_key.json");
    }

    #[test]
    fn import_ephemeral_refuses_reserved_path() {
        let dir = TempDir::new().unwrap();
        let bad_path = dir.path().join("user_private_key.json");
        std::fs::write(&bad_path, "{}").unwrap();
        let err = import_ephemeral(&bad_path).unwrap_err();
        assert!(matches!(err, ClientError::IdentityError(_)));
    }

    #[test]
    fn cold_grant_is_one_shot() {
        let material = GrantKeyMaterial::generate().unwrap();
        let mut cold = ColdGrant::new(material);
        assert!(cold.is_live());

        let sig1 = cold
            .sign_once("g-1", "did:zhtp:alice", "sess-1", 1_000)
            .unwrap();
        assert!(!sig1.is_empty());
        assert!(!cold.is_live());

        let err = cold
            .sign_once("g-1", "did:zhtp:alice", "sess-1", 1_001)
            .unwrap_err();
        assert!(matches!(err, ClientError::IdentityError(_)));
    }

    #[test]
    fn cold_grant_drop_now_discards_without_signing() {
        let material = GrantKeyMaterial::generate().unwrap();
        let cold = ColdGrant::new(material);
        assert!(cold.is_live());
        cold.drop_now();
    }

    #[test]
    fn grant_key_is_independent_of_generation_source() {
        let a = GrantKeyMaterial::generate().unwrap();
        let b = GrantKeyMaterial::generate().unwrap();
        assert_ne!(a.public_key, b.public_key);
    }
}
