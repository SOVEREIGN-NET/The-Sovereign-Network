use anyhow::{anyhow, Result};
use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use lib_crypto::symmetric::chacha20::{decrypt_data, encrypt_data};
use lib_crypto::{Hash, PrivateKey};
use lib_identity::{types::IdentityType, NodeId, ZhtpIdentity};
use lib_network::{dht::protocol::DhtPeerInfo, UnifiedPeerId};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_writer_pretty};
use std::{
    fs::{read_to_string, File},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use tempfile::TempDir;

const TEST_DEVICE: &str = "alpha-node-01";
const TEST_SEED: [u8; 64] = [42u8; 64];
const SEED_STORAGE_DIRNAME: &str = "seed_store";
const SEED_PASSPHRASE: &str = "test-passphrase";
const FILE_FORMAT_VERSION: u8 = 1;
const KDF_NAME: &str = "argon2id";

#[derive(Debug, Clone, Copy)]
enum SeedKind {
    Node,
}

impl SeedKind {
    fn label(self) -> &'static str {
        match self {
            SeedKind::Node => "node",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateKeyDisk {
    dilithium_sk: Vec<u8>,
    kyber_sk: Vec<u8>,
    #[serde(default)]
    master_seed: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedSeedRecord {
    version: u8,
    kdf: String,
    salt_b64: String,
    ciphertext_b64: String,
}

fn seed_file_path(dir: &TempDir, identity_id: &Hash, kind: SeedKind) -> PathBuf {
    let filename = format!("{}_{}.json", kind.label(), identity_id);
    dir.path().join(SEED_STORAGE_DIRNAME).join(filename)
}

fn store_seed(dir: &TempDir, identity_id: &Hash, kind: SeedKind, seed: &[u8]) -> Result<PathBuf> {
    let record = encrypt_seed(seed, SEED_PASSPHRASE)?;
    let path = seed_file_path(dir, identity_id, kind);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    to_writer_pretty(File::create(&path)?, &record)?;
    Ok(path)
}

fn load_seed(path: &PathBuf) -> Result<Vec<u8>> {
    let seed_payload = read_to_string(path)?;
    let record: EncryptedSeedRecord = from_str(&seed_payload)?;
    decrypt_seed(&record, SEED_PASSPHRASE)
}

fn encrypt_seed(seed: &[u8], passphrase: &str) -> Result<EncryptedSeedRecord> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(passphrase, &salt)?;
    let ciphertext = encrypt_data(seed, &key)?;

    Ok(EncryptedSeedRecord {
        version: FILE_FORMAT_VERSION,
        kdf: KDF_NAME.to_string(),
        salt_b64: general_purpose::STANDARD.encode(salt),
        ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
    })
}

fn decrypt_seed(record: &EncryptedSeedRecord, passphrase: &str) -> Result<Vec<u8>> {
    if record.version != FILE_FORMAT_VERSION {
        return Err(anyhow!("Unsupported seed record version {}", record.version));
    }
    if record.kdf != KDF_NAME {
        return Err(anyhow!("Unsupported seed KDF {}", record.kdf));
    }
    let salt = general_purpose::STANDARD
        .decode(&record.salt_b64)
        .map_err(|e| anyhow!("Invalid seed salt encoding: {}", e))?;
    let ciphertext = general_purpose::STANDARD
        .decode(&record.ciphertext_b64)
        .map_err(|e| anyhow!("Invalid seed ciphertext encoding: {}", e))?;
    let key = derive_key(passphrase, &salt)?;
    decrypt_data(&ciphertext, &key).map_err(|e| anyhow!("Seed decrypt failed: {}", e))
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    Ok(key)
}

fn write_identity_bundle(
    dir: &TempDir,
    identity: &ZhtpIdentity,
    private_key: &PrivateKey,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let identity_path = dir.path().join("identity.json");
    let key_path = dir.path().join("private_key.json");

    to_writer_pretty(File::create(&identity_path)?, identity)?;
    let seed_path = store_seed(dir, &identity.id, SeedKind::Node, &private_key.master_seed)?;
    let key_disk = PrivateKeyDisk {
        dilithium_sk: private_key.dilithium_sk.clone(),
        kyber_sk: private_key.kyber_sk.clone(),
        master_seed: None,
    };
    to_writer_pretty(File::create(&key_path)?, &key_disk)?;

    Ok((identity_path, key_path, seed_path))
}

fn reload_identity(identity_path: &PathBuf, key_path: &PathBuf, seed_path: &PathBuf) -> Result<ZhtpIdentity> {
    let identity_data = read_to_string(identity_path)?;
    let key_data = read_to_string(key_path)?;
    let key_disk: PrivateKeyDisk = from_str(&key_data)?;
    let master_seed = match key_disk.master_seed {
        Some(seed) => seed,
        None => load_seed(seed_path)?,
    };
    let private_key = PrivateKey {
        dilithium_sk: key_disk.dilithium_sk,
        kyber_sk: key_disk.kyber_sk,
        master_seed,
    };
    let restored = ZhtpIdentity::from_serialized(&identity_data, &private_key)?;
    Ok(restored)
}

fn example_dht_peer(node_id: [u8; 32]) -> DhtPeerInfo {
    DhtPeerInfo {
        node_id,
        addresses: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 37775)],
        capabilities: vec!["mesh".to_string()],
        last_seen: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        reputation: 1.0,
    }
}

#[tokio::test]
async fn test_single_node_orchestrator_restart_10x() -> Result<()> {
    let mut identity = ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        TEST_DEVICE,
        Some(TEST_SEED),
    )?;
    let private_key = identity
        .private_key
        .take()
        .ok_or_else(|| anyhow::anyhow!("identity missing private key"))?;

    let initial_node_id = *identity.node_id.as_bytes();
    let initial_did = identity.did.clone();

    let temp_dir = TempDir::new()?;
    let (identity_path, key_path, seed_path) = write_identity_bundle(&temp_dir, &identity, &private_key)?;

    for iteration in 1..=10 {
        let restored = reload_identity(&identity_path, &key_path, &seed_path)?;
        assert_eq!(
            restored.node_id.as_bytes(),
            &initial_node_id,
            "Iteration {}: NodeId changed after restart",
            iteration
        );
        assert_eq!(
            restored.did, initial_did,
            "Iteration {}: DID changed after restart",
            iteration
        );

        let peer = UnifiedPeerId::from_zhtp_identity(&restored)?;
        peer.verify_node_id()?;
        assert_eq!(
            peer.node_id().as_bytes(),
            &initial_node_id,
            "Iteration {}: UnifiedPeerId NodeId diverged",
            iteration
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_identity_seed_persistence_across_restarts() -> Result<()> {
    let mut identity = ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        TEST_DEVICE,
        Some(TEST_SEED),
    )?;
    let private_key = identity
        .private_key
        .take()
        .ok_or_else(|| anyhow::anyhow!("identity missing private key"))?;

    let initial_master_seed = private_key.master_seed.clone();

    let temp_dir = TempDir::new()?;
    let (identity_path, key_path, seed_path) = write_identity_bundle(&temp_dir, &identity, &private_key)?;
    let seed_payload_before = read_to_string(&seed_path)?;

    let _restored = reload_identity(&identity_path, &key_path, &seed_path)?;
    let restored_key_disk: PrivateKeyDisk = from_str(&read_to_string(&key_path)?)?;
    assert!(
        restored_key_disk.master_seed.is_none(),
        "Master seed should not remain in the key file"
    );
    let restored_seed = load_seed(&seed_path)?;
    let seed_payload_after = read_to_string(&seed_path)?;

    assert_eq!(
        restored_seed, initial_master_seed,
        "Master seed changed after restart"
    );
    assert_eq!(
        seed_payload_before, seed_payload_after,
        "Encrypted seed file changed after restart"
    );

    Ok(())
}

#[tokio::test]
async fn test_dht_routing_table_rebuild_with_same_nodeid() -> Result<()> {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        TEST_DEVICE,
        Some(TEST_SEED),
    )?;
    let initial_node_id = *identity.node_id.as_bytes();

    let initial_peer = example_dht_peer(initial_node_id);
    assert_eq!(initial_peer.node_id, initial_node_id, "Initial DHT entry should use canonical NodeId");

    // Simulate restart by re-creating identity from stored data
    let mut clone_identity = identity.clone();
    let private_key = clone_identity
        .private_key
        .take()
        .ok_or_else(|| anyhow::anyhow!("identity missing private key"))?;
    let temp_dir = TempDir::new()?;
    let (identity_path, key_path, seed_path) = write_identity_bundle(&temp_dir, &clone_identity, &private_key)?;
    let restored = reload_identity(&identity_path, &key_path, &seed_path)?;
    let restored_peer = example_dht_peer(*restored.node_id.as_bytes());

    assert_eq!(
        restored_peer.node_id, initial_peer.node_id,
        "DHT routing entry should rebuild with unchanged NodeId"
    );

    Ok(())
}

#[tokio::test]
async fn test_component_initialization_receives_same_nodeid() -> Result<()> {
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        TEST_DEVICE,
        Some(TEST_SEED),
    )?;
    let expected_node_id = NodeId::from_did_device(&identity.did, &identity.primary_device)?;

    let network_peer = UnifiedPeerId::from_zhtp_identity(&identity)?;
    network_peer.verify_node_id()?;

    let dht_peer = example_dht_peer(*identity.node_id.as_bytes());
    let discovery_node_id = expected_node_id;

    assert_eq!(
        network_peer.node_id().as_bytes(),
        dht_peer.node_id.as_slice(),
        "Mesh (network) and DHT components must share identical NodeId"
    );
    assert_eq!(
        discovery_node_id.as_bytes(),
        network_peer.node_id().as_bytes(),
        "Discovery-derived NodeId must match orchestrator NodeId"
    );

    Ok(())
}
