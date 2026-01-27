use anyhow::Result;
use lib_crypto::PrivateKey;
use lib_identity::{types::IdentityType, NodeId, ZhtpIdentity};
use lib_network::{dht::protocol::DhtPeerInfo, UnifiedPeerId};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateKeyDisk {
    dilithium_sk: Vec<u8>,
    #[serde(default)]
    dilithium_pk: Vec<u8>,  // Optional for backward compatibility
    kyber_sk: Vec<u8>,
    master_seed: Vec<u8>,
}

fn write_identity_bundle(dir: &TempDir, identity: &ZhtpIdentity, private_key: &PrivateKey) -> Result<(PathBuf, PathBuf)> {
    let identity_path = dir.path().join("identity.json");
    let key_path = dir.path().join("private_key.json");

    to_writer_pretty(File::create(&identity_path)?, identity)?;
    let key_disk = PrivateKeyDisk {
        dilithium_sk: private_key.dilithium_sk.clone(),
        dilithium_pk: private_key.dilithium_pk.clone(),
        kyber_sk: private_key.kyber_sk.clone(),
        master_seed: private_key.master_seed.clone(),
    };
    to_writer_pretty(File::create(&key_path)?, &key_disk)?;

    Ok((identity_path, key_path))
}

fn reload_identity(identity_path: &PathBuf, key_path: &PathBuf) -> Result<ZhtpIdentity> {
    let identity_data = read_to_string(identity_path)?;
    let key_data = read_to_string(key_path)?;
    let key_disk: PrivateKeyDisk = from_str(&key_data)?;
    let private_key = PrivateKey {
        dilithium_sk: key_disk.dilithium_sk,
        dilithium_pk: key_disk.dilithium_pk,
        kyber_sk: key_disk.kyber_sk,
        master_seed: key_disk.master_seed,
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
    let (identity_path, key_path) = write_identity_bundle(&temp_dir, &identity, &private_key)?;

    for iteration in 1..=10 {
        let restored = reload_identity(&identity_path, &key_path)?;
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
    let (identity_path, key_path) = write_identity_bundle(&temp_dir, &identity, &private_key)?;

    let _restored = reload_identity(&identity_path, &key_path)?;
    let restored_key_disk: PrivateKeyDisk = from_str(&read_to_string(&key_path)?)?;
    let restored_key = PrivateKey {
        dilithium_sk: restored_key_disk.dilithium_sk,
        dilithium_pk: restored_key_disk.dilithium_pk,
        kyber_sk: restored_key_disk.kyber_sk,
        master_seed: restored_key_disk.master_seed,
    };

    assert_eq!(
        restored_key.master_seed, initial_master_seed,
        "Master seed changed after restart"
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
    let (identity_path, key_path) = write_identity_bundle(&temp_dir, &clone_identity, &private_key)?;
    let restored = reload_identity(&identity_path, &key_path)?;
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
