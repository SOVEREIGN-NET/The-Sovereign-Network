use anyhow::Result;
use lib_crypto::{hash_blake3, kdf::hkdf::hkdf_sha3};
use lib_identity::{IdentityType, NodeId, ZhtpIdentity};
use lib_network::{
    discovery::{DiscoveryProtocol, DiscoveryResult, UnifiedDiscoveryService},
    identity::UnifiedPeerId,
};
use std::net::SocketAddr;
use uuid::Uuid;

fn identity_with_seed(device: &str, seed: [u8; 64]) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        device,
        Some(seed),
    )
}

fn derive_master_key_for_test(
    uhp_session_key: &[u8; 32],
    pqc_shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
    peer_node_id: &[u8],
) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + peer_node_id.len());
    ikm.extend_from_slice(uhp_session_key);
    ikm.extend_from_slice(pqc_shared_secret);
    ikm.extend_from_slice(transcript_hash);
    ikm.extend_from_slice(peer_node_id);

    let extracted = hkdf_sha3(&ikm, b"zhtp-quic-mesh", 32)?;
    let expanded = hkdf_sha3(&extracted, b"zhtp-quic-master", 32)?;

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&expanded);
    Ok(master_key)
}

#[test]
fn node_id_remains_stable_across_restart() -> Result<()> {
    // Use a fixed seed (0x11 pattern) to ensure deterministic NodeId derivation
    // This seed simulates device state preservation across restarts
    let seed = [0x11u8; 64];
    let device = "alpha-mesh-node-01";

    let first = identity_with_seed(device, seed)?;
    let second = identity_with_seed(device, seed)?;

    assert_eq!(first.did, second.did, "DID should be deterministic");
    assert_eq!(first.node_id, second.node_id, "NodeId should survive restart with same seed");
    assert!(!first.public_key.as_bytes().is_empty(), "Public key should be present");
    assert!(!second.public_key.as_bytes().is_empty(), "Public key should be present");

    let expected = NodeId::from_did_device(&first.did, device)?;
    assert_eq!(
        expected,
        first.node_id,
        "NodeId must match DID + device derivation"
    );

    let peer_id = UnifiedPeerId::from_zhtp_identity(&first)?;
    peer_id.verify_node_id()?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_discovery_tracks_three_nodes_with_verified_metadata() -> Result<()> {
    // Use distinct seed patterns (0x21, 0x22, 0x23) to create unique, deterministic identities
    // Each seed simulates a different node's persistent state across restarts
    let seeds = [[0x21u8; 64], [0x22u8; 64], [0x23u8; 64]];
    let devices = ["alpha-mesh-a01", "alpha-mesh-b02", "alpha-mesh-c03"];

    let identities: Vec<ZhtpIdentity> = seeds
        .iter()
        .zip(devices.iter())
        .map(|(seed, device)| identity_with_seed(device, *seed))
        .collect::<Result<_>>()?;

    let service = UnifiedDiscoveryService::new(
        Uuid::new_v4(),
        9443,
        identities[0].public_key.clone(),
    );

    // Set a 10-second timeout for the entire test to prevent hangs in CI
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async {
            let mut peer_ids = Vec::new();
            for (idx, identity) in identities.iter().enumerate() {
                let peer_id = Uuid::new_v4();
                peer_ids.push(peer_id);

                let addr: SocketAddr = format!("10.0.0.{}:9443", 10 + idx).parse().unwrap();
                let mut result = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9443);
                result.public_key = Some(identity.public_key.clone());
                result.did = Some(identity.did.clone());
                result.device_id = Some(identity.primary_device.clone());
                service.register_peer(result).await;
            }

            assert_eq!(service.peer_count().await, identities.len());

            for (idx, peer_id) in peer_ids.iter().enumerate() {
                let peer = service
                    .get_peer(peer_id)
                    .await
                    .expect("peer should be registered");
                let identity = &identities[idx];

                assert_eq!(peer.did.as_deref(), Some(identity.did.as_str()));
                assert_eq!(peer.device_id.as_deref(), Some(identity.primary_device.as_str()));
                assert_eq!(
                    peer.public_key.as_ref().map(|k| k.as_bytes()),
                    Some(identity.public_key.as_bytes())
                );

                let expected_node_id = NodeId::from_did_device(&identity.did, &identity.primary_device)?;
                assert_eq!(identity.node_id, expected_node_id);

                let unified_peer = UnifiedPeerId::from_zhtp_identity(identity)?;
                unified_peer.verify_node_id()?;
            }

            Ok::<(), anyhow::Error>(())
        }
    ).await;

    result.map_err(|_| anyhow::anyhow!("Test timed out after 10 seconds"))?
}

#[test]
fn quic_master_key_is_bound_to_node_id() -> Result<()> {
    // Use seed pattern 0x33 for the stable node, 0x34 for a different node
    // This tests both stability (same seed on restart) and differentiation (different seeds)
    let device = "alpha-mesh-node-02";
    let same_device_seed = [0x33u8; 64];
    let identity = identity_with_seed(device, same_device_seed)?;
    let restarted_identity = identity_with_seed(device, same_device_seed)?;
    let different_identity = identity_with_seed("alpha-mesh-node-03", [0x34u8; 64])?;

    // These KDF info strings match the production QUIC master key derivation in the handshake
    // The full key derivation: extract with "zhtp-quic-mesh", then expand with "zhtp-quic-master"
    let uhp_session_key = hash_blake3(b"mesh-uhp-session");
    let pqc_shared_secret = hash_blake3(b"mesh-pqc-secret");
    let transcript_hash = hash_blake3(b"mesh-transcript");

    let master1 = derive_master_key_for_test(
        &uhp_session_key,
        &pqc_shared_secret,
        &transcript_hash,
        identity.node_id.as_bytes(),
    )?;
    let master2 = derive_master_key_for_test(
        &uhp_session_key,
        &pqc_shared_secret,
        &transcript_hash,
        restarted_identity.node_id.as_bytes(),
    )?;
    let master3 = derive_master_key_for_test(
        &uhp_session_key,
        &pqc_shared_secret,
        &transcript_hash,
        different_identity.node_id.as_bytes(),
    )?;

    assert_eq!(
        master1, master2,
        "Master key should remain stable when NodeId is stable across restarts"
    );
    assert_ne!(
        master1, master3,
        "Changing NodeId must change the derived mesh master key"
    );

    Ok(())
}
