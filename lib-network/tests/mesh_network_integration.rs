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

#[test]
fn node_id_changes_with_different_seed() -> Result<()> {
    let device = "alpha-mesh-node-01";
    let a = identity_with_seed(device, [0x11u8; 64])?;
    let b = identity_with_seed(device, [0x12u8; 64])?;

    assert_ne!(a.did, b.did, "Different seeds should produce different DIDs");
    assert_ne!(
        a.node_id, b.node_id,
        "Different seeds should produce different NodeIds"
    );

    Ok(())
}

#[test]
fn node_id_changes_with_different_device_name() -> Result<()> {
    let seed = [0x11u8; 64];
    let a = identity_with_seed("alpha-mesh-node-01", seed)?;
    let b = identity_with_seed("alpha-mesh-node-02", seed)?;

    assert_eq!(
        a.did, b.did,
        "Same seed should produce same DID even across devices"
    );
    assert_ne!(
        a.node_id, b.node_id,
        "Different device names should produce different NodeIds"
    );

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
    let other_peer = identity_with_seed("alpha-mesh-node-03", [0x34u8; 64])?;

    let uhp_session_key = [
        0x5e, 0x2a, 0x1c, 0x9f, 0x73, 0x4b, 0x88, 0xd1,
        0x0f, 0xa6, 0x23, 0x4c, 0x71, 0x9d, 0x55, 0x3e,
        0x96, 0x1a, 0xb4, 0x2f, 0x07, 0x65, 0x9c, 0xee,
        0xa3, 0x14, 0x4f, 0x82, 0x19, 0xd8, 0x0c, 0x6a,
    ];
    let pqc_shared_secret = [
        0x0c, 0x91, 0x8d, 0x7b, 0x2e, 0x4a, 0x63, 0xf5,
        0x11, 0xb9, 0xe0, 0x37, 0x58, 0xaa, 0x6f, 0x92,
        0xe5, 0x1d, 0x26, 0x99, 0x43, 0xc0, 0x7a, 0x34,
        0xf8, 0x2b, 0x6d, 0x10, 0x95, 0xce, 0x77, 0x04,
    ];
    let transcript_hash = [
        0x9a, 0x57, 0x02, 0xcc, 0x13, 0x7d, 0xe8, 0x61,
        0xb3, 0x4e, 0x29, 0x90, 0x0a, 0xf6, 0x7b, 0x1d,
        0x48, 0xc2, 0x5f, 0xa9, 0x3c, 0x70, 0x1e, 0xd4,
        0x6b, 0x88, 0x0f, 0x31, 0xad, 0x52, 0xc6, 0x7f,
    ];

    let master = derive_master_key_for_test(
        &uhp_session_key,
        &pqc_shared_secret,
        &transcript_hash,
        identity.node_id.as_bytes(),
    )?;
    assert_eq!(master.len(), 32, "Master key must be 32 bytes");

    let master_restarted = derive_master_key_for_test(
        &uhp_session_key,
        &pqc_shared_secret,
        &transcript_hash,
        restarted_identity.node_id.as_bytes(),
    )?;
    assert_eq!(
        master, master_restarted,
        "Master key should remain stable when NodeId is stable across restarts"
    );

    let master_other_peer = derive_master_key_for_test(
        &uhp_session_key,
        &pqc_shared_secret,
        &transcript_hash,
        other_peer.node_id.as_bytes(),
    )?;
    assert_ne!(
        master, master_other_peer,
        "Changing peer NodeId must change the derived mesh master key"
    );

    let mut uhp_session_key_changed = uhp_session_key;
    uhp_session_key_changed[0] ^= 0x01;
    let master_uhp_changed = derive_master_key_for_test(
        &uhp_session_key_changed,
        &pqc_shared_secret,
        &transcript_hash,
        identity.node_id.as_bytes(),
    )?;
    assert_ne!(
        master, master_uhp_changed,
        "Changing UHP session key must change the derived master key"
    );

    let mut pqc_shared_secret_changed = pqc_shared_secret;
    pqc_shared_secret_changed[0] ^= 0x01;
    let master_pqc_changed = derive_master_key_for_test(
        &uhp_session_key,
        &pqc_shared_secret_changed,
        &transcript_hash,
        identity.node_id.as_bytes(),
    )?;
    assert_ne!(
        master, master_pqc_changed,
        "Changing PQC shared secret must change the derived master key"
    );

    let mut transcript_hash_changed = transcript_hash;
    transcript_hash_changed[0] ^= 0x01;
    let master_transcript_changed = derive_master_key_for_test(
        &uhp_session_key,
        &pqc_shared_secret,
        &transcript_hash_changed,
        identity.node_id.as_bytes(),
    )?;
    assert_ne!(
        master, master_transcript_changed,
        "Changing transcript hash must change the derived master key"
    );

    let mut ikm = Vec::with_capacity(32 + 32 + 32 + identity.node_id.as_bytes().len());
    ikm.extend_from_slice(&uhp_session_key);
    ikm.extend_from_slice(&pqc_shared_secret);
    ikm.extend_from_slice(&transcript_hash);
    ikm.extend_from_slice(identity.node_id.as_bytes());

    let extracted = hkdf_sha3(&ikm, b"zhtp-quic-mesh", 32)?;
    let expanded = hkdf_sha3(&extracted, b"zhtp-quic-master", 32)?;
    assert_eq!(
        master.to_vec(),
        expanded,
        "Master key derivation must use both HKDF labels"
    );

    let wrong_expand = hkdf_sha3(&extracted, b"zhtp-quic-master-wrong", 32)?;
    assert_ne!(
        master.to_vec(),
        wrong_expand,
        "Changing HKDF expansion label must change the derived master key"
    );

    let extracted_wrong = hkdf_sha3(&ikm, b"zhtp-quic-mesh-wrong", 32)?;
    let expanded_wrong = hkdf_sha3(&extracted_wrong, b"zhtp-quic-master", 32)?;
    assert_ne!(
        master.to_vec(),
        expanded_wrong,
        "Changing HKDF extraction label must change the derived master key"
    );

    Ok(())
}
