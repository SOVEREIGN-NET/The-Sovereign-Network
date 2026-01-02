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

    let uhp_session_key: [u8; 32] = [
        0x02, 0x4F, 0x4F, 0xD7, 0x2E, 0x70, 0xF5, 0x8B, 0xDE, 0xDC, 0x55, 0x33, 0x53, 0x09,
        0xC5, 0x71, 0xDD, 0xF5, 0x39, 0xCF, 0x76, 0xEA, 0x25, 0x97, 0x6B, 0x40, 0xEC, 0xDA,
        0x58, 0x33, 0xB5, 0x4D,
    ];
    let pqc_shared_secret: [u8; 32] = [
        0xD9, 0xC8, 0x2C, 0xFE, 0x51, 0xA9, 0x06, 0xEB, 0x9D, 0x97, 0xA1, 0xF1, 0xBD, 0x8A,
        0xB5, 0x57, 0xD7, 0x52, 0xDB, 0x9F, 0xBE, 0x5E, 0xD4, 0xF2, 0xB7, 0xB5, 0x7E, 0x97,
        0xCA, 0x01, 0x08, 0x3A,
    ];
    let transcript_preimage: [u8; 96] = [
        0x01, 0xAC, 0x69, 0x91, 0x1D, 0xB9, 0x66, 0x10, 0xAE, 0x0B, 0xFD, 0x27, 0x79, 0x50,
        0x94, 0x85, 0xA0, 0xEE, 0x69, 0xD0, 0x54, 0xB9, 0x78, 0x62, 0x4A, 0xC3, 0x3F, 0x69,
        0xE8, 0xC7, 0xDE, 0x7C, 0x52, 0x48, 0xA4, 0x50, 0xF3, 0x34, 0xD4, 0xDD, 0x22, 0xCE,
        0x7C, 0xB9, 0xC3, 0x24, 0x94, 0x9C, 0xAE, 0xCB, 0x84, 0xB6, 0x64, 0x10, 0x00, 0xB4,
        0xE4, 0xC6, 0xFB, 0xA0, 0xD8, 0xBA, 0x53, 0xF1, 0x56, 0x44, 0xBD, 0x1A, 0xDE, 0xF4,
        0x34, 0x7E, 0x27, 0xB9, 0xBE, 0xA0, 0xB3, 0x82, 0x36, 0x38, 0x24, 0x95, 0x6A, 0x85,
        0x29, 0xF7, 0xE5, 0x80, 0xD2, 0xA0, 0x20, 0x8C, 0xAE, 0xFB, 0xDA, 0x58,
    ];
    let transcript_hash = hash_blake3(&transcript_preimage);

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
