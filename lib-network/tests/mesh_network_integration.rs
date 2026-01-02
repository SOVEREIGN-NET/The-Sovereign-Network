//! Integration-style tests for mesh networking with deterministic NodeIds.
//! These tests exercise the UHP handshake pipeline directly to validate:
//! - NodeId determinism from seeded identities
//! - Session keys are derived uniquely per peer pair and bound to NodeIds
//! - Handshake verification rejects spoofed NodeIds
//! - Nodes can "restart" (regenerate identities) without changing NodeIds

use anyhow::Result;
use lib_crypto::KeyPair;
use lib_identity::{IdentityType, ZhtpIdentity};
use lib_identity::types::NodeId;
use lib_network::handshake::{
    ClientFinish, ClientHello, HandshakeCapabilities, HandshakeContext, HandshakeResult,
    HandshakeSessionInfo, NonceCache, ServerHello,
};
use std::collections::{HashMap, HashSet};
use tempfile::TempDir;

const BINDING: &[u8] = b"mesh-network-integration-binding";

fn deterministic_identity(seed_byte: u8, device: &str) -> Result<ZhtpIdentity> {
    let seed = [seed_byte; 64];
    ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        device,
        Some(seed),
    )
}

fn ordered_pair(a: NodeId, b: NodeId) -> (NodeId, NodeId) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

struct HandshakeContexts {
    client_ctx: HandshakeContext,
    server_ctx: HandshakeContext,
    _client_dir: TempDir,
    _server_dir: TempDir,
}

fn handshake_contexts() -> Result<HandshakeContexts> {
    let client_dir = TempDir::new()?;
    let server_dir = TempDir::new()?;

    let client_cache = NonceCache::open_default(client_dir.path(), 300)?;
    let server_cache = NonceCache::open_default(server_dir.path(), 300)?;

    let client_ctx = HandshakeContext::new(client_cache)
        .for_client_with_transport(BINDING.to_vec(), "quic");
    let server_ctx = HandshakeContext::new(server_cache)
        .for_server_with_transport(BINDING.to_vec(), "quic");

    Ok(HandshakeContexts {
        client_ctx,
        server_ctx,
        _client_dir: client_dir,
        _server_dir: server_dir,
    })
}

fn quic_capabilities() -> HandshakeCapabilities {
    let mut capabilities = HandshakeCapabilities::default();
    if !capabilities.protocols.iter().any(|p| p == "quic") {
        capabilities.protocols.push("quic".to_string());
    }
    capabilities
}

fn perform_handshake(
    client_identity: &ZhtpIdentity,
    server_identity: &ZhtpIdentity,
) -> Result<(HandshakeResult, HandshakeResult)> {
    let contexts = handshake_contexts()?;
    let HandshakeContexts {
        client_ctx,
        server_ctx,
        _client_dir,
        _server_dir,
    } = contexts;

    let capabilities = quic_capabilities();
    let client_hello = ClientHello::new(client_identity, capabilities.clone(), &client_ctx)?;
    client_hello.verify_signature(&server_ctx)?;

    let server_hello = ServerHello::new(server_identity, capabilities, &client_hello, &server_ctx)?;

    let client_keypair = KeyPair {
        public_key: client_identity.public_key.clone(),
        private_key: client_identity
            .private_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("client missing private key"))?,
    };

    let client_finish =
        ClientFinish::new(&server_hello, &client_hello, &client_keypair, &client_ctx)?;
    client_finish.verify_signature_with_context(
        &server_hello.response_nonce,
        &client_hello.identity.public_key,
        &server_ctx,
    )?;

    let session_info = HandshakeSessionInfo::from_messages(&client_hello, &server_hello)?;

    let client_session = HandshakeResult::new(
        server_hello.identity.clone(),
        server_hello.negotiated.clone(),
        &client_hello.challenge_nonce,
        &server_hello.response_nonce,
        &client_identity.did,
        &server_identity.did,
        client_hello.timestamp,
        &session_info,
    )?;

    let server_session = HandshakeResult::new(
        client_hello.identity.clone(),
        server_hello.negotiated.clone(),
        &client_hello.challenge_nonce,
        &server_hello.response_nonce,
        &client_identity.did,
        &server_identity.did,
        client_hello.timestamp,
        &session_info,
    )?;

    Ok((client_session, server_session))
}

#[test]
fn test_three_node_mesh_handshakes_are_unique_and_symmetric() -> Result<()> {
    let alice = deterministic_identity(0xA1, "alice")?;
    let bob = deterministic_identity(0xB2, "bob")?;
    let charlie = deterministic_identity(0xC3, "charlie")?;

    let pairs = vec![
        (&alice, &bob),
        (&alice, &charlie),
        (&bob, &charlie),
    ];

    let mut session_keys = HashMap::new();
    let mut adjacency: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();

    for (client, server) in pairs {
        let (client_session, server_session) = perform_handshake(client, server)?;

        // Both sides must derive the same key for a given pair
        assert_eq!(client_session.session_key, server_session.session_key);
        assert_eq!(server_session.peer_identity.node_id, client.node_id);
        assert_eq!(client_session.peer_identity.node_id, server.node_id);

        let key = ordered_pair(client.node_id, server.node_id);
        session_keys.insert(key, client_session.session_key);
        adjacency
            .entry(client.node_id)
            .or_default()
            .insert(server.node_id);
        adjacency
            .entry(server.node_id)
            .or_default()
            .insert(client.node_id);
    }

    // Fully connected 3-node mesh => each node should see 2 peers
    assert_eq!(adjacency.get(&alice.node_id).map(|s| s.len()), Some(2));
    assert_eq!(adjacency.get(&bob.node_id).map(|s| s.len()), Some(2));
    assert_eq!(adjacency.get(&charlie.node_id).map(|s| s.len()), Some(2));

    // Session keys must be unique per pair
    let unique_keys: HashSet<_> = session_keys.values().collect();
    assert_eq!(unique_keys.len(), session_keys.len());

    Ok(())
}

#[test]
fn test_nodeid_stability_across_restart_and_rejoin() -> Result<()> {
    let alice_first = deterministic_identity(0xAA, "alice")?;
    let bob = deterministic_identity(0xBB, "bob")?;

    let (first_client_session, first_server_session) =
        perform_handshake(&alice_first, &bob)?;
    assert_eq!(first_server_session.peer_identity.node_id, alice_first.node_id);

    // Simulate restart: regenerate Alice from the same seed
    let alice_restart = deterministic_identity(0xAA, "alice")?;
    assert_eq!(alice_first.node_id, alice_restart.node_id);

    let (second_client_session, second_server_session) =
        perform_handshake(&alice_restart, &bob)?;
    assert_eq!(
        second_server_session.peer_identity.node_id,
        alice_restart.node_id
    );

    // Restarted node should derive a fresh session key even though NodeId is identical
    assert_ne!(
        first_client_session.session_key,
        second_client_session.session_key
    );

    Ok(())
}

#[test]
fn test_handshake_rejects_spoofed_node_id() -> Result<()> {
    let honest = deterministic_identity(0xD1, "honest")?;
    let server = deterministic_identity(0xE2, "server")?;

    let contexts = handshake_contexts()?;
    let HandshakeContexts {
        client_ctx,
        server_ctx,
        _client_dir,
        _server_dir,
    } = contexts;

    let capabilities = quic_capabilities();
    let client_hello = ClientHello::new(&honest, capabilities.clone(), &client_ctx)?;

    // Tamper with the NodeId after signing to simulate spoofing
    let mut tampered = client_hello.clone();
    tampered.identity.node_id = NodeId::from_bytes([0xFF; 32]);

    // Server should reject because the signature no longer matches the identity payload
    assert!(tampered.verify_signature(&server_ctx).is_err());

    // Control: the untampered message should verify
    client_hello.verify_signature(&server_ctx)?;

    // Complete a successful handshake to ensure the path still works
    let server_hello = ServerHello::new(&server, capabilities, &client_hello, &server_ctx)?;
    let client_keypair = KeyPair {
        public_key: honest.public_key.clone(),
        private_key: honest
            .private_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("honest identity missing private key"))?,
    };
    let finish = ClientFinish::new(&server_hello, &client_hello, &client_keypair, &client_ctx)?;
    finish.verify_signature_with_context(
        &server_hello.response_nonce,
        &client_hello.identity.public_key,
        &server_ctx,
    )?;

    Ok(())
}
