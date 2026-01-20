mod common;

use common::mesh_test_utils::{MulticastFabric, Node};

#[test]
fn mesh_connectivity_three_nodes_discover_each_other() {
    let mut fabric = MulticastFabric::new();
    let nodes = vec![
        Node::new("did:zhtp:alpha", "device-a"),
        Node::new("did:zhtp:beta", "device-b"),
        Node::new("did:zhtp:gamma", "device-c"),
    ];

    for node in nodes.iter() {
        node.advertise_multicast(&mut fabric);
    }

    for node in nodes.iter() {
        node.discover_peers(&fabric);
        let peers = node.peers.lock().unwrap();
        assert_eq!(peers.len(), 2, "each node should see two peers");
    }
}

#[test]
fn mesh_connectivity_persists_node_id_across_restart() {
    let original = Node::new("did:zhtp:delta", "device-d");
    let original_id = original.node_id.clone();
    original.persist();

    let mut restarted = Node::new("did:zhtp:delta", "device-d");
    restarted.persisted_state = original.persisted_state.clone();
    restarted.restore();

    assert_eq!(restarted.node_id, original_id, "NodeId should persist across restart");
}

#[test]
fn mesh_connectivity_rejects_invalid_did() {
    let valid = Node::new("did:zhtp:hand-a", "device-a");
    let invalid = Node::new("did:invalid:hand-b", "device-b");

    assert!(
        !valid.handshake_with(&invalid),
        "handshake should reject peers without the did:zhtp prefix"
    );
}
