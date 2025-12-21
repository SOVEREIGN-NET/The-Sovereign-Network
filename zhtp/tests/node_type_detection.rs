//! Integration tests for node type detection system
//!
//! Tests canonical node type detection to ensure:
//! - Single source of truth
//! - No scattered boolean checks
//! - Proper capability queries

use lib_types::NodeType;

#[test]
fn test_node_type_from_config_string() {
    // Test all supported node types
    assert_eq!(NodeType::from_config_string("validator"), NodeType::Validator);
    assert_eq!(NodeType::from_config_string("VALIDATOR"), NodeType::Validator);
    assert_eq!(NodeType::from_config_string("Validator"), NodeType::Validator);
    
    assert_eq!(NodeType::from_config_string("edge"), NodeType::EdgeNode);
    assert_eq!(NodeType::from_config_string("Edge"), NodeType::EdgeNode);
    assert_eq!(NodeType::from_config_string("EDGE"), NodeType::EdgeNode);
    
    assert_eq!(NodeType::from_config_string("relay"), NodeType::Relay);
    assert_eq!(NodeType::from_config_string("Relay"), NodeType::Relay);
    
    assert_eq!(NodeType::from_config_string("full"), NodeType::FullNode);
    assert_eq!(NodeType::from_config_string("fullnode"), NodeType::FullNode);
    assert_eq!(NodeType::from_config_string("full-node"), NodeType::FullNode);
    
    // Unknown types default to FullNode
    assert_eq!(NodeType::from_config_string("unknown"), NodeType::FullNode);
    assert_eq!(NodeType::from_config_string(""), NodeType::FullNode);
}

#[test]
fn test_node_type_from_legacy_config() {
    // Validator: validator_enabled = true
    assert_eq!(
        NodeType::from_legacy_config(true, true, 1000),
        NodeType::Validator
    );
    assert_eq!(
        NodeType::from_legacy_config(true, false, 50),
        NodeType::Validator
    );
    
    // Edge node: no smart contracts + low storage
    assert_eq!(
        NodeType::from_legacy_config(false, false, 50),
        NodeType::EdgeNode
    );
    assert_eq!(
        NodeType::from_legacy_config(false, false, 0),
        NodeType::EdgeNode
    );
    assert_eq!(
        NodeType::from_legacy_config(false, false, 99),
        NodeType::EdgeNode
    );
    
    // Full node: smart contracts enabled
    assert_eq!(
        NodeType::from_legacy_config(false, true, 50),
        NodeType::FullNode
    );
    assert_eq!(
        NodeType::from_legacy_config(false, true, 500),
        NodeType::FullNode
    );
    
    // Full node: high storage
    assert_eq!(
        NodeType::from_legacy_config(false, false, 100),
        NodeType::FullNode
    );
    assert_eq!(
        NodeType::from_legacy_config(false, false, 500),
        NodeType::FullNode
    );
}

#[test]
fn test_validator_capabilities() {
    let node = NodeType::Validator;
    
    // Validators can do everything
    assert!(node.can_produce_blocks());
    assert!(node.can_validate());
    assert!(node.needs_full_blockchain());
    assert!(node.can_run_smart_contracts());
    assert!(node.stores_blockchain());
    assert!(node.should_enable_mining());
    
    // Validators are not constrained
    assert!(!node.is_headers_only());
    assert!(!node.is_constrained());
    
    // Validators require stake
    assert!(node.min_stake_required().is_some());
    assert_eq!(node.min_stake_required(), Some(1000));
}

#[test]
fn test_full_node_capabilities() {
    let node = NodeType::FullNode;
    
    // Full nodes can validate but not produce blocks
    assert!(!node.can_produce_blocks());
    assert!(node.can_validate());
    assert!(node.needs_full_blockchain());
    assert!(node.can_run_smart_contracts());
    assert!(node.stores_blockchain());
    assert!(!node.should_enable_mining());
    
    // Full nodes are not constrained
    assert!(!node.is_headers_only());
    assert!(!node.is_constrained());
    
    // Full nodes don't require stake
    assert!(node.min_stake_required().is_none());
}

#[test]
fn test_edge_node_capabilities() {
    let node = NodeType::EdgeNode;
    
    // Edge nodes have minimal capabilities
    assert!(!node.can_produce_blocks());
    assert!(!node.can_validate());
    assert!(!node.needs_full_blockchain());
    assert!(!node.can_run_smart_contracts());
    assert!(!node.should_enable_mining());
    
    // Edge nodes ARE constrained and use headers-only
    assert!(node.is_headers_only());
    assert!(node.is_constrained());
    assert!(node.stores_blockchain()); // Still stores headers
    
    // Edge nodes have header limits
    assert!(node.max_headers().is_some());
    assert_eq!(node.max_headers(), Some(500));
}

#[test]
fn test_relay_node_capabilities() {
    let node = NodeType::Relay;
    
    // Relay nodes only route
    assert!(!node.can_produce_blocks());
    assert!(!node.can_validate());
    assert!(!node.needs_full_blockchain());
    assert!(!node.can_run_smart_contracts());
    assert!(!node.should_enable_mining());
    
    // Relay nodes are constrained
    assert!(!node.is_headers_only());
    assert!(node.is_constrained());
    
    // Relay nodes don't store blockchain
    assert!(!node.stores_blockchain());
}

#[test]
fn test_storage_recommendations() {
    assert_eq!(NodeType::Validator.recommended_storage_gb(), 1000);
    assert_eq!(NodeType::FullNode.recommended_storage_gb(), 500);
    assert_eq!(NodeType::EdgeNode.recommended_storage_gb(), 10);
    assert_eq!(NodeType::Relay.recommended_storage_gb(), 1);
}

#[test]
fn test_max_headers() {
    // Only edge nodes have header limits
    assert_eq!(NodeType::EdgeNode.max_headers(), Some(500));
    assert_eq!(NodeType::FullNode.max_headers(), None);
    assert_eq!(NodeType::Validator.max_headers(), None);
    assert_eq!(NodeType::Relay.max_headers(), None);
}

#[test]
fn test_display_formatting() {
    assert_eq!(NodeType::Validator.display_name(), "Validator");
    assert_eq!(NodeType::FullNode.display_name(), "Full Node");
    assert_eq!(NodeType::EdgeNode.display_name(), "Edge Node");
    assert_eq!(NodeType::Relay.display_name(), "Relay Node");
    
    assert_eq!(NodeType::Validator.to_string(), "Validator");
    assert_eq!(NodeType::FullNode.to_string(), "Full Node");
}

#[test]
fn test_icons() {
    assert_eq!(NodeType::Validator.icon(), "🔶");
    assert_eq!(NodeType::FullNode.icon(), "🔷");
    assert_eq!(NodeType::EdgeNode.icon(), "📱");
    assert_eq!(NodeType::Relay.icon(), "🔀");
}

#[test]
fn test_default() {
    assert_eq!(NodeType::default(), NodeType::FullNode);
}

#[test]
fn test_from_string() {
    let node: NodeType = "validator".into();
    assert_eq!(node, NodeType::Validator);
    
    let node: NodeType = String::from("edge").into();
    assert_eq!(node, NodeType::EdgeNode);
}

#[test]
fn test_serialization() {
    use serde_json;
    
    // Test serialization
    let validator = NodeType::Validator;
    let json = serde_json::to_string(&validator).unwrap();
    assert!(json.contains("Validator"));
    
    // Test deserialization
    let deserialized: NodeType = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, NodeType::Validator);
}

#[test]
fn test_capability_consistency() {
    // Validators should be a superset of full nodes
    assert!(NodeType::Validator.can_validate());
    assert!(NodeType::FullNode.can_validate());
    assert!(NodeType::Validator.can_produce_blocks());
    assert!(!NodeType::FullNode.can_produce_blocks());
    
    // Edge nodes should be most restricted
    assert!(!NodeType::EdgeNode.can_validate());
    assert!(!NodeType::EdgeNode.can_produce_blocks());
    assert!(!NodeType::EdgeNode.can_run_smart_contracts());
    
    // Relay nodes don't store blockchain
    assert!(!NodeType::Relay.stores_blockchain());
    assert!(NodeType::EdgeNode.stores_blockchain()); // Headers only
    assert!(NodeType::FullNode.stores_blockchain());
    assert!(NodeType::Validator.stores_blockchain());
}
