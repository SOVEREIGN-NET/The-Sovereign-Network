//! Canonical node type definitions.
//!
//! This module provides the single source of truth for network node classification.
//! It lives in `lib-types` so that access control, networking, and configuration
//! layers can all reference the same enum without circular dependencies.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Canonical network node type.
///
/// This enum defines the 4 primary node types. All code should query this type
/// instead of checking scattered boolean flags (edge_mode, validator_enabled, etc).
/// The node type is determined ONCE at startup from config and is immutable thereafter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// Full node: complete blockchain, can sync and verify
    #[serde(rename = "full")]
    FullNode,

    /// Edge node: headers-only, ZK proof validation, no mining
    #[serde(rename = "edge")]
    EdgeNode,

    /// Validator node: full node + active block production and consensus
    #[serde(rename = "validator")]
    Validator,

    /// Relay node: routing only, no blockchain state
    #[serde(rename = "relay")]
    Relay,

    /// Gateway node: public ingress proxy that forwards to backend validators/full nodes
    #[serde(rename = "gateway")]
    Gateway,
}

impl Default for NodeType {
    fn default() -> Self {
        NodeType::FullNode
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::FullNode => write!(f, "full"),
            NodeType::EdgeNode => write!(f, "edge"),
            NodeType::Validator => write!(f, "validator"),
            NodeType::Relay => write!(f, "relay"),
            NodeType::Gateway => write!(f, "gateway"),
        }
    }
}

impl NodeType {
    /// Determine node type from config field "node_type"
    ///
    /// Config should contain one of: "full", "edge", "validator", "relay"
    /// Returns FullNode if not specified (safe default)
    pub fn from_config(node_type_str: Option<&str>) -> Self {
        match node_type_str {
            Some("validator") => NodeType::Validator,
            Some("edge") => NodeType::EdgeNode,
            Some("relay") => NodeType::Relay,
            Some("gateway") => NodeType::Gateway,
            Some("full") | None => NodeType::FullNode,
            Some(unknown) => {
                // Unknown node types fall back to FullNode safely.
                eprintln!(
                    "Warning: unknown node_type {:?}; falling back to \"full\"",
                    unknown
                );
                NodeType::FullNode
            }
        }
    }

    /// Check if this node type can mine/validate blocks
    pub fn can_mine(&self) -> bool {
        matches!(self, NodeType::Validator)
    }

    /// Check if this node can verify blocks (syntactic/semantic validation)
    /// Note: Only Validator nodes can participate in active consensus
    pub fn can_verify_blocks(&self) -> bool {
        matches!(self, NodeType::FullNode | NodeType::Validator)
    }

    /// Check if this node type can serve as a backend for gateway routing
    pub fn is_backend_candidate(&self) -> bool {
        matches!(self, NodeType::FullNode | NodeType::Validator)
    }

    /// Check if this node needs the complete blockchain
    pub fn needs_full_blockchain(&self) -> bool {
        matches!(self, NodeType::FullNode | NodeType::Validator)
    }

    /// Check if this node stores only headers (edge mode)
    pub fn headers_only(&self) -> bool {
        matches!(self, NodeType::EdgeNode)
    }

    /// Check if this node participates in mesh networking
    /// All node types participate in mesh for communication/routing
    pub fn is_mesh_enabled(&self) -> bool {
        true
    }

    /// Check if this node maintains blockchain state
    pub fn maintains_state(&self) -> bool {
        matches!(self, NodeType::FullNode | NodeType::Validator)
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            NodeType::FullNode => "Full node: complete blockchain, can sync and verify",
            NodeType::EdgeNode => "Edge node: headers-only mode, minimal storage",
            NodeType::Validator => "Validator: full blockchain + block production",
            NodeType::Relay => "Relay node: routing only, no blockchain state",
            NodeType::Gateway => "Gateway node: public ingress proxy to backend nodes",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nodetype_parsing() {
        assert_eq!(
            NodeType::from_config(Some("validator")),
            NodeType::Validator
        );
        assert_eq!(NodeType::from_config(Some("edge")), NodeType::EdgeNode);
        assert_eq!(NodeType::from_config(Some("relay")), NodeType::Relay);
        assert_eq!(NodeType::from_config(Some("gateway")), NodeType::Gateway);
        assert_eq!(NodeType::from_config(Some("full")), NodeType::FullNode);
        assert_eq!(NodeType::from_config(None), NodeType::FullNode);
    }

    #[test]
    fn test_nodetype_capabilities() {
        let validator = NodeType::Validator;
        assert!(validator.can_mine());
        assert!(validator.can_verify_blocks());
        assert!(validator.needs_full_blockchain());
        assert!(!validator.headers_only());

        let edge = NodeType::EdgeNode;
        assert!(!edge.can_mine());
        assert!(!edge.can_verify_blocks());
        assert!(!edge.needs_full_blockchain());
        assert!(edge.headers_only());

        let full = NodeType::FullNode;
        assert!(!full.can_mine());
        assert!(full.can_verify_blocks());
        assert!(full.needs_full_blockchain());
        assert!(!full.headers_only());

        let relay = NodeType::Relay;
        assert!(!relay.can_mine());
        assert!(!relay.can_verify_blocks());
        assert!(!relay.needs_full_blockchain());
        assert!(!relay.headers_only());

        let gateway = NodeType::Gateway;
        assert!(!gateway.can_mine());
        assert!(!gateway.can_verify_blocks());
        assert!(!gateway.needs_full_blockchain());
        assert!(!gateway.headers_only());
        assert!(!gateway.is_backend_candidate());
        assert!(validator.is_backend_candidate());
        assert!(full.is_backend_candidate());
    }

    #[test]
    fn test_nodetype_display() {
        // Display output matches serde names so round-tripping through config works.
        assert_eq!(NodeType::FullNode.to_string(), "full");
        assert_eq!(NodeType::EdgeNode.to_string(), "edge");
        assert_eq!(NodeType::Validator.to_string(), "validator");
        assert_eq!(NodeType::Relay.to_string(), "relay");
        assert_eq!(NodeType::Gateway.to_string(), "gateway");
    }
}
