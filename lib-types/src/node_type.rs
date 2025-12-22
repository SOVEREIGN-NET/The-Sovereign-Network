//! Node Type Detection System
//! 
//! Provides canonical node type identification - single source of truth.
//! Eliminates scattered boolean checks and inconsistent node type detection.

use std::fmt;
use serde::{Deserialize, Serialize};

/// Canonical node type - single source of truth for node capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    /// Full node: complete blockchain, can validate transactions
    /// - Stores full blockchain state
    /// - Validates all transactions and blocks
    /// - Can participate in consensus (if staked)
    /// - Provides full API capabilities
    FullNode,
    
    /// Edge node: headers-only, ZK proof validation, no mining
    /// - Headers-only blockchain sync (lightweight)
    /// - ZK proof validation without full state
    /// - Optimized for constrained devices (mobile, IoT)
    /// - Limited storage and bandwidth
    EdgeNode,
    
    /// Validator node: full node + active block production
    /// - All FullNode capabilities
    /// - Actively produces blocks
    /// - Requires stake
    /// - Higher uptime requirements
    Validator,
    
    /// Relay node: routing only, no blockchain state
    /// - Network routing and peer discovery
    /// - No blockchain state
    /// - Optimized for connectivity
    /// - Low storage requirements
    Relay,
}

impl NodeType {
    /// Determine node type from config string (called ONCE at startup)
    pub fn from_config_string(config_str: &str) -> Self {
        match config_str.to_lowercase().as_str() {
            "validator" => NodeType::Validator,
            "edge" => NodeType::EdgeNode,
            "relay" => NodeType::Relay,
            "full" | "fullnode" | "full-node" => NodeType::FullNode,
            _ => {
                // Default to FullNode for unknown types
                // Note: Unknown type in config, defaulting to FullNode
                NodeType::FullNode
            }
        }
    }
    
    /// Determine node type from legacy config fields (backward compatibility)
    /// This method handles migration from old boolean-based detection
    pub fn from_legacy_config(
        validator_enabled: bool,
        smart_contracts: bool,
        hosted_storage_gb: u64,
    ) -> Self {
        // Validator nodes must explicitly enable validator mode
        if validator_enabled {
            return NodeType::Validator;
        }
        
        // Edge nodes are constrained devices:
        // - Don't validate blocks
        // - Don't run smart contracts
        // - Don't host much storage (<100GB)
        if !smart_contracts && hosted_storage_gb < 100 {
            return NodeType::EdgeNode;
        }
        
        // Default to full node
        NodeType::FullNode
    }
    
    // === Capability Queries ===
    
    /// Can this node produce blocks?
    pub fn can_produce_blocks(&self) -> bool {
        matches!(self, NodeType::Validator)
    }
    
    /// Can this node validate transactions and blocks?
    pub fn can_validate(&self) -> bool {
        matches!(self, NodeType::FullNode | NodeType::Validator)
    }
    
    /// Does this node need the full blockchain state?
    pub fn needs_full_blockchain(&self) -> bool {
        matches!(self, NodeType::FullNode | NodeType::Validator)
    }
    
    /// Does this node use headers-only sync?
    pub fn is_headers_only(&self) -> bool {
        matches!(self, NodeType::EdgeNode)
    }
    
    /// Does this node store blockchain state?
    pub fn stores_blockchain(&self) -> bool {
        !matches!(self, NodeType::Relay)
    }
    
    /// Can this node run smart contracts?
    pub fn can_run_smart_contracts(&self) -> bool {
        matches!(self, NodeType::FullNode | NodeType::Validator)
    }
    
    /// Should this node enable mining services?
    pub fn should_enable_mining(&self) -> bool {
        matches!(self, NodeType::Validator)
    }
    
    /// Is this a constrained/lightweight node?
    pub fn is_constrained(&self) -> bool {
        matches!(self, NodeType::EdgeNode | NodeType::Relay)
    }
    
    /// Get recommended storage capacity in GB
    pub fn recommended_storage_gb(&self) -> u64 {
        match self {
            NodeType::FullNode => 500,
            NodeType::Validator => 1000,
            NodeType::EdgeNode => 10,
            NodeType::Relay => 1,
        }
    }
    
    /// Get recommended max headers for edge nodes
    pub fn max_headers(&self) -> Option<usize> {
        match self {
            NodeType::EdgeNode => Some(500), // ~100KB storage
            _ => None, // Full nodes store all headers
        }
    }
    
    /// Get minimum stake required (in base units)
    pub fn min_stake_required(&self) -> Option<u64> {
        match self {
            NodeType::Validator => Some(1000),
            _ => None,
        }
    }
    
    /// Get display name for UI
    pub fn display_name(&self) -> &'static str {
        match self {
            NodeType::FullNode => "Full Node",
            NodeType::EdgeNode => "Edge Node",
            NodeType::Validator => "Validator",
            NodeType::Relay => "Relay Node",
        }
    }
    
    /// Get emoji icon for CLI display
    pub fn icon(&self) -> &'static str {
        match self {
            NodeType::FullNode => "🔷",
            NodeType::EdgeNode => "📱",
            NodeType::Validator => "🔶",
            NodeType::Relay => "🔀",
        }
    }
}

impl Default for NodeType {
    fn default() -> Self {
        NodeType::FullNode
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl From<&str> for NodeType {
    fn from(s: &str) -> Self {
        Self::from_config_string(s)
    }
}

impl From<String> for NodeType {
    fn from(s: String) -> Self {
        Self::from_config_string(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_from_config_string() {
        assert_eq!(NodeType::from_config_string("validator"), NodeType::Validator);
        assert_eq!(NodeType::from_config_string("VALIDATOR"), NodeType::Validator);
        assert_eq!(NodeType::from_config_string("edge"), NodeType::EdgeNode);
        assert_eq!(NodeType::from_config_string("Edge"), NodeType::EdgeNode);
        assert_eq!(NodeType::from_config_string("relay"), NodeType::Relay);
        assert_eq!(NodeType::from_config_string("full"), NodeType::FullNode);
        assert_eq!(NodeType::from_config_string("fullnode"), NodeType::FullNode);
        assert_eq!(NodeType::from_config_string("unknown"), NodeType::FullNode);
    }
    
    #[test]
    fn test_from_legacy_config() {
        // Validator
        assert_eq!(
            NodeType::from_legacy_config(true, true, 1000),
            NodeType::Validator
        );
        
        // Edge node (no smart contracts, low storage)
        assert_eq!(
            NodeType::from_legacy_config(false, false, 50),
            NodeType::EdgeNode
        );
        
        // Full node (smart contracts enabled)
        assert_eq!(
            NodeType::from_legacy_config(false, true, 500),
            NodeType::FullNode
        );
        
        // Full node (high storage)
        assert_eq!(
            NodeType::from_legacy_config(false, false, 500),
            NodeType::FullNode
        );
    }
    
    #[test]
    fn test_capabilities() {
        let validator = NodeType::Validator;
        assert!(validator.can_produce_blocks());
        assert!(validator.can_validate());
        assert!(validator.needs_full_blockchain());
        assert!(!validator.is_headers_only());
        assert!(validator.can_run_smart_contracts());
        
        let edge = NodeType::EdgeNode;
        assert!(!edge.can_produce_blocks());
        assert!(!edge.can_validate());
        assert!(!edge.needs_full_blockchain());
        assert!(edge.is_headers_only());
        assert!(!edge.can_run_smart_contracts());
        assert!(edge.is_constrained());
        
        let relay = NodeType::Relay;
        assert!(!relay.stores_blockchain());
        assert!(relay.is_constrained());
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
        assert_eq!(NodeType::EdgeNode.max_headers(), Some(500));
        assert_eq!(NodeType::FullNode.max_headers(), None);
        assert_eq!(NodeType::Validator.max_headers(), None);
    }
    
    #[test]
    fn test_display() {
        assert_eq!(NodeType::Validator.to_string(), "Validator");
        assert_eq!(NodeType::EdgeNode.to_string(), "Edge Node");
        assert_eq!(NodeType::FullNode.display_name(), "Full Node");
        assert_eq!(NodeType::Relay.icon(), "🔀");
    }
}
