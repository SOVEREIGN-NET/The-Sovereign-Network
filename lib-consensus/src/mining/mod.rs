//! Mining coordination module
//!
//! This module provides consensus-based block proposer selection for mining coordination.
//! It helps determine whether a node should mine based on validator consensus.

use anyhow::Result;
use tracing::{info, warn};

use crate::validators::ValidatorManager;
use lib_crypto::Hash;
use lib_identity::IdentityId;

/// Helper function to check if a node should mine the next block based on consensus
///
/// # Arguments
/// * `validator_manager` - The validator manager for consensus coordination
/// * `node_identity` - The node's identity ID
/// * `current_height` - Current blockchain height
/// * `consensus_round` - Current consensus round
/// * `identity_registry` - Identity registry mapping DIDs to identity data
///
/// # Returns
/// * `Ok(true)` - Node should mine (selected as proposer or no validators registered)
/// * `Ok(false)` - Node should wait (not selected as proposer)
/// * `Err(_)` - Error during consensus check
pub async fn should_mine_block(
    validator_manager: &ValidatorManager,
    node_identity: &IdentityId,
    current_height: u64,
    consensus_round: u32,
    identity_registry: &std::collections::HashMap<String, IdentityData>,
) -> Result<bool> {
    // Get active validators from validator manager
    let active_validators = validator_manager.get_active_validators();

    // Check if there are any active validators
    if active_validators.is_empty() {
        // No validators yet - any node can mine (bootstrap phase)
        warn!(
            "⛏️ BOOTSTRAP MODE: No validators registered in consensus, mining without coordination"
        );
        warn!("   → This means validator sync from blockchain failed!");
        return Ok(true);
    }

    // Select proposer using consensus
    info!(
        "CONSENSUS ACTIVE: {} validators registered",
        active_validators.len()
    );
    let next_height = current_height + 1;

    if let Some(proposer) = validator_manager.select_proposer(next_height, consensus_round) {
        // Check if this node is the selected proposer
        let is_proposer = check_if_proposer(node_identity, &proposer.identity, identity_registry)?;

        if is_proposer {
            info!(
                "CONSENSUS: This node selected as block proposer for height {} (round {})",
                next_height, consensus_round
            );
            Ok(true)
        } else {
            info!(
                "CONSENSUS: Waiting - proposer is {:?} (round {})",
                hex::encode(&proposer.identity.as_bytes()[..8]),
                consensus_round
            );
            Ok(false)
        }
    } else {
        warn!("CONSENSUS: No proposer selected, falling back to permissionless mining");
        Ok(true)
    }
}

/// Check if this node's owner is the selected proposer
///
/// This function handles the architecture where:
/// - Validators are USER DIDs (humans/orgs)
/// - Nodes are DEVICE identities controlled by USER DIDs  
/// - node_id = NODE device IdentityId
/// - Validator manager stores the original IdentityId Hash
/// - proposer.identity = original IdentityId Hash from DID
fn check_if_proposer(
    node_identity: &IdentityId,
    proposer_identity: &Hash,
    identity_registry: &std::collections::HashMap<String, IdentityData>,
) -> Result<bool> {
    let node_id_hex = hex::encode(node_identity.as_bytes());

    info!(
        "IDENTITY MATCHING: Looking for node '{}' in identity registry",
        node_id_hex
    );
    info!(
        "IDENTITY MATCHING: Identity registry has {} entries",
        identity_registry.len()
    );
    info!(
        "IDENTITY MATCHING: Proposer identity = {}",
        hex::encode(&proposer_identity.as_bytes())
    );

    // Scan identity registry to find which USER controls this node
    for (did_string, identity_data) in identity_registry.iter() {
        // Check if this USER identity's controlled_nodes contains our node
        if identity_data.controlled_nodes.contains(&node_id_hex) {
            let did_preview = if did_string.len() > 70 {
                &did_string[..70]
            } else {
                did_string
            };

            info!(
                "FOUND MATCHING USER: This node is controlled by {}",
                did_preview
            );

            // Extract the hex part from DID and convert to Hash
            if let Some(identity_hex) = did_string.strip_prefix("did:zhtp:") {
                if let Ok(identity_bytes) = hex::decode(identity_hex) {
                    if identity_bytes.len() < 32 {
                        warn!("Identity bytes too short: {} bytes", identity_bytes.len());
                        continue;
                    }

                    let user_identity_hash = Hash::from_bytes(&identity_bytes[..32]);

                    info!(
                        "User identity hash: {}",
                        hex::encode(&user_identity_hash.as_bytes())
                    );

                    // Compare original identity Hash with proposer's identity
                    if user_identity_hash == *proposer_identity {
                        info!(
                            "Node owner is proposer: {}",
                            &did_string[..32.min(did_string.len())]
                        );
                        info!(
                            "  Node device ID: {}",
                            &node_id_hex[..32.min(node_id_hex.len())]
                        );
                        return Ok(true);
                    } else {
                        info!("User identity does NOT match proposer");
                    }
                } else {
                    warn!("Failed to decode identity hex from DID");
                }
            } else {
                warn!("DID format invalid: {}", did_string);
            }
        }
    }

    info!("IDENTITY MATCHING FAILED: This node's owner is NOT the selected proposer");
    Ok(false)
}

/// Identity data structure for mining coordination
///
/// This is a simplified view of blockchain's IdentityTransactionData,
/// containing only the fields needed for mining coordination.
#[derive(Debug, Clone)]
pub struct IdentityData {
    /// List of node device IDs (hex strings) controlled by this identity
    pub controlled_nodes: Vec<String>,
}

impl IdentityData {
    /// Create new identity data
    pub fn new(controlled_nodes: Vec<String>) -> Self {
        Self { controlled_nodes }
    }

    /// Create from blockchain's IdentityTransactionData controlled_nodes field
    pub fn from_controlled_nodes(controlled_nodes: Vec<String>) -> Self {
        Self { controlled_nodes }
    }
}
