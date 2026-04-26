//! Mining coordination module
//!
//! This module provides consensus-based block proposer selection for mining coordination.
//! It helps determine whether a node should mine based on validator consensus.

use anyhow::Result;
use tracing::{info, warn};

use lib_consensus::ValidatorManager;
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

/// Check if this node's owner is the selected proposer.
///
/// Architecture:
/// - Validators are USER DIDs (humans/orgs).
/// - Nodes are DEVICE identities controlled by USER DIDs.
/// - `node_identity` = the local NODE device's IdentityId.
/// - `proposer_identity` = the USER identity Hash chosen by `select_proposer`.
/// - `identity_registry` maps each USER DID string to its controlled nodes.
///
/// Walks the registry, finds the USER that owns this node, and compares the
/// USER's identity hash to the proposer's. Logs only the loaded-bearing
/// outcomes (match found / search failed / malformed DIDs); per-candidate
/// "did not match" noise is dropped — that case fires once per non-matching
/// validator and only obscures real signal.
fn check_if_proposer(
    node_identity: &IdentityId,
    proposer_identity: &Hash,
    identity_registry: &std::collections::HashMap<String, IdentityData>,
) -> Result<bool> {
    let node_id_hex = hex::encode(node_identity.as_bytes());

    for (did_string, identity_data) in identity_registry.iter() {
        if !identity_data.controlled_nodes.contains(&node_id_hex) {
            continue;
        }

        let user_identity_hash = match decode_did_user_identity(did_string) {
            Some(hash) => hash,
            None => continue,
        };

        if user_identity_hash == *proposer_identity {
            info!(
                did = &did_string[..32.min(did_string.len())],
                node_device = &node_id_hex[..32.min(node_id_hex.len())],
                "node owner is proposer"
            );
            return Ok(true);
        }
    }

    info!(
        node = &node_id_hex[..16.min(node_id_hex.len())],
        registry_size = identity_registry.len(),
        "this node's owner is not the selected proposer"
    );
    Ok(false)
}

/// Decode the 32-byte USER identity hash from a `did:zhtp:<hex>` string.
///
/// Returns `None` (and warns) for malformed DIDs — non-`did:zhtp:` prefix,
/// non-hex body, or fewer than 32 decoded bytes. Callers skip such entries
/// rather than aborting the registry scan.
fn decode_did_user_identity(did_string: &str) -> Option<Hash> {
    let identity_hex = match did_string.strip_prefix("did:zhtp:") {
        Some(hex) => hex,
        None => {
            warn!(did = did_string, "DID format invalid: missing did:zhtp: prefix");
            return None;
        }
    };

    let identity_bytes = match hex::decode(identity_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            warn!(did = did_string, "failed to decode identity hex from DID");
            return None;
        }
    };

    if identity_bytes.len() < 32 {
        warn!(
            did = did_string,
            len = identity_bytes.len(),
            "DID identity bytes too short"
        );
        return None;
    }

    Some(Hash::from_bytes(&identity_bytes[..32]))
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
