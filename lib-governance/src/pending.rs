//! Pending Governance Changes
//!
//! Structures for tracking governance changes that are waiting to activate.
//! These are stored in chain state and applied at the specified block height.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use lib_types::{BlockHeight, TokenId};

use crate::fields::ConfigField;
use crate::tx::GovernanceConfigTx;
use crate::errors::{GovernanceError, GovernanceResult};

/// A pending configuration change
///
/// Created when a GovernanceConfigTx is accepted and stored until activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChange {
    /// Target token or contract
    pub target: TokenId,
    /// Field being modified
    pub field: ConfigField,
    /// Hash of new value
    pub new_value_hash: [u8; 32],
    /// Block height when submitted
    pub submitted_at: BlockHeight,
    /// Block height when it activates
    pub activates_at: BlockHeight,
    /// Transaction hash that created this change
    pub tx_hash: [u8; 32],
}

impl PendingChange {
    /// Create from a governance transaction
    pub fn from_tx(tx: &GovernanceConfigTx, submitted_at: BlockHeight, tx_hash: [u8; 32]) -> Self {
        Self {
            target: tx.target,
            field: tx.field,
            new_value_hash: tx.new_value_hash,
            submitted_at,
            activates_at: tx.activates_at,
            tx_hash,
        }
    }

    /// Check if this change should activate at the given height
    pub fn should_activate(&self, height: BlockHeight) -> bool {
        height >= self.activates_at
    }

    /// Get unique identifier for this change (target + field)
    ///
    /// Uses Blake3 hash for deterministic IDs across all nodes.
    pub fn change_id(&self) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new();

        // Domain separator for governance change IDs
        hasher.update(b"ZHTP_GOVERNANCE_CHANGE_V1");
        hasher.update(self.target.as_bytes());

        // Serialize ConfigField deterministically
        let field_bytes = bincode::serialize(&self.field)
            .expect("ConfigField must be serializable");
        hasher.update(&field_bytes);

        *hasher.finalize().as_bytes()
    }
}

/// Collection of pending governance changes
///
/// Stored in chain state and queried during block execution.
/// Uses BTreeMap for deterministic ordering by activation height.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingChanges {
    /// Changes indexed by activation height, then by change_id
    by_height: BTreeMap<BlockHeight, Vec<PendingChange>>,
    /// Quick lookup by change_id to detect conflicts
    by_id: BTreeMap<[u8; 32], BlockHeight>,
}

impl PendingChanges {
    /// Create empty pending changes
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new pending change
    ///
    /// Returns error if there's already a pending change for the same target+field
    pub fn add(&mut self, change: PendingChange) -> GovernanceResult<()> {
        let change_id = change.change_id();

        // Check for existing change to same target+field
        if let Some(&existing_height) = self.by_id.get(&change_id) {
            return Err(GovernanceError::ConflictingChange {
                target: change.target,
                field: change.field,
                existing_activation: existing_height,
            });
        }

        // Add to indexes
        let height = change.activates_at;
        self.by_height.entry(height).or_default().push(change);
        self.by_id.insert(change_id, height);

        Ok(())
    }

    /// Get all changes that should activate at the given height
    pub fn get_activating(&self, height: BlockHeight) -> Vec<&PendingChange> {
        self.by_height
            .get(&height)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Remove and return all changes that should activate at the given height
    pub fn take_activating(&mut self, height: BlockHeight) -> Vec<PendingChange> {
        if let Some(changes) = self.by_height.remove(&height) {
            // Remove from by_id index
            for change in &changes {
                self.by_id.remove(&change.change_id());
            }
            changes
        } else {
            Vec::new()
        }
    }

    /// Check if there's a pending change for a target+field
    pub fn has_pending(&self, target: &TokenId, field: ConfigField) -> bool {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        target.as_bytes().hash(&mut hasher);
        field.hash(&mut hasher);

        let hash = hasher.finish();
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());

        self.by_id.contains_key(&id)
    }

    /// Cancel a pending change (governance veto)
    pub fn cancel(&mut self, target: &TokenId, field: ConfigField) -> Option<PendingChange> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        target.as_bytes().hash(&mut hasher);
        field.hash(&mut hasher);

        let hash = hasher.finish();
        let mut change_id = [0u8; 32];
        change_id[..8].copy_from_slice(&hash.to_le_bytes());

        if let Some(height) = self.by_id.remove(&change_id) {
            if let Some(changes) = self.by_height.get_mut(&height) {
                if let Some(pos) = changes.iter().position(|c| c.change_id() == change_id) {
                    return Some(changes.remove(pos));
                }
            }
        }
        None
    }

    /// Get total number of pending changes
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Check if there are no pending changes
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Get all pending changes (for serialization/debugging)
    pub fn all_changes(&self) -> impl Iterator<Item = &PendingChange> {
        self.by_height.values().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_change(field: ConfigField, activates_at: BlockHeight) -> PendingChange {
        PendingChange {
            target: TokenId::default(),
            field,
            new_value_hash: [0u8; 32],
            submitted_at: 100,
            activates_at,
            tx_hash: [0u8; 32],
        }
    }

    #[test]
    fn test_add_and_get_activating() {
        let mut pending = PendingChanges::new();

        let change1 = create_test_change(ConfigField::TransferFeeBps, 200);
        let change2 = create_test_change(ConfigField::BurnFeeBps, 200);
        let change3 = create_test_change(ConfigField::FeeCap, 300);

        pending.add(change1).unwrap();
        pending.add(change2).unwrap();
        pending.add(change3).unwrap();

        assert_eq!(pending.len(), 3);

        // Get changes at height 200
        let activating = pending.get_activating(200);
        assert_eq!(activating.len(), 2);

        // Get changes at height 300
        let activating = pending.get_activating(300);
        assert_eq!(activating.len(), 1);
    }

    #[test]
    fn test_conflicting_change_rejected() {
        let mut pending = PendingChanges::new();

        let change1 = create_test_change(ConfigField::TransferFeeBps, 200);
        let change2 = create_test_change(ConfigField::TransferFeeBps, 300); // Same field, different height

        pending.add(change1).unwrap();
        let result = pending.add(change2);

        assert!(matches!(result, Err(GovernanceError::ConflictingChange { .. })));
    }

    #[test]
    fn test_take_activating() {
        let mut pending = PendingChanges::new();

        let change1 = create_test_change(ConfigField::TransferFeeBps, 200);
        let change2 = create_test_change(ConfigField::BurnFeeBps, 200);

        pending.add(change1).unwrap();
        pending.add(change2).unwrap();

        assert_eq!(pending.len(), 2);

        let taken = pending.take_activating(200);
        assert_eq!(taken.len(), 2);
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_cancel() {
        let mut pending = PendingChanges::new();

        let change = create_test_change(ConfigField::TransferFeeBps, 200);
        pending.add(change).unwrap();

        assert!(pending.has_pending(&TokenId::default(), ConfigField::TransferFeeBps));

        let cancelled = pending.cancel(&TokenId::default(), ConfigField::TransferFeeBps);
        assert!(cancelled.is_some());
        assert!(!pending.has_pending(&TokenId::default(), ConfigField::TransferFeeBps));
    }
}
