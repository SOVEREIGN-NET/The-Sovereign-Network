//! DAO Bootstrap Council types and governance phase definitions.

use serde::{Deserialize, Serialize};

/// Governance phase of the DAO.
///
/// Progresses monotonically: Bootstrap → Hybrid → FullDao.
/// Phase transitions are irreversible and recorded on-chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernancePhase {
    /// Phase 0: Bootstrap Council controls all governance decisions.
    /// Voting is restricted to council members.
    #[default]
    Bootstrap = 0,
    /// Phase 1: Hybrid — DAO vote + Council co-sign required for execution.
    Hybrid = 1,
    /// Phase 2: Full DAO — community-governed with time-locked auto-execution.
    FullDao = 2,
}

/// A member of the Bootstrap Council.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CouncilMember {
    /// DID string (e.g. `did:zhtp:...`)
    pub identity_id: String,
    /// Hex-encoded wallet ID
    pub wallet_id: String,
    /// SOV stake committed by this member
    pub stake_amount: u64,
    /// Block height when this member joined the council
    pub joined_at_height: u64,
}

/// Configuration for bootstrapping the initial council, loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouncilBootstrapConfig {
    /// Initial council members
    pub members: Vec<CouncilBootstrapEntry>,
    /// Minimum number of council yes-votes required for execution (default: 4)
    #[serde(default = "default_threshold")]
    pub threshold: u8,
}

impl Default for CouncilBootstrapConfig {
    fn default() -> Self {
        Self { members: Vec::new(), threshold: 4 }
    }
}


fn default_threshold() -> u8 {
    4
}

/// One entry in the council bootstrap configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CouncilBootstrapEntry {
    /// DID of the council member
    pub identity_id: String,
    /// Hex wallet ID of the council member
    pub wallet_id: String,
    /// Initial SOV stake
    pub stake_amount: u64,
}
