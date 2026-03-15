//! DAO Treasury execution types (dao-2)

use serde::{Deserialize, Serialize};

/// Canonical `proposal_type` string for treasury allocation proposals.
/// Used everywhere `DaoProposalData.proposal_type` is compared or set.
pub const TREASURY_ALLOCATION_PROPOSAL_TYPE: &str = "treasury_allocation";

/// Decode a lowercase-hex-encoded 32-byte value (with or without `0x` prefix).
pub fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let decoded = hex::decode(trimmed).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Some(out)
}

/// Categorizes a treasury spending proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TreasurySpendingCategory {
    GrantsFunding,
    OperationalBudget,
    SectorDaoAllocation,
    Emergency,
    Infrastructure,
}

/// Canonical treasury source for governance-controlled SOV allocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TreasurySource {
    /// The nonprofit treasury registered in EntityRegistry.
    Nonprofit,
}

/// Parameters embedded in `DaoProposalData.execution_params` for treasury execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryExecutionParams {
    #[serde(default = "default_treasury_execution_schema_version")]
    pub schema_version: u8,
    pub category: TreasurySpendingCategory,
    pub source_treasury: TreasurySource,
    pub source_wallet_id: String,
    pub destination_dao_id: String,
    pub recipient_wallet_id: String,
    pub amount: u64,
}

const fn default_treasury_execution_schema_version() -> u8 {
    1
}
