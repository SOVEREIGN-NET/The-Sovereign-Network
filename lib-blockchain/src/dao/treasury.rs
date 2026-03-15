//! DAO Treasury execution types (dao-2)

use serde::{Deserialize, Serialize};

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
