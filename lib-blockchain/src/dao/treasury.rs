//! DAO Treasury execution types (dao-2)

use serde::{Deserialize, Serialize};

/// Categorizes a treasury spending proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TreasurySpendingCategory {
    GrantsFunding,
    OperationalBudget,
    SectorDaoAllocation,
    Emergency,
    Infrastructure,
}

/// Parameters embedded in `DaoProposalData.execution_params` for treasury execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryExecutionParams {
    pub category: TreasurySpendingCategory,
    pub recipient_wallet_id: String,
    pub amount: u64,
}
