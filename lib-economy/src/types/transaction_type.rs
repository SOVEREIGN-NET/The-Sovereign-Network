//! Transaction types for economic operations
//! 
//! Defines all types of economic transactions in the ZHTP network,
//! from rewards and payments to UBI distribution and governance.

use serde::{Serialize, Deserialize};

/// Types of economic transactions in the ZHTP network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    /// Reward payment for network services (routing, storage, compute)
    Reward,
    /// Standard payment between users
    Payment,
    /// Staking tokens for consensus participation or infrastructure investment
    Stake,
    /// Unstaking tokens from consensus or infrastructure
    Unstake,
    /// Network infrastructure fee payment
    NetworkFee,
    /// DAO fee for Universal Basic Income fund (mandatory 2% on transactions)
    DaoFee,
    /// Token burning (for deflationary mechanics if needed)
    Burn,
    /// Universal Basic Income payment to verified citizens
    UbiDistribution,
    /// Welfare service funding (healthcare, education, infrastructure)
    WelfareDistribution,
    /// DAO proposal voting transaction
    ProposalVote,
    /// DAO proposal execution transaction
    ProposalExecution,
}

impl TransactionType {
    /// Check if this transaction type is fee-exempt
    pub fn is_fee_exempt(&self) -> bool {
        matches!(self, 
            TransactionType::UbiDistribution | 
            TransactionType::WelfareDistribution
        )
    }
    
    /// Check if this transaction type requires DAO fee
    pub fn requires_dao_fee(&self) -> bool {
        !self.is_fee_exempt() && !matches!(self, TransactionType::DaoFee)
    }
    
    /// Get the base gas cost for this transaction type
    pub fn base_gas_cost(&self) -> u64 {
        match self {
            TransactionType::Payment => 1000,
            TransactionType::Reward => 800,
            TransactionType::Stake | TransactionType::Unstake => 1200,
            TransactionType::NetworkFee | TransactionType::DaoFee => 500,
            TransactionType::Burn => 1500,
            TransactionType::UbiDistribution => 0, // Fee-free
            TransactionType::WelfareDistribution => 0, // Fee-free
            TransactionType::ProposalVote => 2000,
            TransactionType::ProposalExecution => 3000,
        }
    }
    
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            TransactionType::Reward => "Network service reward",
            TransactionType::Payment => "User payment",
            TransactionType::Stake => "Stake tokens",
            TransactionType::Unstake => "Unstake tokens",
            TransactionType::NetworkFee => "Network infrastructure fee",
            TransactionType::DaoFee => "DAO fee for UBI fund",
            TransactionType::Burn => "Token burn",
            TransactionType::UbiDistribution => "Universal Basic Income",
            TransactionType::WelfareDistribution => "Welfare service funding",
            TransactionType::ProposalVote => "DAO proposal vote",
            TransactionType::ProposalExecution => "DAO proposal execution",
        }
    }
}
