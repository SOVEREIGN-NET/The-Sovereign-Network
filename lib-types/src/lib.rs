//! Sovereign Network primitives.
//! Stable, protocol-neutral, behavior-free.
//!
//! Rule: No String identifiers in consensus state. Ever.

pub mod primitives;
pub mod node_id;
pub mod peer;
pub mod dht;
pub mod chunk;
pub mod errors;
pub mod fees;
pub mod consensus;
pub mod economy;

// Canonical consensus types (Phase 1)
pub use primitives::{Address, Amount, BlockHash, BlockHeight, Bps, TokenId, TxHash};

pub use node_id::NodeId;
pub use peer::PeerId;
pub use dht::*;
pub use chunk::*;
pub use errors::*;
pub use fees::{FeeDeficit, FeeInput, FeeParams, SigScheme, TxKind};
pub use consensus::{
    ConsensusType, UsefulWorkType, ValidatorStatus, VoteType, ConsensusStep,
    SlashType, ConsensusConfig, FeeDistributionResult, MIN_BFT_VALIDATORS,
};
pub use economy::{
    Priority, TransactionType, TreasuryFund, TreasuryOperationType, UbiRecipientCategory,
    WorkMetrics, IspBypassWork, NetworkStats, TreasuryFundData, FundEfficiencyMetrics,
    UbiDistributionStats, MonthlyUbiData, UbiImpactMetrics, TreasuryOperation,
    GovernanceApproval, TreasuryHealthMetrics, TreasurySettings, TreasuryStats,
    SOV_TOTAL_SUPPLY, TRANSACTION_FEE_RATE, UBI_ALLOCATION_PERCENTAGE,
    SECTOR_DAO_ALLOCATION_PERCENTAGE, EMERGENCY_ALLOCATION_PERCENTAGE,
    DEV_GRANT_ALLOCATION_PERCENTAGE, DEFAULT_ROUTING_RATE, DEFAULT_STORAGE_RATE,
    DEFAULT_COMPUTE_RATE, ISP_BYPASS_CONNECTIVITY_RATE, ISP_BYPASS_MESH_RATE,
    ISP_BYPASS_UPTIME_BONUS, QUALITY_BONUS_THRESHOLD, UPTIME_BONUS_THRESHOLD,
    HIGH_UTILIZATION_THRESHOLD, LOW_UTILIZATION_THRESHOLD,
    HIGH_UTILIZATION_ADJUSTMENT, LOW_UTILIZATION_ADJUSTMENT,
};
