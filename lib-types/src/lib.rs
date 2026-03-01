//! Sovereign Network primitives.
//! Stable, protocol-neutral, behavior-free.
//!
//! Rule: No String identifiers in consensus state. Ever.

pub mod chunk;
pub mod consensus;
pub mod dht;
pub mod economy;
pub mod errors;
pub mod fees;
pub mod mempool;
pub mod node_id;
pub mod peer;
pub mod primitives;
pub mod storage;

// Canonical consensus types (Phase 1)
pub use primitives::{Address, Amount, BlockHash, BlockHeight, Bps, TokenId, TxHash};

pub use chunk::*;
pub use consensus::{
    ConsensusConfig, ConsensusStep, ConsensusType, FeeDistributionResult, SlashType,
    UsefulWorkType, ValidatorStatus, VoteType, MIN_BFT_VALIDATORS,
};
pub use dht::*;
pub use economy::{
    FundEfficiencyMetrics, GovernanceApproval, IspBypassWork, MonthlyUbiData, NetworkStats,
    Priority, TransactionType, TreasuryFund, TreasuryFundData, TreasuryHealthMetrics,
    TreasuryOperation, TreasuryOperationType, TreasurySettings, TreasuryStats,
    UbiDistributionStats, UbiImpactMetrics, UbiRecipientCategory, WorkMetrics,
    DEFAULT_COMPUTE_RATE, DEFAULT_ROUTING_RATE, DEFAULT_STORAGE_RATE,
    DEV_GRANT_ALLOCATION_PERCENTAGE, EMERGENCY_ALLOCATION_PERCENTAGE, HIGH_UTILIZATION_ADJUSTMENT,
    HIGH_UTILIZATION_THRESHOLD, ISP_BYPASS_CONNECTIVITY_RATE, ISP_BYPASS_MESH_RATE,
    ISP_BYPASS_UPTIME_BONUS, LOW_UTILIZATION_ADJUSTMENT, LOW_UTILIZATION_THRESHOLD,
    QUALITY_BONUS_THRESHOLD, SECTOR_DAO_ALLOCATION_PERCENTAGE, SOV_TOTAL_SUPPLY,
    TRANSACTION_FEE_RATE, UBI_ALLOCATION_PERCENTAGE, UPTIME_BONUS_THRESHOLD,
};
pub use errors::*;
pub use fees::{FeeDeficit, FeeInput, FeeParams, SigScheme, TxKind};
pub use node_id::NodeId;
pub use peer::PeerId;
pub use storage::StorageStats;
