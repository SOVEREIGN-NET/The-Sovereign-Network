//! Economics Contracts Module
//!
//! This module contains all economic contracts for the SOV system:
//!
//! - `fee_router`: DOC 02 - Fee collection and 45/30/15/10 distribution
//! - `tribute_router`: DOC 04 - 20% tribute enforcement (Week 2)

pub mod fee_router;
pub mod tribute_router;

// Re-export key types
pub use fee_router::{
    DaoDistribution, FeeDistribution, FeeRouter, FeeRouterError, PoolAddresses,
    DAO_ALLOCATION_PERCENT, DEV_ALLOCATION_PERCENT, EMERGENCY_ALLOCATION_PERCENT,
    FEE_RATE_BASIS_POINTS, NUM_SECTOR_DAOS, PER_DAO_ALLOCATION_PERCENT, UBI_ALLOCATION_PERCENT,
};
pub use tribute_router::{
    AntiCircumventionRule, ProfitSettlement, SettlementStatus, TributeRouter, TributeRouterError,
    TRIBUTE_RATE_BASIS_POINTS, TRIBUTE_RATE_PERCENTAGE,
};
