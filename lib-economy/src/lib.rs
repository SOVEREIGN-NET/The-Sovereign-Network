//! SOV Economics Engine
//! 
//! Post-scarcity economics system for the quantum-resistant Web4 internet that replaces ISPs.
//! Provides economic models, rewards calculation, wallet management, transaction 
//! processing, Universal Basic Income distribution, and incentives.
//! 
//! ISP REPLACEMENT ECONOMICS 
//! 
//! The Sovereign Network creates a free internet by incentivizing users to share resources:
//! - Route packets: Earn SOV tokens for bandwidth sharing (replaces ISP revenue)
//! - Store content: Earn SOV tokens for distributed storage (replaces CDN revenue) 
//! - Validate transactions: Earn SOV tokens for network security (replaces authority fees)
//! - Share internet: Earn SOV tokens for connectivity sharing (crowd-sourced ISP)
//! 
//! ALL PARTICIPANTS RECEIVE UBI:
//! - 2% of all network activity funds Universal Basic Income
//! - DAO governance distributes UBI to all verified humans
//! - Network growth funds welfare and public services
//! - Creates a sustainable society where technology serves everyone
//! 
//! ECONOMIC MODEL: Post-scarcity economics through abundant network resources

pub mod wasm;
pub mod types;
pub mod models;
pub mod transactions;
pub mod wallets;
pub mod incentives;
pub mod distribution;
pub mod treasury_economics;
pub mod supply;
pub mod pricing;
pub mod integration;
pub mod testing;
pub mod rewards;
pub mod network_types;
pub mod tokens;
pub mod fee_distribution;

// Re-export main types and functions
pub use types::*;
pub use models::*; // All models exports are okay
pub use transactions::*;
pub use wallets::*;
pub use incentives::*;
pub use distribution::*;
pub use treasury_economics::*;
pub use supply::{management, total_supply}; // Module-level exports to avoid conflicts
pub use pricing::*;
pub use rewards::*;
pub use tokens::*;
pub use fee_distribution::{distribute_fee, FeeDistribution, FeeDistributionError, SectorDao};

/// Economic constants - aligned with financial projections (docs/sov_final/)
///
/// Total SOV supply: 1 trillion tokens (fixed, not inflationary)
pub const SOV_TOTAL_SUPPLY: u64 = 1_000_000_000_000; // 1 trillion

/// Transaction fee rate: 1% (expressed in basis points)
/// Fee amount = (transaction_amount * TRANSACTION_FEE_RATE) / 10000
pub const TRANSACTION_FEE_RATE: u64 = 100; // 1% in basis points
pub const DEFAULT_DAO_FEE_RATE: u64 = 100; // 1% in basis points

pub const MINIMUM_DAO_FEE: u64 = 5;
pub const MINIMUM_NETWORK_FEE: u64 = 10;

/// Fee allocation percentages (must sum to 100%)
/// Applied to 1% transaction fee across all transactions
///
/// Example Year 3 projection: $500M monthly volume
/// - 1% fee collected = $5M
/// - UBI (45%): $2.25M
/// - Sector DAOs (30%): $1.5M (6% each to Healthcare, Education, Energy, Housing, Food)
/// - Emergency Reserve (15%): $750K
/// - Dev Grants (10%): $500K
pub const UBI_ALLOCATION_PERCENTAGE: u64 = 45; // 45% → Universal Basic Income
pub const SECTOR_DAO_ALLOCATION_PERCENTAGE: u64 = 30; // 30% → Sector DAOs (5 DAOs × 6% each)
#[deprecated(note = "Use SECTOR_DAO_ALLOCATION_PERCENTAGE instead; this constant refers specifically to Sector DAOs.")]
pub const DAO_ALLOCATION_PERCENTAGE: u64 = SECTOR_DAO_ALLOCATION_PERCENTAGE; // Backwards-compatible alias
pub const EMERGENCY_ALLOCATION_PERCENTAGE: u64 = 15; // 15% → Emergency Reserve Fund
pub const DEV_GRANT_ALLOCATION_PERCENTAGE: u64 = 10; // 10% → Development Grants

/// Phase 1 temporary allocation (kept for compatibility)
///
/// Phase 1 allocation: 45% UBI + 40% Welfare = 85% (15% reserved)
/// Phase 2+ allocation: 45% UBI + 30% DAOs + 15% Emergency + 10% Dev Grants = 100%
///
/// This constant represents the temporary Phase 1 welfare bucket that will be
/// split into separate DAOs, Emergency Reserves, and Dev Grants contracts in Phase 2.
/// The 40% value is a transitional value kept for backwards compatibility.
pub const WELFARE_ALLOCATION_PERCENTAGE: u64 = 40; // Phase 1 temporary - superseded in Phase 2+

/// ISP replacement economic constants
pub const DEFAULT_ROUTING_RATE: u64 = 1; // SOV per MB routed
pub const DEFAULT_STORAGE_RATE: u64 = 10; // SOV per GB stored per month
pub const DEFAULT_COMPUTE_RATE: u64 = 5; // SOV per validation
pub const ISP_BYPASS_CONNECTIVITY_RATE: u64 = 100; // SOV per GB shared
pub const ISP_BYPASS_MESH_RATE: u64 = 1; // SOV per MB routed
pub const ISP_BYPASS_UPTIME_BONUS: u64 = 10; // SOV per hour uptime

/// Staking and infrastructure investment constants
pub const LARGE_INFRASTRUCTURE_THRESHOLD: u64 = 100_000; // SOV threshold for large infrastructure
pub const LARGE_INFRASTRUCTURE_DAILY_YIELD: u64 = 10000; // 0.01% daily yield (divisor)
pub const SMALL_INFRASTRUCTURE_DAILY_YIELD: u64 = 5000; // 0.02% daily yield (divisor)
pub const MAX_ANNUAL_YIELD_PERCENTAGE: u64 = 10; // 10% max annual return

/// Network utilization thresholds
pub const HIGH_UTILIZATION_THRESHOLD: f64 = 0.9; // 90%
pub const LOW_UTILIZATION_THRESHOLD: f64 = 0.3; // 30%
pub const HIGH_UTILIZATION_ADJUSTMENT: u64 = 105; // +5%
pub const LOW_UTILIZATION_ADJUSTMENT: u64 = 98; // -2%

/// Quality and uptime bonus thresholds
pub const QUALITY_BONUS_THRESHOLD: f64 = 0.95; // 95% quality
pub const UPTIME_BONUS_THRESHOLD: u64 = 23; // 23 hours (99%+ uptime)
pub const MESH_CONNECTIVITY_THRESHOLD: u32 = 3; // Minimum peers for mesh rewards

#[cfg(test)]
mod invariant_tests {
    use super::*;

    #[test]
    fn allocation_percentages_sum_to_100() {
        // Invariant: Fee allocation must sum to exactly 100% (no gaps, no overflow)
        // This ensures all collected fees are accounted for
        let total = UBI_ALLOCATION_PERCENTAGE
            + DAO_ALLOCATION_PERCENTAGE
            + EMERGENCY_ALLOCATION_PERCENTAGE
            + DEV_GRANT_ALLOCATION_PERCENTAGE;

        assert_eq!(
            total, 100,
            "Fee allocation percentages must sum to 100%, but got: UBI={}% + DAO={}% + EMERGENCY={}% + DEV={}% = {}%",
            UBI_ALLOCATION_PERCENTAGE,
            DAO_ALLOCATION_PERCENTAGE,
            EMERGENCY_ALLOCATION_PERCENTAGE,
            DEV_GRANT_ALLOCATION_PERCENTAGE,
            total
        );
    }
}
