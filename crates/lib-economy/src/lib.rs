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

/// Economic constants
pub const DEFAULT_DAO_FEE_RATE: u64 = 200; // 2% in basis points
pub const MINIMUM_DAO_FEE: u64 = 5;
pub const MINIMUM_NETWORK_FEE: u64 = 10;
pub const UBI_ALLOCATION_PERCENTAGE: u64 = 60; // 60% of DAO fees
pub const WELFARE_ALLOCATION_PERCENTAGE: u64 = 40; // 40% of DAO fees

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
