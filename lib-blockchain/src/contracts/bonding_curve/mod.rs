//! Bonding Curve Token System
//!
//! Two-phase lifecycle for user-issued tokens:
//! Phase 1: Bonding Curve (protocol-controlled price + liquidity)
//! Phase 2: AMM (market-driven liquidity + price discovery)
//!
//! # State Machine
//! ```text
//!   ┌─────────┐     Threshold Met      ┌───────────┐     Pool Seeded      ┌─────┐
//!   │  Curve  │ ─────────────────────▶ │ Graduated │ ──────────────────▶ │ AMM │
//!   └─────────┘    (irreversible)      └───────────┘    (irreversible)   └─────┘
//! ```
//!
//! # Architecture
//! - `BondingCurveToken`: Core contract with state machine
//! - `BondingCurveRegistry`: Index of all curve tokens
//! - `types`: State machine types, pricing formulas, thresholds
//! - `events`: Event types for indexing

pub mod amm_pool;
pub mod event_indexer;
pub mod events;
pub mod pricing;
pub mod registry;
pub mod token;
pub mod types;

// Re-export core types
pub use amm_pool::{
    create_amm_pool_for_graduated_token,
    AmmPoolCreationResult,
    // Issue #1848: AMM pool creation constants
    GRADUATED_POOL_FEE_BPS, LP_TOKEN_LOCK_ADDRESS, MINIMUM_AMM_LIQUIDITY, PRICE_SCALE,
};
pub use event_indexer::SledEventIndexer;
pub use events::{BondingCurveEvent, EventIndexer, InMemoryEventIndexer, ReserveUpdateReason};
pub use pricing::PiecewiseLinearCurve;
pub use registry::{BondingCurveRegistry, RegistryStats};
pub use token::{BondingCurveToken, RESERVE_SPLIT_DIVISOR};
pub use types::{
    ConfidenceLevel, CurveError, CurveStats, CurveType, Phase, PriceSource, Threshold, Valuation,
    // Issue #1846: Graduation threshold constants
    GRADUATION_CONFIRMATION_BLOCKS, GRADUATION_THRESHOLD_USD, MAX_ORACLE_PRICE_AGE_SECONDS,
    USD_PRICE_SCALE,
};

/// Default token decimals
pub const DEFAULT_DECIMALS: u8 = 8;

/// Stablecoin decimals (e.g., USDC)
pub const STABLE_DECIMALS: u8 = 6;
