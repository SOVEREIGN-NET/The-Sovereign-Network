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
//! - `pol_pool`: Issue #1849 - Protocol-Owned Liquidity pool

pub mod amm_pool;
pub mod canonical;
pub mod event_indexer;
pub mod events;
pub mod pol_pool;
pub mod pricing;
pub mod registry;
pub mod token;
pub mod types;

// Re-export core types
pub use amm_pool::{
    AmmPool,
    create_amm_pool_for_graduated_token,
    create_pol_pool_for_graduated_token,
    AmmPoolCreationResult,
    // Issue #1848: AMM pool creation constants
    GRADUATED_POOL_FEE_BPS, MINIMUM_AMM_LIQUIDITY,
};
pub use canonical::{
    Band as CanonicalBand, BondingCurveBuyReceipt, BondingCurveBuyTx, BondingCurveSellReceipt,
    BondingCurveSellTx, BAND_COUNT as CANONICAL_BAND_COUNT, BANDS as CANONICAL_BANDS,
    INTERCEPT_0, MAX_DELTA_S_PER_TX, MAX_GROSS_SOV_PER_TX, MAX_SUPPLY as CANONICAL_MAX_SUPPLY,
    SCALE as CANONICAL_SCALE, integer_sqrt,
};
// Issue #1849: Re-export POL pool
pub use pol_pool::{
    PolPool, PolPoolError, BASIS_POINTS_DENOMINATOR, POL_FEE_BPS,
    POL_MINIMUM_INITIAL_LIQUIDITY,
};
pub use event_indexer::SledEventIndexer;
pub use events::{BondingCurveEvent, EventIndexer, InMemoryEventIndexer, ReserveUpdateReason};
pub use pricing::PiecewiseLinearCurve;
pub use registry::{BondingCurveRegistry, RegistryStats};
pub use token::{BondingCurveToken, RESERVE_SPLIT_DENOMINATOR, RESERVE_SPLIT_NUMERATOR};
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
