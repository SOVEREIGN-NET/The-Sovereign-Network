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

pub mod types;
pub mod events;
pub mod token;
pub mod registry;
pub mod event_indexer;

// Re-export core types
pub use types::{
    Phase, CurveType, Threshold, CurveStats, CurveError,
    ConfidenceLevel, Valuation, PriceSource,
};
pub use events::{
    BondingCurveEvent, ReserveUpdateReason, EventIndexer, InMemoryEventIndexer,
};
pub use event_indexer::SledEventIndexer;
pub use token::BondingCurveToken;
pub use registry::{BondingCurveRegistry, RegistryStats};

/// Default token decimals
pub const DEFAULT_DECIMALS: u8 = 8;

/// Stablecoin decimals (e.g., USDC)
pub const STABLE_DECIMALS: u8 = 6;
