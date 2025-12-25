//! Satellite Protocol Suite
//!
//! Long-distance mesh networking via satellite:
//! - Satellite link establishment and teardown
//! - Low-bandwidth message routing
//! - Global connectivity for remote mesh nodes

pub mod satellite;

// Re-exports for convenience
pub use self::satellite::*;
