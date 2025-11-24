//! State proof system for aggregated blockchain state verification
//! 
//! This module provides ZKP-based state proofs that allow new nodes to bootstrap
//! without downloading the entire blockchain history. It supports hierarchical
//! mesh networks with dynamic connectivity and on-demand proof generation.

pub mod state_proof;
pub mod aggregation;
pub mod bootstrap;
pub mod verification;

pub use state_proof::*;
pub use aggregation::*;
pub use bootstrap::*;
pub use verification::*;