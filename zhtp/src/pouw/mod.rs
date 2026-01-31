//! Proof-of-Useful-Work (PoUW) Backend Implementation
//!
//! This module implements the node-side functionality for the PoUW protocol:
//! - Challenge token generation (Phase 1)
//! - Receipt validation (Phase 2)
//! - Reward calculation (Phase 3)
//!
//! Reference: docs/dapps_auth/pouw-protocol-spec.md

pub mod challenge;
pub mod types;

pub use challenge::ChallengeGenerator;
pub use types::*;
