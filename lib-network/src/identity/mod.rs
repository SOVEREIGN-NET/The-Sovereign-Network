//! Identity module for unified peer identification
//!
//! # Security Enhancements
//!
//! - **CRITICAL FIX C1**: Proof-of-Work module prevents Sybil attacks
//! - **CRITICAL FIX C3**: Atomic state updates prevent race conditions

pub mod proof_of_work;
pub mod unified_peer;

pub use proof_of_work::{ProofOfWork, calculate_adaptive_difficulty};
pub use unified_peer::{UnifiedPeerId, PeerIdMapper, PeerMapperConfig};
