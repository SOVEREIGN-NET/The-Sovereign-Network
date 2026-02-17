//! Identity module for unified peer identification
//!
//! # Security Enhancements
//!
//! - **CRITICAL FIX C1**: Proof-of-Work module prevents Sybil attacks
//! - **CRITICAL FIX C3**: Atomic state updates prevent race conditions
//! - **#984**: Sybil resistance via validator-set membership check

pub mod proof_of_work;
pub mod sybil_resistance;
pub mod unified_peer;

pub use proof_of_work::{ProofOfWork, calculate_adaptive_difficulty};
pub use sybil_resistance::{
    assert_consensus_sender_is_validator,
    assert_peer_identity_valid,
};
pub use unified_peer::{UnifiedPeerId, PeerIdMapper, PeerMapperConfig};
