//! Core consensus value types.
//!
//! Populated by:
//! - **CONS-304: `ConsensusRound`** with `state: FsmState`, `entered_at:
//!   Instant`, `deterministic_round_id: u64` and `state_age()` helper.
//! - **CONS-201 Scope B: `ConsensusProof`, `ConsensusProposal`,
//!   `ConsensusVote`** — moved from `lib-consensus/src/types/mod.rs`.
//!   The proof fields became opaque `Option<Vec<u8>>` to satisfy
//!   AD-002 (no `lib-storage` / `lib-proofs` dep). Encode/decode
//!   ergonomics live on `lib_consensus::ConsensusProofExt`.
//!
//! Still hosted in lib-consensus:
//! - The unified `ValidatorMessage` enum and `Justification` struct —
//!   they live next to the network codec until CONS-501b moves them
//!   alongside `lib-consensus-net`'s remaining modules.

pub mod messages;
pub mod proposal;
pub mod round;

pub use messages::{
    ConsensusStateView, HaltMessage, HeartbeatMessage, Justification, NetworkSummary,
    ProposeMessage, ValidatorMessage, VoteMessage,
};
pub use proposal::{ConsensusProof, ConsensusProposal, ConsensusVote};
pub use round::ConsensusRound;
