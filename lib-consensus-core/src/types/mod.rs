//! Core consensus value types.
//!
//! Currently populated by:
//! - **CONS-304: `ConsensusRound`** with `state: FsmState`, `entered_at:
//!   Instant`, `deterministic_round_id: u64` and `state_age()` helper.
//!
//! Future relocations (deferred):
//! - `ConsensusStep`, `VoteType`, `ConsensusVote`, `ConsensusProposal`,
//!   and the unified `ValidatorMessage` are still hosted in lib-consensus
//!   because `ConsensusProof::storage_proof` references
//!   `lib_storage::proofs::StorageCapacityAttestation` and adding
//!   lib-storage as a dep on lib-consensus-core is forbidden by AD-002.
//!   The cycle was noted on CONS-104 and CONS-201's deferred Scope B.

pub mod round;

pub use round::ConsensusRound;
