//! Consensus-mechanism proofs (PoS / PoUW).
//!
//! Relocated here from `lib-consensus/src/proofs/` per **CONS-104** and
//! **AD-003** (`docs/epics/consensus-rewrite-decisions.md`). Houses the
//! pure data definitions and self-contained validation. The
//! `verify_*_against_network_state` chain stays in lib-consensus because
//! it references `NetworkState`, `ComputeResult`, and storage-attestation
//! types whose homes (lib-consensus + lib-storage) cannot be pulled into
//! lib-proofs without a cycle.
//!
//! Storage-capacity attestations are NOT moved here — they continue to live
//! in `lib_storage::proofs` (already the canonical home).

pub mod stake_proof;
pub mod work_proof;

pub use stake_proof::{StakeDelegation, StakeProof};
pub use work_proof::{ProofOfUsefulWork, WorkProof};
