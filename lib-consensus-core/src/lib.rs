//! lib-consensus-core — pure BFT consensus FSM with no IO.
//!
//! See `docs/forensics/bft-consensus-architecture-analysis.md` § 3.1 for the
//! target shape. This crate is the destination for the consensus engine code
//! currently in `lib-consensus/src/engines/consensus_engine/` plus the
//! `ValidatorFsm` introduced in CONS-301..302.
//!
//! # Module map (per architecture doc § 3.1)
//!
//! - [`engine`] — `ConsensusEngine`, `RoundTimer`, `TimerToken`. Populated by
//!   CONS-305 (handler migration) and CONS-306/307 (action channel).
//! - [`fsm`] — `FsmState`, `Event`, `Action`, total `transition()`. Populated
//!   by CONS-301..304.
//! - [`types`] — `ConsensusStep`, `VoteType`, `ConsensusVote`,
//!   `ConsensusProposal`, the unified `ValidatorMessage`. Populated by
//!   CONS-201 (message unification).
//! - [`validator_set`] — `ValidatorManager`, snapshots, churn rules.
//! - [`vote_pool`] — `VotePoolKey`, equivocation detection.
//! - [`byzantine`] — `EvidenceStore`, fault classification.
//! - [`invariants`] — `NoFork`, `MonotonicHeight`, `QuorumRequired`,
//!   `FinalityIrreversible`.
//! - [`slashing`] — pure slash math (no policy).
//! - [`ports`] — trait definitions for side-effect adapters
//!   (`MessageBroadcaster`, `BlockFinalizationSink`, `TransportInfo`,
//!   `RewardCallback`, `FeeCallback`, `GovernanceCallback`,
//!   `CatchUpSyncTrigger`).
//! - [`budget`] — consensus-affecting constants
//!   (`WRONG_CHAIN_HALT_THRESHOLD`, `MAX_BROADCAST_BUDGET_MS`, etc.). Populated
//!   by CONS-310.

#![forbid(unsafe_code)]

pub mod budget;
pub mod byzantine;
pub mod engine;
pub mod fsm;
pub mod invariants;
pub mod ports;
pub mod slashing;
pub mod types;
pub mod validator_set;
pub mod vote_pool;
