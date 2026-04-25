//! lib-consensus-runtime — orchestration glue for `lib-consensus-core`.
//!
//! See `docs/forensics/bft-consensus-architecture-analysis.md` § 3.4 for the
//! target shape. `ConsensusRuntime` is the single owner of:
//!
//! - the `ConsensusEngine` (wired from `lib-consensus-core::engine`)
//! - the `Action` executor task (drains the engine's `action_rx`, dispatches
//!   broadcast / finalization / commit-failure handling)
//! - the watchdog task (CONS-309)
//! - the catch-up sync task (moved from `zhtp/src/runtime/components/consensus.rs`
//!   in CONS-506)
//! - the fork-divergence policy
//!   (`lib_consensus_core::budget::WRONG_CHAIN_HALT_THRESHOLD`)
//! - the startup transport-compatibility check (CONS-310)
//!
//! # Module map
//!
//! - [`runtime`] — `ConsensusRuntime` and the unified `tokio::select!`.
//!   Populated by CONS-502.
//! - [`catch_up_sync`] — `run_catch_up_sync_task`, `prioritize_catchup_peers`,
//!   `catchup_sync_from_peer`, `HashMismatchError`, `CatchUpSyncChannel`.
//!   Populated by CONS-506.
//! - [`fork_policy`] — fork-divergence handling. Populated by CONS-310/CONS-506.
//! - [`adapters`] — `ConsensusMeshBroadcaster`, `ConsensusBlockCommitter`
//!   (rewritten as `BlockFinalizationSink` impl per CONS-504),
//!   `BlockchainValidatorAdapter`, `QuicValidatorTransport`. Populated by
//!   CONS-503/504/505.
//!
//! # Architectural deletions tracked here
//!
//! When CONS-505 lands, `lib-blockchain/src/integration/consensus_integration.rs`
//! (the parallel `BlockchainConsensusCoordinator`) is deleted in favor of the
//! single driver in this crate.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod catch_up_sync;
pub mod fork_policy;
pub mod runtime;
