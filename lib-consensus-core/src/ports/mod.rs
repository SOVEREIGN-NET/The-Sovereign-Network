//! Side-effect ports: traits the engine calls, runtime implements.
//!
//! Per AD-002 (no IO in lib-consensus-core), every external interaction
//! flows through a trait declared here and implemented by
//! `lib-consensus-runtime` (broadcast, finalization, governance) or by
//! the runtime's adapter layer.
//!
//! Populated by:
//! - CONS-202 (and CONS-401 verification): `MessageBroadcaster`
//!   with the new latency-budget signature.
//! - CONS-402: `BlockFinalizationSink` (replaces `BlockCommitCallback`),
//!   `FinalizationError`.
//! - CONS-403: `TransportInfo` (idle-timeout introspection).
//! - **CONS-103: `RewardCallback`** ← this PR.
//! - CONS-404: `FeeCallback`.
//! - CONS-106: `GovernanceCallback`.
//! - Existing: `CatchUpSyncTrigger` migrates from
//!   `lib-consensus/src/types/mod.rs:494`.

pub mod broadcaster;
pub mod fees;
pub mod finalization;
pub mod governance;
pub mod rewards;
pub mod transport;

pub use broadcaster::MessageBroadcaster;
pub use fees::{FeeCallback, NoOpFeeCallback};
pub use finalization::{BlockFinalizationSink, FinalizationError, NoOpBlockFinalizationSink};
pub use governance::{GovernanceCallback, NoOpGovernanceCallback};
pub use rewards::{NoOpRewardCallback, RewardCallback, ValidatorRewardInput};
pub use transport::{NoOpTransportInfo, TransportInfo};
