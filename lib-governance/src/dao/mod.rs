//! DAO governance — proposal lifecycle, voting, treasury, parameter updates.
//!
//! Relocated from `lib-consensus/src/dao/` per **CONS-106** and **AD-003**.
//! The consensus engine drives this through the `GovernanceCallback` trait
//! defined in `lib_consensus_core::ports::governance` — see `consensus_adapter`
//! for the implementation.

pub mod consensus_adapter;
pub mod dao_engine;
pub mod dao_types;

pub use consensus_adapter::ConsensusGovernanceAdapter;
pub use dao_engine::DaoEngine;
pub use dao_types::*;
