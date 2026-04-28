//! Validator management for ZHTP consensus

pub mod genesis;
pub mod validator;
pub mod validator_manager;
pub mod validator_protocol;

// CONS-501: `validator_discovery` migrated to `lib_consensus_net::discovery`.
// Re-export keeps internal `lib-consensus` callers (engine, tests) compiling.
// External crates import from `lib_consensus_net::discovery` directly —
// `lib-network` already does.
pub mod validator_discovery {
    pub use lib_consensus_net::discovery::*;
}

pub use genesis::*;
pub use validator::*;
pub use validator_discovery::*;
pub use validator_manager::*;
pub use validator_protocol::*;
