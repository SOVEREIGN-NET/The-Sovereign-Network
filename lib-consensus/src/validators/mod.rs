//! Validator management for ZHTP consensus

pub mod genesis;
pub mod validator;
pub mod validator_manager;

// CONS-501a: `validator_discovery` migrated to `lib_consensus_net::discovery`.
// CONS-501b: `validator_protocol` migrated to `lib_consensus_net::validator_protocol`.
// Re-export modules keep internal `lib-consensus` callers (engine, tests)
// compiling. External crates import from the canonical `lib_consensus_net`
// paths directly.
pub mod validator_discovery {
    pub use lib_consensus_net::discovery::*;
}
pub mod validator_protocol {
    pub use lib_consensus_net::validator_protocol::*;
}

pub use genesis::*;
pub use validator::*;
pub use validator_discovery::*;
pub use validator_manager::*;
pub use validator_protocol::*;
