//! Core identity types for ZHTP Identity Management

pub mod credential_types;
pub mod identity_types;
pub mod identity_views;
pub mod node_id;
pub mod peer_identity;
pub mod proof_params;
pub mod verification_result;

// Re-exports
pub use credential_types::*;
pub use identity_types::*;
pub use identity_views::*;
pub use node_id::{get_network_genesis, set_network_genesis, try_set_network_genesis, NodeId};
pub use peer_identity::DhtPeerIdentity;
pub use proof_params::*;
pub use verification_result::*;

// DID-related types from did module (remaining types after cleanup)
// Note: Removed placeholder creation types - use IdentityManager::create_citizen_identity() instead
