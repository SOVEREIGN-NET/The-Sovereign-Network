//! Core identity types for ZHTP Identity Management

pub mod credential_types;
pub mod identity_types;
pub mod node_id;
pub mod peer_identity;
pub mod proof_params;
pub mod verification_result;
pub mod node_id;
pub mod peer_identity;

// Re-exports
pub use credential_types::*;
pub use identity_types::*;
pub use node_id::{get_network_genesis, set_network_genesis, try_set_network_genesis, NodeId};
pub use peer_identity::DhtPeerIdentity;
pub use proof_params::*;
pub use verification_result::*;
pub use node_id::NodeId;
pub use peer_identity::DhtPeerIdentity;

// DID-related types from did module (remaining types after cleanup)
// Note: Removed placeholder creation types - use IdentityManager::create_citizen_identity() instead
