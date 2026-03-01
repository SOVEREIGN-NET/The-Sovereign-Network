//! NodeId - Re-export from lib-types with backward compatibility
//!
//! This module re-exports the canonical NodeId from lib-types to maintain
//! a single source of truth while preserving backward compatibility for
//! existing code that imports from lib_identity::types.

// Re-export all NodeId-related items from the canonical lib-types definition
pub use lib_types::node_id::{
    NodeId,
    set_network_genesis,
    try_set_network_genesis,
    get_network_genesis,
};
