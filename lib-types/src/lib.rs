//! Sovereign Network primitives.
//! Stable, protocol-neutral, behavior-free.
//!
//! Rule: No String identifiers in consensus state. Ever.

pub mod primitives;
pub mod node_id;
pub mod peer;
pub mod dht;
pub mod chunk;
pub mod errors;

// Canonical consensus types (Phase 1)
pub use primitives::{Address, Amount, BlockHash, BlockHeight, Bps, TokenId, TxHash};

pub use node_id::NodeId;
pub use peer::PeerId;
pub use dht::*;
pub use chunk::*;
pub use errors::*;
