//! DHT integration surface for lib-network.
//!
//! `ZkDHTIntegration` delegates storage to a `DhtBackend` trait implementation.
//! The application layer (zhtp) injects a persistent backend backed by
//! lib-storage's `DhtStorage`. An in-memory default is provided for tests.

pub mod backend;
pub mod integration;
pub mod protocol;

pub use backend::{DhtBackend, InMemoryDhtBackend};
pub use integration::*;
pub use lib_types::dht::*;
