//! Distributed consistency primitives

pub mod vector_clock;
pub mod crdt;
pub mod quorum;
pub mod conflict;

pub use vector_clock::VectorClock;
pub use crdt::{LWWRegister, GCounter, PNCounter};
pub use quorum::{QuorumConfig, QuorumManager, QuorumResult};
pub use conflict::{ConflictResolver, ConflictStrategy, Resolution};
