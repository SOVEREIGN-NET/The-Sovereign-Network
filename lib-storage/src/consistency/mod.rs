//! Distributed consistency primitives

pub mod conflict;
pub mod crdt;
pub mod quorum;
pub mod vector_clock;

pub use conflict::{ConflictResolver, ConflictStrategy, Resolution};
pub use crdt::{GCounter, LWWRegister, PNCounter};
pub use quorum::{QuorumConfig, QuorumManager, QuorumResult};
pub use vector_clock::VectorClock;
