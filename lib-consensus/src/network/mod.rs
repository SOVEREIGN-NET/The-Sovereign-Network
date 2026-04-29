//! Network layer for consensus message transport
//!
//! This module provides serialization and framing for consensus messages
//! to be transmitted over QUIC and other network protocols.
//!
//! # Purpose
//!
//! The network module is the boundary between consensus logic and transport.
//! It ensures deterministic serialization/deserialization of consensus messages
//! while remaining opaque to message semantics.

// CONS-501b: codec + heartbeat migrated to lib-consensus-net.
// Re-export modules so existing internal callers compile unchanged.
pub mod codec {
    pub use lib_consensus_net::codec::*;
}
pub mod heartbeat {
    pub use lib_consensus_net::heartbeat::*;
}
pub mod liveness_monitor;

pub use codec::{BincodeConsensusCodec, CodecError, ConsensusMessageCodec};
pub use heartbeat::{
    check_consensus_health, ConsensusMetrics, HeartbeatProcessingResult, HeartbeatTracker,
    HeartbeatValidationError,
};
pub use liveness_monitor::{
    LivenessMonitor, HEARTBEAT_LIVENESS_TIMEOUT_SECS, LIVENESS_JAIL_THRESHOLD,
    MAX_CONSECUTIVE_ROUND_TIMEOUTS, MAX_MISSED_BLOCKS, ROUND_TIMEOUT_SECS,
};
