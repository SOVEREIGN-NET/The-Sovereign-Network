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

pub mod codec;
pub mod heartbeat;
pub mod liveness_monitor;

pub use codec::{BincodeConsensusCodec, CodecError, ConsensusMessageCodec};
pub use heartbeat::{HeartbeatProcessingResult, HeartbeatTracker, HeartbeatValidationError};
pub use liveness_monitor::{
    LivenessMonitor,
    MAX_MISSED_BLOCKS,
    ROUND_TIMEOUT_SECS,
    LIVENESS_JAIL_THRESHOLD,
    MAX_CONSECUTIVE_ROUND_TIMEOUTS,
    HEARTBEAT_LIVENESS_TIMEOUT_SECS,
};
