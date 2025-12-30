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

pub use codec::{BincodeConsensusCodec, CodecError, ConsensusMessageCodec};
