//! lib-consensus-net — wire format + transport adapters for `lib-consensus-core`.
//!
//! See `docs/forensics/bft-consensus-architecture-analysis.md` § 3.1 for the
//! target shape. This crate is the destination for code currently in:
//! - `lib-consensus/src/network/codec.rs`
//! - `lib-consensus/src/network/heartbeat.rs`
//! - `lib-consensus/src/validators/validator_protocol.rs`
//! - `lib-consensus/src/validators/validator_discovery.rs`
//!
//! # Module map
//!
//! - [`codec`] — `BincodeConsensusCodec`, `ConsensusMessageCodec` trait.
//!   Populated by CONS-501.
//! - [`heartbeat`] — `HeartbeatTracker`, `HeartbeatMessage`,
//!   `HeartbeatProcessingResult`. Populated by CONS-501.
//! - [`validator_protocol`] — signed-envelope middleware,
//!   `ValidatorNetworkTransport`. Populated by CONS-501.
//! - [`discovery`] — `ValidatorDiscoveryProtocol`, `ValidatorEndpoint`,
//!   `ValidatorAnnouncement`. Populated by CONS-501. The deep-import
//!   `lib-network/src/validator_discovery_transport.rs:33` migrates to
//!   `use lib_consensus_net::discovery::*` here.

#![forbid(unsafe_code)]

pub mod codec;
pub mod discovery;
pub mod heartbeat;
pub mod validator_protocol;
