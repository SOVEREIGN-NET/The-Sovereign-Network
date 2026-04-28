//! Adapter implementations for the `lib-consensus-core::ports` traits.
//!
//! - `ConsensusMeshBroadcaster` (CONS-503) — implements `MessageBroadcaster`
//!   over zhtp's QUIC mesh, parallel sends with per-peer timeout.
//! - `ConsensusBlockCommitter` (CONS-504) — implements `BlockFinalizationSink`
//!   with a dedicated writer task that owns the blockchain mutation lane.
//! - `BlockchainValidatorAdapter` — type adapter between
//!   `lib_blockchain::ValidatorInfo` and `lib_consensus_core::validator_set`.
//! - `QuicValidatorTransport` — wires `ValidatorNetworkTransport` to the QUIC
//!   mesh.
//! - `CatchUpSyncChannel` — channel-based `CatchUpSyncTrigger` impl.
