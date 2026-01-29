# BFT Networking Integration Investigation

**Date**: 2026-01-29
**Branch**: `investigate/bft-networking-integration`
**Status**: ❌ **CONFIRMED STUBBED**

## Executive Summary

The networking integration for BFT consensus is **STUBBED** in the production runtime. While the `ConsensusEngine` correctly calls `broadcast_to_validators()` and a fully-functional `MeshMessageBroadcaster` exists, the actual wiring in the runtime uses `NoOpBroadcaster` which drops all messages silently.

## Evidence Chain

### 1. State Machine Broadcasts (✅ Correct)

`lib-consensus/src/engines/consensus_engine/state_machine.rs` correctly calls `broadcast_to_validators()` at multiple points:

| Line | Step | Message Type |
|------|------|--------------|
| 266-275 | run_propose_step() | Proposal |
| 304-313 | run_prevote_step() | PreVote |
| 346-355 | run_precommit_step() | PreCommit |
| 394-404 | run_commit_step() | Commit |
| 1084-1092 | enter_prevote_step() | PreVote |
| 1121-1129 | enter_precommit_step() | PreCommit |
| 1164-1172 | enter_commit_step() | Commit |

Example from `run_propose_step()`:
```rust
// Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
if let Err(e) = self.broadcaster
    .broadcast_to_validators(msg, &validator_ids)
    .await
{
    tracing::debug!(
        error = ?e,
        height = self.current_round.height,
        "Failed to broadcast proposal to validators (continuing per CE-ENG-4)"
    );
}
```

### 2. MeshMessageBroadcaster (✅ Fully Implemented)

`lib-network/src/message_broadcaster.rs` provides a production-ready implementation:

```rust
pub struct MeshMessageBroadcaster {
    local_peer_id: UnifiedPeerId,
    peer_registry: SharedPeerRegistry,
    mesh_router: Arc<MeshMessageRouter>,
}

impl MessageBroadcaster for MeshMessageBroadcaster {
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        target_validators: &[PublicKey],
    ) -> Result<BroadcastResult> {
        // ... finds validators in PeerRegistry
        // ... wraps in ZhtpMeshMessage::ValidatorMessage
        // ... routes via mesh_router.route_message()
    }
}
```

### 3. Runtime Wiring (❌ STUBBED)

`zhtp/src/runtime/components/consensus.rs:268-269`:

```rust
let broadcaster = Arc::new(NoOpBroadcaster);  // ❌ STUB!
let mut consensus_engine = lib_consensus::init_consensus(config, broadcaster)?;
```

### 4. NoOpBroadcaster Definition

`lib-consensus/src/testing/mod.rs:14-25`:

```rust
/// No-op message broadcaster for use in tests and development
///
/// This implementation ignores all broadcast calls and always succeeds.
/// Use this when message broadcasting is not relevant to the test.
pub struct NoOpBroadcaster;

impl MessageBroadcaster for NoOpBroadcaster {
    async fn broadcast_to_validators(
        &self,
        _message: ValidatorMessage,
        _validator_ids: &[IdentityId],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())  // DROPS ALL MESSAGES
    }
}
```

## Impact

With `NoOpBroadcaster`:
- ❌ Proposals are NOT broadcast to validators
- ❌ PreVotes are NOT broadcast
- ❌ PreCommits are NOT broadcast
- ❌ Commit votes are NOT broadcast
- ❌ Heartbeats are NOT broadcast
- ❌ Multi-node consensus CANNOT work
- ❌ BFT is single-node only

## Root Cause

The `ConsensusComponent` was designed with dependency injection for the broadcaster, but the production wiring was never completed. The `NoOpBroadcaster` was used as a placeholder during development and never replaced.

## Fix Required

Replace `NoOpBroadcaster` with `MeshMessageBroadcaster` in the runtime:

```rust
// Current (BROKEN):
let broadcaster = Arc::new(NoOpBroadcaster);

// Fixed:
let broadcaster = Arc::new(MeshMessageBroadcaster::new(
    local_peer_id,
    peer_registry,
    mesh_router,
));
```

This requires:
1. Access to `UnifiedPeerId` (local node identity)
2. Access to `SharedPeerRegistry` (peer registry)
3. Access to `Arc<MeshMessageRouter>` (message router)

These components exist in the `ProtocolsComponent` and need to be passed to `ConsensusComponent`.

## Conclusion

**The original claim "Networking Integration Stubbed" is CORRECT.**

The statement was retracted in error. While the code structure is correct (state machine calls broadcast, MeshMessageBroadcaster exists), the actual runtime wiring uses a no-op stub.

## Files Examined

| File | Purpose |
|------|---------|
| `lib-consensus/src/engines/consensus_engine/state_machine.rs` | Broadcast calls |
| `lib-consensus/src/engines/consensus_engine/mod.rs` | Engine definition |
| `lib-consensus/src/engines/consensus_engine/network.rs` | Message handling loop |
| `lib-network/src/message_broadcaster.rs` | MeshMessageBroadcaster impl |
| `lib-consensus/src/testing/mod.rs` | NoOpBroadcaster definition |
| `zhtp/src/runtime/components/consensus.rs` | Runtime wiring (STUBBED) |
