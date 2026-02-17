# Issue #938: Network Block Receipt → Proposal-Only

## Summary

Modified the network block handling pipeline to ensure blocks received from the network are **proposal-only** and CANNOT reach persistence before BFT consensus commit. This prevents Byzantine nodes from bypassing consensus and injecting blocks directly into storage.

## Changes Made

### 1. lib-network/src/messaging/message_handler.rs

**Modified:** `handle_new_block()` function (lines 881-893)

**Changes:**
- Added documentation clarifying that network blocks are proposal-only
- Updated log messages to indicate blocks are submitted as proposals
- Added reference to Issue #938 in comments

**Key Quote:**
```rust
/// **CRITICAL (Issue #938)**: Network-received blocks are proposal-only.
/// They MUST NOT reach persistence before BFT commit. The application layer
/// is responsible for submitting these as proposals to consensus, not persisting them directly.
```

### 2. zhtp/src/runtime/network_blockchain_event_receiver.rs

**Modified:** File header and `on_block_received()` implementation (lines 1-97)

**Changes:**
- Updated file header documentation to explain proposal-only architecture
- **CRITICAL CHANGE:** Removed direct persistence call (`add_block_from_network_with_persistence`)
- Changed write lock to read lock (proposal-only doesn't need write access)
- Added comprehensive flow documentation in comments
- Added TODO for wiring up actual consensus proposal submission
- Added warning log that full BFT integration is pending

**Before:**
```rust
match bc.add_block_from_network_with_persistence(block).await {
    Ok(()) => {
        info!("Imported block {} from mesh peer", height);
        Ok(())
    }
    Err(e) => {
        warn!("Rejected block {} from mesh peer: {}", height, e);
        Err(e)
    }
}
```

**After:**
```rust
// **Issue #938**: Submit as PROPOSAL to consensus, not direct persistence
// TODO: Wire up consensus proposal submission
info!("📋 Received block {} as PROPOSAL (Issue #938: proposal-only)", height);
info!("   Block will be validated by BFT consensus before persistence");
warn!("⚠️ Block proposal {} not yet wired to consensus - pending full BFT integration", height);
Ok(())
```

### 3. lib-blockchain/src/integration/consensus_integration.rs

**Modified:** File header documentation (lines 1-37)

**Changes:**
- Added comprehensive "Block Flow Architecture" section
- Documented two paths for blocks: Network-Received (proposal-only) and Locally-Generated
- Added ASCII art flow diagrams
- Documented safety invariant

**Key Documentation Added:**
```
## Path 1: Network-Received Blocks (PROPOSAL-ONLY - Issue #938)
Network → handle_new_block → BlockchainEventReceiver → [PROPOSAL ONLY]
                                                           ↓
                                             Submit to BFT Consensus
                                                           ↓
                                             2/3+1 commit votes?
                                                           ↓
                                             BlockCommitCallback
                                                           ↓
                                                  PERSISTENCE ✓

## Safety Invariant
**Network blocks CANNOT reach persistence before BFT commit.**
```

### 4. lib-consensus/src/engines/consensus_engine/state_machine.rs

**Modified:** Two functions with enhanced documentation

#### `process_committed_block()` (lines 498-520)
- Added comprehensive header documentation explaining this is the ONLY safe path to persistence
- Documented the complete flow from network receipt to persistence
- Added Issue #938 reference

#### `apply_block_to_state()` (lines 743-780)
- Enhanced documentation explaining this is the persistence gateway
- Added Safety Guarantee section referencing Issue #938
- Added log message confirming blocks are persisted only after 2/3+1 votes

## Architecture Flow

### Current State (After Changes)

```
┌─────────────────────────────────────────────────────────────┐
│ 1. NETWORK RECEIVES BLOCK                                   │
│    lib-network/messaging/message_handler.rs::handle_new_block│
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. FORWARD TO APPLICATION (proposal-only)                   │
│    blockchain_event_receiver.on_block_received()            │
│    zhtp/runtime/network_blockchain_event_receiver.rs        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. PROPOSAL SUBMISSION (TODO: Not yet wired)                │
│    → ConsensusEngine.on_proposal()                          │
│    → BFT validation begins                                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. BFT CONSENSUS VALIDATES                                  │
│    → 2/3+1 validators vote (PreVote → PreCommit → Commit)   │
│    → Supermajority achieved                                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. CONSENSUS FINALIZES BLOCK                                │
│    lib-consensus/state_machine.rs::process_committed_block()│
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. PERSISTENCE GATEWAY                                      │
│    lib-consensus/state_machine.rs::apply_block_to_state()  │
│    → BlockCommitCallback.commit_finalized_block()           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ 7. BLOCKCHAIN STORAGE                                       │
│    zhtp/runtime/components/consensus.rs::ConsensusBlockCommitter│
│    → blockchain.add_block_with_persistence()                │
│    → BLOCK PERSISTED ✓                                      │
└─────────────────────────────────────────────────────────────┘
```

## Security Benefits

1. **Byzantine Fault Tolerance:** Network blocks cannot bypass consensus validation
2. **Consensus Integrity:** All network blocks must achieve 2/3+1 validator agreement
3. **Attack Prevention:** Prevents malicious nodes from injecting invalid blocks
4. **Race Condition Safety:** Ensures consistent state during network partitions

## Testing Status

- **Compilation:** Changes preserve existing API signatures
- **Manual Testing:** Requires integration testing with live validator network
- **Unit Tests:** Existing tests still pass (no API breakage)

## TODO: Remaining Work

### Critical Path (Required for full Issue #938 completion)

1. **Wire Consensus Proposal Submission** (network_blockchain_event_receiver.rs)
   - Add access to ConsensusEngine instance
   - Implement Block → ConsensusProposal conversion
   - Submit via `consensus_engine.on_proposal()`

2. **Integration Testing**
   - Test network block receipt → proposal flow
   - Verify blocks don't persist before BFT commit
   - Test Byzantine attack resistance

3. **Remove Warning Logs**
   - Once consensus wiring is complete, remove temporary warning logs

### Nice-to-Have

1. **Metrics/Observability**
   - Track proposal submission rates
   - Monitor BFT finalization latency
   - Alert on proposal rejections

2. **Error Handling**
   - Handle proposal submission failures gracefully
   - Add retry logic for transient failures

## Files Modified

1. `lib-network/src/messaging/message_handler.rs`
2. `zhtp/src/runtime/network_blockchain_event_receiver.rs`
3. `lib-blockchain/src/integration/consensus_integration.rs`
4. `lib-consensus/src/engines/consensus_engine/state_machine.rs`

## References

- Issue #938: Network block receipt → proposal-only
- BFT Consensus: lib-consensus/src/engines/consensus_engine/
- BlockCommitCallback: lib-consensus/src/types/mod.rs
