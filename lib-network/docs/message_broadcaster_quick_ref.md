# MessageBroadcaster - Quick Reference

## What Is It?

A trait that enables consensus validators to broadcast pre-signed messages through the mesh network. Think of it as a **delivery service, not a post office**.

- **The post office (consensus)** decides what messages to send and signs them
- **The delivery service (network)** routes them to recipients
- **The customer (consensus) never worries** whether all recipients got their mail

---

## One-Minute Overview

```
Consensus Layer              Network Layer              Peer Registry
    │                            │                           │
    ├─ Creates message          │                           │
    ├─ Signs message            │                           │
    ├─ Picks validators         │                           │
    │                           │                           │
    └──> broadcast_to_validators(msg, [pk1, pk2, ...])    │
                                 │                           │
                                 ├─ Find validators         │
                                 │──────────────────────────>│
                                 │<──────────────────────────│
                                 │ (verified peers only)      │
                                 │                           │
                                 ├─ Skip self               │
                                 ├─ Route each msg          │
                                 │                           │
                                 └─> BroadcastResult
                                    {delivered: 2,
                                     failed: 1, ...}

    ⚠️  Only use result for logging!
        Not for consensus decisions!
```

---

## Four Methods You Need

### 1. Broadcast to Multiple (Most Common)

```rust
let result = broadcaster.broadcast_to_validators(
    message,              // Already signed by consensus
    &[pk1, pk2, pk3],    // Target validators
).await?;

println!("Sent to: {}/{}", result.delivered, result.attempted);
```

**Result Fields:**
- `attempted` - How many you wanted to send to
- `delivered` - Actually routed successfully
- `failed` - Network failures (transient, could retry)
- `skipped` - Not found (e.g., joined mid-epoch)
- `failed_validators` - Which ones failed (telemetry only!)

### 2. Send to Single Validator

```rust
broadcaster.send_to_validator(&validator_pubkey, message).await?;
```

**Returns:** `Ok(())` if queued, `Err()` if:
- Validator not found
- Validator not verified (bootstrap mode)
- You're trying to send to yourself

### 3. Check How Many Are Reachable

```rust
let reachable = broadcaster
    .reachable_validator_count(&[pk1, pk2, pk3])
    .await?;

println!("Can reach {}/{} validators", reachable, 3);
```

**Use Case:** Before broadcasting, see if quorum is reachable (informational only!)

### 4. Check Single Validator

```rust
if broadcaster.is_validator_reachable(&pubkey).await? {
    println!("Validator is online and verified");
}
```

**Returns:** `true` if verified peer exists

---

## What Not To Do (Authority Boundary)

```rust
// ❌ DON'T: Network layer creating ValidatorMessage
let msg = ValidatorMessage::Propose(ProposalData {
    proposal,
    signature: sign_message(...), // ❌ Network doesn't sign!
});

// ✅ DO: Consensus layer creates, network just routes
let msg = consensus_layer.create_and_sign_proposal(data)?;
broadcaster.broadcast_to_validators(msg, targets).await?;
```

---

## Testing with MockMessageBroadcaster

### Setup: Create a mock
```rust
let mock = MockMessageBroadcaster::new(5); // 5 validators exist
```

### Scenario 1: All reachable
```rust
let result = mock.broadcast_to_validators(msg, &[pk1, pk2, pk3]).await?;
assert_eq!(result.delivered, 3); // All made it
```

### Scenario 2: Network partition
```rust
mock.set_reachable(Some({pk1, pk2})).await; // Only these two exist

let result = mock.broadcast_to_validators(msg, &[pk1, pk2, pk3]).await?;
assert_eq!(result.delivered, 2);
assert_eq!(result.skipped, 1); // pk3 partitioned away
```

### Scenario 3: One validator flaky
```rust
mock.set_fail_on({pk2}).await; // pk2 always fails

let result = mock.broadcast_to_validators(msg, &[pk1, pk2, pk3]).await?;
assert_eq!(result.delivered, 2);
assert_eq!(result.failed, 1); // pk2 failed
```

### Check what was sent
```rust
assert_eq!(mock.broadcast_count().await, 1); // Called once
assert_eq!(mock.send_count().await, 0);     // Point-to-point not used
```

---

## Performance Guidelines

| Scenario | Time | Implementation |
|----------|------|-----------------|
| 10 validators | ~100ms | Sequential (current) |
| 100 validators | ~1-2s | Sequential (current) ⚠️ |
| 1000 validators | ~10s+ | Need parallel (#520) |

**Current:** Sequential, suitable for <100 validators
**Future:** Parallel broadcasting via tokio::spawn (#520)

---

## Guardian Checks Built-In

| Guard | What It Does | Why |
|-------|-------------|-----|
| **Self-Send Check** | Skips routing to yourself | Prevents re-entrancy loops |
| **Verified Peer Filter** | Only `is_verified()==true` peers | Bootstrap-mode peers excluded |
| **Opaque Message Type** | Single `ConsensusMessage` type | Network layer never interprets kind |
| **Failed List Warning** | Explicit non-authoritative docs | Prevents misuse in consensus |

---

## Decision: Why PublicKey, Not PeerTier?

❌ **Wrong:** `if peer_tier == Tier1 { send_to_validator() }`

✅ **Right:** Consensus layer passes `[target_pubkeys]`, network routes

**Because:**
- Tier1 is about network bandwidth/relay role
- Validators are about consensus authority
- A Tier1 peer might not be a validator
- A validator might temporarily go offline
- PoS validators change each epoch

---

## The One Rule: Non-Authoritative Telemetry

```rust
let result = broadcaster.broadcast_to_validators(msg, targets).await?;

// ✅ OK: Logging and monitoring
println!("Delivered to {}/{}", result.delivered, result.attempted);
metrics.inc_broadcast_failures(result.failed);

// ❌ WRONG: Using in consensus
if result.delivered < targets.len() / 2 {
    // ❌ DON'T: Make consensus decisions based on network telemetry!
    consensus.mark_validator_offline()?;
}

// Why: Network failures are transient, not authority changes
// Validators might be temporarily unreachable but still authorized
```

---

## Integration Checklist

- [ ] Create `MessageBroadcaster` in `ValidatorProtocol` constructor
- [ ] Call `broadcast_to_validators()` after message is signed
- [ ] Pass `target_validators` list from consensus (not inferred)
- [ ] Never construct `ValidatorMessage` in network code
- [ ] Never sign messages in network code
- [ ] Use `BroadcastResult` for logging only
- [ ] Write tests with `MockMessageBroadcaster`
- [ ] Test network partition scenarios
- [ ] Test failure scenarios
- [ ] Document usage in protocol module

---

## Common Questions

**Q: What if delivery fails?**
A: It's expected in gossip networks. Don't retry automatically—consensus must be independent of delivery success.

**Q: Can I use failed_validators for slashing?**
A: No! It's transient network failures, not validator misbehavior. Slashing comes from consensus violations.

**Q: Should I block until all validators receive?**
A: No! It's best-effort, fire-and-forget. Blocking would defeat the purpose of async.

**Q: Why does the mock support partitions?**
A: To test real-world network scenarios: edge cases, Byzantine conditions, recovery.

**Q: What's the difference between failed vs skipped?**
A: `skipped` = validator not found in registry. `failed` = found but routing failed (transient).

---

## See Also

- **Full Architecture:** [message_broadcaster.md](message_broadcaster.md)
- **Source:** `lib-network/src/message_broadcaster.rs`
- **Issue:** #519 - Peer-to-Peer Message Broadcasting
- **Future:** #520 (parallel), #521 (errors), #522 (rate limit), #523 (versioning)
