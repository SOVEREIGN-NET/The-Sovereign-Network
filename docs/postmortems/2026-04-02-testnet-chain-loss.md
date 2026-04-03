# Postmortem: Testnet Chain Loss — Apr 2, 2026

## Summary

At ~08:17 UTC, validator g1 detected a chain divergence at height 1346 and
auto-wiped its sled store, restarting from height 0. This isolated g1 from
the network (stale nonce cache epoch), causing the remaining 3 validators
to lose BFT quorum (need 3/4). The chain halted for ~2 hours.

## Timeline

| Time | Event |
|------|-------|
| ~08:17:05 | g1 detects CHAIN DIVERGENCE: sled has block `ec1d3889` but BFT finalized `c935f04e` at height 1346 |
| ~08:17:05 | g1's divergence handler auto-wipes sled and calls `process::exit(1)` |
| ~08:17+ | g1 restarts with empty state. Nonce cache epoch mismatch (`0xfd71c185` vs `0x112b9ba6`) blocks all QUIC connections |
| ~08:17+ | g1 isolated. 3 remaining validators lose BFT quorum. Chain halts |
| Recovery 1 | Restored 06:00 sled backups per-node. Chain resumed but halted at height 1134: `Invalid nonce: expected 4, got 3` (inconsistent nonce state across nodes) |
| Recovery 2 | Used g2's sled (largest/most complete) as authoritative copy, rsync'd to all 4 nodes. Chain resumed |
| Post-recovery | Peers rejected at QUIC handshake: `DID not registered in identity registry`. Fixed `is_registered` to check both `identity_registry` and `validator_registry` |

## Root Cause

**The divergence was caused by a race condition between catch-up sync and BFT block commit.**

Both paths write blocks to the same blockchain/sled through the same `Arc<RwLock<Blockchain>>`:

1. **BFT commit** (`ConsensusBlockCommitter::commit_finalized_block`) — writes blocks finalized by 2/3+1 validator votes
2. **Catch-up sync** (`catchup_sync_from_peer`) — downloads blocks from a peer when the consensus engine detects it's behind

The race:

```
Time 0: blockchain.height = 1345
Time 1: Catch-up sync triggered (peer votes at height 1347)
Time 2: Catch-up downloads block 1346 from peer, acquires write lock, applies it (hash H_peer)
Time 3: BFT consensus finalizes block 1346 (hash H_bft, different proposer → different hash)
Time 4: BFT commit acquires write lock, sees block 1346 already exists
Time 5: Hash comparison: H_peer ≠ H_bft → CHAIN DIVERGENCE
Time 6: Divergence handler wipes sled and exits → node isolated → quorum lost
```

The catch-up sync block and the BFT-finalized block had different hashes because they came from different sources (different proposers or different transaction ordering). Catch-up sync wrote first, BFT tried to commit second, detected the mismatch, and destroyed the node's state.

## Contributing Factors

1. **No mutual exclusion** — catch-up sync and BFT commit were not coordinated. Both could write blocks at the same height concurrently.
2. **Auto-wipe on divergence** — the divergence handler deleted the sled directory and exited, instead of halting and alerting.
3. **Stale nonce cache** — after restart with empty state, the nonce cache epoch didn't match the network genesis, preventing reconnection.
4. **Identity verifier too narrow** — `is_registered` only checked `identity_registry`, missing validator DIDs in `validator_registry`.
5. **Inconsistent per-node backups** — each node's cron backup ran independently, capturing different sled states.

## Fixes Applied

### Immediate (deployed during incident)

- **Nonce cache auto-recovery**: clears stale nonce cache on epoch mismatch and reinitializes
- **Identity verifier**: `is_registered` checks both `identity_registry` and `validator_registry`

### Structural (PRs)

| Fix | PR | Status |
|-----|----|--------|
| Self-wipe → halt+alert (both divergence paths) | #2032 | Merged |
| Catch-up sync validates prev-hash (not trusted blindly) | #2032 | Merged |
| Catch-up sync uses real node identity (not rejected by verifier) | #2032 | Merged |
| Dead validator re-sync fixed (engine moved to None) | #2032 | Merged |
| Legacy save_to_file removed | #2032 | Merged |
| **BFT active height guard** — catch-up sync skips blocks at/above BFT consensus height | This PR | New |

### BFT Active Height Guard (the root cause fix)

A shared `AtomicU64` tracks the height BFT consensus is actively working on:

- The consensus loop publishes `current_round.height` at the start of each iteration, but only when BFT mode is active (>= 4 validators). In bootstrap mode the guard is cleared (set to 0) so catch-up can fill the gap freely.
- Catch-up sync reads the atomic **under the blockchain write lock** before applying each block. If `block.height >= bft_active_height`, the block is skipped.
- This eliminates the race: catch-up sync only fills gaps below the BFT frontier, BFT is the sole authority for the current height.

**Residual TOCTOU window**: during the BFT mode transition (bootstrap → BFT), there's a brief window where the atomic is first published. If catch-up already holds the write lock at that exact height, it proceeds. The consequence (hash mismatch) is now handled gracefully — error return, no wipe. The probability of this window aligning is very low and the impact is a single rejected commit, not chain loss.

## Lessons Learned

1. **Never auto-destroy state** — divergence detection should halt and alert, never wipe. Data destruction is irreversible and cascades.
2. **Concurrent write paths must be coordinated** — any system with two paths writing to the same store needs explicit mutual exclusion or ordering.
3. **Backups must be consistent** — per-node independent backups create divergent state. Use a single authoritative source.
4. **Test the recovery path** — the nonce cache epoch mismatch and identity verifier bugs were only discovered during actual recovery.
