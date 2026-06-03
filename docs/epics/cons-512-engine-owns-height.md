# CONS-512 · Engine owns consensus height; storage is downstream

**Status.** Draft (2026-06-03). Drafted in response to the 2026-06-03 stall at H=123008/123009 where two of five validators wedged because their engine's `current_round.height` and `blockchain.height` drifted by one.

**Branch.** `fix/synchronous-commit-path-cons508` (branch name predates the CONS-512 ticket assignment — the synchronous-commit work was originally scoped under CONS-508's "delete legacy lib-consensus" umbrella before being scoped down to this surgical change. Kept as-is to preserve PR continuity; future references should use CONS-512.)

**Tracks.** CONS-307, CONS-504, CONS-505. Supersedes the "wire a `ConsensusEvent::NewBlock` event" patch sketch.

---

## What's broken

Right now there are two height counters in one process:

- `ConsensusEngine.current_round.height` — what the engine is voting on.
- `Blockchain.height` — what's actually persisted in sled.

They are coordinated via `sync_height_with_blockchain()`, which reads `blockchain.height` and sets `engine.current_round.height = blockchain.height + 1`. **The engine derives its height from storage.**

`sync_height_with_blockchain` is called from exactly four places:

1. `run_consensus_loop` start (boot)
2. `handle_consensus_event(ConsensusEvent::NewBlock)` — *event never constructed in production code* (grep-verified: only constructed in tests)
3. `on_round_timeout(Commit)` — only fires if the engine is sitting in the `Commit` step when the timer fires
4. Bootstrap → BFT mode transition

If anything causes the engine to leave the `Commit` step at height N before its timer fires — a stale-round vote from a slow peer, a round-bump, anything — and the engine then falls into PreVote/PreCommit timeouts at H=N (because no peer will vote for N anymore, they've all moved on), **the engine has no recovery path.** PreVote timeouts don't sync height. The engine spins at H=N forever while `blockchain.height` quietly sits at N too. They look the same to the API (both report N) but the engine is voting for N when it should be voting for N+1.

This is exactly what happened to g2 and g3 today. They committed H=123008 in the morning, something kicked them out of Commit step before the timer fired, and they've been spinning PreVote rounds at H=123008 for 11 hours.

## Why this design exists

CONS-307 explicitly made the commit path async fire-and-forget to fix the "storage blocks consensus" hang (epic line 575-589). That change is correct *for storage*. What CONS-307 got wrong was treating engine *height advancement* as a downstream consequence of the storage write, instead of an immediate consequence of the consensus decision.

In BFT, a block is final the moment 2/3+1 commit votes are observed. Persistence is a separate concern. The engine should advance its height the instant BFT decides, not when sled finishes writing.

## What we change

### 1. Engine owns its height.

`process_committed_block` advances `current_round.height` synchronously, in the same call frame, right after `apply_block_to_state_with_proof().await` returns. Same code that `advance_to_next_round()` already implements — just called from the commit success path, not from `on_round_timeout(Commit)`.

### 2. `sync_height_with_blockchain` becomes boot-only.

Called only from `run_consensus_loop` start. Removed from `on_round_timeout(Commit)`, removed from the Bootstrap→BFT mode transition, removed from the (vestigial) `handle_consensus_event(ConsensusEvent::NewBlock)` handler.

The function name is unchanged in this PR — the rename to `init_height_from_storage` was considered to make the intent explicit but deferred to keep the diff focused on the safety-critical behavior change. The doc comment now spells out the boot-only contract in unambiguous terms, and any future caller addition is required to justify itself as a non-regression in the PR description.

### 3. `ConsensusEvent::NewBlock` — kept, but neutered.

Grep confirms zero production constructors of this variant; only test code builds it. We considered deleting both the variant and its handler in this PR but kept them, for two reasons:

- The handler does post-block bookkeeping (governance callback, byzantine fault detection, reward callback) that is duplicated in `process_committed_block`. Cleanly de-duplicating is a separate, scoped refactor, and bundling it into a safety-critical change is the kind of scope creep that turns a 4-file diff into a 20-file diff with a wider blast radius.
- The handler is a plausible attachment point for a future external block-ingest path (archive-node replay, fast-sync apply).

What this PR *does* change in the handler: the `sync_height_with_blockchain()` call inside it is removed, and a CONS-512 contract comment is added stating that re-adding it would re-introduce the engine ↔ storage drift bug.

Deletion of the variant + handler is tracked as a follow-up cleanup, not a prerequisite for the CONS-512 contract.

### 4. Storage write stays async (CONS-307 unchanged).

`spawn_commit_executor`'s fire-and-forget pattern is preserved. Storage-write failures still surface via `Event::HaltScheduled` and transition the FSM to `Halting`. The engine has already advanced past N at that point — on restart, the boot path re-syncs from whichever storage tip persisted (this node or peers).

### 5. Boot path's storage-vs-engine reconciliation.

On boot, `blockchain.height` from sled is authoritative. Engine initializes to `blockchain.height + 1`. If consensus has progressed beyond what's in sled (another node committed but this one's writer task hadn't flushed before crash), catch-up sync downloads the missing blocks during the Bootstrap phase before BFT mode engages. This already works today; we don't touch it.

## What this rules out

- **Engine drifting behind storage.** The engine no longer reads storage post-boot, so there's no "engine syncs to old value" race.
- **Engine drifting ahead of storage.** When the engine commits N, it advances to N+1 immediately. If storage fails, halt scheduling is exactly the existing path.
- **Silent stall.** The bug we hit today required `sync_height_with_blockchain` to be the only advance trigger AND for that trigger to never fire. Both prerequisites go away.

## Risk

**Medium.** This is a consensus correctness change. Failure modes to validate:

1. *Engine advances, storage fails, restart:* engine boots at storage tip, catches up via sync from peers. **Existing path.**
2. *Engine advances, storage succeeds, restart:* engine boots at storage tip + 1. **Trivial.**
3. *Same-height fork after restart (PR #2620 scenario):* unaffected — the fix here is orthogonal to quorum-proof determinism.
4. *Storage falls arbitrarily behind:* engine keeps advancing, halt scheduler eventually fires on accumulated failures. *This is new behavior.* In the old design the engine would block on storage and stop voting, providing implicit backpressure. We need the watchdog (CONS-309) to be the explicit backpressure: if the engine produces commits faster than storage applies them, that's a `Hung` condition the watchdog detects via stale `state_age`.

## Touchpoints

| File | Change |
|---|---|
| `lib-consensus/src/engines/consensus_engine/state_machine.rs` | `process_committed_block` advances height after `apply_block_to_state_with_proof` returns; delete `ConsensusEvent::NewBlock` handler arm (line 526); delete the height-sync path in `on_round_timeout(Commit)` (line 2606-2632, replace with a simple round-bump). |
| `lib-consensus/src/engines/consensus_engine/mod.rs` | Rename `sync_height_with_blockchain` → `init_height_from_storage`; tighten doc comment to "boot only". |
| `lib-consensus/src/engines/consensus_engine/network.rs` | Single call site updated (line 35). Delete the call at line 137 (mode transition). |
| `lib-consensus/src/types/mod.rs` | Delete `ConsensusEvent::NewBlock` variant. |
| `lib-consensus/src/engines/consensus_engine/tests.rs` | Update tests that construct `ConsensusEvent::NewBlock` to use the direct advancement path. |
| `lib-consensus-runtime/src/runtime.rs` | No structural changes. `spawn_commit_executor` stays as-is — async write with halt-on-failure. |

Estimated ~250 lines net deletion, ~80 lines added.

## Migration

None. Schema-compatible. Storage format unchanged. Network messages unchanged. Validator identity unchanged.

## Test plan

- Unit: existing state-machine tests pass after migrating away from `ConsensusEvent::NewBlock`.
- Unit: new test — engine commits at H=N, advances to H=N+1 synchronously in the same call frame, with a delayed-writer stub.
- Unit: storage-failure path — writer returns Err, engine reaches `Halting` via `Event::HaltScheduled` while at H=N+1.
- Integration: existing BFT integration tests must continue to commit a sequence of blocks.
- Regression: the specific stall pattern (engine kicked out of Commit step without height advance) — construct a state machine, drive a commit, force a round-bump before the Commit timer fires, assert the engine is at N+1, not N.
- Live: staged rollout per HALT-BEFORE-DEPLOY. g1 canary first; verify normal block production for ≥100 blocks before extending.
