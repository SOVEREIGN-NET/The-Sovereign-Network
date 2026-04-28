# EPIC — Consensus Rewrite (`lib-consensus` → `core` + `net` + `runtime`)

**Status:** Proposed
**Owner:** TBD
**Date:** 2026-04-25
**Companion docs:**
- `docs/forensics/bft-consensus-forensic-analysis.md` (FSM-level audit)
- `docs/forensics/bft-consensus-architecture-analysis.md` (structural audit)

**Decision context:** the current `lib-consensus` crate has confirmed unbounded-latency hang risks (forensic D1, D2, D3) and structural violations (broadcaster duplication, BFT commit lock contention, callback shape forcing inline-await). The chosen path is **full rewrite + chain restart**, not patches. This epic captures the work.

---

## Outcome (Definition of Done)

When this epic ships:

1. **Three crates exist:**
   - `lib-consensus-core` (~6 K LOC) — pure FSM, no IO, no domain leak.
   - `lib-consensus-net` (~3 K LOC) — wire codec, heartbeat, validator-protocol, discovery.
   - `lib-consensus-runtime` (~1 K LOC) — orchestration glue, single owner of side effects.
2. **`lib-consensus` (mega-crate) is deleted** — workspace member removed from `Cargo.toml`.
3. **`BlockchainConsensusCoordinator` (`lib-blockchain/src/integration/consensus_integration.rs`) is deleted** — single consensus driver.
4. **`ValidatorMessage` is one type, `MessageBroadcaster` is one trait.**
5. **No inline `.await` on side effects in the FSM transition path** — all I/O dispatched through an `Action` channel to executor tasks.
6. **`ValidatorFsm` exists** with explicit states `Idle | Proposing | Prevoting | Precommitting | Committed | Rejected | Hung | HaltedForUpgrade` and a total `transition(state, event) -> next_state`.
7. **Watchdog runs in an independent task** with `step_entered_at` enforcement.
8. **Chain restarted from new genesis** with new binary; old chain history archived for forensics.
9. **All workspace tests pass; new architecture-invariant tests in place.**

Net code change: **~30 K LOC of `lib-consensus` becomes ~10 K LOC across three crates**, plus deletion of ~5 K LOC of duplication elsewhere.

---

## Phase Map

```
Phase 0 — Decisions & Setup            [1 week]
   │
   └──▶ Phase 1 — Mechanical extractions   [2 weeks, parallel-safe]
           │
           └──▶ Phase 2 — Wire format unification   [1 week, big-bang]
                   │
                   └──▶ Phase 3 — Core FSM rewrite   [3 weeks, single-track]
                           │
                           └──▶ Phase 4 — New port traits   [1 week]
                                   │
                                   └──▶ Phase 5 — Adapter & runtime rewrite   [3 weeks]
                                           │
                                           └──▶ Phase 6 — Verification & cutover   [2 weeks]

Total: ~13 weeks (one engineer, sequential).
With two engineers parallelizing Phases 1 + (4 || partial 5): ~9 weeks.
```

## Dependency Graph (issues)

```
CONS-001 ── CONS-002 ── CONS-003
                │
                ├── CONS-101..108  (Phase 1, all independent)
                │       │
                │       └── CONS-201 ── CONS-202 ── CONS-203
                │                              │
                │                              └── CONS-301 ── CONS-302 ── CONS-303 ── CONS-304
                │                                                                  │
                │                                                                  └── CONS-305 ── CONS-306 ── CONS-307
                │                                                                                                  │
                │                                                                                                  └── CONS-308 ── CONS-309 ── CONS-310
                │                                                                                                                                  │
                │                                                                                                                                  └── CONS-401..404
                │                                                                                                                                          │
                │                                                                                                                                          └── CONS-501..508
                │                                                                                                                                                  │
                │                                                                                                                                                  └── CONS-601..606
```

---

## Risk Radio Blast Legend

For every issue:

- **Files touched** — count of edited / deleted / created files.
- **Crates affected** — workspace members modified.
- **External consumers** — count of `use lib_consensus::...` call sites that break (baseline: 34 files outside `lib-consensus/`).
- **Network impact** — does this change require a coordinated network restart?
- **Reversibility** — can this be reverted without state loss?
- **Risk** — Low | Medium | High | Catastrophic.

---

# Phase 0 — Decisions & Setup

## CONS-001 · Lock the design

**What.** Designate `bft-consensus-architecture-analysis.md` as the single source of truth for the rewrite. Every PR in this epic links back to it. Any deviation requires updating the architecture doc first.

**Why.** Without a frozen design, scope creep is guaranteed and the rewrite becomes another `lib-consensus`.

**Acceptance criteria.**
- [ ] `docs/forensics/bft-consensus-architecture-analysis.md` ratified by tech lead.
- [ ] A new file `docs/epics/consensus-rewrite-decisions.md` exists, listing every decision the architecture doc commits to (3-crate split, ValidatorFsm shape, port traits, etc.) with one-line rationale and a link to the architecture section.
- [ ] PR template gains a "Architecture compliance: (link to section)" field.

**Blast radius.** Files: 2. Crates: 0. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 2 days.

---

## CONS-002 · Workspace scaffolding

**What.** Create three empty crates: `lib-consensus-core`, `lib-consensus-net`, `lib-consensus-runtime`. Add to root `Cargo.toml` workspace members. No code yet — just `Cargo.toml` and `src/lib.rs` with module skeletons matching architecture doc §3.1.

**Why.** Lets Phase 1 extractions land into the new crates immediately rather than into `lib-consensus` first and then moving them.

**Acceptance criteria.**
- [ ] `cargo build --workspace` succeeds with the three new empty crates.
- [ ] `lib-consensus-core/Cargo.toml` declares **only** `lib-types`, `lib-crypto`, `lib-identity`, `serde`, `thiserror`, `tracing`, `async-trait` as deps. **No `tokio`, `lib-storage`, `lib-proofs`, `chrono`, `dashmap`.**
- [ ] `cargo doc --no-deps -p lib-consensus-core` produces an empty crate doc (no missing-link warnings).

**Blast radius.** Files: ~10 (3 Cargo.toml + 3 lib.rs + workspace Cargo.toml). Crates: 4. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 1 day.

---

## CONS-003 · Test corpus capture

**What.** Before any deletion, snapshot every consensus-relevant test that currently passes:
- All 45 tests in `lib-consensus/src/engines/consensus_engine/tests.rs`.
- All tests in `lib-consensus/tests/*.rs` (15 files).
- Integration tests in `lib-blockchain/tests/consensus_integration_tests.rs`.
- Multi-node soak test scripts in `tests/integration/`.

Tag the current commit `pre-consensus-rewrite-baseline`. Run the full suite, capture pass/fail ratio. Any test that already fails today is **excluded** from the regression corpus and listed separately as known failures (per the user's "own all failures" rule, fix them in this phase or document why they're being deleted, do not silently leave them broken).

**Why.** A successful rewrite must preserve every behavior the existing tests assert. Without this baseline you have no way to claim "no regressions."

**Acceptance criteria.**
- [ ] Tag `pre-consensus-rewrite-baseline` exists at the current `development` HEAD.
- [ ] `docs/epics/consensus-rewrite-test-baseline.md` lists: total tests, passing count, failing count with file:line + reason for each failure, and a per-failure decision (fix-now | delete-with-rationale | preserve-as-known-issue).
- [ ] CI green on `pre-consensus-rewrite-baseline` after fix-now items land.

**Blast radius.** Files: ~5 (doc + any test fixes). Crates: varies. External consumers: 0. Network: none. Reversibility: full. Risk: Low (but failure-fixes may surface real bugs).

**Estimate.** 3 days.

---

# Phase 1 — Mechanical Extractions (parallel-safe)

> All Phase 1 issues are independent and can land in any order. They reduce `lib-consensus` from ~30 K LOC to ~12 K LOC of "just BFT" before the FSM rewrite begins.

## CONS-101 · Delete `lib-consensus/src/mempool/`

**What.** Remove the duplicate mempool. Replace all `lib_consensus::Mempool*` uses with `lib_mempool::*` (the workspace member that already exists at `Cargo.toml:18`).

**Why.** Two mempools is two sources of truth. `lib-mempool` is the canonical one.

**Acceptance criteria.**
- [ ] `lib-consensus/src/mempool/` deleted.
- [ ] `lib-consensus/src/lib.rs:42` re-export deleted.
- [ ] Every `use lib_consensus::Mempool` / `MempoolStats` / `MempoolTransaction` rewritten to `use lib_mempool::*`. Verify with `grep -rn "lib_consensus::Mempool" --include="*.rs"` returning zero results.
- [ ] `cargo test --workspace` passes.

**Blast radius.** Files: ~10. Crates: `lib-consensus`, `lib-mempool`, anything that imported the consensus mempool. External consumers: 1-2 (tools-style). Network: none. Reversibility: full. Risk: Low.

**Estimate.** 2 days.

---

## CONS-102 · Delete `lib-consensus/src/mining/`

**What.** Move `should_mine_block()` (`lib-consensus/src/mining/mod.rs`) to `lib-blockchain` (or `zhtp/runtime`). Mining is a blockchain-level decision, not consensus.

**Why.** BFT consensus has no mining. The single function is used by `zhtp/src/runtime/services/mining_service.rs:18`.

**Acceptance criteria.**
- [ ] `lib-consensus/src/mining/` deleted.
- [ ] `lib-consensus/src/lib.rs:43` re-export deleted.
- [ ] `should_mine_block()` lives in `lib-blockchain/src/mining.rs` (or named target).
- [ ] `zhtp/src/runtime/services/mining_service.rs` imports from new location.
- [ ] Workspace builds and tests pass.

**Blast radius.** Files: ~4. Crates: `lib-consensus`, `lib-blockchain`, `zhtp`. External consumers: 1. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 1 day.

---

## CONS-103 · Move `lib-consensus/src/rewards/` → `lib-economy`

**What.** Relocate `RewardCalculator` + `RewardRound` types to `lib-economy/src/rewards/`. The consensus engine's current direct call (`mod.rs:475`) is replaced by a callback trait `RewardCallback` (defined in `lib-consensus-core/ports/`) that the runtime wires to the lib-economy impl.

**Why.** Rewards are economics, not consensus. The current direct dependency makes lib-consensus impossible to use without lib-economy's reward semantics.

**Acceptance criteria.**
- [ ] `lib-consensus/src/rewards/` deleted.
- [ ] `RewardCalculator` lives in `lib-economy/src/rewards/`.
- [ ] New trait `RewardCallback` in `lib-consensus-core/src/ports/rewards.rs` with method `fn distribute(&self, height: u64, validator_set: &[IdentityId])`.
- [ ] Runtime layer wires `RewardCallback` impl that delegates to `lib_economy::RewardCalculator`.
- [ ] All `lib-consensus/src/engines/consensus_engine/mod.rs` calls to `self.reward_calculator.*` replaced with `self.reward_callback.distribute(...)`.
- [ ] Workspace builds and tests pass; reward distribution still happens at finalization.

**Blast radius.** Files: ~8. Crates: `lib-consensus`, `lib-economy`, `lib-consensus-core` (new). External consumers: 0 (rewards are internal). Network: none. Reversibility: medium (move is mechanical, callback wiring is new code). Risk: Medium.

**Estimate.** 3 days.

---

## CONS-104 · Move `lib-consensus/src/proofs/` → `lib-proofs`

**What.** Relocate `StakeProof`, `WorkProof`, `StorageCapacityAttestation`, `ProofOfUsefulWork` types and verification logic to `lib-proofs` (workspace member already exists at `Cargo.toml:30`). Keep BFT verification (vote signature + quorum proof) inside lib-consensus-core.

**Why.** Proof systems are reusable across consensus mechanisms; lib-proofs is the right home.

**Acceptance criteria.**
- [ ] `lib-consensus/src/proofs/` deleted.
- [ ] All proof types live in `lib-proofs/src/`.
- [ ] `lib-consensus/src/lib.rs:48` re-export deleted.
- [ ] Engine callers (`engines/consensus_engine/proofs.rs`) re-import from `lib_proofs::*`.
- [ ] Workspace builds; `cargo test -p lib-proofs` passes.

**Blast radius.** Files: ~12. Crates: `lib-consensus`, `lib-proofs`, `lib-blockchain`, `lib-storage`. External consumers: 3-5. Network: none. Reversibility: full. Risk: Medium (proof types are coupled to validator info).

**Estimate.** 4 days.

---

## CONS-105 · Move `lib-consensus/src/observer/` → new `lib-consensus-observer`

**What.** Create new workspace crate `lib-consensus-observer`, move all of `lib-consensus/src/observer/` (~3,810 LOC) into it. The new crate is **optional** — observer-runtime nodes pull it in, validator nodes do not.

**Why.** Observer is ML/anomaly detection. Per its own `mod.rs:1-3`: "deterministic, passive observer layer for consensus behavior analysis." Has no business inside the consensus engine crate.

**Acceptance criteria.**
- [ ] `lib-consensus-observer/` exists as workspace member.
- [ ] All 9 observer files moved (`consensus_parser.rs`, `event_normalizer.rs`, `height_scoring.rs`, `observer_service.rs`, `state_encoder.rs`, `surprisal_engine.rs`, `trajectory_builder.rs`, `transition_model.rs`, `mod.rs`).
- [ ] `lib-consensus-observer/Cargo.toml` depends on `lib-consensus-core` (NOT the reverse — consensus must compile without observer).
- [ ] `lib-consensus/tests/observer_deterministic_replay_tests.rs` moved to `lib-consensus-observer/tests/`.
- [ ] `cargo build --workspace` builds; `cargo build -p lib-consensus-core` builds **without** pulling in observer.

**Blast radius.** Files: ~15. Crates: `lib-consensus`, `lib-consensus-observer` (new), `lib-consensus-core` (new). External consumers: 0 (observer is end-user tooling). Network: none. Reversibility: full. Risk: Low.

**Estimate.** 3 days.

---

## CONS-106 · Move `lib-consensus/src/dao/` → `lib-governance`

**What.** Relocate the entire DAO governance engine (`DaoEngine`, `DaoProposal`, `DaoVote`, `GovernanceParameterUpdate`, `DaoExecutionAction`, etc., ~2,043 LOC) to `lib-governance` (workspace member at `Cargo.toml:21`). Replace the consensus-engine's direct ownership of `dao_engine: DaoEngine` (`mod.rs:471`) with a callback trait `GovernanceCallback`.

**Why.** DAO is governance. Strongest signal: `lib-blockchain/src/blockchain/dao.rs:772-815` already deep-imports `lib_consensus::dao::dao_types::*`.

**Acceptance criteria.**
- [ ] `lib-consensus/src/dao/` deleted.
- [ ] All DAO types and engine in `lib-governance/src/dao/`.
- [ ] New trait `GovernanceCallback` in `lib-consensus-core/src/ports/governance.rs` with methods `fn process_expired_proposals(&self, height: u64)` and `fn apply_param_update(&self, update: &GovernanceParameterUpdate)`.
- [ ] All `lib-blockchain/src/blockchain/dao.rs` deep-imports rewritten: `lib_governance::dao_types::*` instead of `lib_consensus::dao::dao_types::*`.
- [ ] `lib-consensus/src/engines/consensus_engine/mod.rs` calls to `self.dao_engine.*` replaced with `self.governance_callback.*`.
- [ ] DAO API handlers (`zhtp/src/api/handlers/dao/mod.rs:26`) updated.
- [ ] `lib-consensus/src/lib.rs:62-63` `#[cfg(feature = "dao")] pub use dao::*;` deleted.
- [ ] All workspace tests pass.

**Blast radius.** Files: ~25. Crates: `lib-consensus`, `lib-governance`, `lib-blockchain`, `zhtp`. External consumers: ~10 (DAO has the deepest reach). Network: none. Reversibility: medium. Risk: Medium-High.

**Estimate.** 5 days.

---

## CONS-107 · Move `chain_evaluation.rs` and `difficulty.rs` to `lib-blockchain`

**What.** `chain_evaluation.rs` (longest-chain rule — irrelevant to BFT) and `difficulty.rs` (PoW difficulty management) move to `lib-blockchain/src/`.

**Why.** Both are blockchain-layer concerns, not BFT.

**Acceptance criteria.**
- [ ] Both files moved to `lib-blockchain/src/`.
- [ ] `lib-consensus/src/lib.rs:32-33` re-exports deleted.
- [ ] `lib-blockchain/src/lib.rs:166` updates: `pub use crate::difficulty::*;` instead of `pub use lib_consensus::*`.
- [ ] Workspace builds; tests pass.

**Blast radius.** Files: ~8. Crates: `lib-consensus`, `lib-blockchain`. External consumers: 2-3. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 2 days.

---

## CONS-108 · Delete the theatrical `[features]` block

**What.** Delete `dao`, `byzantine`, `rewards`, `ubi`, `full` features from `lib-consensus/Cargo.toml:42-50`. Delete the three `#[cfg(feature = ...)]` re-exports at `lib-consensus/src/lib.rs:62-69`.

**Why.** They don't actually gate compilation (verified in architecture report §2.1). Their presence misleads operators about what is and isn't optional.

**Acceptance criteria.**
- [ ] `[features]` block in `lib-consensus/Cargo.toml` keeps only `default = []`, `testing = []`, `dev-insecure = []` — the ones with real semantics.
- [ ] No `#[cfg(feature = "dao")]` / `byzantine` / `rewards` in `lib-consensus/src/`.
- [ ] `cargo build --workspace --no-default-features` succeeds.
- [ ] `cargo build --workspace --all-features` succeeds.

**Blast radius.** Files: 2. Crates: `lib-consensus`. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 0.5 days.

---

# Phase 2 — Wire Format Unification (big-bang)

> Phase 2 is the only Phase that **must** ship as a single PR. It is a wire-format change; partial deployment is impossible.

## CONS-201 · Collapse two `ValidatorMessage` types into one

**What.** Delete `lib-consensus/src/validators/validator_protocol.rs::ValidatorMessage` (5 variants: `Propose`, `Vote`, `Commit`, `RoundChange`, `Heartbeat`). Keep and extend `lib-consensus/src/types/mod.rs::ValidatorMessage` (3 variants: `Propose`, `Vote`, `Heartbeat`). The `Commit` variant is redundant (already covered by `Vote { vote_type: Commit }`); the `RoundChange` variant is unused by the engine.

Delete `convert_to_network_message()` (`zhtp/src/runtime/components/consensus.rs:241-320`) and `convert_*_message()` (`lib-network/src/messaging/message_handler.rs:2169-2200`).

Delete the wall-clock timestamp injection (`zhtp/src/runtime/components/consensus.rs:308-311`) and the nonce-based message-ID hack (`zhtp/src/runtime/components/consensus.rs:293-301`) — both exist solely because of the duplicate types.

**Why.** Two types with the same name in the same crate, with conversion shims that re-introduce wall-clock time and nonce hacks. See architecture doc §1.3.

**Acceptance criteria.**
- [ ] One `ValidatorMessage` type in the workspace, located at `lib-consensus-core/src/types/messages.rs`.
- [ ] Zero conversion functions between message types.
- [ ] `grep -rn "convert_to_network_message\|convert_.*_message" --include="*.rs"` returns zero matches.
- [ ] `grep -rn "lib_consensus::validators::ValidatorMessage" --include="*.rs"` returns zero matches.
- [ ] Wire-format test: serialize a vote with the new type, deserialize, byte-compare against the legacy serialization for the same logical content (or, if not byte-equal, document the wire-format change in CONS-203).

**Blast radius.** Files: ~15. Crates: `lib-consensus`, `lib-network`, `zhtp`. External consumers: ~8. Network: **chain restart required** (wire format changes). Reversibility: high cost. Risk: High.

**Estimate.** 4 days.

---

## CONS-202 · Collapse two `MessageBroadcaster` traits into one

**What.** Delete `lib-network/src/message_broadcaster.rs::MessageBroadcaster` (the lib-network trait that uses `PublicKey` and returns `BroadcastResult`). Keep one trait in `lib-consensus-core/src/ports/broadcaster.rs` with a **new signature** that mandates a latency budget:

```rust
#[async_trait]
pub trait MessageBroadcaster: Send + Sync {
    /// Best-effort broadcast. MUST return within `budget`. Implementations
    /// parallelize per-recipient sends and apply per-recipient timeouts internally.
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        validator_ids: &[IdentityId],
        budget: Duration,
    );

    /// Diagnostic only — engine MUST NOT branch on this.
    fn last_delivered_count(&self) -> usize;
}
```

Note: no `Result`. The broadcaster contract is "fire and forget within budget"; failure is a metric, not an error path. Per Invariant CE-ENG-4 ("MUST NOT depend on broadcast success"), this makes the invariant *enforceable* by the type system instead of aspirational.

**Why.** Architecture doc §6.2: both traits underspecify latency, both impls inherit the broken pattern. The signature change forces every impl to bound its own latency.

**Acceptance criteria.**
- [ ] One `MessageBroadcaster` trait in the workspace.
- [ ] `lib-network/src/message_broadcaster.rs` deleted.
- [ ] All call sites pass an explicit `Duration` budget.
- [ ] No `Result` return on broadcaster calls (callers cannot accidentally branch on broadcast success).
- [ ] `MockMessageBroadcaster` rewritten against new trait, supports asserting on `(message, recipients, budget)` triples.

**Blast radius.** Files: ~10. Crates: `lib-consensus`, `lib-consensus-core`, `lib-network`, `zhtp`. External consumers: ~6. Network: API change; no wire impact. Reversibility: medium. Risk: Medium.

**Estimate.** 3 days.

---

## CONS-203 · Bump `CONSENSUS_PROTOCOL_VERSION`

**What.** Bump `CONSENSUS_PROTOCOL_VERSION` (`lib-consensus/src/engines/consensus_engine/mod.rs:247`) from 1 → 2. Document the wire format change in `docs/protocol/consensus-v2.md`.

**Why.** CONS-201 changes the wire format. Nodes on v1 and v2 must reject each other's messages cleanly via signature mismatch (per the existing version-mismatch handling at `validation.rs:486-496`).

**Acceptance criteria.**
- [ ] `CONSENSUS_PROTOCOL_VERSION = 2`.
- [ ] `docs/protocol/consensus-v2.md` exists and lists every wire-format delta from v1.
- [ ] Test: a v1 message decoded by a v2 node is rejected with `ConsensusError::ByzantineFault("protocol version mismatch")` (existing semantic, preserved).

**Blast radius.** Files: 3. Crates: `lib-consensus`. External consumers: 0 (it's a constant). Network: every node must run v2 binary at restart. Reversibility: full (just decrement). Risk: Low.

**Estimate.** 1 day.

---

# Phase 3 — Core FSM Rewrite

> The hard part. Single-track. Each issue depends on the previous.

## CONS-301 · Introduce `ValidatorFsm` with explicit states

**What.** Create `lib-consensus-core/src/fsm/state.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmState {
    Idle,
    Proposing,
    Prevoting,
    Precommitting,
    Committed,
    Rejected(RejectionReason),
    Hung,
    HaltedForUpgrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    InsufficientPrevotes,
    InsufficientPrecommits,
    Timeout,
    InvalidBlock,
}
```

Replace `ConsensusRound.step: ConsensusStep` with `ConsensusRound.state: FsmState`. The legacy `ConsensusStep` enum survives **only** as a wire-format type for backward compatibility with v1 audit logs (or is deleted if v1 logs are not preserved).

**Why.** Forensic doc §1: today there is no `Idle`, no `Rejected`, no `Hung`, no `HaltedForUpgrade`. The FSM is incomplete.

**Acceptance criteria.**
- [ ] `FsmState` and `RejectionReason` exist in `lib-consensus-core/src/fsm/state.rs`.
- [ ] All 8 variants reachable in tests.
- [ ] `cargo doc -p lib-consensus-core --open` shows complete state diagram in module docs.

**Blast radius.** Files: ~5 (new core files). Crates: `lib-consensus-core`. External consumers: 0 (still scaffolding). Network: none. Reversibility: full. Risk: Low.

**Estimate.** 2 days.

---

## CONS-302 · Introduce total `transition(state, event) -> next_state`

**What.** Create `lib-consensus-core/src/fsm/transition.rs`:

```rust
pub fn transition(state: FsmState, event: Event) -> (FsmState, Vec<Action>) {
    match (state, event) {
        // total match — every (state, event) pair handled
        (FsmState::Idle, Event::SelectedAsProposer) => (FsmState::Proposing, vec![Action::CreateProposal]),
        (FsmState::Idle, Event::ReceivedProposal(p)) => (FsmState::Prevoting, vec![Action::SendPrevote(...)]),
        // ... every combination ...
        // INVALID transitions are explicit:
        (FsmState::Committed, Event::ReceivedProposal(_)) => (FsmState::Committed, vec![Action::LogIgnoredEvent("late proposal in Committed")]),
        (FsmState::HaltedForUpgrade, _) => (FsmState::HaltedForUpgrade, vec![]),  // halt is absorbing
    }
}
```

Use a Rust trick (or `#[deny(non_exhaustive_omitted_patterns)]`, or a `match` over `(FsmState, Event)` with explicit `_` only for the absorbing `HaltedForUpgrade` case) to ensure totality at compile time.

**Why.** Forensic §6: today there is no central `transition()`. `on_round_timeout(NewRound)` is `_ => {}`, `on_proposal()` PreCommit/Commit branches are `_ => {}`, `handle_consensus_event()` has `_ => Ok(vec![])` for ~12 of 17 variants. Silent drops are baked in.

**Acceptance criteria.**
- [ ] `transition()` function exists, single source of truth.
- [ ] Compile-time check (clippy lint or compile_error if a (state, event) pair is omitted).
- [ ] Property test: for every (state, event) pair, `transition()` returns a valid (next_state, actions) tuple — no panic, no `unreachable!`.
- [ ] Architecture invariant test: `grep -rn "_ => {}" lib-consensus-core/src/fsm/` returns zero matches OR every `_ => {}` has a `// totality: covered by ...` comment that points to a regression test.

**Blast radius.** Files: ~3. Crates: `lib-consensus-core`. External consumers: 0. Network: none. Reversibility: full. Risk: Medium (totality is hard to maintain over time).

**Estimate.** 4 days.

---

## CONS-303 · Introduce `Event` and `Action` enums

**What.** Create `lib-consensus-core/src/fsm/events.rs`:

```rust
pub enum Event {
    SelectedAsProposer,
    ReceivedProposal(ConsensusProposal),
    PrevoteThresholdReached(Hash),
    PrecommitThresholdReached(Hash),
    CommitQuorumReached(Hash),
    VoteFailed(RejectionReason),
    Timeout,
    WatchdogFired { age: Duration },
    UpgradeSignal { halt_at_height: u64 },
}

pub enum Action {
    CreateProposal,
    BroadcastBlock(ConsensusProposal),
    SendPrevote(ConsensusVote),
    SendPrecommit(ConsensusVote),
    CommitBlock(ConsensusProposal, BftQuorumProof),
    AdvanceRound,
    ResetWatchdog,
    HaltForUpgrade,
    LogHung { reason: String },
    LogIgnoredEvent(&'static str),
}
```

**Why.** Today events are partially typed (`ConsensusEvent`), partially implicit (boolean checks), partially split across `ValidatorMessage` variants. Today actions are inline `await` calls with no type representation. Both are needed for the totality check in CONS-302 and for the action-channel pattern in CONS-306.

**Acceptance criteria.**
- [ ] Both enums exist in `lib-consensus-core/src/fsm/events.rs`.
- [ ] Every existing `ConsensusEvent` variant has a corresponding `Event` (with the noise — `RoundCompleted`, `RoundPrepared`, `ValidatorRegistered` etc. — pruned; the new `Event` enum is consensus-internal only, not a public observability bus).
- [ ] Public observability bus (`liveness_event_tx` equivalent) becomes a separate `ObservabilityEvent` enum that the runtime emits, decoupled from FSM internals.

**Blast radius.** Files: ~3. Crates: `lib-consensus-core`. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 2 days.

---

## CONS-304 · Introduce `step_entered_at: Instant`

**What.** Add `entered_at: std::time::Instant` to `ConsensusRound` struct (`lib-consensus-core/src/types.rs`). Set it inside the new `enter()` method (CONS-305) every time `state` changes.

Keep the existing deterministic `start_time = height` field, renamed to `deterministic_round_id` for clarity. The two serve different purposes (one for replay determinism, one for liveness measurement).

**Why.** Forensic §5, §9 risk #5: today `start_time` is repurposed to `height`, and there is no per-state-entry timestamp. Without this field, `state_timed_out()` is impossible and the watchdog has no signal to fire on.

**Acceptance criteria.**
- [ ] `ConsensusRound.entered_at: Instant` exists and is updated on every state transition.
- [ ] `ConsensusRound.deterministic_round_id: u64` exists and is `height` (preserves replay determinism).
- [ ] New method `fn state_age(&self) -> Duration { self.entered_at.elapsed() }`.
- [ ] Test: after `transition()` returns a new state, `entered_at` reflects the call time within 1ms.

**Blast radius.** Files: ~5. Crates: `lib-consensus-core`. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 1 day.

---

## CONS-305 · Migrate every handler to call `transition()`

**What.** Rewrite every handler in `lib-consensus/src/engines/consensus_engine/state_machine.rs`:

- `on_proposal` → `let event = Event::ReceivedProposal(p); let (new_state, actions) = transition(self.state, event); self.enter(new_state); for a in actions { self.dispatch(a); }`.
- `on_prevote`, `on_precommit`, `on_commit_vote`, `on_round_timeout` → same pattern.
- `enter_propose_step`, `enter_prevote_step`, `enter_precommit_step`, `enter_commit_step` → **deleted**. Their work moves into action handlers.

The handler functions become thin event-translators; all decision logic lives in `transition()`.

**Why.** Today decision logic is scattered across 5 `on_*` handlers and 4 `enter_*` methods, with implicit (state, event) match arms. CONS-302 centralizes it; CONS-305 makes the engine actually use the centralized version.

**Acceptance criteria.**
- [ ] No `on_*_step` or `enter_*_step` methods that contain decision logic — they only translate or do not exist.
- [ ] Every state mutation goes through `self.enter(new_state)` which updates `entered_at` (CONS-304).
- [ ] Existing test corpus (CONS-003 baseline) passes unchanged.

**Blast radius.** Files: ~3 (state_machine.rs is the main one, ~2300 LOC rewritten). Crates: `lib-consensus-core`. External consumers: 0 (the public API of the engine is preserved). Network: none. Reversibility: medium. Risk: High (this is the central rewrite).

**Estimate.** 7 days.

---

## CONS-306 · Replace inline `broadcaster.await` with `action_tx.send(Action::Send*)`

**What.** Add `action_tx: tokio::sync::mpsc::UnboundedSender<Action>` field to `ConsensusEngine`. Every place the current code awaits `self.broadcaster.broadcast_to_validators(...)` becomes `let _ = self.action_tx.send(Action::SendPrevote(vote))`. The runtime spawns a separate executor task that owns the broadcaster and drains `action_rx`.

**Why.** Forensic D1 / architecture §6.2: inline-await on the broadcaster is the proximate cause of the broadcast-blocks-consensus hang. Action channel + executor task eliminates the inline await structurally.

**Acceptance criteria.**
- [ ] No `.await` on `MessageBroadcaster` calls anywhere in `lib-consensus-core/src/`.
- [ ] `action_tx` is `UnboundedSender` so `send` never blocks (correctness depends on the executor being faster than the producer in practice; document the back-pressure strategy in the Action executor).
- [ ] Architecture invariant test: `grep -rn "broadcaster.*\.await\|broadcast_to_validators(.*).await" lib-consensus-core/src/` returns zero matches.
- [ ] Stress test: simulate a broadcaster impl that hangs forever; assert the engine completes a round (timeout-driven advance) within `propose_timeout + prevote_timeout + precommit_timeout + 1s`.

**Blast radius.** Files: ~5. Crates: `lib-consensus-core`, `lib-consensus-runtime`. External consumers: 0. Network: none. Reversibility: medium. Risk: High (changes the engine's core control flow).

**Estimate.** 5 days.

---

## CONS-307 · Replace inline `commit_callback.await` with `action_tx.send(Action::CommitBlock)`

**What.** Same pattern as CONS-306, but for `BlockCommitCallback`. The new port trait is `BlockFinalizationSink` (CONS-402). Engine emits `Action::CommitBlock(proposal, proof)` and continues. The runtime's commit-executor task acquires the blockchain lock, writes the block, and signals failure via a separate `commit_failure_rx` channel that the engine polls **between rounds** (out of the hot path).

**Why.** Forensic D2 / architecture §6.4: inline-await on commit callback is the storage-blocks-consensus hang. Sink + dedicated writer task eliminates it.

**Acceptance criteria.**
- [ ] No `.await` on `BlockCommitCallback` / `BlockFinalizationSink` anywhere in `lib-consensus-core/src/`.
- [ ] Halt-on-commit-failure semantic preserved: when the runtime's writer task signals failure, the engine transitions to `FsmState::HaltedForUpgrade` (or new variant `HaltedForStorageError`) on its next round-boundary check.
- [ ] Stress test: simulate a `BlockFinalizationSink` impl that hangs forever; assert the engine still emits `Hung` via the watchdog (CONS-309) within `state_age > propose_timeout * 5`.
- [ ] Idempotency: if the same block-finalize action is emitted twice (engine restart, replay), the writer task handles it idempotently (existing semantic preserved).

**Blast radius.** Files: ~5. Crates: `lib-consensus-core`, `lib-consensus-runtime`. External consumers: 0. Network: none. Reversibility: medium. Risk: High.

**Estimate.** 5 days.

---

## CONS-308 · Typed rejection reasons, `RoundRejected` event

**What.** Use `RejectionReason` (introduced in CONS-301). Engine emits `ObservabilityEvent::RoundRejected { height, round, reason }` from `transition()`'s rejection paths. Replace all log-only rejection messages with typed events.

**Why.** Forensic §2: today rejection reasons are stringly-typed and never propagated to the observability bus from the live loop.

**Acceptance criteria.**
- [ ] `ObservabilityEvent::RoundRejected` is emitted from every `(state, Event::Timeout) -> (FsmState::Rejected(reason), ...)` transition.
- [ ] Operators can subscribe to the observability bus and see typed rejection reasons in real time.
- [ ] Test: trigger each `RejectionReason` variant via test fixtures; assert the corresponding event is observed.

**Blast radius.** Files: ~4. Crates: `lib-consensus-core`, `lib-consensus-runtime`. External consumers: any monitoring stack (currently none — there is no live consumer of `liveness_event_tx`). Network: none. Reversibility: full. Risk: Low.

**Estimate.** 2 days.

---

## CONS-309 · Watchdog task

**What.** Independent tokio task spawned by `ConsensusRuntime`. Polls `engine.state_age()` every 500ms. When `age > 5 × max(propose_timeout, prevote_timeout, precommit_timeout)`, sends `Event::WatchdogFired { age }` into the engine's event channel. The engine's `transition()` handles `WatchdogFired` by transitioning to `FsmState::Hung` and emitting `Action::LogHung`.

The watchdog task **does not share** the same `tokio::select!` as the engine's main loop — it runs on its own task so a blocked engine cannot block the watchdog (forensic §7).

**Why.** Forensic §7, §9: today there is no watchdog that can detect or escape a hang. With CONS-306/307 eliminating the inline-await hang sources, the watchdog catches anything else (logic bugs, runtime starvation, deadlocks not yet identified).

**Acceptance criteria.**
- [ ] `ConsensusRuntime::spawn_watchdog()` spawns an independent `tokio::task::JoinHandle`.
- [ ] Watchdog fires `Event::WatchdogFired` when `state_age` exceeds threshold.
- [ ] Threshold is configurable via `ConsensusConfig::watchdog_threshold_multiplier` (default 5×).
- [ ] Test: simulate a stuck FSM (force the engine to never call `transition()` after entering `Proposing`); assert `FsmState::Hung` reached within `watchdog_threshold + 1s`.
- [ ] Test: confirm the watchdog task continues to fire even when the main engine task is blocked on a slow callback (using a deliberately misbehaving `BlockFinalizationSink` impl).

**Blast radius.** Files: ~3. Crates: `lib-consensus-core`, `lib-consensus-runtime`. External consumers: 0. Network: none. Reversibility: full. Risk: Medium.

**Estimate.** 3 days.

---

## CONS-310 · Move catch-up + fork-policy constants into `lib-consensus-core/budget.rs`

**What.** Create `lib-consensus-core/src/budget.rs` containing:

```rust
pub const WRONG_CHAIN_HALT_THRESHOLD: u32 = 3;     // was zhtp/runtime/components/consensus.rs:479
pub const MAX_BROADCAST_BUDGET_MS: u64 = 750;       // new — explicit per-call budget
pub const WATCHDOG_THRESHOLD_MULTIPLIER: u32 = 5;   // CONS-309
pub const COMMIT_FAILURE_HALT_THRESHOLD: u32 = 1;   // halt on first persistent commit failure
```

Add a runtime startup check in `ConsensusRuntime::new()`: query `TransportInfo::idle_timeout()` (new trait, CONS-403); if it exceeds `MAX_BROADCAST_BUDGET_MS * 100`, fail to start with a clear error.

**Why.** Architecture §6.3: today consensus-safety constants live in `lib-network` (`max_idle_timeout = 300s`) and `zhtp/runtime` (`WRONG_CHAIN_WIPE_THRESHOLD = 3`). Consensus crate has no awareness or control. Centralization + startup assertion turns silent latency cliffs into startup errors.

**Acceptance criteria.**
- [ ] All consensus-affecting constants live in `lib-consensus-core/src/budget.rs`.
- [ ] `grep -rn "max_idle_timeout\|WRONG_CHAIN" lib-network/src/ zhtp/src/` returns zero matches that are consensus-affecting (or each match is a `pub use lib_consensus_core::budget::*`).
- [ ] Runtime startup fails fast if transport idle timeout > 100× broadcast budget.

**Blast radius.** Files: ~5. Crates: `lib-consensus-core`, `lib-network`, `zhtp`. External consumers: 0. Network: none. Reversibility: full. Risk: Low-Medium (startup behavior change).

**Estimate.** 2 days.

---

# Phase 4 — New Port Traits

## CONS-401 · `MessageBroadcaster` redesign — see CONS-202 (already done in Phase 2)

CONS-202 already establishes the new trait shape. This issue is a marker confirming the trait lives in `lib-consensus-core/src/ports/broadcaster.rs` and is the only `MessageBroadcaster` in the workspace.

**Acceptance criteria.**
- [ ] `lib-consensus-core/src/ports/broadcaster.rs` is the single source.
- [ ] No re-exports of older trait shapes anywhere.

**Estimate.** 0 days (covered by CONS-202).

---

## CONS-402 · `BlockCommitCallback` → `BlockFinalizationSink`

**What.** Replace the `BlockCommitCallback` trait (`lib-consensus/src/types/mod.rs:519-568`) with `BlockFinalizationSink`:

```rust
pub trait BlockFinalizationSink: Send + Sync {
    /// Engine emits this when 2f+1 commits arrive. Synchronous, non-blocking.
    /// Implementation owns the actual write task.
    fn finalized(&self, proposal: ConsensusProposal, proof: BftQuorumProof);

    /// Async query — engine polls between rounds (NOT inline).
    async fn recent_failure(&self) -> Option<FinalizationError>;
}
```

**Why.** Architecture §6.4: callback shape forces inline-await; sink shape doesn't.

**Acceptance criteria.**
- [ ] Trait lives in `lib-consensus-core/src/ports/finalization.rs`.
- [ ] No `async` on `finalized()` — it's a synchronous channel send.
- [ ] All call sites in `lib-consensus-core` invoke `finalized()` non-async.
- [ ] Engine polls `recent_failure()` once per round-boundary check, not inline.

**Blast radius.** Files: ~4. Crates: `lib-consensus-core`, `lib-consensus-runtime`. External consumers: 1 (the runtime's `ConsensusBlockCommitter`). Network: none. Reversibility: medium. Risk: Medium.

**Estimate.** 2 days.

---

## CONS-403 · `TransportInfo` trait

**What.** New trait `TransportInfo` in `lib-consensus-core/src/ports/transport.rs`:

```rust
pub trait TransportInfo: Send + Sync {
    fn idle_timeout(&self) -> Duration;
    fn name(&self) -> &str;
}
```

The runtime queries this at startup (CONS-310) to assert the transport's idle timer is compatible with the consensus broadcast budget.

**Acceptance criteria.**
- [ ] Trait exists.
- [ ] zhtp QUIC adapter implements it returning the actual `max_idle_timeout` (currently 300s).
- [ ] Test: a misconfigured transport (returns 60 minutes) causes `ConsensusRuntime::new()` to fail with a clear error message naming the constant and the transport.

**Blast radius.** Files: ~3. Crates: `lib-consensus-core`, `lib-consensus-runtime`, `zhtp`. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 1 day.

---

## CONS-404 · `RewardCallback` and `FeeCallback` traits

**What.** Already defined as part of CONS-103 (rewards). Add `FeeCallback` for the analogous pattern with `lib-fees`. Both live in `lib-consensus-core/src/ports/economy.rs`.

```rust
pub trait RewardCallback: Send + Sync {
    fn distribute(&self, height: u64, validator_set: &[IdentityId]);
}

pub trait FeeCallback: Send + Sync {
    fn collect_and_distribute(&self, block: &BlockMetadata);
}
```

**Acceptance criteria.**
- [ ] Both traits live in `lib-consensus-core/src/ports/economy.rs`.
- [ ] No `Result` returns — fee/reward distribution failures are observability events, not engine errors.
- [ ] Engine invocations are synchronous (no `.await`).

**Blast radius.** Files: ~3. Crates: `lib-consensus-core`, `lib-economy`, `lib-fees`. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 1 day.

---

# Phase 5 — Adapter & Runtime Rewrite

## CONS-501 · `lib-consensus-net` crate (move wire layer)

**What.** Move into `lib-consensus-net`:
- `lib-consensus/src/network/codec.rs` (866 LOC).
- `lib-consensus/src/network/heartbeat.rs` (849 LOC).
- `lib-consensus/src/validators/validator_protocol.rs` (1,556 LOC).
- `lib-consensus/src/validators/validator_discovery.rs` (783 LOC).

Update `lib-network/src/validator_discovery_transport.rs:33` deep-import to `use lib_consensus_net::discovery::*`.

**Acceptance criteria.**
- [ ] `lib-consensus-net/Cargo.toml` depends on `lib-consensus-core`, `lib-network`, `lib-crypto`.
- [ ] All four modules compile in the new home.
- [ ] No deep-imports of `lib_consensus::validators::validator_discovery` anywhere.

**Blast radius.** Files: ~20. Crates: `lib-consensus`, `lib-consensus-net`, `lib-network`, `zhtp`. External consumers: 4-5. Network: none (these are internal modules). Reversibility: medium. Risk: Medium.

**Estimate.** 4 days.

---

## CONS-502 · `lib-consensus-runtime` crate

**What.** Create `lib-consensus-runtime/src/runtime.rs` containing `ConsensusRuntime` (architecture doc §3.4). Owns:

- The `ConsensusEngine`.
- The `Action` executor task (drains `action_rx`, dispatches broadcast / finalization / commit failure handling).
- The watchdog task (CONS-309).
- The catch-up sync task (moved from `zhtp/src/runtime/components/consensus.rs:445-619` in CONS-506).
- The fork-divergence policy (`WRONG_CHAIN_HALT_THRESHOLD` from `lib-consensus-core::budget`).
- The startup transport-compatibility check (CONS-310).

Single `tokio::select!` over the engine, the action receiver, the watchdog, the catch-up sync rx, and the validator-update rx.

**Acceptance criteria.**
- [ ] `ConsensusRuntime::run()` exists and runs the engine + all background tasks.
- [ ] No `tokio::select!` in `lib-consensus-core` — it lives only in the runtime.
- [ ] All inline `.await`s on side effects are gone from the engine (CONS-306, CONS-307 acceptance criteria re-verified at integration level).

**Blast radius.** Files: ~10. Crates: `lib-consensus-runtime`, `lib-consensus-core`, `zhtp`. External consumers: 1 (the zhtp runtime that wires `ConsensusRuntime` instead of bare `ConsensusEngine`). Network: none. Reversibility: medium. Risk: High (this is the integration point).

**Estimate.** 6 days.

---

## CONS-503 · Rewrite `ConsensusMeshBroadcaster` against new trait

**What.** Rewrite `zhtp/src/runtime/components/consensus.rs:28-143` against the new `MessageBroadcaster` trait (CONS-202). Replace the sequential per-peer loop with `futures::stream::FuturesUnordered`. Apply per-peer `tokio::time::timeout(budget / num_peers, send_to_peer(...))`. Total call returns within `budget`.

**Acceptance criteria.**
- [ ] `for peer_id in recipients { ... .await }` pattern gone — replaced with parallel send.
- [ ] Per-peer `tokio::time::timeout` applied.
- [ ] Test: 100 recipients with one stalled (mock send hangs); broadcaster returns within 2× per-peer budget, not within 100× per-peer budget.
- [ ] Test: `last_delivered_count()` accurate after partial failure.

**Blast radius.** Files: 1. Crates: `zhtp`. External consumers: 0. Network: none. Reversibility: full. Risk: Medium.

**Estimate.** 2 days.

---

## CONS-504 · Rewrite `ConsensusBlockCommitter` as `BlockFinalizationSink`

**What.** Rewrite `zhtp/src/runtime/components/consensus.rs:1052-1340` against the new `BlockFinalizationSink` trait (CONS-402). The new impl owns a dedicated writer task with its own input mpsc channel; `finalized()` just sends to the channel. Failures are buffered in a `recent_failure: Arc<RwLock<Option<FinalizationError>>>` slot polled by the engine.

The dedicated writer task is the only writer to `blockchain_arc` — it does not share the lock with catch-up sync (which sends `Action::ApplyTrustedBlocks` on the same channel and is naturally serialized).

**Acceptance criteria.**
- [ ] No inline `.await` on `blockchain_arc.write()` in any consensus-path code.
- [ ] Catch-up sync writes go through the same writer task (no lock contention with BFT).
- [ ] Test: stress test with concurrent BFT commits + catch-up sync; assert no lock-contention-induced delays in BFT commit latency.
- [ ] Halt-on-commit-failure preserved: persistent error in writer task → `FinalizationError` returned by `recent_failure()` → engine transitions to `FsmState::HaltedForStorageError`.

**Blast radius.** Files: 2-3. Crates: `zhtp`, `lib-blockchain`. External consumers: 0. Network: none. Reversibility: medium. Risk: High (concurrency rewrite).

**Estimate.** 5 days.

---

## CONS-505 · Delete `BlockchainConsensusCoordinator`

**What.** Delete `lib-blockchain/src/integration/consensus_integration.rs` (2,124 LOC). Migrate the few methods that aren't already covered:

- `create_consensus_proposal()` (`consensus_integration.rs:923`) → folds into the engine's `create_proposal()` (`state_machine.rs:1873`).
- `consensus_proposal_to_block()` (`consensus_integration.rs:1258`) → `BlockFinalizationSink::finalized` impl (CONS-504).
- `block_production_loop` (`consensus_integration.rs:862`) → handled by the engine's existing proposer-selection path.
- `dao_governance_loop` (`consensus_integration.rs:993`) → moves to `lib-governance`.
- `reward_distribution_loop` (`consensus_integration.rs:1018`) → moves to `lib-economy`.

**Acceptance criteria.**
- [ ] `lib-blockchain/src/integration/consensus_integration.rs` deleted.
- [ ] No "second consensus driver" in the workspace. Verify with `grep -rn "consensus_event_loop" --include="*.rs"` returning only the runtime's single driver.
- [ ] `lib-blockchain/examples/full_consensus_integration.rs` either deleted or rewritten against the new runtime.

**Blast radius.** Files: ~10. Crates: `lib-blockchain`, `lib-governance`, `lib-economy`, `zhtp`. External consumers: 5+ (anything importing `BlockchainConsensusCoordinator`). Network: none. Reversibility: medium. Risk: High.

**Estimate.** 5 days.

---

## CONS-506 · Move catch-up sync to `lib-consensus-runtime`

**What.** Move `run_catch_up_sync_task`, `prioritize_catchup_peers`, `catchup_sync_from_peer`, `HashMismatchError` from `zhtp/src/runtime/components/consensus.rs:445-1050` (~600 LOC) to `lib-consensus-runtime/src/catch_up_sync.rs`.

The runtime owns the catch-up trigger channel and dispatches `Action::ApplyTrustedBlocks` through the same writer task as BFT commits (CONS-504).

**Acceptance criteria.**
- [ ] All catch-up code in `lib-consensus-runtime`.
- [ ] `WRONG_CHAIN_HALT_THRESHOLD` import from `lib-consensus-core::budget` (CONS-310).
- [ ] `zhtp/src/runtime/components/consensus.rs` shrinks to <500 LOC of pure adapter wiring.

**Blast radius.** Files: ~4. Crates: `lib-consensus-runtime`, `zhtp`, `lib-blockchain`. External consumers: 0. Network: none. Reversibility: medium. Risk: Medium.

**Estimate.** 3 days.

---

## CONS-507 · Delete `lib-network/src/message_broadcaster.rs`

**What.** Delete the second `MessageBroadcaster` trait (lib-network's). All consumers route through the lib-consensus-core trait.

**Acceptance criteria.**
- [ ] `lib-network/src/message_broadcaster.rs` deleted.
- [ ] `MeshMessageBroadcaster` and `MockMessageBroadcaster` either deleted or moved to `lib-consensus-runtime` (rewritten against the new trait).
- [ ] `grep -rn "lib_network::.*MessageBroadcaster\|lib_network::MeshMessageBroadcaster" --include="*.rs"` returns zero matches.

**Blast radius.** Files: ~5. Crates: `lib-network`, dependents. External consumers: 2-3. Network: none. Reversibility: full. Risk: Low (covered by CONS-202).

**Estimate.** 1 day.

---

## CONS-508 · Final lib-consensus crate deletion

**What.** Delete `lib-consensus/` from the workspace. By this point all its contents have moved to `lib-consensus-core`, `lib-consensus-net`, `lib-consensus-observer`, `lib-governance`, `lib-economy`, `lib-mempool`, `lib-blockchain`, `lib-proofs`, or have been deleted entirely.

**Acceptance criteria.**
- [ ] `lib-consensus/` directory deleted.
- [ ] Workspace `Cargo.toml` no longer lists `lib-consensus`.
- [ ] `grep -rn "use lib_consensus" --include="*.rs"` returns zero matches.
- [ ] `cargo build --workspace` succeeds.
- [ ] `cargo test --workspace` matches or exceeds the CONS-003 baseline.

**Blast radius.** Files: 100+ deleted. Crates: 1 (whole `lib-consensus`). External consumers: 0 (all have been migrated). Network: none. Reversibility: full (it's all in git). Risk: Low (verification step, no new logic).

**Estimate.** 1 day.

---

# Phase 6 — Verification & Cutover

## CONS-601 · Full integration test suite

**What.** Restore and extend the test corpus from CONS-003. Add new tests:

- **Total transition test** — for every (FsmState × Event) pair, assert `transition()` returns a documented (next_state, actions) tuple. ~64 cases.
- **Watchdog escape test** — engine stuck in each state for `5 × max_timeout`; assert `Hung` reached.
- **Adapter latency test** — broadcaster impl that hangs forever; assert engine advances rounds via timeout.
- **Concurrent-writer test** — BFT commit + catch-up sync running in parallel; assert no lock contention delays BFT commit by >100ms.
- **Wire-format regression test** — round-trip every `ValidatorMessage` variant through the new codec; assert byte stability across releases.

**Acceptance criteria.**
- [ ] All baseline tests from CONS-003 still pass.
- [ ] All new tests above pass.
- [ ] Test count is documented in `docs/epics/consensus-rewrite-test-baseline.md` (delta: +N tests).

**Blast radius.** Files: ~15 (new tests). Crates: all new crates. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 5 days.

---

## CONS-602 · Multi-node soak test

**What.** Stand up a 4-validator and a 21-validator local network using the new binary. Run for 24h. Inject:

- Network partition (kill peer-to-peer between halves for 5 minutes, restore).
- Slow peer (one validator's broadcast hangs for 60s on every send).
- Slow disk (one validator's sled write artificially delayed by 30s).
- Byzantine equivocation (one validator double-signs at random heights).

**Acceptance criteria.**
- [ ] All four scenarios result in either: (a) BFT recovery within bounded time, or (b) clean halt with operator-actionable error message.
- [ ] No silent hangs (verified by absence of multi-minute gaps in audit log).
- [ ] No chain divergence (all healthy nodes converge on the same final block at end of soak).
- [ ] Soak report posted to `docs/epics/consensus-rewrite-soak-report.md`.

**Blast radius.** Files: ~3 (test harness, report). Crates: 0. External consumers: 0. Network: dedicated soak network. Reversibility: full. Risk: Medium (uncovers latent bugs).

**Estimate.** 5 days (one for setup, three for runs, one for report).

---

## CONS-603 · Architecture invariant tests

**What.** Add CI-enforced grep-style tests that prevent regressions:

```rust
// tests/architecture_invariants.rs

#[test]
fn no_inline_await_in_fsm() {
    let output = std::process::Command::new("grep")
        .args(["-rn", "broadcaster.*\\.await\\|finalize.*\\.await", "lib-consensus-core/src/fsm/"])
        .output().unwrap();
    assert!(output.stdout.is_empty(), "FSM has inline awaits on side effects");
}

#[test]
fn no_lib_consensus_re_exports() {
    let output = std::process::Command::new("grep")
        .args(["-rn", "use lib_consensus", "--include=*.rs", "."])
        .output().unwrap();
    assert!(output.stdout.is_empty(), "Old lib_consensus uses still exist");
}

#[test]
fn no_consensus_constants_in_lib_network() {
    // similar grep against lib-network for max_idle_timeout, WRONG_CHAIN_*, etc.
}
```

Plus the totality check from CONS-302 wired into CI.

**Acceptance criteria.**
- [ ] `cargo test -p workspace-architecture-invariants` runs in CI on every PR.
- [ ] Failing any of these tests blocks merge.

**Blast radius.** Files: 2-3. Crates: new test crate. External consumers: 0. Network: none. Reversibility: full. Risk: Low.

**Estimate.** 2 days.

---

## CONS-604 · New genesis with fresh chain ID

**What.** Generate a new `genesis-v2.toml` with:
- New chain ID (e.g. `sovn-mainnet-v2`).
- Initial validator set (same identities as v1 if desired).
- `CONSENSUS_PROTOCOL_VERSION = 2` baked in.
- Note in genesis comments: pointer to v1 archive.

Archive the current `genesis.toml` as `archive/genesis-v1.toml` and document the v1 → v2 reset event in `docs/protocol/v2-cutover.md`.

**Acceptance criteria.**
- [ ] `genesis-v2.toml` exists, validates against schema.
- [ ] `archive/genesis-v1.toml` preserved.
- [ ] `docs/protocol/v2-cutover.md` documents: cutover datetime, chain ID change rationale, archive location of v1 chain state, recovery procedure if cutover fails.

**Blast radius.** Files: 3. Crates: 0. External consumers: 0 (no v1 nodes remain after cutover). Network: defines the new network. Reversibility: full at this stage (until cutover). Risk: Medium.

**Estimate.** 2 days.

---

## CONS-605 · Operator runbook for cutover

**What.** Write `docs/operations/v2-cutover-runbook.md`:

1. Pre-cutover: announce 72h in advance to all validator operators.
2. T-1h: validators stop accepting new transactions (`txpool freeze` API).
3. T-0: all nodes stop the v1 binary, archive their `data/sled/` directory to `data/sled-v1-archive/` (DO NOT delete — operator-investigatable per Apr 2 2026 policy).
4. T+0: operators install v2 binary, start with `--genesis genesis-v2.toml`.
5. T+30m: chain begins producing blocks; observability dashboard confirms BFT mode active.
6. Rollback procedure if v2 fails: stop v2 binary, restore `data/sled-v1-archive/` to `data/sled/`, restart v1 binary. Network resumes from last v1 block.

**Acceptance criteria.**
- [ ] Runbook exists, peer-reviewed by operations team.
- [ ] Dry-run executed on testnet before mainnet cutover.

**Blast radius.** Files: 1. Crates: 0. External consumers: 0. Network: documents the cutover. Reversibility: documents how. Risk: Low (it's a doc).

**Estimate.** 2 days.

---

## CONS-606 · Chain restart — synchronized network-wide

**What.** Execute the runbook from CONS-605 on testnet first, then mainnet.

**Acceptance criteria.**
- [ ] Testnet cutover succeeds: chain produces blocks within 30 minutes of v2 binary start.
- [ ] Testnet runs 7 days without consensus-related incidents.
- [ ] Mainnet cutover scheduled with 14-day operator notice after testnet success.
- [ ] Mainnet cutover succeeds: same criteria as testnet.
- [ ] Postmortem document produced regardless of outcome: `docs/epics/consensus-rewrite-postmortem.md`.

**Blast radius.** Files: 1 (postmortem). Crates: 0. External consumers: every validator. Network: full restart. Reversibility: per CONS-605 rollback procedure. Risk: **Catastrophic if it fails — but bounded by the rollback path.**

**Estimate.** 14 days (testnet soak) + 14 days (mainnet notice) + 1 day (mainnet cutover).

---

# Summary Table

| ID | Title | Phase | Estimate | Risk |
|---|---|---|---|---|
| CONS-001 | Lock the design | 0 | 2d | Low |
| CONS-002 | Workspace scaffolding | 0 | 1d | Low |
| CONS-003 | Test corpus capture | 0 | 3d | Low |
| CONS-101 | Delete mempool | 1 | 2d | Low |
| CONS-102 | Delete mining | 1 | 1d | Low |
| CONS-103 | Move rewards → lib-economy | 1 | 3d | Medium |
| CONS-104 | Move proofs → lib-proofs | 1 | 4d | Medium |
| CONS-105 | Move observer → new crate | 1 | 3d | Low |
| CONS-106 | Move dao → lib-governance | 1 | 5d | Med-High |
| CONS-107 | Move chain_evaluation + difficulty → lib-blockchain | 1 | 2d | Low |
| CONS-108 | Delete theatrical features | 1 | 0.5d | Low |
| CONS-201 | Collapse ValidatorMessage | 2 | 4d | High |
| CONS-202 | Collapse MessageBroadcaster + new signature | 2 | 3d | Medium |
| CONS-203 | Bump protocol version | 2 | 1d | Low |
| CONS-301 | FsmState enum | 3 | 2d | Low |
| CONS-302 | Total transition() | 3 | 4d | Medium |
| CONS-303 | Event + Action enums | 3 | 2d | Low |
| CONS-304 | step_entered_at | 3 | 1d | Low |
| CONS-305 | Migrate handlers to transition() | 3 | 7d | High |
| CONS-306 | action_tx for broadcaster | 3 | 5d | High |
| CONS-307 | action_tx for finalization | 3 | 5d | High |
| CONS-308 | Typed RoundRejected | 3 | 2d | Low |
| CONS-309 | Watchdog task | 3 | 3d | Medium |
| CONS-310 | Centralize budget constants | 3 | 2d | Low-Med |
| CONS-401 | MessageBroadcaster trait (marker) | 4 | 0d | — |
| CONS-402 | BlockFinalizationSink | 4 | 2d | Medium |
| CONS-403 | TransportInfo trait | 4 | 1d | Low |
| CONS-404 | Reward + Fee callbacks | 4 | 1d | Low |
| CONS-501 | lib-consensus-net crate | 5 | 4d | Medium |
| CONS-502 | lib-consensus-runtime crate | 5 | 6d | High |
| CONS-503 | Rewrite ConsensusMeshBroadcaster | 5 | 2d | Medium |
| CONS-504 | Rewrite ConsensusBlockCommitter | 5 | 5d | High |
| CONS-505 | Delete BlockchainConsensusCoordinator | 5 | 5d | High |
| CONS-506 | Move catch-up sync to runtime | 5 | 3d | Medium |
| CONS-507 | Delete lib-network broadcaster | 5 | 1d | Low |
| CONS-508 | Delete lib-consensus | 5 | 1d | Low |
| CONS-601 | Integration test suite | 6 | 5d | Low |
| CONS-602 | Multi-node soak | 6 | 5d | Medium |
| CONS-603 | Architecture invariant tests | 6 | 2d | Low |
| CONS-604 | New genesis | 6 | 2d | Medium |
| CONS-605 | Cutover runbook | 6 | 2d | Low |
| CONS-606 | Chain restart | 6 | 29d | Catastrophic-bounded |

**Engineering days: ~115d** (one engineer, sequential).
**Calendar weeks: ~13** sequential, **~9** with one parallel engineer on Phases 1+4.
**Cutover calendar: +4 weeks** (testnet soak + mainnet notice).
**Total: ~17 calendar weeks from kickoff to mainnet v2.**

---

# Honest caveats

- **Phase 3 is the hard one.** CONS-305 (rewriting handlers against `transition()`) and CONS-306/307 (action channel) are the deepest changes. They cannot be parallelized within Phase 3 — each builds on the previous. Budget for surprises.
- **CONS-201 / CONS-203 are the only wire-format breaks.** Everything else is internal API. If schedule pressure mounts, those two can ship together with CONS-606 in a single network restart; deferring lets earlier work land continuously without coordinating downtime.
- **CONS-606 (the actual restart) is bounded-catastrophic.** The rollback path in CONS-605 limits the blast radius, but it requires every operator to follow the runbook precisely. Dry-run twice on testnet, not once.
- **The 115-day estimate assumes no scope creep.** Per CONS-001, every deviation must update the architecture doc first. Hold the line.
- **Memory rule reminder:** *"do it right the first time"* and *"no band-aid fixes"*. This epic is the embodiment of those rules; if any phase is tempted to ship a shortcut, refer back to those rules and to the design doc.
