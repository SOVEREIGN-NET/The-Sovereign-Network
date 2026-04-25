# Consensus Rewrite v2 — Architectural Decisions Record

**Epic:** [#2365](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2365)
**Source:** `docs/forensics/bft-consensus-architecture-analysis.md`
**Status:** Ratified (merged into `development` via the PR that closes [#2323](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2323))
**Authority:** This document is the single source of truth for the consensus rewrite. Any deviation requires updating this document **first**, in a separate PR, before the deviating implementation lands.

Each decision below carries an ID (`AD-NNN`), a one-line rationale, and a link to the architecture document section that develops it in full.

---

## AD-001 · Three-crate split

**Decision.** `lib-consensus` is split into `lib-consensus-core`, `lib-consensus-net`, `lib-consensus-runtime`. The mega-crate is deleted.

**Rationale.** Today's `lib-consensus` mixes a Tendermint-like BFT engine with DAO governance, ML observer, mempool, mining, slashing, rewards, PoS/PoStorage/PoUW proofs, validator-discovery + protocol middleware, and wire codec. A consensus crate that another project could reuse must contain only consensus.

**Reference.** `docs/forensics/bft-consensus-architecture-analysis.md` § 3.1.

---

## AD-002 · `lib-consensus-core` performs no IO

**Decision.** `lib-consensus-core` declares only `lib-types`, `lib-crypto`, `lib-identity`, `serde`, `thiserror`, `tracing`, `async-trait` as dependencies. No `tokio` (full features), no `lib-storage`, no `lib-proofs`, no `chrono`, no `dashmap`. All side effects go through `ports/*` traits implemented by `lib-consensus-runtime`.

**Rationale.** The "no IO" constraint is the load-bearing rule that guarantees pluggable transport, pluggable storage, no domain leak.

**Reference.** § 3.5.

---

## AD-003 · Domain modules exit `lib-consensus`

**Decision.** DAO ⇒ `lib-governance`. Observer ⇒ new `lib-consensus-observer`. Mempool ⇒ `lib-mempool` (delete duplicate). Mining ⇒ `lib-blockchain`. Proofs ⇒ `lib-proofs`. Rewards ⇒ `lib-economy`. `chain_evaluation.rs`, `difficulty.rs` ⇒ `lib-blockchain`. `validators/{validator_protocol, validator_discovery, genesis}.rs` ⇒ `lib-consensus-net` + `lib-blockchain`. `network/{codec, heartbeat}.rs` ⇒ `lib-consensus-net`.

**Rationale.** §2 of the architecture doc enumerates each leak. Removing the entire `lib-governance` crate must compile `lib-consensus-core` clean — that is the test.

**Reference.** § 2 (table), § 3.2 (table).

---

## AD-004 · One `ValidatorMessage` type, one `MessageBroadcaster` trait

**Decision.** Delete the 5-variant `lib_consensus::validators::ValidatorMessage`. Keep the 3-variant `lib_consensus::types::ValidatorMessage`, relocated to `lib-consensus-core/src/types/messages.rs`. Delete `lib-network/src/message_broadcaster.rs::MessageBroadcaster`. Keep one trait in `lib-consensus-core/src/ports/broadcaster.rs`.

**Rationale.** Two types with the same name + conversion shims caused wall-clock-time leakage and nonce-based dedup hacks. One trait per concept, one type per concept.

**Reference.** § 1.3, § 1.4.

---

## AD-005 · Latency budget is a first-class trait parameter

**Decision.** `MessageBroadcaster::broadcast_to_validators(message, validator_ids, budget: Duration)` — no `Result` return. Best-effort by contract. `BlockFinalizationSink::finalized(proposal, proof)` is sync and non-blocking; failures surface via async `recent_failure()` polled at round boundaries.

**Rationale.** Today both adapter impls have unbounded latency on the consensus loop's critical path. Putting the latency budget on the trait makes the contract enforceable instead of aspirational. Per-call `Result` returns invite engine code to branch on broadcast success, violating Invariant CE-ENG-4.

**Reference.** § 6.2, § 6.4. Forensic D1, D2.

---

## AD-006 · Single consensus driver

**Decision.** `BlockchainConsensusCoordinator` (`lib-blockchain/src/integration/consensus_integration.rs`, 2,124 LOC) is deleted. `ConsensusRuntime` in `lib-consensus-runtime` is the single owner of the consensus loop and all side-effect dispatch.

**Rationale.** Two parallel drivers is a recipe for divergent state. The engine already enforces a single-driver invariant internally; the rewrite makes that hold workspace-wide.

**Reference.** § 1.1, § 3.4.

---

## AD-007 · `ValidatorFsm` with explicit states

**Decision.** Introduce `FsmState { Idle, Proposing, Prevoting, Precommitting, Committed, Rejected(RejectionReason), Hung, HaltedForUpgrade }` and a total `transition(state, event) -> (next_state, Vec<Action>)` function in `lib-consensus-core/src/fsm/`.

**Rationale.** The current FSM has no `Idle`, no typed `Rejected`, no `Hung`, no `HaltedForUpgrade`. Transition logic is scattered across `on_*` and `enter_*` handlers with implicit `_ => {}` drops. Centralizing into a total `transition()` makes incompleteness a compile-time error.

**Reference.** § 3.3. Forensic § 1, § 6.

---

## AD-008 · `step_entered_at` enables the watchdog

**Decision.** Add `entered_at: Instant` to `ConsensusRound`, set by `enter()` on every state transition. Rename existing deterministic `start_time = height` field to `deterministic_round_id`.

**Rationale.** Without per-state-entry timestamps, `state_timed_out()` is impossible and the watchdog has no signal. The existing field was a misnomer (it held `height`, not a timestamp).

**Reference.** Forensic § 5, § 9 risk #5.

---

## AD-009 · Action channel replaces inline `.await`

**Decision.** Side effects (broadcast, commit, advance round, etc.) are emitted as `Action` enum values via an `mpsc::UnboundedSender<Action>`. The runtime spawns separate executor tasks that drain the channel and own the I/O. The engine never awaits on a port-trait method during a transition.

**Rationale.** Inline `.await` on `MessageBroadcaster` and `BlockCommitCallback` is the proximate cause of the silent-hang failure mode (forensic D1, D2). Action channel + executor task eliminates the entire class structurally.

**Reference.** § 3.3, § 6.4.

---

## AD-010 · Independent watchdog task

**Decision.** A `WatchdogTask` is spawned by `ConsensusRuntime` on its own `tokio::task`, NOT inside the engine's `tokio::select!`. It polls `engine.state_age()` every 500ms and emits `Event::WatchdogFired { age }` when `age > 5 × max_step_timeout`.

**Rationale.** The current liveness-check loop runs in the same `tokio::select!` as the engine, so a blocked engine blocks the watchdog too. Separation guarantees rescue.

**Reference.** § 3.4. Forensic § 7.

---

## AD-011 · Consensus-affecting constants live in `lib-consensus-core::budget`

**Decision.** `WRONG_CHAIN_HALT_THRESHOLD`, `MAX_BROADCAST_BUDGET_MS`, `WATCHDOG_THRESHOLD_MULTIPLIER`, `COMMIT_FAILURE_HALT_THRESHOLD` all live in `lib-consensus-core/src/budget.rs`. The runtime asserts at startup that the configured `TransportInfo::idle_timeout()` is compatible.

**Rationale.** Today `max_idle_timeout = 300s` lives in `lib-network/src/protocols/quic_mesh.rs` and `WRONG_CHAIN_WIPE_THRESHOLD = 3` lives in `zhtp/src/runtime/components/consensus.rs`. Both are consensus-safety constants in disguise. Centralization + startup assertion turns silent latency cliffs into startup errors.

**Reference.** § 6.3.

---

## AD-012 · Concurrency isolation for finalization

**Decision.** A single dedicated writer task in `ConsensusRuntime` owns all blockchain mutation. BFT commit, catch-up sync, and observer paths all send `Action`s to the same writer task and are naturally serialized. No code outside this task acquires `blockchain_arc.write()`.

**Rationale.** Today BFT commit shares the global blockchain `RwLock` with catch-up sync, network-observer commits, and proposer reads. The most safety-critical write competes with non-BFT writers.

**Reference.** § 6.1.

---

## AD-013 · Theatrical features deleted

**Decision.** The `dao`, `byzantine`, `rewards`, `ubi`, `full` features in `lib-consensus/Cargo.toml` are deleted. Only `default = []`, `testing = []`, `dev-insecure = []` remain.

**Rationale.** The deleted features only gated `pub use` re-exports, not compilation. Their presence misled operators about what was optional.

**Reference.** § 2.1.

---

## AD-014 · Wire-format break = `CONSENSUS_PROTOCOL_VERSION = 2` + chain restart

**Decision.** The `ValidatorMessage` consolidation (AD-004) breaks the wire format. `CONSENSUS_PROTOCOL_VERSION` bumps to 2 and the network restarts from a fresh `genesis-v2.toml`. The v1 chain is archived, not migrated.

**Rationale.** Migrating an in-flight consensus state to a new wire format under load is intractable. A coordinated restart from genesis is the only honest path.

**Reference.** Epic § CONS-201, CONS-203, CONS-606.

---

## AD-015 · Chain restart is operator-orchestrated, not automatic

**Decision.** `docs/operations/v2-cutover-runbook.md` (CONS-605) defines the cutover. Validators stop the v1 binary, archive `data/sled/` to `data/sled-v1-archive/` (DO NOT delete, per the Apr 2 2026 incident policy), then start the v2 binary against `genesis-v2.toml`. Rollback path: stop v2, restore the archive, restart v1.

**Rationale.** Auto-wiping caused total chain loss in Apr 2 2026. Manual archive preserves rollback.

**Reference.** Epic § CONS-605.

---

## AD-016 · Architecture invariants enforced in CI

**Decision.** A test crate `tests/architecture-invariants/` runs grep-style assertions on every PR: no `lib_consensus::` re-exports remain; no inline `.await` on side-effect ports inside `lib-consensus-core/src/fsm/`; no consensus-affecting constants in `lib-network/src/`. The totality check from AD-007 is wired into CI as well.

**Rationale.** Without CI enforcement, the architecture invariants drift the moment the rewrite ships. Compile-time and grep-time checks are the only durable form.

**Reference.** Epic § CONS-603.

---

## Process rules

- **Every PR in this epic** carries `Implements <doc> § <section>` in its description (PR template enforces).
- **Deviations** require a doc-update PR landing FIRST, then the implementation PR cites the new section.
- **Adding a new decision** appends an `AD-NNN` entry here in a separate PR; do not retroactively edit a ratified decision.
- **Rejecting a decision** marks it `**Status:** Rejected — see AD-NNN` and links the replacement; keeps audit trail.
