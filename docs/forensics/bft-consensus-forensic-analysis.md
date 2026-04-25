# BFT Consensus — Forensic Analysis

**Repository:** `The-Sovereign-Network`
**Crate audited:** `lib-consensus` (focus: `lib-consensus/src/engines/consensus_engine/`)
**Algorithm declared:** Tendermint-like BFT (`CONSENSUS_ALGORITHM`, `mod.rs:256`)
**Date:** 2026-04-25

This report walks the forensic spec section by section and, for every item, marks it **FOUND / PARTIAL / MISSING** with the exact `file:line` reference. All references are to the on-disk code at the time of the audit. Wherever a concept is missing, the file/struct that should own it is named.

---

## 1. Validator States

There is no `ValidatorState` enum or `ValidatorFSM`. Consensus state lives in the `step` field of `ConsensusRound`. The enum that holds steps is `ConsensusStep`, defined in `lib-types`:

- `lib-types/src/consensus.rs:112` — `pub enum ConsensusStep { Propose, PreVote, PreCommit, Commit, NewRound }`
- `lib-consensus/src/types/mod.rs:113-134` — `pub struct ConsensusRound { height, round, step, start_time, proposer, proposals, votes, timed_out, locked_proposal, valid_proposal }`

| State | Status | Evidence |
|---|---|---|
| `Idle` | **MISSING** | No `Idle` variant; pre-genesis is gated by `chain_started: bool` (`mod.rs:469`) and `is_bft_mode_active` (`mod.rs:784`). Should be added to `ConsensusStep` in `lib-types/src/consensus.rs:112`. |
| `Proposing` | **FOUND** | `ConsensusStep::Propose` — `lib-types/src/consensus.rs:114`; entered in `enter_propose_step()` `state_machine.rs:1844`. |
| `Prevoting` | **FOUND** | `ConsensusStep::PreVote` — `lib-types/src/consensus.rs:116`; entered in `enter_prevote_step()` `state_machine.rs:1939`. |
| `Precommitting` | **FOUND** | `ConsensusStep::PreCommit` — `lib-types/src/consensus.rs:118`; entered in `enter_precommit_step()` `state_machine.rs:1971`. |
| `Committed` | **PARTIAL** | `ConsensusStep::Commit` — `lib-types/src/consensus.rs:120` is the *step* in which a commit vote is cast. Persistence of the committed block is handled in `process_committed_block()` `state_machine.rs:820`. There is no separate "post-commit / committed" state — once `process_committed_block` returns, the engine waits for the timer to drive `on_round_timeout(Commit)` which then advances to the next height. |
| `Rejected` | **MISSING** | No typed `Rejected` state. Round rejection is implicit: the timer fires, `on_round_timeout()` `state_machine.rs:1761` advances to the next step or round. The `RoundFailed { height, error: String }` event in `types/mod.rs:248` is the closest analog but is emitted only by the deprecated `run_consensus_round()` synchronous driver (`state_machine.rs:308-313`), not by the live `run_consensus_loop()`. |
| `Hung` | **MISSING** | No `Hung` state. `LivenessMonitor::is_stalled()` (`network/liveness_monitor.rs:433`) detects when >1/3 of validators are unresponsive (validator-level liveness, not FSM hung-state). The closest *event* is `ConsensusEvent::ConsensusStalled` (`types/mod.rs:263`) emitted from `network.rs:363`. Consensus-engine never enters a "hung" status; it just keeps re-arming the timer. Should be added as a `ConsensusStep` variant or as a `hung_since: Option<Instant>` field on `ConsensusRound` (`types/mod.rs:113`). |

**NOTES (analyst):**
- State is **NOT a single enum**. The `step` field gives one slice; `chain_started`, `is_bft_mode_active`, and `validator_set_history` together produce the full state. There is no `ValidatorFSM`-like central type.
- `Rejected` is **implicit** — driven by timeouts in `on_round_timeout()` `state_machine.rs:1761`. There is no event or state recording *why* a round failed.
- No `Hung` equivalent on the consensus FSM. There is a per-*validator* `TimeoutState::Responsive | TimedOut` enum (`liveness_monitor.rs:209-215`) but that classifies peers, not the local engine.

---

## 2. Rejection Reasons

The error type is `ConsensusError` at `lib-consensus/src/lib.rs:76-126` (12 variants, `thiserror`-derived). Round-failure events use `RoundFailed { height, error: String }` (`types/mod.rs:249`), where the reason is a stringified error.

| Reason | Status | Evidence |
|---|---|---|
| `InsufficientPrevotes` | **MISSING** | Not typed. Rejection happens silently when `check_supermajority()` `state_machine.rs:369` returns false; the timer eventually fires `on_round_timeout(PreVote)` `state_machine.rs:1773` which calls `enter_precommit_step()` (which itself silently does nothing if no prevote quorum, see `state_machine.rs:1971-2054`). |
| `InsufficientPrecommits` | **MISSING** | Same pattern: silent. `on_round_timeout(PreCommit)` `state_machine.rs:1776` calls `enter_commit_step()` which casts no commit vote when precommit quorum is absent (`state_machine.rs:2056-2155`). |
| `Timeout` | **PARTIAL** | Not a typed reason. The timer drives transitions via `on_round_timeout()` `state_machine.rs:1761` but emits no `Timeout` event. `tracing::debug!("Round timeout at height {} round {} step {:?}", ...)` `state_machine.rs:1762-1767` is log-only. |
| `InvalidBlock` | **PARTIAL** | `ConsensusError::ByzantineFault(...)` (`lib.rs:87`) is thrown by `validate_no_fork_proposal()` `validation.rs:562-616`, `validate_incoming_proposal()` `validation.rs:479-533`, and `verify_proposal_signature()` `validation.rs:391-456`. But the rejection path in `on_proposal()` `state_machine.rs:1279-1294` and `state_machine.rs:1328-1338` *swallows* the error (logs and `return Ok(())`), so the error is never propagated to peers or stored as evidence. |

**NOTES (analyst):**
- Rejection reasons are **mostly log strings**, not typed.
- Reasons are **not propagated to peers**. Local rejections are logged via `tracing::warn!` and dropped. The `ConsensusEvent::ByzantineFault { error: String }` (`types/mod.rs:255`) only fires from the deprecated `run_consensus_round()` path (`mod.rs:255`) and from `handle_consensus_event` (`state_machine.rs:289`).
- Reasons are **not stored for diagnostics**. There is no `rejection_log` field on `ConsensusEngine`. `round_history: VecDeque<ConsensusRound>` (`mod.rs:461`) archives completed rounds but not their failure cause — the cloned `ConsensusRound` does not carry an `error` field.

---

## 3. Consensus Events / Triggers

The wire-message enum is `ValidatorMessage` at `lib-consensus/src/types/mod.rs:338`:

```rust
pub enum ValidatorMessage {
    Propose { proposal: ConsensusProposal },
    Vote { vote: ConsensusVote },
    Heartbeat { message: HeartbeatMessage },
}
```

The high-level event enum is `ConsensusEvent` at `types/mod.rs:235-289` — used by `handle_consensus_event()` (`state_machine.rs:171`) and the liveness emit channel `liveness_event_tx` (`mod.rs:489`).

The dispatch is split:
- **Wire messages** route through `on_message()` `network.rs:503` → `on_proposal / on_prevote / on_precommit / on_commit_vote`.
- **Lifecycle events** route through `handle_consensus_event()` `state_machine.rs:175`.

| Event | Status | Evidence |
|---|---|---|
| `SelectedAsProposer` | **PARTIAL** | Implicit. `compute_proposer_for_round()` `mod.rs:817` returns the proposer and `enter_propose_step()` `state_machine.rs:1844-1937` checks `if is_local_proposer { create_proposal().await }` (`state_machine.rs:1866`). No typed event is emitted. |
| `ReceivedProposal` | **FOUND** | `ConsensusEvent::ProposalReceived { proposal }` typed (`types/mod.rs:259`); handler is `on_proposal()` `state_machine.rs:1264-1417`. |
| `BlockBroadcast` | **FOUND** | `broadcaster.broadcast_to_validators(ValidatorMessage::Propose { proposal }, ...)` at `state_machine.rs:1892-1900` (in `enter_propose_step`) and `state_machine.rs:472-481` (in deprecated `run_propose_step`). |
| `PrevoteThresholdReached` | **PARTIAL** | Implicit boolean check `check_supermajority(prevote_count, total_validators)` `state_machine.rs:1502, 2031, 575`. No typed event. Triggers `enter_precommit_step()` (`state_machine.rs:1525`). |
| `PrecommitThresholdReached` | **PARTIAL** | Same pattern: `check_supermajority(precommit_count, total_validators)` `state_machine.rs:1615, 2115, 651`. Triggers `enter_commit_step()` (`state_machine.rs:1636`). |
| `VoteFailed` | **MISSING** | No typed event; failed votes are `tracing::warn!`-logged and dropped (e.g. `state_machine.rs:1437-1444`, `validation.rs:215-222`, `validation.rs:268-275`). Should be added to `ConsensusEvent` in `types/mod.rs:235`. |
| `Timeout` | **FOUND** | Driven by `RoundTimer::next_deadline()` `state_machine.rs:340-353` returning a `tokio::time::Sleep`. Timer fires inside `tokio::select!` at `network.rs:130` and dispatches to `on_round_timeout()` (`network.rs:218`) — but only after the `TimerToken::matches` check (`network.rs:211`) drops stale fires. |
| `WatchdogFired` | **MISSING** | There is **no watchdog**. The closest mechanism is `liveness_check_interval: tokio::time::Interval` (`mod.rs:499`), ticked every 5s in the same `tokio::select!` (`network.rs:333-339`), which calls `LivenessMonitor::watch_timeouts()` (`liveness_monitor.rs:308`) to reclassify validators. It does NOT inject a `Timeout` event into the FSM and does NOT force round advance. Should be added as a separate task that monitors `current_round.step` duration and synthesizes a `WatchdogFired` event. Belongs in `consensus_engine/network.rs` or a new `consensus_engine/watchdog.rs`. |
| `UpgradeSignal` | **MISSING** | No reference to `upgrade`, `halt_for_upgrade`, `coordinated_halt`, `target_halt_height` anywhere in `lib-consensus/src` or `lib-types/src`. There is no upgrade-coordination machinery. Should be added as a `ConsensusEvent` variant and a `halt_at_height: Option<u64>` field on `ConsensusEngine` (`mod.rs:445`). |

**NOTES (analyst):**
- Events are **partially typed** (`ConsensusEvent`, `ValidatorMessage`) and **partially implicit** (boolean checks, function calls).
- There **is** a central event loop: `run_consensus_loop()` at `network.rs:22-501` uses `tokio::select!` over five sources (timer, message_rx, heartbeat_interval, liveness_check_interval, validator_update_rx). However, transitions inside the handlers are scattered across `on_proposal / on_prevote / on_precommit / on_commit_vote / on_round_timeout` — there is no single `transition()` function (see §6).
- Proposer selection is **deterministic round-robin by height**: `proposer_index = (height + round) % num_validators` over the *snapshot* validator set, sorted by `IdentityId` bytes for determinism (`mod.rs:817-836`, declared in `LEADER_ROTATION_RULE` constant `mod.rs:265`). No VRF, no weighted stake.

---

## 4. Transition Actions

| Action | Status | Evidence |
|---|---|---|
| `BroadcastBlock` | **FOUND** | `broadcaster.broadcast_to_validators(ValidatorMessage::Propose { proposal }, &validator_ids).await` at `state_machine.rs:1894-1900`. |
| `SendPrevote` | **FOUND** | `cast_vote(proposal_id, VoteType::PreVote)` `state_machine.rs:1952` followed by broadcast `state_machine.rs:1956-1965`. |
| `SendPrecommit` | **FOUND** | `cast_vote(proposal_id, VoteType::PreCommit)` `state_machine.rs:2032-2034` + broadcast `state_machine.rs:2040-2049`. |
| `CommitBlock` | **FOUND** | `process_committed_block(proposal_id, commit_round)` `state_machine.rs:820-982`, called from `maybe_finalize()` `state_machine.rs:2216`. Persistence delegated to `BlockCommitCallback::commit_finalized_block_with_proof` (`types/mod.rs:552`) — failure halts the node (`state_machine.rs:1197-1211`). |
| `AdvanceRound` | **PARTIAL** | Two separate code paths:<br>1. `advance_to_next_round()` `state_machine.rs:419-432`: `height += 1; round = 0; step = Propose`.<br>2. `on_round_timeout(Commit)` `state_machine.rs:1779-1830`: `sync_height_with_blockchain` then conditionally `round = current_round.round + 1` (if height didn't advance) or `round = 0` (if it did).<br>**Not atomic**: `on_round_timeout(Commit)` interleaves an `await` (`sync_height_with_blockchain` at `state_machine.rs:1787`) before resetting state, and a second `await` (`enter_propose_step` at `state_machine.rs:1822`) after. |
| `ResetWatchdog` | **MISSING** | No watchdog → no reset. Should be added alongside the watchdog (see §3). |
| `HaltForUpgrade` | **MISSING** | No upgrade machinery exists. Should be added as a method on `ConsensusEngine` that sets `halt_at_height` and an early-return guard at the top of `run_consensus_loop()` (`network.rs:111`). |
| `LogHung` | **MISSING** | No Hung concept. Closest: `tracing::warn!(event = "ConsensusStalled", ...)` `network.rs:352-362` which fires when the **validator-liveness** stall threshold is crossed. This is not a per-FSM-state hung-detection. |

**NOTES (analyst):**
- Actions are **all async** — every `enter_*_step` and every broadcast `await`s. See §9 for the implications.
- `AdvanceRound` is **not atomic** and the two paths are subtly different. The fallback path inside `on_round_timeout(Commit)` is concerning: when `sync_height_with_blockchain` errors (`state_machine.rs:1788-1794`), it falls through to `advance_to_next_round()` which unconditionally increments height — even though no commit happened. This can desync local height from blockchain height.
- `CommitBlock` runs **in the same task** as the consensus loop. `process_committed_block` → `apply_block_to_state_with_proof` → `BlockCommitCallback.commit_finalized_block_with_proof` is awaited inline (`state_machine.rs:1180-1212`). If the runtime-injected callback blocks on storage (sled write), the consensus loop blocks. Documented in `types/mod.rs:531-534`: the callback failure halts the node, but the *latency* of a successful callback is also load-bearing.

---

## 5. ValidatorFSM Structure

There is no struct named `ValidatorFSM`. The consensus-engine state lives in `ConsensusEngine` at `lib-consensus/src/engines/consensus_engine/mod.rs:445-528` (29 fields). The per-round state is a sub-struct `ConsensusRound` at `lib-consensus/src/types/mod.rs:113-134`:

```rust
pub struct ConsensusRound {
    pub height: u64,
    pub round: u32,
    pub step: ConsensusStep,
    pub start_time: u64,            // repurposed; see below
    pub proposer: Option<IdentityId>,
    pub proposals: Vec<Hash>,
    pub votes: HashMap<Hash, Vec<Hash>>,   // legacy/unused
    pub timed_out: bool,
    pub locked_proposal: Option<Hash>,
    pub valid_proposal: Option<Hash>,
}
```

| Spec field | Status | Evidence |
|---|---|---|
| `state` | **FOUND** | `ConsensusRound.step: ConsensusStep` `types/mod.rs:119`. |
| `height` | **FOUND** | `ConsensusRound.height: u64` `types/mod.rs:115`. |
| `round` | **FOUND** | `ConsensusRound.round: u32` `types/mod.rs:117`. |
| `entered_at` | **MISSING** | `ConsensusRound.start_time: u64` `types/mod.rs:121` exists, but it is **explicitly repurposed**: `state_machine.rs:425` and `state_machine.rs:1810` set it to `current_round.height` ("REMOVED: Wall-clock start_time (nondeterministic). Use deterministic value based on height for consensus ordering"). It is **not** a "state entered at" timestamp. There is no per-step entry time — timeout duration is fixed by `ConsensusConfig::propose_timeout / prevote_timeout / precommit_timeout` (`lib-types/src/consensus.rs:166-170`) measured from when the timer was last armed, not when the state was entered. Should be added as `step_entered_at: std::time::Instant` on `ConsensusRound` `types/mod.rs:113`. |
| `action_tx` | **PARTIAL** | No dedicated channel. Side effects go through `broadcaster: Arc<dyn MessageBroadcaster>` (`mod.rs:485`) which is `await`ed inline. There is `liveness_event_tx: Option<mpsc::UnboundedSender<ConsensusEvent>>` (`mod.rs:489`) but it is *only* used for observability (`emit_liveness_event` `mod.rs:859`) and never for action dispatch. |

**Additional engine-level state of note (`ConsensusEngine`, `mod.rs:445-528`):**
- `vote_pool: HashMap<VotePoolKey, (ConsensusVote, Hash)>` `mod.rs:459` — composite-keyed on `(height, round, vote_type, validator_id)` (`state_machine.rs:379-384`); the only correct vote store. The `ConsensusRound.votes` field at `types/mod.rs:127` is legacy and unused.
- `pending_proposals: VecDeque<ConsensusProposal>` `mod.rs:455` — proposals admitted but not yet finalized.
- `validator_set_history: VecDeque<ValidatorSetSnapshot>` `mod.rs:463` — write-once snapshots per height (`mod.rs:1432-1459`); guarantees membership immutability across a height.
- `pending_validator_changes: VecDeque<PendingValidatorChange>` `mod.rs:465` — applied at epoch boundaries with churn cap (1/3 per epoch, `mod.rs:1258-1410`).

**NOTES (analyst):**
- State is **distributed**: `current_round` (per-round volatile state) + `vote_pool` (persistent across rounds at same height) + `validator_set_history` (per-height) + `pending_*` (governance/queue) + `chain_started: bool` (lifecycle). No single struct owns the FSM.
- `entered_at` is **NOT tracked**. Timeouts are NOT deterministic in the per-state-duration sense — they are deterministic only in the timer-Duration sense. If the engine is delayed (e.g. blocked on `await`), the state could be entered well before the timer fires; there is no record of when entry actually happened.
- **Owner**: clear and single. `ConsensusEngine` is owned by the task spawned to run `run_consensus_loop()` (`network.rs:22`). All state mutations happen via `&mut self` inside that task. The only external mutators are receiver-channels (`message_rx`, `validator_update_rx`) which deliver messages, not state mutations.

---

## 6. Core Methods

| Method | Status | Evidence |
|---|---|---|
| `new()` | **FOUND** | `ConsensusEngine::new(config, broadcaster)` `mod.rs:553-618`. Initializes `current_round` with `step: ConsensusStep::Propose` (not `Idle`), `start_time: 0`, all other fields default-empty. |
| `transition()` | **MISSING** | **There is no central `transition(state, event) -> next_state` function.** Transitions are scattered:<br>• `on_message()` `network.rs:503-598` matches on `ValidatorMessage` variant.<br>• `on_proposal()` `state_machine.rs:1264-1417` matches on `current_round.step` (lines 1360-1414) — covers `Propose` and `PreVote`; **everything else hits `_ => {}`** (`state_machine.rs:1413`).<br>• `on_round_timeout()` `state_machine.rs:1761-1835` matches on `current_round.step` — covers `Propose`, `PreVote`, `PreCommit`, `Commit`; **`NewRound => {}`** at `state_machine.rs:1831` (silent drop).<br>• `on_prevote / on_precommit / on_commit_vote` (`state_machine.rs:1419, 1535, 1646`) do not match on local step — they unconditionally store the vote and check supermajority.<br>The "FSM" is therefore the **union** of these handlers. No code anywhere enforces totality. |
| `enter()` | **PARTIAL** | One `enter_*` per terminal step:<br>• `enter_propose_step()` `state_machine.rs:1844-1937`<br>• `enter_prevote_step()` `state_machine.rs:1939-1969`<br>• `enter_precommit_step()` `state_machine.rs:1971-2054`<br>• `enter_commit_step()` `state_machine.rs:2056-2155`<br>**None capture an entry timestamp.** Each sets `current_round.step = ...` and immediately performs side effects. |
| `send()` | **PARTIAL** | The only "send" is `broadcaster.broadcast_to_validators(...)`. It is `async` and **awaited inline** in every `enter_*_step` (e.g. `state_machine.rs:1956-1965`, `state_machine.rs:2040-2049`). Per Invariant CE-ENG-4 (`mod.rs:362`) it is documented as best-effort, but the `await` is real — the broadcaster impl decides whether to block on per-peer I/O. |
| `state_timed_out()` | **MISSING** | No method asks "did this state exceed its budget?". Instead `RoundTimer::next_deadline(height, round, step)` (`state_machine.rs:340-353`) returns a `tokio::time::Sleep` of fixed duration; the *timer firing* is the only signal. Without `entered_at`, it is impossible to distinguish "we just entered this state and the timer hasn't reset" from "we have been here for 20s and the timer should have fired by now". Should be added as `fn state_timed_out(&self) -> bool` on `ConsensusEngine` `mod.rs:445`, depending on a new `step_entered_at` field. |

**CRITICAL ANSWERS:**

1. **Is `transition()` total?** **No.** Two examples of unhandled (state, event) pairs:
   - `on_round_timeout(NewRound)` is `_ => {}` → `state_machine.rs:1831` — explicit silent drop. If a node ever lands in `NewRound`, the timer fires forever with no progress.
   - `on_proposal()` while in `PreCommit` or `Commit` step matches `_ => {}` at `state_machine.rs:1413` after storing the proposal — this is intentional (the proposal is too late for prevote) but it is a silent acceptance with no event/log indicating "late proposal at PreCommit stored but ignored".

2. **Can any (state, event) reach a panic or deadlock?**
   - **Panic**: `pending_proposals.remove(proposal_index).expect("Proposal index came from position(), element must exist")` at `state_machine.rs:887-890` — would panic on a logic bug. `enforce_consensus_invariants` (`invariants.rs:201-216`) panics on safety violation.
   - **Deadlock**: not a hard deadlock (Rust+tokio prevents most), but `process_committed_block` → `BlockCommitCallback.commit_finalized_block_with_proof` is awaited inline (`state_machine.rs:1186-1212`). If the runtime callback hangs, the consensus loop hangs. Same for `broadcaster.broadcast_to_validators` if the broadcaster impl blocks on per-peer I/O.

3. **Is `send()` ever awaited inside the transition path?** **Yes — pervasively.** Every `enter_*_step` ends with an awaited broadcast. `process_committed_block` ends with an awaited callback. `cast_vote` awaits `sign_vote_data` (`state_machine.rs:758`). The transition path is "transition + await side effect" rather than "transition + dispatch action to a separate task". This is the structural source of the hang risk identified in §9.

---

## 7. Watchdog

| Component | Status | Evidence |
|---|---|---|
| Independent timer task | **MISSING** | The only periodic checker is `liveness_check_interval: tokio::time::Interval` (`mod.rs:499`, initialized at `liveness.rs:16-28` to 5s) — but it lives inside the **same** `tokio::select!` as the consensus loop (`network.rs:333-449`). It is not an independent task; if the consensus loop is blocked on `await`, this checker is also blocked. |
| Periodic timeout injection into FSM | **MISSING** | The liveness checker calls `LivenessMonitor::watch_timeouts()` (`network.rs:341`) and emits `ConsensusEvent::ConsensusStalled` (`network.rs:363-369`). It never injects a `Timeout` event into the consensus FSM and never advances the round. |
| Hung detection | **MISSING** | `LivenessMonitor::is_stalled()` (`liveness_monitor.rs:433-441`) detects when **>n/3 validators are unresponsive** (validator-level), not when the local FSM is stuck in one step. There is no `step_entered_at` to compare against. |
| Forced round advance | **MISSING** | No code path forces `advance_to_next_round()` outside of `on_round_timeout(Commit)` (`state_machine.rs:1793`). The liveness checker's only escalation is calling `catch_up_sync_trigger.trigger(our_blockchain_height)` (`network.rs:382, 445`), which downloads committed blocks from peers — it does not skip a stuck round on the local engine. |

**Where it would need to hook in:**
- **New file**: `lib-consensus/src/engines/consensus_engine/watchdog.rs` (paralleling `liveness.rs`).
- **New field** on `ConsensusEngine` (`mod.rs:445`): `watchdog_handle: Option<tokio::task::JoinHandle<()>>` for an *independent* spawned task.
- **New field** on `ConsensusRound` (`types/mod.rs:113`): `step_entered_at: std::time::Instant`.
- **New event** in `ConsensusEvent` (`types/mod.rs:235`): `WatchdogFired { height, round, step, age_secs }`.
- **Hook into the loop** at `network.rs:111`: add a `watchdog_rx` arm to the `tokio::select!`.

---

## 8. Tests

Counting `lib-consensus/src/engines/consensus_engine/tests.rs` (2798 lines, **45 `#[test]` / `#[tokio::test]`** functions) plus the integration suite under `lib-consensus/tests/`. Survey:

| Scenario | Status | Evidence |
|---|---|---|
| Happy path commit | **COVERED** | `test_canonical_convergence_different_vote_order` `tests.rs:1606`, `test_canonical_convergence_seven_validators` `tests.rs:1939`, `lib-consensus/tests/consensus_engine_tests.rs` (full suite), `lib-consensus/tests/integration_tests.rs`. |
| Rejection advances round | **PARTIAL** | `test_canonical_convergence_no_quorum_split_votes` `tests.rs:1774` exercises split votes (no quorum) but the assertion is "no commit happens", not "round advances to round+1 cleanly". The round-advance code in `on_round_timeout(Commit)` `state_machine.rs:1779-1830` has no direct unit test that calls it with `step=Commit, no quorum` and asserts `round == prev_round + 1`. |
| Timeout advances round | **PARTIAL** | `test_gap4_timer_token_staleness_detection` `tests.rs:728` covers timer-token validity but not full round-advance. The tokio-time-driven `on_round_timeout()` is exercised only via integration. There is **no** `#[tokio::test]` that fast-forwards `tokio::time` and asserts the FSM advanced from `Propose -> PreVote -> PreCommit -> Commit -> NewHeight` solely via timeouts. |
| Hung escape | **MISSING** | No Hung concept exists, so no test exists. |
| Double vote / Byzantine | **COVERED** | `test_canonical_convergence_with_equivocation` `tests.rs:2059`, `lib-consensus/tests/byzantine_tests.rs` (10 tests), `lib-consensus/tests/byzantine_evidence_tests.rs` (~20 tests), `lib-consensus/tests/bft_safety_partition_tests.rs:71` (`test_double_sign_detection_with_4_validators`). |
| Validator set change at boundary | **PARTIAL** | `test_validator_snapshot_is_write_once` `tests.rs:2749` covers snapshot immutability. `lib-consensus/tests/validator_manager_tests.rs` covers the manager. The full path "queue change → epoch boundary → churn-cap-enforced apply" in `apply_epoch_boundary_changes` (`mod.rs:1258-1410`) is exercised but the **mid-round** rejection (no validator can join mid-height) relies on the snapshot being write-once — that *invariant* is tested but the end-to-end "validator joins, snapshot still excludes them, votes from new validator are rejected at this height" is not. |
| Upgrade halt | **MISSING** | No `UpgradeSignal` exists. No test exists. |

Additional notable coverage:
- **Vote-validation gates** (`tests.rs:1081-1490`): height/round mismatch, non-member, signature failure, empty key, placeholder key, prevote-in-propose-step (PARTIAL: this is now allowed per the step-independent rule), commit-always-valid.
- **Proposal admission** (`tests.rs:2422-2622`): wrong proposer, invalid signature, prev-hash mismatch, decode failure, valid acceptance, wrong protocol version.
- **Future-round messages** (`tests.rs:2623-2712`): future-round Proposal/PreVote/PreCommit do not advance local round.
- **Single-driver invariant** (`tests.rs:1492`): `NewBlock` event respects single-driver rule.

**NOTES (analyst):**
- Transitions are tested **mostly via integration**, not in isolation. `on_round_timeout()` has no isolated unit test that exercises every (state, event) match arm.
- **Rejection-then-recovery is not directly tested**. The rejected-round → next-round → quorum-on-next-round flow is implicit in the canonical-convergence tests but not explicitly asserted. This is the most likely source of subtle desync bugs and is the highest-value test gap to close.

---

## 9. Known Risk Areas — Inspect These First

| # | Risk | Status | Evidence |
|---|---|---|---|
| 1 | **Blocking call in transition path** | **CONFIRMED — present.** | `process_committed_block` → `apply_block_to_state_with_proof` → `BlockCommitCallback::commit_finalized_block_with_proof` is awaited inline at `state_machine.rs:1186-1212`. This is a *runtime-injected* callback — the consensus engine has no control over its latency. If the runtime's sled write blocks (lock contention, fsync stall, disk pressure), the consensus loop blocks: no further timer fires are processed (network.rs:130 select arm cannot fire), no further messages are processed (network.rs:248 select arm cannot fire). The "best-effort" invariant CE-ENG-4 (`mod.rs:362`) applies to broadcasting only, **not** to the commit callback. Additionally, every `enter_*_step` `await`s `broadcaster.broadcast_to_validators` (e.g. `state_machine.rs:1956-1965`); if the broadcaster impl serializes per-peer sends with no timeout, that also blocks. |
| 2 | **Unhandled rejection path** | **CONFIRMED — present.** | `on_round_timeout(NewRound)` is `_ => {}` at `state_machine.rs:1831` — an explicit silent drop. The `ConsensusStep::NewRound` variant exists (`lib-types/src/consensus.rs:122`) and is **referenced elsewhere** — in engine matching/timer code (e.g. `RoundTimer::next_deadline` at `engines/consensus_engine/mod.rs:350`, the timeout-match arm at `state_machine.rs:1831`, the display-name test at `state_machine.rs:167`), in heartbeat conversion paths outside the engine (`validators/validator_protocol.rs:1109`, `lib-network/src/messaging/message_handler.rs:2211`), and in observer log parsing (`observer/event_normalizer.rs:147`, `observer/consensus_parser.rs:347`) — but it is **never assigned to the live engine round state** by any code in `lib-consensus/src/engines/consensus_engine/`. Grep of that subtree confirms zero assignments to `current_round.step = ConsensusStep::NewRound`. So in *current* engine operation the dead `_ => {}` branch cannot be hit, but the FSM is not total: a future code change that sets `step = NewRound` in the engine would create a hang. The deeper issue is that `Rejected` / `RoundFailed` paths do not propagate via `ConsensusEvent` from the live `run_consensus_loop()` — `RoundFailed` is only emitted from the deprecated `run_consensus_round()` (`state_machine.rs:309-314`) and from `handle_consensus_event` (`state_machine.rs:221-225, 308-314`). The live loop never emits a `Rejected` signal anywhere. |
| 3 | **Validator set change mid-round** | **DEFENDED.** | Validator additions/removals are queued (`mod.rs:1146-1234`) for `next_epoch_start(current_round.height)` and applied only at epoch boundaries by `apply_epoch_boundary_changes()` (`mod.rs:1258-1410`). Snapshots are **write-once** (`mod.rs:1432-1459`): `is_validator_member(voter, height)` (`validation.rs:89-100`) reads the sealed snapshot for `height`. A validator that registers mid-height appears only in the next snapshot. There is even a churn cap of 1/3 per epoch (`MAX_CHURN_NUMERATOR / MAX_CHURN_DENOMINATOR` `mod.rs:213-216`, enforced by an `assert!` at `mod.rs:1378-1388`). |
| 4 | **Round counter not reset on height advance** | **PARTIAL — two paths, one bug.** | Path A: `advance_to_next_round()` `state_machine.rs:419-432` does `height += 1; round = 0` — correct.<br>Path B: `on_round_timeout(Commit)` `state_machine.rs:1779-1830` calls `sync_height_with_blockchain` first; if the blockchain advanced, sets `round = 0`; if not, sets `round = round + 1`.<br>**Bug**: when `sync_height_with_blockchain` errors (`state_machine.rs:1788-1794`), it **falls back to `advance_to_next_round()`** which unconditionally `height += 1`. If no commit actually happened (e.g. quorum failed and the timer just fired), this advances local height past the blockchain height — desync. The fallback should re-use the no-commit branch (increment round, keep height) instead. |
| 5 | **State timestamp not captured** | **CONFIRMED — present.** | `ConsensusRound.start_time: u64` exists (`types/mod.rs:121`) but is explicitly set to `current_round.height` (`state_machine.rs:425`, `state_machine.rs:1810`) — **deterministic, not wall-clock, and not "state entered at"**. There is no `step_entered_at` field. The `RoundTimer.next_deadline(_, _, step)` (`state_machine.rs:340-353`) returns a `tokio::time::Sleep` keyed only on the `step` (selecting the configured `propose_timeout / prevote_timeout / precommit_timeout`); the timer is re-armed **whenever** the loop notices a state change (`network.rs:265-281`), so the actual elapsed-in-step duration is non-deterministic across nodes under any scheduling delay. |
| 6 | **No total transition function** | **CONFIRMED — present.** | Already enumerated under §6. Specific drop sites:<br>• `on_round_timeout()` `state_machine.rs:1831`: `ConsensusStep::NewRound => {}`<br>• `on_proposal()` `state_machine.rs:1413`: `_ => {}` (matches PreCommit, Commit, NewRound)<br>• `handle_consensus_event()` `state_machine.rs:330-333`: `_ => { tracing::debug!("Unhandled consensus event: {:?}", event); Ok(vec![]) }` — **eight** of the seventeen `ConsensusEvent` variants fall into this catch-all (RoundPrepared, RoundCompleted, RoundFailed, ValidatorRegistered, DaoError, ByzantineFault, RewardError, ProposalReceived, VoteReceived, ConsensusStalled, ConsensusRecovered, ModeTransitionToBft, ModeTransitionToBootstrap).<br>• `on_message()` `network.rs:560-565`: `VoteType::Against` reaches a defensive warning instead of a panic, but the *match itself* is exhaustive on the four `VoteType` variants. |

---

## 10. Top 5 Most Dangerous Findings

Ranked by *likelihood of producing a stuck or desynced network* under realistic operational stress.

1. **`process_committed_block` blocks the consensus loop on storage** — `state_machine.rs:1186-1212`. The runtime-injected `BlockCommitCallback.commit_finalized_block_with_proof` is awaited inline. A slow or hung sled write stops the consensus loop; no timer fires, no messages are processed, no liveness check runs. Failure mode: **silent hang while the network falls behind**, indistinguishable from a partition.

2. **`on_round_timeout(Commit)` desyncs height on `sync_height_with_blockchain` error** — `state_machine.rs:1786-1794`. The fallback unconditionally calls `advance_to_next_round()` which increments height by 1. If the blockchain provider erred for any reason (transient sled lock, IO timeout), the local consensus engine gets one height ahead of reality and starts proposing for `H+1` while peers are still at `H`. The proposer-rotation rule `(height + round) % n` then disagrees across nodes, breaking liveness for the affected height.

3. **No watchdog, no `step_entered_at`** — `mod.rs:445` (engine struct), `types/mod.rs:113` (round struct). The only "watchdog" is `liveness_check_interval` running in the same `tokio::select!` as the consensus loop (`network.rs:333`), so if the loop is blocked the watchdog is blocked too. There is no per-step elapsed-time tracking. Failure mode: **no upper bound on how long a step can hang before something forces progress**. Combined with finding #1, the system has no internal mechanism for self-rescue.

4. **No `Rejected` event from the live loop** — `state_machine.rs:1761-1835` (round-timeout) does not emit anything to `liveness_event_tx`. `RoundFailed` is wired only into the deprecated `run_consensus_round` path (`state_machine.rs:309`). Failure mode: **operators cannot tell from observability whether rounds are succeeding or silently looping on timeouts** — the only signal is `ConsensusStalled` after >1/3 of validators time out, which is too late.

5. **`enter_*_step` awaits broadcaster inline** — `state_machine.rs:1956-1965`, `state_machine.rs:2040-2049`, `state_machine.rs:1894-1900`, `state_machine.rs:2129-2138`. Every step transition is followed by an `await` on `broadcaster.broadcast_to_validators`. The trait contract (Invariant CE-ENG-4 at `mod.rs:362`) says "MUST NOT depend on broadcast success", but the *latency* is not bounded. A broadcaster impl that loops over peers with synchronous per-peer connect-then-send (no per-peer timeout) can stall the consensus loop arbitrarily long. The mitigation lives in the broadcaster impl, which is in a different crate not audited here.

---

## 11. Coverage Gaps in This Audit

Stated explicitly per the brief.

- **Read in full**: `engines/consensus_engine/{state_machine.rs (2302), mod.rs (1511), network.rs (610), validation.rs (617), storage.rs, liveness.rs, proofs.rs (header only)}`, `lib-consensus/src/types/mod.rs`, `lib-consensus/src/lib.rs`, `lib-consensus/src/invariants.rs`, `lib-consensus/src/network/liveness_monitor.rs`, `lib-types/src/consensus.rs` (relevant slice), `lib-consensus/src/byzantine/fault_detector.rs` (header). Names of all 45 tests in `engines/consensus_engine/tests.rs` enumerated; bodies sampled.
- **Sampled, not exhaustive**: `lib-consensus/src/byzantine/{evidence.rs, lru_cache.rs}`, `lib-consensus/src/validators/*` (722 + 783 + 532 + 1556 + 284 + 13 = 3890 lines — only the trait/method names were checked via grep), `lib-consensus/src/observer/*` (referenced for `NewRound` usage but not audited for FSM behavior), `lib-consensus/src/network/heartbeat.rs`, `lib-consensus/src/dao/*`, `lib-consensus/src/rewards/*`, `lib-consensus/src/slashing/*`, `lib-consensus/src/proofs/*`.
- **Not read**: `lib-consensus/tests/*.rs` bodies (test names listed, but no per-test assertion review). `lib-network/src/*.rs` (the `MessageBroadcaster` impl that determines whether the inline-await risk in §9 actually materializes). `zhtp/src/runtime/*` (the `BlockCommitCallback` impl that determines whether finding #1 actually materializes).
- **Recommended next audit**: the `MessageBroadcaster` impl in `lib-network` and the `BlockCommitCallback` impl in `zhtp` (or wherever it lives). Findings #1 and #5 above are *only* dangerous if those two impls have unbounded latency. If they have tight per-peer / per-write timeouts, the consensus engine's inline-await is acceptable.

---

## Tally

- **FOUND**: 14
- **PARTIAL**: 14
- **MISSING**: 17

---

## 12. Follow-up Audit — Broadcaster + Commit Callback Latency

**Scope of follow-up.** The §11 brief flagged that findings #1 and #5 in §10 are conditional: dangerous *only if* `MessageBroadcaster` and `BlockCommitCallback` impls have unbounded latency. This section closes that gap by reading the actual impls.

**Verdict: both impls have unbounded latency.** Findings #1 and #5 are confirmed dangerous in the current build.

### 12.1 `ConsensusMeshBroadcaster` (the impl the engine uses)

**File:** `zhtp/src/runtime/components/consensus.rs:28-143` — implements `lib_consensus::types::MessageBroadcaster`.

**Hot path** (`broadcast_to_validators`, `consensus.rs:59-142`):

```rust
let mut delivered = 0usize;
for peer_id in recipients {                                  // sequential, no parallelism
    if quic_protocol
        .send_to_peer(&peer_id, ZhtpMeshMessage::ValidatorMessage(...))
        .await                                               // no per-peer timeout
        .is_ok()
    { delivered += 1; }
}
```

- **No `tokio::time::timeout`** anywhere in this function (verified via grep across the file: the only `timeout` calls in `consensus.rs` are at lines 736, 745, 820 — all in the catch-up sync path, none in the broadcaster).
- **Sequential per-peer loop** (line 115) — N peers means N awaited sends in serial order.
- **No overall budget** — the function returns only after iterating every peer.

### 12.2 Underlying QUIC layer

**File:** `lib-network/src/protocols/quic_mesh.rs`.

`send_to_peer` (`quic_mesh.rs:1210-1238`) calls `Self::send_encrypted_to(&conn, &session_key, &message_bytes).await` (line 1226).

`send_encrypted_to` (`quic_mesh.rs:1107-1120`):

```rust
let mut stream = conn.open_uni().await.context("Failed to open UNI stream")?;
stream.write_all(&encrypted).await.context("Failed to write to UNI stream")?;
stream.finish().context("Failed to finish UNI stream")?;
```

- `conn.open_uni().await` — **NO timeout**. If the QUIC connection is congested or the peer is not draining streams, this blocks until QUIC's idle timer fires.
- `stream.write_all(&encrypted).await` — **NO timeout**. Stalls under back-pressure.
- The QUIC layer's only bound is `transport_config.max_idle_timeout(Some(Duration::from_secs(300)))` (`quic_mesh.rs:1706-1708, 1760-1762`). Per Issue #907 this was **raised from 30s to 300s** to prevent premature peer disconnection — a deliberate trade against responsiveness.

**Worst-case stall per broadcast call**: `min(num_peers × 300s, qc_idle_timer)`. For a 4-validator network, a single hung peer can stall a single broadcast for up to 5 minutes; for a 21-validator network, up to ~105 minutes if each peer stalls in sequence (extremely unlikely but the budget is there).

The same broadcast function is invoked **once per step transition** — `enter_propose_step` (1×), `enter_prevote_step` (1×), `enter_precommit_step` (1×), `enter_commit_step` (1×), and on every relayed message in `on_proposal / on_prevote / on_precommit / on_commit_vote` (`state_machine.rs:1349-1356, 1479-1487, 1592-1600, 1735-1743`). A single round therefore takes the latency hit between four and eight times.

### 12.3 `lib_network::message_broadcaster::MeshMessageBroadcaster` (the *other* broadcaster)

**File:** `lib-network/src/message_broadcaster.rs:151-321`.

This implements the **second** `MessageBroadcaster` trait (the lib-network one — see §1.4 of the architecture report). The consensus engine does not use this impl, but it is used by other workspace consumers and exhibits the same anti-pattern (`message_broadcaster.rs:223-256`):

```rust
for validator in validators {
    if validator == self.local_peer_id { skipped += 1; continue; }
    match self.mesh_router.route_message(...).await {     // no per-call timeout
        Ok(_) => delivered += 1,
        Err(e) => { failed += 1; ... }
    }
}
```

Same sequential loop, same lack of per-peer timeout. Documented here for completeness; not on the consensus hot path.

### 12.4 `ConsensusBlockCommitter` (the impl the engine uses)

**File:** `zhtp/src/runtime/components/consensus.rs:1052-1340` — implements `lib_consensus::types::BlockCommitCallback`.

**Hot path** (`commit_finalized_block`, `consensus.rs:1071-1288`):

1. `let slot = self.blockchain_slot.read().await;` (line 1076) — RwLock read; uncontended unless someone holds `write`.
2. `let mut blockchain = blockchain_arc.write().await;` (line 1083) — **acquires the GLOBAL blockchain write lock with no timeout**. Blocks indefinitely if any other writer is holding it.
3. `blockchain.add_block(committed_block.clone()).await` (line 1196) — **no timeout**. Calls `process_and_commit_block` (`lib-blockchain/src/blockchain.rs:903`) which awaits the executor + `persist_block` (line 1562) → `storage_manager.write().await` → `storage_manager.store_block(block).await` (`blockchain.rs:729-737`). No `tokio::time::timeout` anywhere in this chain (verified by grep across `lib-blockchain/src/` and `lib-storage/src/` — timeouts exist only in `lib-storage/src/dht/` for DHT messaging, none on the block-store path).

`commit_finalized_block_with_proof` (`consensus.rs:1290-1340`) follows the same pattern: `blockchain_arc.write().await` (line 1304), then `blockchain.add_block(...).await` (line 1323).

**Implications for finding #1.** The forensic report flagged that storage latency stalls the consensus loop. Confirmed:

- The `add_block` write lock is **shared** with at least three concurrent writers in the runtime: catch-up sync (`apply_block_trusted_for_sync` `blockchain.rs:882`), `add_block_from_network` (`blockchain.rs:868`), and the proposer's `get_pending_transactions` (which holds `blockchain.read()`, blocking the writer).
- The comment at `consensus.rs:1192-1195` acknowledges the deadlock risk explicitly: *"use add_block (not add_block_with_proof) so the write lock is released before ZK proof generation and DHT indexing, preventing a deadlock where the proposer's get_pending_transactions() blocks on blockchain.read() while the write lock is held during slow ZK proof work."* The fix avoids one specific deadlock; it does not cap the latency of `add_block` itself.
- ZK proof and DHT indexing ARE moved off the hot path via `tokio::spawn` (`consensus.rs:1252, 1272`). That is the only mitigation — and it only applies after the synchronous `add_block.await` returns.

### 12.5 Resulting Danger Findings

**D1. Confirmed:** Forensic finding #5 (broadcaster blocks consensus). The `ConsensusMeshBroadcaster` has no per-peer timeout and no overall budget. Worst-case per-call stall is bounded only by QUIC's `max_idle_timeout = 300s` per peer × number of peers, executed sequentially. Mitigation requires either:
- Wrapping the entire `broadcast_to_validators` body in `tokio::time::timeout(Duration::from_millis(config.propose_timeout / 4), ...)` so a hung broadcast does not eat more than a fraction of the round budget, AND
- Parallelizing per-peer sends with `futures::stream::FuturesUnordered` so one slow peer does not delay the others.

**D2. Confirmed:** Finding #1 of the broader storage hang (block commit blocks consensus). The `ConsensusBlockCommitter` awaits an unbounded `RwLock::write()` followed by an unbounded `add_block`. Mitigation requires either:
- Bounding the lock acquisition: `tokio::time::timeout(commit_budget, blockchain_arc.write())`, returning a typed error on timeout that the engine treats as "halt at this height" (existing semantics per `state_machine.rs:1197-1211`).
- Bounding `add_block` similarly, or moving block persistence into a separate task that the engine signals via a `tokio::sync::oneshot` (the `Action`-channel pattern recommended in the architecture report §3.3).

**D3. New — concurrent-writer hazard:** `ConsensusBlockCommitter::commit_finalized_block` shares the `blockchain_arc` write lock with `apply_block_trusted_for_sync` (catch-up sync), `add_block_from_network` (sync/observer path), and `proposer.get_pending_transactions` (read holder). Even with the ZK-spawn mitigation, BFT commit can be delayed by an in-flight catch-up sync writing a long batch. The `bft_active_height` atomic (`mod.rs:527`, set in `network.rs:118`) is the only signal preventing catch-up from racing — but it does not prevent **lock contention** with sync that started before BFT entered the height. Mitigation: BFT commits should hold a higher-priority lock or use a separate dedicated writer task.

**D4. Existing constant deepens D1:** `transport_config.max_idle_timeout` was raised from 30s to 300s per Issue #907 (`quic_mesh.rs:1706-1708`). This decision optimized for connection longevity but multiplied the worst-case per-peer broadcast stall by 10×. The consensus crate has no awareness of this constant.

### 12.6 Updated Top-5 Severity (replacing §10)

After the follow-up audit:

1. **`ConsensusBlockCommitter` blocks the consensus loop on the global blockchain write lock.** Was #1; promoted in confidence — confirmed unbounded. `consensus.rs:1083, 1304`.
2. **`ConsensusMeshBroadcaster` blocks the consensus loop sequentially per peer with QUIC's 300s idle timer as the only bound.** Was #5; promoted to #2 because every step transition triggers it (4-8× per round) and the latency is multiplicative in peer count. `consensus.rs:115-128`, `quic_mesh.rs:1107-1120, 1706-1708`.
3. **`on_round_timeout(Commit)` desyncs height on `sync_height_with_blockchain` error.** Unchanged from previous #2. `state_machine.rs:1786-1794`.
4. **No watchdog, no `step_entered_at`.** Unchanged from previous #3. The follow-up audit makes this *more* important: with confirmed unbounded latency in the storage and broadcast adapters, the absence of a watchdog means there is no mechanism to detect or escape a hang.
5. **No `Rejected` event from the live loop.** Unchanged from previous #4.

Findings 1 and 2 should be addressed first; they are the proximate cause of the observed silent-hang failure mode. The architectural fixes proposed in the companion architecture report §3.3 (`Action`-channel + non-blocking `send`) eliminate the entire class.
