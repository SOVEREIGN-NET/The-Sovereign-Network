# Dry-run audit: removing `ConsensusRound.height`

**Scope**: GitHub issue #2671 — eliminate the cached `current_round.height` field
on `ConsensusEngine` so that engine ⇄ blockchain drift becomes structurally
impossible.

**Status**: investigation only. No code changes on this branch.

---

## Headline numbers

| | Count |
|---|---|
| Production reads (`grep -v tests.rs`) | **148** |
| Production writes (assignments) | **3** |
| Test-file reads (`tests.rs` only) | **41** |
| Test-file writes (poke the field directly) | **14** |
| Files touched | 7 (6 production + 1 inline-test) |
| Crates touched | 1 (`lib-consensus`) |

Distribution by file:

```
state_machine.rs   74 reads   2 writes  (advance_to_next_height, advance_to_next_round)
network.rs         39 reads   0 writes
proofs.rs          12 reads   0 writes
validation.rs      11 reads   0 writes
mod.rs             11 reads   1 write   (sync_height_with_blockchain)
storage.rs          1 read    0 writes
tests.rs           41 reads  14 writes
```

---

## Surprises (these are why the issue's "150–200 lines" estimate is wrong)

### Surprise 1 — there are TWO `ConsensusRound` types

* `lib_consensus_core::types::round::ConsensusRound` — round-scoped FSM
  state. Has `state`, `entered_at`, `deterministic_round_id`. **Not
  `Serialize`** by design (comment: `Instant` has no stable serialization).
* `lib_consensus::types::ConsensusRound` — engine's working round.
  Has `height`, `round`, `step`, locks, etc. **IS `Serialize, Deserialize`**.

The engine (`lib-consensus`) uses the second one. The first one exists in
`lib-consensus-core` and looks like an in-progress migration (CONS-201
mentions Scope B types moved across crates). **No external code uses
the lib-consensus one**, and **no code actually serializes it** — the
derive is unused. Removing `pub height: u64` from the lib-consensus type
does NOT break any wire format.

→ **Implication**: drop the unused `Serialize, Deserialize` from
`lib-consensus::types::ConsensusRound` as part of the same change; don't
let future readers assume it gets sent on the wire.

### Surprise 2 — height advance is COUPLED with state cleanup

`advance_to_next_round()` (state_machine.rs:737) does *more* than
increment height — it clears the round-scoped state that belongs to the
height we're leaving:

```rust
fn advance_to_next_round(&mut self) {
    self.current_round.height += 1;          // (1)
    self.current_round.round = 0;             // (2) reset round
    self.current_round.step = ConsensusStep::Propose;
    self.current_round.start_time = self.current_round.height;
    self.current_round.proposer = None;
    self.current_round.proposals.clear();     // (3) clear proposals
    self.current_round.votes.clear();         // (4) clear votes
    self.current_round.timed_out = false;
    self.current_round.locked_proposal = None;// (5) clear lock state
    self.current_round.locked_round = None;
    self.current_round.valid_proposal = None;
    self.current_round.valid_round = None;
    self.proposal_for_round.clear();          // (6) clear round-keyed buffer
}
```

`advance_to_next_height()` (state_machine.rs:660) does the same in
miniature: sets height and snapshots the validator set for it.

**Implication**: if you delete the field and derive height from the
blockchain on each read, the engine's `round = 0 / locks cleared /
proposals cleared` invariant is **silently broken** whenever catch-up
sync advances the blockchain (which is exactly the bug we're fixing —
height "jumps" forward by N).

The current code never has to deal with that because
`current_round.height` only changed via these two functions, which
*also* did the cleanup. Decoupling height from cleanup creates new
failure modes:

* Engine "thinks" we're at height H+5 but `locked_proposal` is still
  set from height H. A subsequent Prevote at H+5 may apply the unlock
  rule incorrectly.
* `proposal_for_round` HashMap retains entries keyed at H — memory
  leak that lasts until restart.
* `votes` HashMap counts votes for proposals that no longer exist.

**This is the real reason the refactor is bigger than 150 lines.** You
have to introduce an explicit height-change detector that fires the
same cleanup, otherwise you've introduced a worse class of bugs in the
name of fixing the original one.

### Surprise 3 — most production reads are in async contexts (good news)

Per-function read frequency (top sites):

```
37   run_consensus_loop          (async)
 9   enter_propose_step          (async)
 6   validate_remote_vote        (async)
 6   sync_height_with_blockchain (async — will be deleted anyway)
 5   create_proposal             (async)
 5   cast_vote                   (async)
 4 each across ~10 more methods, all async
```

**Sync functions that read height** (8 total):

```
advance_to_next_round       (writes; trivial)
advance_to_next_height       (writes; trivial)
get_active_validator_ids
next_epoch_start
queue_validator_add
queue_validator_removal
schedule_epoch_length_update
count_votes_for_proposal
validate_no_fork_proposal
```

All eight are short helpers. They can either (a) take `height: u64` as
a parameter from the caller (who can do the async lookup), or (b) read
the cached `last_processed_height` field that the detector maintains.

→ **Implication**: async-ification cascade is NOT large. ~150 reads
swap from `self.current_round.height` to `let h = self.current_height().await;`
followed by `h`, often hoisted to the top of the method.

### Surprise 4 — tests rely on the writable field for setup

14 test-file writes set `engine.current_round.height = N` directly to
construct scenarios at specific heights. They look like:

```rust
let mut engine = build_test_engine().await;
engine.current_round.height = 5;       // ← arrange
engine.snapshot_validator_set(5);
engine.run_consensus_round().await?;   // ← act
```

Without the field, every test needs to instead inject a fake
`ConsensusBlockchainProvider` that reports height 5. The test harness
at `tests.rs:148` already has a `MockBlockchainProvider`. Three
patterns to migrate:

1. Tests calling `set_blockchain_provider(MockProvider::at(5))` → easy.
2. Tests that mutate height mid-test (e.g., simulate the engine
   advancing) → need a settable mock (`mock.set_height(6)`).
3. Tests that expect `engine.current_round.height == X` as assertion →
   become `engine.current_height().await == X`.

→ **Implication**: the test work is not just renames. ~14 setup sites
become 14 mock injections, ~10 assertion sites become async, the mock
provider's API grows a setter. Plan for **roughly equivalent test
churn to production code**.

### Surprise 5 — `sync_height_with_blockchain` has a *deliberate* invariant check

Looking at `sync_height_with_blockchain` (mod.rs:915–1005):

```rust
if new_height != old_height {
    let state = InvariantState { ... };
    for invariant in &[
        ConsensusInvariant::MonotonicHeight,
        ConsensusInvariant::NoFork,
    ] {
        if let Err(msg) = check_invariant(invariant, &state) {
            tracing::error!("Height sync invariant violated: {}", msg);
            return Err(ConsensusError::ValidatorError(msg));
        }
    }
}
```

This is a **safety check** — refuses to sync if monotonicity is
violated (e.g., chain rolled back, which should never happen but does
during botched recoveries). Deleting `sync_height_with_blockchain`
without replacing the check loses that safety net.

→ **Implication**: the height-change detector must re-implement this
check. Don't silently delete it.

---

## Revised plan

The original 4-phase plan in #2671 stays valid in shape but Phase 3 is
where Surprise 2 lives. Updated:

### Phase 1 (~30 lines, no behavior change)

Add `ConsensusEngine::current_height_cached(&self) -> u64` that just
returns `self.current_round.height`. Replace all 148 production reads
with this getter. Pure mechanical rename. Lands first, isolates the
field from direct field-access so subsequent phases only touch the
getter body.

### Phase 2 (~60 lines, new async getter — for callers that need fresh truth)

Add `ConsensusEngine::current_height_chain(&self) -> ConsensusResult<u64>`
(async). Returns `blockchain_provider.get_blockchain_height().await + 1`.
Convert the **semantic-correctness** reads (snapshot_validator_set,
compute_proposer_for_round, vote/proposal construction, validate_remote_vote)
to use this. Cosmetic reads (logs, events) stay on `_cached`. Behavior
change is bounded to a small set of sites and observable in tests.

### Phase 3 (~80 lines + invariant migration, the dangerous one)

Introduce an internal `HeightAdvanceDetector` that:

* On every tick / commit / catch-up event, queries blockchain height.
* If blockchain > `last_processed_height`, runs the **full cleanup
  block from `advance_to_next_round`** (round=0, clear locks, clear
  proposals, etc.) and runs the **invariant check from
  `sync_height_with_blockchain`** (monotonic, no-fork).
* Updates `last_processed_height`.

The cached `current_round.height` becomes `last_processed_height` —
same field, narrower semantic, only ever moves on the detector path.

Delete `sync_height_with_blockchain`. Delete the polling-tick patch
from PR #2665. Delete the two writes in `advance_to_next_round` and
`advance_to_next_height` — the detector now owns height updates.

### Phase 4 (~30 lines + ~50 test churn)

Remove the public `pub height: u64` field from
`lib-consensus::types::ConsensusRound`. (Keep `last_processed_height`
private inside `ConsensusEngine`.) Also drop the unused `Serialize,
Deserialize` derives. Migrate tests to use `MockBlockchainProvider::at(N)`
and `mock.advance_to(N)`. Update assertions to use the async getter.

---

## Risk assessment

| Risk | Severity | Mitigation |
|---|---|---|
| Phase 3 cleanup-block omission → silent lock-state retention | **High** | Land Phase 3 behind a feature flag for one release; add an integration test that asserts `locked_proposal == None` after a catch-up advance |
| `MonotonicHeight` invariant lost in deletion of sync_height_with_blockchain | High | Move the check verbatim into `HeightAdvanceDetector` before deleting the old site |
| Test churn underestimated (per Surprise 4) | Medium | Add the mock setter as Phase 0; convert tests opportunistically as each phase lands rather than all at the end |
| Two `ConsensusRound` types confuse readers during migration | Low | Add a doc comment to each; consider unifying as a separate CONS-201 follow-up |
| Async-ification of `validate_no_fork_proposal` cascades into validators that call it sync | Low | Audit shows it's already only called from async contexts; double-check before Phase 2 |
| `pub` field removal breaks downstream | None | No external crate uses it (verified by grep across all crates) |

---

## Recommended order to land

1. Phase 0: add mock setter to `MockBlockchainProvider`. ~10 lines.
2. Phase 1: cosmetic rename. ~30 lines. Mergeable independently.
3. Phase 2: semantic-correctness reads switch to async. ~60 lines.
   Mergeable independently.
4. Phase 3: detector + delete old write paths. ~80 + invariant move.
   Single PR. **Land with a 1-week feature-flag soak on testnet
   before main**.
5. Phase 4: field deletion + test migration. ~30 + ~50.

Total ~260 lines + invariant code + ~50 test changes. The "150–200"
estimate in the issue was honest given the surface scan but missed
Surprise 2 (state cleanup coupling) and Surprise 5 (the
MonotonicHeight invariant). Realistic estimate now: **~300 LoC
production, ~50 LoC test churn, 4 reviewable PRs**.

---

## What the dry-run *did not* do

* Did not change any code.
* Did not delete the `Serialize, Deserialize` derives (recommended in
  Surprise 1, but premature without consensus on the migration path).
* Did not run the test suite (no code changes to validate).
* Did not benchmark `get_blockchain_height().await` latency in the hot
  path — Phase 2 will need a microbench since 148 reads × ~tick-rate
  becomes the new call frequency. If the provider lookup is more than
  ~1µs the cumulative cost matters.
