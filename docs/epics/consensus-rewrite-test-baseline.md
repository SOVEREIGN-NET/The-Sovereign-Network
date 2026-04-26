# Consensus Rewrite v2 — Test Baseline

**Epic:** [#2365](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2365)
**Issue:** [#2325 — CONS-003](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2325)
**Branch:** `2325-test-corpus-capture`
**Baseline tag:** `pre-consensus-rewrite-baseline` at `a7df539d` (pushed to origin)
**Captured:** 2026-04-25

This document is the regression baseline the rewrite must preserve. Per AD-007/AD-008 in `docs/epics/consensus-rewrite-decisions.md`, every PR in the epic must keep the **fix-now** corpus green. The **preserve-as-known-issue** entries are documented stale tests that the rewrite is expected to replace; each one names the CONS issue that supersedes it.

---

## Reproducing the baseline

```sh
# Check out the tagged baseline
git fetch --tags origin
git checkout pre-consensus-rewrite-baseline

# Run the consensus suites that this document tracks
cargo test -p lib-consensus --no-fail-fast
cargo test -p lib-blockchain --test consensus_integration_tests --no-fail-fast
cargo test -p lib-blockchain --test zk_merkle_consensus_tests --no-fail-fast
```

The `pre-consensus-rewrite-baseline` tag points at the parent of this branch (`a7df539d`, `fix: gate dangerous API endpoints`). It captures the workspace **before** the fix-now items in this PR landed.

---

## Headline numbers

After the fix-now items in this PR:

| Crate / suite | Tests passed | Tests failed | Total |
|---|---:|---:|---:|
| `lib-consensus` lib unit | 270 | 4 | 274 |
| `lib-consensus` integration tests (14 files) | 200 | 3 | 203 |
| `lib-consensus` doc tests | 1 (4 ignored) | 0 | 5 |
| `lib-blockchain --test consensus_integration_tests` | 21 | 0 | 21 |
| `lib-blockchain --test zk_merkle_consensus_tests` | 4 | 1 | 5 |
| **Total** | **496** | **8** | **508** |

**Pass rate after fix-now: 97.6 %.**

---

## Fix-now items landed in this PR

| ID | Test / file | Root cause | Resolution |
|---|---|---|---|
| FN-01 | `lib-consensus/src/engines/consensus_engine/tests.rs:159` (test fixture `ReadyProvider::decode_block_data`) | Type mismatch with the trait at `lib-consensus/src/types/mod.rs:445` (test fixture returned `(u32, u128)`, trait says `(u32, u64)`). Introduced by PR #2287 (UTXO `u128` widening) which forgot to update the test fixture. | Changed fixture to `(u32, u64)` to match the trait. Production impl at `zhtp/src/runtime/components/consensus.rs:1504` was already correct. Compile-blocker fix. |
| FN-02 | `lib-consensus/tests/validator_manager_tests.rs:421` (`test_sufficient_validators_check`) | Test asserted minimum BFT validators = 4. Documented and code-enforced minimum is 3 (`BFT_MIN_VALIDATORS` at `lib-consensus/src/engines/consensus_engine/mod.rs:286`). | Updated assertion to `i >= 3` with an explanatory comment citing `BFT_MIN_VALIDATORS`. |
| FN-03 | `lib-consensus/tests/dao_tests.rs:222` (`test_governance_parameter_validation`) | Test passed `GovernanceParameterValue::MaxValidators(100)`; `MAX_VALIDATORS_HARD_CAP = 21` rejects any value > 21. | Changed value to `21` with comment naming the cap. |
| FN-04 | `lib-consensus/tests/integration_tests.rs` (8 tests: `test_full_consensus_flow`, `test_dao_governance_integration`, `test_byzantine_fault_handling`, `test_validator_lifecycle_management`, `test_reward_system_integration`, `test_system_resilience_under_load`, `test_treasury_integration`, `test_consensus_with_insufficient_validators`) | Integration fixtures registered the genesis validator with `consensus_key = [0u8; 2592]`. The engine's vote-signature hardening rejects placeholder keys (`lib-consensus/src/engines/consensus_engine/validation.rs:116-124`). All 8 tests panicked at registration. | Replaced 7 occurrences of `[i as u8; 2592]` with `[(i + 1) as u8; 2592]` so seed `0` is never used. (Line 246 already used `(i + 2)`; line 296 used the literal `99u8`.) |

After FN-01..FN-04, **10 previously-failing tests are now green.** The remaining 8 failures are catalogued below.

---

## Preserve-as-known-issue (8)

Each entry names the CONS issue in the epic that will supersede the test. The rewrite must NOT regress these in any direction other than the linked CONS issue's resolution.

### KI-01 · `engines::consensus_engine::tests::test_future_round_proposal_does_not_advance_local_round`

**File / line:** `lib-consensus/src/engines/consensus_engine/tests.rs:2647`
**Failure:** `assert_eq!(local_round, 0)` fails with `left: 2, right: 0`.
**Why it fails:** The engine intentionally advances local round on a higher-round proposal — `lib-consensus/src/engines/consensus_engine/state_machine.rs:1303-1319` (`Round-sync: advancing from round X to Y on received proposal at H=...`). The test was written before that round-sync behavior was added.
**Superseded by:** CONS-302 (total `transition()` function) — the rewrite makes round advancement an explicit `(state, event) → (state, actions)` decision. New tests in CONS-601 will cover the round-sync behavior under its current contract.

### KI-02 · `engines::consensus_engine::tests::test_gap4_idempotence_and_equivocation_invariant`

**File / line:** `lib-consensus/src/engines/consensus_engine/tests.rs:670`
**Failure:** `assert_eq!(vote_pool_count, 1)` fails with `left: 2, right: 1`.
**Why it fails:** The engine's vote-relay path (`state_machine.rs:1479-1487`) re-broadcasts received prevotes to all validators, which inflates the local node's count of votes for the same `(H, R, type, validator)` key beyond 1 in some test setups using `NoOpBroadcaster` interleavings.
**Superseded by:** CONS-306 (action channel for broadcaster) — the action channel decouples relay from local pool insertion; new tests in CONS-601 will cover the idempotence invariant under the rewritten dispatch model.

### KI-03 · `engines::consensus_engine::tests::test_gap4_message_relevance_invariant`

**File / line:** `lib-consensus/src/engines/consensus_engine/tests.rs:618`
**Failure:** `assert_eq!(relevant_count, 1)` fails with `left: 2, right: 1`.
**Why it fails:** Same root cause as KI-02 — vote-relay path inflates the count.
**Superseded by:** CONS-306. Same resolution path as KI-02.

### KI-04 · `engines::consensus_engine::tests::test_hardening_commit_vote_accepts_past_round`

**File / line:** `lib-consensus/src/engines/consensus_engine/tests.rs:1569`
**Failure:** Engine returns `ValidatorError("FINALIZATION FAILED: commit quorum reached for proposal Hash(...) at H=5 R=3 but the proposal artifact was never received. This node cannot apply the committed block.")`.
**Why it fails:** The test injects a commit vote for a proposal it never first delivered as a `Propose` message. The engine's safety hardening (`state_machine.rs:880-883`) requires the proposal artifact to be present before finalization. The test was written before that hardening landed.
**Superseded by:** CONS-307 (action channel for finalization) — the rewrite makes "commit vote without proposal artifact" a typed `RejectionReason` rather than a panic. CONS-601 will cover the past-round commit path against the new sink-based finalization.

### KI-05 · `bft_safety_partition_tests::test_byzantine_fault_detection_for_slashing`

**File / line:** `lib-consensus/tests/bft_safety_partition_tests.rs:714`
**Failure:** `assert!(!faults.is_empty(), "SAFETY: Byzantine fault must be detected")` fails because `faults.is_empty()`.
**Why it fails:** Test calls `detector.detect_equivocation(&vote_a, ...)` and `detector.detect_equivocation(&vote_b, ...)`, then expects `detector.detect_faults(...)` to return the fault. But `detect_equivocation` (`lib-consensus/src/byzantine/fault_detector.rs:336-401`) populates only `evidence_log`, not `double_signs`. `detect_faults` iterates `double_signs`, which requires an explicit `record_double_sign()` call. The test was written before the API was split into detection vs recording.
**Superseded by:** CONS-309 (watchdog task) and CONS-309's companion fault-evidence rework — the rewrite consolidates fault detection through a single `Event::ByzantineFaultDetected` path, eliminating the dual-API gap.

### KI-06 · `bft_safety_partition_tests::test_byzantine_validator_evidence_collection`

**File / line:** `lib-consensus/tests/bft_safety_partition_tests.rs:854`
**Failure:** `assert!(!faults.is_empty(), "Faults must be detected")` fails for the same reason as KI-05.
**Superseded by:** CONS-309. Same resolution as KI-05.

### KI-07 · `bft_safety_partition_tests::test_exactly_one_third_byzantine_threshold`

**File / line:** `lib-consensus/tests/bft_safety_partition_tests.rs:765`
**Failure:** `assert!(can_commit, "System should maintain liveness at exactly 2/3 voting power")` fails because `online_voting_power < byzantine_threshold`.
**Why it fails:** Test computes `online_voting_power = (total * 4) / 6 = 66.6...%` (integer division loses the fraction); `byzantine_threshold` is computed at strict `> 2/3 + 1` precision. The test asserts liveness at *exactly* 2n/3, but BFT requires *strictly greater than* 2n/3 (by `has_supermajority` at `lib-types/src/consensus.rs:45`). The test's premise is incorrect: at exactly 2n/3, BFT does NOT guarantee liveness.
**Superseded by:** CONS-302 (total transition + property tests) — the rewrite's property tests will cover the `2n/3 + 1` boundary correctly. The current test should be deleted, but is kept for now to preserve the intent of "edge case at threshold" — CONS-601 will add the correct assertion.

### KI-08 · `lib-blockchain::test_dual_node_merkle_root_consensus_with_real_zk_proofs`

**File / line:** `lib-blockchain/tests/zk_merkle_consensus_tests.rs` (one test in the file)
**Failure:** `Error: Stub ZK proof operations are disabled in production builds. Real ZK backend not yet integrated.`
**Why it fails:** ZK backend integration is incomplete; the stub is disabled in default builds.
**Superseded by:** **None — out of scope for Consensus Rewrite v2.** This test is preserved as a known issue for the separate ZK-backend integration epic. The rewrite must not change its status.

---

## Tests that already passed and MUST stay green

Every test outside the KI-01..KI-08 list above is part of the regression corpus. Any PR in this epic that turns one of them red without explicit approval (i.e. a new entry in this document) blocks the epic's progression.

The full passing-list is enumerated by the reproduction commands above; running them on the new codebase after each phase is the verification gate.

---

## Maintenance rules

- **Adding a fix-now entry retroactively** (i.e. the rewrite fixes one of KI-01..KI-08 incidentally): move the entry to a new "Resolved during rewrite" section here, in the same PR that does the fix.
- **Adding a new known-issue** (e.g. the rewrite reveals a previously-hidden behavior gap): add a new KI-NN entry with file:line, root cause, and superseded-by link.
- **Deleting a test** (because the rewrite renders it obsolete): move the entry to a "Deleted" section here with rationale and the CONS issue that justifies the deletion.
- **Never silently delete or skip a test** without an entry in this document. Per CLAUDE.md memory rule: *own all failures*.

---

## Deleted in CONS-103

### `lib-consensus/tests/reward_tests.rs` (11 tests)

Deleted in PR for CONS-103. The file directly exercised `lib_consensus::RewardCalculator`'s public surface (`calculate_round_rewards(&ValidatorManager, height)`); both the type and the method signature moved out of `lib-consensus` per AD-003:

- `RewardCalculator`, `RewardRound`, `ValidatorReward`, `RewardStatistics`, `UsefulWorkType` now live in `lib-economy/src/rewards/`.
- Method signature is now `calculate_round_rewards(&[ValidatorRewardInput], height)` — neutral input (defined in `lib-consensus-core::ports`), no `ValidatorManager` coupling.
- The engine consumes the calculator via `lib_consensus_core::ports::RewardCallback` (fire-and-forget, AD-005), not by direct `RewardCalculator` use.

The 4 inline tests in `lib-economy/src/rewards/calculator.rs` (`calculator_zero_validators_zero_total`, `calculator_two_validators_history_grows`, `adapter_implements_callback_without_panic`, `adjust_base_reward_changes_subsequent_calculation`) cover the orchestration surface against the new signature. Re-creating the 11 lib-consensus tests against the new lib-economy surface is tracked as **optional follow-up** — the inline coverage is sufficient for CONS-103's scope; broader scenario coverage is in the larger reward-system overhaul that the rewrite does not undertake.

---

## Added in CONS-103

### KI-09 · `lib-economy` test build fails on pre-existing u128 transaction-amount mismatches

**File / line:** `lib-economy/src/transactions/...` (17 errors, all "expected `u128`, found `u64`" on `create_payment_transaction(...)` and friends).
**Why it fails:** Transaction-creation helpers were widened to `u128` per PR #2287 (UTXO unification); the test files in lib-economy were not updated alongside. Same family as FN-01 (consensus tests) and KI-08 (zk_merkle_consensus_tests).
**Verified pre-existing:** Stashed CONS-103 changes and re-ran `cargo test -p lib-economy --no-fail-fast` against bare `development` — same 17 errors. Out of scope for CONS-103.
**Superseded by:** Out of scope for the consensus rewrite. Should be batched with KI-08 in a separate u128-test-fixup PR (mechanical `.into()` casts on the call sites). `cargo build --workspace` (production code) is unaffected.
