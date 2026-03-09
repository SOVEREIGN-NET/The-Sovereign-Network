# Agent Task List - TokenCreation Fee Cleanup

**Last Updated:** 2026-03-09 UTC by Codex
**Primary Agent:** Agent 3 - Token Consensus Agent
**Secondary Reviewers Required:** Agent 2 - Storage and Atomicity, Agent 4 - Runtime/API Contract, Agent 8 - Security and Replay Assurance, Agent 10 - QA and Release Readiness
**Status:** Implemented and verified

## Scope Summary

Finish the `TokenCreation` fee mess by leaving exactly one live fee authority:

- DAO-governed `TxFeeConfig.token_creation_fee`
- exact-fee enforcement in validator
- exact-fee enforcement in executor
- fee-config API exposure
- lib-client consumption of the same field

## Invariants

- [x] `TokenCreation` has exactly one canonical required fee.
- [x] `TokenCreation` fee is not derived from legacy size-based estimation.
- [x] `TokenCreation` fee is not derived from `FeeModelV2`.
- [x] Validator and executor enforce the same exact fee rule.
- [x] `/api/v1/blockchain/fee-config` exposes the canonical `token_creation_fee`.
- [x] `lib-client` sets `tx.fee` to exactly the canonical `token_creation_fee`.
- [x] No duplicate live `TokenCreation` fee logic remains.

## Review Pass Findings

- [x] Active pending admission path reviewed: [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/blockchain.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/blockchain.rs) uses `add_pending_transaction()` -> `verify_transaction()` -> `StatefulTransactionValidator`; current live mempool path does not go through `lib-mempool` for `TokenCreation`.
- [x] Consensus/block production path reviewed: runtime block assembly pulls from `blockchain.pending_transactions`, and committed blocks go through `BlockExecutor.apply_block()`, so validator changes affect pending admission and executor changes affect final consensus application.
- [x] Trusted replay path reviewed: [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/sync/mod.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/sync/mod.rs) uses `BlockExecutor::from_config_trusted_replay(...)`, which skips fee validation for replayed peer blocks.
- [x] Parallel fee infrastructure reviewed: [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-mempool/src/admission.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-mempool/src/admission.rs), [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/validation/tx_validate.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/validation/tx_validate.rs), and [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/fees/classifiers.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/fees/classifiers.rs) do not currently classify `TokenCreation`; they remain repo debt but are not the live `TokenCreation` authority.
- [x] Persistence compatibility reviewed: adding a new field to [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/fee.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/fee.rs) is not backward-compatible unless `TxFeeConfig` gains serde defaults for missing fields.
- [x] Fee-config API surface reviewed: [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/api/handlers/blockchain/mod.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/api/handlers/blockchain/mod.rs) exposes `fee-config`, `estimate-fee`, and `quote-fee`; the generic `estimate-fee` request does not currently carry transaction type.
- [x] Client/binding surfaces reviewed: [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/lib.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/lib.rs) exposes C and JNI fee-config setters and a generic `quote_fee_for_tx_hex`; because the client surface is fully controlled, these bindings can be changed directly as part of canonical cleanup.
- [x] `lib-client` review completed: `zhtp_client_set_fee_config(...)` and `Java_com_sovereignnetworkmobile_Identity_nativeSetFeeConfig(...)` currently take exactly three numeric fee knobs; if canonical cleanup requires it, update these exported function signatures rather than adding compatibility shims.
- [x] `lib-client` generic quote path reviewed: `zhtp_client_quote_fee_for_tx_hex(...)` currently routes through legacy size-based `calculate_min_fee_for_tx_hex(...)`; this will be wrong for canonical fixed-fee `TokenCreation` unless explicitly special-cased or blocked.
- [x] `lib-client` token builder reviewed: `build_create_token_tx(...)` is the only in-repo token creation builder and currently hardcodes size-estimated fee assignment; removing that logic should not require changing the exported `zhtp_client_build_token_create(...)` signature.
- [x] Existing targeted tests reviewed: current executor `TokenCreation` fixture uses arbitrary `fee: 10_000`, so it does not lock the intended canonical fee behavior.

## Review-Derived Constraints

- [x] Make `TxFeeConfig` backward-compatible for deserialization before adding `token_creation_fee`.
- [x] Remove compatibility assumptions for controlled clients; update C/JNI fee-config bindings directly if needed so only one canonical client fee path remains.
- [x] Keep exactly one client fee path for `TokenCreation`; no compatibility wrapper, alternate setter, or shadow config path survives.
- [x] Decide explicit behavior for `/api/v1/blockchain/transaction/estimate-fee` because current request body cannot infer `TokenCreation` from size alone.
- [x] Decide explicit behavior for `zhtp_client_quote_fee_for_tx_hex(...)` when passed a `TokenCreation` transaction.
- [x] Keep `lib-mempool` / alternate fee-v2 paths out of scope for `TokenCreation` cleanup unless they become live admission paths.

## Keep / Extend

- [x] Extend [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/fee.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/fee.rs) `TxFeeConfig` with `token_creation_fee` defaulting to `1000`, with serde defaults for backward compatibility.
- [x] Extend [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-consensus/src/dao/dao_types.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-consensus/src/dao/dao_types.rs) with a governance parameter for `token_creation_fee`.
- [x] Extend [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/blockchain.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/blockchain.rs) governance application path to persist `token_creation_fee`.
- [x] Extend [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/api/handlers/blockchain/mod.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/api/handlers/blockchain/mod.rs) fee-config response with `token_creation_fee`.
- [x] Extend [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/token_tx.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/token_tx.rs) fee-config ingestion to cache `token_creation_fee`.
- [x] Update [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/lib.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/lib.rs) bindings to match the canonical fee-config shape exactly, with no compatibility wrapper left behind.

## Remove From Live TokenCreation Fee Path

- [x] Remove `TokenCreation` size-based fee estimation from [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/token_tx.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/token_tx.rs).
- [x] Remove `TokenCreation` dependence on `calculate_minimum_fee_with_config(...)` in [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/validation.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/validation.rs).
- [x] Remove `TokenCreation` fallthrough into `FeeModelV2` in [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/execution/executor.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/execution/executor.rs).
- [x] Remove or special-case stale generic token-creation fee quoting in [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/api/handlers/blockchain/mod.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/api/handlers/blockchain/mod.rs).
- [x] Ensure `/api/v1/blockchain/transaction/estimate-fee` does not pretend to quote `TokenCreation` from size-only input.
- [x] Remove or special-case stale client-side generic fee quoting for `TokenCreation` in [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/lib.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/lib.rs).

## Canonical Rule Implementation

- [x] Add one shared `TokenCreation` required-fee helper in `lib-blockchain` that reads `TxFeeConfig.token_creation_fee`.
- [x] Make stateless validation enforce `tx.fee == token_creation_fee` for `TokenCreation`.
- [x] Make stateful/executor validation enforce `tx.fee == token_creation_fee` for `TokenCreation`.
- [x] Make `lib-client` build `TokenCreation` transactions with `tx.fee = token_creation_fee`.
- [x] Make server fee quote endpoints return the fixed `token_creation_fee` for `TokenCreation` or explicitly reject generic quoting for that tx type.

## Test Gates

- [x] Add validator test: `TokenCreation` with exact configured fee is accepted.
- [x] Add validator test: `TokenCreation` with lower fee is rejected.
- [x] Add validator test: `TokenCreation` with higher fee is rejected.
- [x] Add executor test: client-equivalent `TokenCreation` with exact configured fee is accepted.
- [x] Replace arbitrary high-fee executor fixture with canonical fee-driven fixture.
- [x] Add governance test: DAO update changes `token_creation_fee`.
- [x] Add API test: `/api/v1/blockchain/fee-config` returns `token_creation_fee`.
- [x] Add client config parse test for `token_creation_fee`.
- [x] Add backward-compatibility test: old serialized `TxFeeConfig` / blockchain state loads with default `token_creation_fee`.
- [x] Add API test for explicit `TokenCreation` quoting behavior on `/transaction/quote-fee` and `/transaction/estimate-fee`.

## File-Level Diff Map

- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/fee.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/fee.rs)
- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/validation.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/transaction/validation.rs)
- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/execution/executor.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/execution/executor.rs)
- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/blockchain.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-blockchain/src/blockchain.rs)
- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-consensus/src/dao/dao_types.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-consensus/src/dao/dao_types.rs)
- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-consensus/src/dao/dao_engine.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-consensus/src/dao/dao_engine.rs)
- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/api/handlers/blockchain/mod.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/api/handlers/blockchain/mod.rs)
- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/token_tx.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/token_tx.rs)
- [x] [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/lib.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/lib-client/src/lib.rs)

## Risk Notes

- [x] Ensure `TokenMint` policy remains unchanged unless explicitly requested.
- [x] Ensure replay/catch-up paths do not create a second `TokenCreation` fee rule.
- [x] Ensure trusted replay remains intentionally fee-skipping and does not become an accidental second authority for fresh `TokenCreation` admission.
- [x] Ensure fee quote endpoints do not keep returning stale size-based values for `TokenCreation`.
- [x] Ensure no parallel `TokenCreation` fee helper survives after cleanup.
- [x] Ensure controlled client binding changes are applied coherently so there is still only one canonical fee-config contract.

## Rollback Strategy

- [x] If rollout fails, revert the full `TokenCreation` fee cleanup as one unit.
  Rollback unit: revert the `TxFeeConfig.token_creation_fee` field, DAO governance parameter, validator exact-fee rule, executor exact-fee rule, API fee-config/quote changes, and `lib-client` fee-config + builder changes together.
- [x] Do not leave partial state where client, validator, and executor disagree.
  Required rollback rule: do not ship or backport any subset of the change; client bindings, server fee-config exposure, validator enforcement, and executor enforcement move together or are reverted together.

## Type Architecture Compliance

- [x] No duplicate fee-config type is introduced outside canonical existing types.
- [x] No new `V2` or parallel `TokenCreation` fee model is introduced.

---

# Agent Task List - ORACLE Protocol v1 Implementation

**Last Updated:** 2026-03-09 UTC by Codex

## ORACLE Protocol v1 Implementation - All Subtasks Complete

### PR Queue Status

| Subtask | PR | Branch | Status |
|---------|-----|--------|--------|
| ORACLE-7 | #1717 | feature/ORACLE-7-oracle-slashing-base | COMPLETE |
| ORACLE-8 | #1719 | feature/ORACLE-8-oracle-slashing-api | COMPLETE |
| ORACLE-9 | #1720 | feature/ORACLE-9-oracle-slashing-validation | COMPLETE |
| ORACLE-10 | #1721 | feature/ORACLE-10-oracle-slashing-import-export | COMPLETE |
| ORACLE-11 | #1722 | feature/ORACLE-11-oracle-slashing-governance | COMPLETE |
| ORACLE-12 | #1723 | feature/ORACLE-12-oracle-slash-misbehaving-validator | COMPLETE |
| ORACLE-13 | #1724 | feature/ORACLE-13-storage-migration-docs | COMPLETE |

### Implementation Summary

**ORACLE-7**: Epoch-based oracle committee updates with `last_oracle_epoch_processed` tracking
**ORACLE-8**: API hardening - reduced visibility to `pub(crate)` for internal methods
**ORACLE-9**: Attestation transaction type (36) with full validation (committee membership, epoch match, replay protection, signature verification)
**ORACLE-10**: Import/export with oracle state persistence and validation
**ORACLE-11**: Pending update expiry mechanism (`expires_at_epoch = activate_at_epoch + 2`) + CancelOracleUpdate transaction type (37)
**ORACLE-12**: `committee_for_epoch(epoch)` method for deterministic epoch-locked committee resolution
**ORACLE-13**: BlockExecutor integration - CBE gate validation runs for both legacy and executor paths

### Test Results

All 34 oracle-related tests passing:
- 22 oracle state/attestation tests
- 6 CBE graduation oracle gate tests
- 6 transaction/oracle governance tests

---

## ORACLE-3 (#1688): Sovereign Exchange Price Feed - COMPLETED ✅

### Summary
Implemented §5 of Oracle Spec v1: 3 independent on-chain exchange price sources for SOV/USDC.

**Post-Review Fix:** Renamed misleading test `governance_path_is_enforced` → `committee_changes_require_governance_path` (PR #1702 follow-up). Added `compile_fail` doctest to `set_members_genesis_only` to actually verify API unreachability from external crates.

### Changes Made

**lib-blockchain (Exchange State):**
- Created `lib-blockchain/src/exchange/mod.rs` - Exchange module
- Created `lib-blockchain/src/exchange/state.rs` with:
  - `ExchangeState` - On-chain order book state
  - `TradingPair` - Trading pair identifier (SOV/USDC)
  - `LastTradePrice` - Last trade price with timestamp
  - `last_trade_price_sov_usdc()` - Most recent trade price
  - `order_book_mid_sov_usdc()` - (best_bid + best_ask) / 2
  - `vwap_sov_usdc(since_ts, until_ts)` - Volume-weighted average price
- Integrated `exchange_state: ExchangeState` into `Blockchain` struct
- Updated storage format V4 to persist exchange state
- All prices use `ORACLE_PRICE_SCALE` (1e8) fixed-point

**zhtp (Exchange Price Feed Service):**
- Created `zhtp/src/runtime/components/oracle_exchange_feed.rs`:
  - `ExchangePriceFeed` service for gathering prices
  - `PriceSample` - Price with source and timestamp
  - `PriceSource` enum (LastTrade, OrderBookMid, Vwap)
  - `gather_prices()` - Queries blockchain for 3 price sources
  - `median_price()` - Calculates median from samples
  - `is_price_valid()` - Sanity check for price bounds
- Updated `zhtp/src/runtime/components/oracle.rs`:
  - `gather_prices()` now uses `ExchangePriceFeed` with on-chain state
  - Falls back to 3 synthetic mock sources when `mock_sov_usd_price` is set

**Tests:**
- `lib-blockchain/src/exchange/state.rs` - 4 unit tests
- `lib-blockchain/tests/oracle_exchange_feed_tests.rs` - 9 integration tests
- `zhtp/src/runtime/components/oracle_exchange_feed.rs` - 3 unit tests
- All oracle tests passing (committee tests: 9, epoch tests: 8)

### Spec Compliance
- ✅ §5: 3 independent on-chain sources (last_trade, order_book_mid, vwap)
- ✅ §5: All prices in ORACLE_PRICE_SCALE (1e8) atomic units
- ✅ §4.1: Epoch derived from block timestamp (not wall clock)

---

## Legacy: TYPES Migration (Phase B Complete)

**Last Updated:** 2026-02-28 by Code

### TYPES-EPIC #1642: Phase B Status

### Completed ✅

| PR | Title | Status |
|----|-------|--------|
| #1680 | TYPES-12: Move mempool primitives to lib-types | MERGED |
| #1681 | TYPES-13: Document type architecture rule | MERGED |

### Summary of Changes

**TYPES-12 (#1680):**
- Moved mempool primitives to `lib-types`: `MempoolConfig`, `MempoolState`, `AdmitResult`, `AdmitTx`
- Created extension traits in `lib-mempool`: `MempoolConfigExt`, `MempoolStateExt`, `AdmitResultExt`
- Fixed all review comments:
  - Added `current_block` parameter to `AdmitResult::with_capacity_checked()`
  - Added per-TxKind witness cap check (`witness_bytes` > `tx_kind.effective_witness_cap()`)
  - Preserved original `MempoolConfig` defaults for size limits
  - Restored `From<AdmitErrorKind>` impl for `MempoolError`
- All 13 mempool tests passing

**TYPES-13 (#1681):**
- Documented type architecture rule in `lib-types/README.md`
- Added AGENTS.md Agent 11: Type Architecture Guardian
- Updated PR template with type architecture checklist

### Technical Debt Identified (Out of Scope for Current PR)

**Duplicate Types in lib-blockchain:**
- `lib-blockchain/src/fees/types.rs` has duplicate `FeeInput`, `TxKind`, `SigScheme`
- These have different field names/types than `lib-types` versions
- Requires coordinated migration in separate PR (TYPES-14+)

### Extension Trait Pattern Established

Pure data types in `lib-types`, behavior via extension traits in domain crates:
- `lib_economy::TransactionTypeExt` → provides `description()` method
- `lib_mempool::MempoolConfigExt` → provides mempool operations
- `lib_mempool::MempoolStateExt` → provides state operations

### Build Status
```
cargo check --workspace  ✅ PASSING
cargo test -p lib-mempool ✅ 13/13 tests passing
```

---

## Legacy: Casino PRs

**Last Updated:** 2026-03-09 UTC by Codex
**Scope:** ONLY PRs by scasino983/casino

**IMPORTANT:** When you complete a task, add `[DONE]` next to it and leave a note.
When ALL tasks are done, add `## ALL TASKS COMPLETE` at the bottom.
Opus will review your work.

---

## PR Status Summary - ALL PASSING CI

| PR | Branch | CI | Ready |
|----|--------|----|----|
| #1035 | 846-fix-resubmit | PASS | DONE IN REPO (legacy note) |
| #1036 | 878-phase1-resubmit | PASS | YES |
| #1037 | 879-880-phase2-3-resubmit | PASS | YES |
| #1038 | network-tests-resubmit | PASS | YES |
| #1041 | 881-phase4-security-hardening | PASS | YES |
| #1042 | 882-phase5-stress-testing | PASS | YES (Copilot cleaned) |
| #1043 | mesh-dedup-sonarcloud-fix | PASS | YES |

---

## Historical Note: PR #1035 DHT Fix

Legacy note from the original PR review:
- PR #1035 initially only partially fixed Issue #846.
- The missing DHT-side change was to use `QuicMeshProtocol.connections` in `handle_dht_find_node()`.

Current repo state:
- [`/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/server/mesh/udp_handler.rs`](/Users/supertramp/Dev/SOVN-workspace/SOVN/The-Sovereign-Network/zhtp/src/server/mesh/udp_handler.rs) now uses `self.quic_protocol.read().await` and `quic.connections.iter()` inside `handle_dht_find_node()`.
- The `self.connections.read().await` usage around line 229 is a separate UDP requester registration check, not the stale DHT lookup path.

[DONE] The repository already contains the required DHT fix. This section is kept only as historical context for the old PR thread.

---

## Task 1: Delete Copilot Inline Comments

External blocker: requires valid `gh` authentication and network access.

Delete these Copilot comment IDs using:
```bash
gh api -X DELETE repos/SOVEREIGN-NET/The-Sovereign-Network/pulls/comments/ID
```

**PR #1038:**
2749194078 2749194088 2749194096 2749194102 2749194108 2749194114 2749194118 2749194123 2749194128 2749194133 2749194140 2749194142 2749194146 2749194152 2749194155 2749194158 2749194164 2749194168 2749194172 2749194177

**PR #1041:**
2750062498 2750062518 2750062523 2750062530 2750062536 2750062537 2750062541 2750062545 2750062551 2750062564

**PR #1043:**
2750343201 2750343210 2750343219 2750343230 2750343238

Then remove Copilot as reviewer:
```bash
gh pr edit 1038 1041 1043 --remove-reviewer "copilot-pull-request-reviewer"
```

---

## Completed by Opus

- [x] Fixed #1043 Cargo.lock issue
- [x] Deleted 29 Copilot comments from PRs #1035, #1036, #1037
- [x] Deleted 14 Copilot comments from PR #1042
- [x] Removed Copilot reviewer from #1042
- [x] All PRs marked ready (not draft)
- [x] All PRs passing CI

---

## Task 2: Request Reviews (Priority: MEDIUM)

External blocker: requires valid `gh` authentication and a concrete reviewer username.

All these PRs are passing CI and ready:

```bash
gh pr edit 1035 1036 1037 1038 1041 1042 --add-reviewer REVIEWER_USERNAME
```

Or manually request reviews in GitHub UI.

---

## Merge Order (HUMAN ONLY)

PRs must be merged in this order (dependencies):

1. #1035 (Block Sync - CRITICAL) - FIX DHT FIRST
2. #1036 (Phase 1)
3. #1037 (Phase 2+3)
4. #1038 (Network Tests)
5. #1041 (Phase 4)
6. #1042 (Phase 5)
7. #1043 (Dedup fix)

**DO NOT MERGE AS AGENT** - Only human reviewers merge.

---

## Notes for Agents

1. Check `agent_context.yaml` for session state
2. Check `agent_db.json` for known fixes
3. Only touch files in the PR you're fixing
4. Run `cargo check --workspace` before pushing
5. Mark tasks `[DONE]` when complete with brief note
6. When ALL tasks done, add `## ALL TASKS COMPLETE` at bottom

**DO NOT MERGE AS AGENT** - Only human reviewers merge.

---

## Completed

- [x] All PRs marked as ready (not draft)
- [x] Identified #1043 failure cause (Cargo.lock)
- [x] PRs #1035-1042 all passing CI

---

## Notes for Haiku/Sonnet

1. Check `agent_context.yaml` for session state
2. Check `agent_db.json` for known fixes
3. Only touch files in the PR you're fixing
4. Run `cargo check` before pushing
5. Leave `[READY FOR REVIEW]` comment when done

## ORACLE-15: Oracle Config Parameter Validation - COMPLETED ✅

**Last Updated:** 2026-03-03 by Kimi

### Summary
Implemented comprehensive parameter validation for `OracleConfig` to prevent insane configurations (e.g., `max_price_staleness_epochs = 0`, `max_source_age_secs >= epoch_duration_secs`).

### Changes Made

**lib-blockchain/src/oracle/mod.rs:**
- Added `OracleConfigError` enum with two variants:
  - `InvalidField { field, message }` - Individual field validation failures
  - `Inconsistent { fields, message }` - Cross-field consistency failures
- Implemented `Display` and `Error` traits for `OracleConfigError`
- Added `OracleConfig::validate()` method with comprehensive bounds checking:
  - `epoch_duration_secs`: 60..=86_400 (1 minute to 24 hours)
  - `max_source_age_secs`: 10.. (minimum 10 seconds for fetch time)
  - `max_deviation_bps`: 1..=2000 (0.01% to 20%, prevents rejection of all prices)
  - `max_price_staleness_epochs`: 1..=100 (at least 1 epoch, at most 100)
  - `price_scale`: Must equal `ORACLE_PRICE_SCALE` (100_000_000, i.e. 1e8)
- Cross-field validation:
  - `max_source_age_secs < epoch_duration_secs` (source age must fit within epoch)
- Updated `schedule_config_update()` to call `validate()` and return `OracleConfigError`
- Added 13 unit tests for validation (all passing)

**lib-blockchain/src/lib.rs:**
- Exported `OracleConfigError` in public API

**zhtp/src/api/handlers/oracle/mod.rs:**
- Added import for `OracleConfigError`
- Updated `handle_propose_config()` to validate proposed config before DAO proposal
- Returns 400 Bad Request with detailed error message on validation failure

### Tests Added
- `default_oracle_config_is_valid` - Ensures default config passes validation
- `config_rejects_epoch_duration_too_small` - min 60 seconds
- `config_rejects_epoch_duration_too_large` - max 86400 seconds
- `config_rejects_max_source_age_zero` - must be > 0
- `config_rejects_max_source_age_too_small` - min 10 seconds
- `config_rejects_max_deviation_bps_zero` - 0 would reject all prices
- `config_rejects_max_deviation_bps_too_large` - max 2000 (20%)
- `config_rejects_max_price_staleness_epochs_zero` - must be >= 1
- `config_rejects_max_price_staleness_epochs_too_large` - max 100 epochs
- `config_rejects_cross_field_source_age_gte_epoch_duration` - source age must fit in epoch
- `config_accepts_boundary_values` - tests min/max boundary acceptance
- `config_accepts_valid_cross_field_combination` - tests valid cross-field combinations
- `schedule_config_update_uses_validation` - tests validation in state updates

### Build Status
```
cargo check -p lib-blockchain ✅ PASSING
cargo check -p zhtp ✅ PASSING
cargo test -p lib-blockchain --lib oracle ✅ 49/49 tests passing
```


## ORACLE-16 (#1700): Comprehensive Oracle Integration Test Suite - COMPLETED ✅

**Last Updated:** 2026-03-03 by Kimi

### Summary
Implemented comprehensive end-to-end integration tests for the Oracle protocol, including a reusable `OracleTestHarness` for multi-validator test scenarios.

### Changes Made

**lib-blockchain/tests/common/oracle_harness.rs** (new):
- `OracleTestHarness` - Test infrastructure for oracle integration tests
  - `new(validator_count)` - Creates blockchain with N validators in committee
  - `mine_blocks(n)` - Advances blockchain with timestamp advancement
  - `advance_oracle_epoch()` - Mines blocks until next epoch
  - `produce_attestation(idx, epoch, price)` - Creates signed attestations
  - `process_attestation(att)` - Processes attestations through oracle state
  - `finalize_epoch(epoch, price)` - Finalizes prices with threshold attestations
  - Helper methods: `current_epoch()`, `threshold()`, `validator_key_id()`, etc.
- `ValidatorKeys` - Keypair management for test validators

**lib-blockchain/tests/oracle_persistence_tests.rs** (new):
- `test_oracle_state_survives_blockchain_restart` - Save/load round-trip
- `test_oracle_state_in_blockchain_import` - Export/import (ignored, needs ORACLE-10)
- `test_oracle_config_persists_across_restart` - Config persistence
- `test_pending_updates_persist_across_restart` - Pending update persistence

**lib-blockchain/tests/oracle_epoch_advance_integration_tests.rs** (new):
- `test_pending_committee_activates_at_epoch_boundary`
- `test_pending_config_activates_at_epoch_boundary`
- `test_multiple_pending_updates_activate_correctly`
- `test_epoch_advance_requires_multiple_blocks`
- `test_finalized_prices_preserved_across_epoch_advance`
- `test_committee_member_can_attest_after_epoch_advance`
- `test_stale_price_detection_after_epoch_advance`

**lib-blockchain/tests/oracle_cbe_integration_tests.rs** (new):
- `test_cbe_graduation_blocked_without_fresh_oracle_price`
- `test_cbe_graduation_rejected_with_stale_oracle_price`
- `test_cbe_graduation_accepted_with_fresh_oracle_price`
- `test_cbe_graduation_accepts_price_at_staleness_boundary`
- `test_non_cbe_token_skips_oracle_gate`
- `test_already_graduated_token_skips_oracle_gate`

**lib-blockchain/tests/oracle_slashing_integration_tests.rs** (new):
- `test_double_sign_is_rejected` - Conflicting attestation rejection
- `test_slashed_validator_cannot_attest`
- `test_slashing_preserved_across_restart`
- `test_committee_threshold_adjusts_after_slashing`
- `test_multiple_validators_can_finalize_after_slashing`
- `test_slash_event_contains_correct_metadata`

**lib-blockchain/tests/oracle_e2e_governance_tests.rs** (new):
- `test_oracle_committee_update_pipeline`
- `test_oracle_config_update_through_governance_pipeline`
- `test_governance_proposal_rejected_for_invalid_oracle_config`
- `test_multiple_governance_updates_queue_correctly`
- `test_committee_member_removed_by_governance_cannot_attest`
- `test_threshold_recalculation_after_committee_change`

### Test Results
```
cargo test -p lib-blockchain --test oracle_persistence_tests         ✅ 7 passed, 1 ignored
cargo test -p lib-blockchain --test oracle_epoch_advance_integration_tests ✅ 11 passed
cargo test -p lib-blockchain --test oracle_cbe_integration_tests     ✅ 10 passed
cargo test -p lib-blockchain --test oracle_slashing_integration_tests ✅ 10 passed
cargo test -p lib-blockchain --test oracle_e2e_governance_tests      ✅ 10 passed
cargo test -p lib-blockchain --test oracle_executor_tests            ✅ 6 passed

Total: 54 integration tests passing (1 ignored pending ORACLE-10)
```

### Notes
- One test (`test_oracle_state_in_blockchain_import`) is ignored pending ORACLE-10 completion (BlockchainImport oracle_state field)
- All tests use the `OracleTestHarness` for consistent test setup
- Config validation tests verify cross-field consistency (e.g., max_source_age < epoch_duration)
