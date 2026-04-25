# Observer Admission — DAO-Ready Readiness Spec

> Epic: `feature/observer-admission-2` … `feature/observer-admission-9`.
> Status at last update: **all branches implemented, integration gate green**.

## 1. Scope summary

The Observer Admission epic introduces a sponsor-bonded, quota-bounded
admission lifecycle for ZHTP observer nodes, with policy evaluation
gating both transaction execution (executor) and runtime bootstrap
(`zhtp::runtime::observer_admission_check`). The epic spans:

| Branch                              | Deliverable |
|-------------------------------------|-------------|
| `feature/observer-admission-2`      | `lib-types::observer_admission` data model: records, statuses, proof levels, rate-limit tiers, action metadata, policy. |
| `feature/observer-admission-3`      | Persistence: `BlockchainStore::{get,put,iter}_observer_record`, `iter_observer_records_for_sponsor`, `{get,save}_observer_policy`. `SledStore` real impl wires the `observer_registry` tree + `OBSERVER_POLICY` meta key. |
| `feature/observer-admission-4`      | Transaction surface: `RegisterObserver`, `UpdateObserverMetadata`, `SuspendObserver`, `RevokeObserver`, `ReauthorizeObserver` payloads + `Transaction::new_*` constructors. Executor `apply_*` handlers with sponsor-quota and proof-level enforcement. |
| `feature/observer-admission-5`      | Canonical admission policy module: `observer::policy::{evaluate_admission, check_sponsor_quota, default_policy}`, `AdmissionDecision`, `PolicyDenial`. Runtime hook: `try_initial_sync_from_peer` consults the gate before accepting peer headers as authoritative. |
| `feature/observer-admission-6`      | HTTP / ZHTP API surface (`/observer/admission/*` register, suspend, revoke, reauthorize, status). Custom-router dispatch via `(ZhtpMethod, &str)` tuples. |
| `feature/observer-admission-7`      | Discovery / sync trust: `RemoteChainState::Committed { height, hash }`, `TipInfo.head_hash`, `select_trusted_sync_sources` peer selector consuming admission state + operator allowlist + network expectation. |
| `feature/observer-admission-8`      | Rate-limit + abuse counter scaffolding: `TokenBucket` per-tier and per-sponsor aggregates (`SPONSOR_AGGREGATE_FACTOR = 0.75`), abuse `EscalationAction` (`record_violation`, `evaluate_escalation`), policy fields `bond_amount`, `abuse_suspend_threshold`, `abuse_revoke_threshold`. API: `resolve_admission_policy` reads from store; register handler enforces minimum sponsor proof level (HTTP 403 on anonymous / below-min). |
| `feature/observer-admission-9`      | End-to-end integration test suite (`lib-blockchain/tests/observer_admission_integration_tests.rs`), `scripts/validate-observer-admission.sh` release gate, gates appended to `scripts/validate-dao-ready-gates.sh`, this readiness spec. |

## 2. Integration test coverage map

`lib-blockchain/tests/observer_admission_integration_tests.rs` exercises
the full executor + storage + policy stack via the public lib-blockchain
API. Each test corresponds 1:1 to a release gate.

| Test                                                              | Property under test |
|-------------------------------------------------------------------|---------------------|
| `replay_determinism_for_admission_tx_sequence`                    | Two independent stores produce identical observer registry fingerprints when the same admission tx sequence is replayed. Foundational property for cross-node convergence. |
| `duplicate_registration_rejected`                                 | Re-registering the same DID in a later block is rejected by the executor. |
| `invalid_sponsor_binding_rejected`                                | Empty sponsor DID is rejected at apply time (executor surface), not silently persisted. |
| `anonymous_sponsor_rejected_by_policy`                            | `ObserverProofLevel::None` sponsor fails the canonical proof-level check. |
| `sponsor_quota_enforced_for_basic_tier`                           | Basic-tier sponsor (default quota = 1) cannot register a second observer. |
| `pending_observer_cannot_bootstrap`                               | `evaluate_admission` denies a Pending record with `NotAuthorizedStatus(Pending)` — the exact rule consumed by `zhtp::runtime::observer_admission_check::try_initial_sync_from_peer`. |
| `status_transitions_active_suspend_reauthorize`                   | A → S → A via `SuspendObserver` then `ReauthorizeObserver`. Suspended denied bootstrap; reauthorized → `Authorized`. |
| `status_transitions_revoke_paths_all_deny_bootstrap`              | `RevokeObserver` from A, S, and P all yield Revoked + denial. Confirms revocation is terminal across every prior status. |
| `trusted_sync_source_enforcement_via_evaluate_admission`          | Active record on matching network → `Authorized`; same record evaluated against `"mainnet"` → `Denied(NetworkMismatch)`. |
| `expired_record_denied_bootstrap`                                 | Active record with `expires_at < now` → `Denied(Expired)` even though status is Active. |

In addition, `cargo test --locked -p lib-blockchain --lib observer`
runs the in-crate unit suite for the `observer::{policy, rate_limit,
abuse}` modules (47 tests at the time of this spec).

## 3. Release gates

**Per-epic gate** (canonical for the observer-admission epic):

```bash
bash scripts/validate-observer-admission.sh
```

**DAO-READY gate** (composite — observer-admission gates appended to the
existing token / treasury / contract / DAO gates):

```bash
bash scripts/validate-dao-ready-gates.sh
```

Both gates must exit 0 for the observer-admission epic to be considered
release-ready.

## 4. Residual risks and out-of-scope items

These are intentionally deferred — they are not regressions, but
operators must be aware before promoting observer-admission to mainnet.

1. **Policy `bond_amount` field is plumbed but unconsumed.**
   admission-8 added `ObserverAdmissionPolicy.bond_amount: Option<u64>`.
   No on-chain bond escrow / slashing path exists yet. The field is
   reserved for a follow-up branch (`observer-bond-*`). Setting it in
   genesis today has no enforcement effect.

2. **Discovery probe still uses operator allowlist + admission registry
   as inputs to the selector — it does not yet rewire `DiscoveryConfig`
   to carry a `BlockchainStore` handle.** The authoritative gate runs
   inside `try_initial_sync_from_peer` (admission-5), so unauthorized
   peers cannot influence the canonical chain tip. The discovery probe
   merely surfaces them in the initial peer set; downstream sync will
   reject any non-admitted source. See the TODO in
   `zhtp/src/discovery_coordinator.rs` near `highest_committed_hash`.

3. **`RemoteChainState::Committed.hash` is currently a placeholder
   `[0u8; 32]` at the discovery boundary.** The TipInfo struct carries
   a `head_hash: String` (hex), but the discovery coordinator does not
   yet decode it into the Committed payload — it stores zeros and
   relies on `try_initial_sync_from_peer` to validate the actual block
   contents. Hash-binding will be tightened in a follow-up branch when
   the discovery probe gains store access.

4. **Rate-limit `TokenBucket` is implemented and unit-tested but is not
   yet wired into the ZHTP API ingress path.** API-level throttling
   per observer / per sponsor is a follow-up. The data structures and
   per-tier quotas are stable; only the request-time enforcement hook
   in `zhtp::api::handlers::*` is missing.

5. **Abuse counter increments on policy violations are scaffolded
   (`record_violation`, `evaluate_escalation`) but no caller invokes
   them at API ingress.** Same pattern as (4): semantics + unit tests
   are in place; the hook into request handlers is deferred.

6. **`apply_reauthorize_observer` clears `action_meta = None` on S→A.**
   This is the v1 policy: a manual reauthorization resets the abuse
   counter. Suspend / revoke preserve the counter. If governance later
   wants escalation memory across reauthorization, this is a one-line
   change in `lib-blockchain/src/execution/executor.rs::apply_reauthorize_observer`.

7. **lib-network has a pre-existing Windows compile breakage**
   (`BLE_MESH_SERVICE_UUID`, missing `Mutex` imports) that prevents
   `cargo check -p zhtp` from completing on Windows. This is unrelated
   to the observer-admission epic and is documented for the runtime
   crate. lib-blockchain (where all admission logic lives) compiles
   cleanly on Windows and Linux.

## 5. Operator notes

* The canonical default policy (`observer::default_policy()`) has
  `auto_approve = false`. Operators who want observers to land in
  `Active` immediately on registration must `save_observer_policy()`
  with `auto_approve = true` at genesis bootstrap. The integration
  tests (`status_transitions_*`, `trusted_sync_source_*`,
  `expired_record_*`) exercise both modes.
* Sponsor quota defaults: Basic = 1, Enhanced = 5, Premium = 25.
  Override per-deployment via `ObserverAdmissionPolicy.{basic_quota,
  enhanced_quota, premium_quota}`.
* Abuse thresholds default to `suspend = 3`, `revoke = 5`. Counters
  are saturating (`u32`) and persisted in `ObserverAdmissionActionMeta`.

## 6. Change log

| Date         | Branch                                | Notes |
|--------------|---------------------------------------|-------|
| (this epic)  | `feature/observer-admission-9`        | Integration suite + readiness spec + DAO-READY wiring. |
