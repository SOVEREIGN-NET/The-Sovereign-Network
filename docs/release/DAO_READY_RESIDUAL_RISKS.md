# DAO-READY Residual Risks

## Scope

This document tracks non-blocking residual risks after DAO-READY gates pass.

## Residual Risks

1. Test-suite runtime
   - Impact: The DAO-READY gate suite runs many integration tests and increases CI duration.
   - Mitigation: Keep gates focused to determinism/security invariants; optimize test setup in follow-up performance work.

2. Legacy API/CLI pathways still present
   - Impact: Older command paths may remain documented in scattered docs and can confuse operators.
   - Mitigation: Continue doc convergence around canonical command set in follow-up cleanup issues.

3. Warnings in workspace
   - Impact: High warning volume can hide signal in CI output.
   - Mitigation: Track warning reduction as separate hygiene work; treat new warnings in changed files as regressions.

4. Environment-sensitive integration tests
   - Impact: Some networking/runtime tests can be slower or flaky under constrained CI conditions.
   - Mitigation: DAO-READY gate focuses on deterministic blockchain/consensus invariants and keeps pass/fail strict for those.

5. Emergency restore remains a high-risk operator action
   - Impact: `blockchain.dat` recovery can restore a node from a local backup that must still be reconciled with canonical network state.
   - Mitigation: keep emergency restore explicit, validate genesis compatibility by default, require explicit override for mismatches, and verify catch-up to canonical height after recovery.

## Rollback And Recovery Expectations

- Standard startup must reconstruct from canonical chain state in Sled or peer sync.
- `blockchain.dat` is an emergency recovery input only; it is not a normal startup fallback.
- If standard startup fails, operators should prefer peer resync before local backup restore.
- If emergency restore is used, operators must review logs for restore warnings and confirm the node rejoins canonical height before returning it to service.
- Genesis mismatch overrides are exceptional and require explicit operator acknowledgment because they bypass the default compatibility guard.

## Explicitly Not Residual (Blocking)

The following are treated as hard blockers and are enforced by DAO-READY gates:

- consensus divergence under replay/restart/cross-node application
- token mutation through deprecated ContractExecution paths
- unauthorized token minting
- bypass of Treasury Kernel authorization constraints
- crash-recovery visibility of uncommitted state
