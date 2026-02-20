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

## Explicitly Not Residual (Blocking)

The following are treated as hard blockers and are enforced by DAO-READY gates:

- consensus divergence under replay/restart/cross-node application
- token mutation through deprecated ContractExecution paths
- unauthorized token minting
- bypass of Treasury Kernel authorization constraints
- crash-recovery visibility of uncommitted state
