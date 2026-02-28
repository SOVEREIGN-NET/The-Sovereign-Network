# Oracle v1 Release Checklist

This checklist gates release readiness for the CBE Graduation Oracle v1 consensus path.

## Required CI Gate

- [ ] `./scripts/validate-oracle-v1-gates.sh` passes on target branch.

## Gate Coverage Matrix

- [ ] ContractExecution token mutation rejection remains green.
- [ ] Oracle admission parity (`precheck` vs execution) is deterministic.
- [ ] Oracle finalization follows first-threshold-wins and rejects conflicting thresholds.
- [ ] Duplicate and out-of-epoch attestations are rejected deterministically.
- [ ] Replay reconstructs identical finalized oracle prices.
- [ ] Duplicate/replay slashing evidence remains deterministic after restart.
- [ ] Oracle persisted state round-trips across restart.
- [ ] Unsaved oracle updates do not survive restart (crash safety boundary).
- [ ] CBE graduation gate enforces finalized+fresh oracle price and threshold checks.
- [ ] Runtime/API side paths cannot auto-graduate tokens.

## Operational Sign-off

- [ ] Oracle v1 epic implementation PRs merged.
- [ ] Project board statuses moved to `Done` for merged items.
- [ ] Residual risk document reviewed: `docs/release/ORACLE_V1_RESIDUAL_RISKS.md`.
- [ ] Rollback owner identified and rollback path verified.
