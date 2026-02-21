# DAO-READY Release Checklist

This checklist gates release readiness for contract deployment, DAO creation/execution, token issuance, and Treasury Kernel enforcement.

## Required CI Gate

- [ ] `./scripts/validate-dao-ready-gates.sh` passes on target branch.

## Gate Coverage Matrix

- [ ] ContractExecution token mutation rejection (`burn`, `transfer`) enforced.
- [ ] Token mint authorization parity (`creator` accepted, unauthorized signer rejected).
- [ ] Treasury Kernel governance constraints enforced (`missing auth`, `burn delay`).
- [ ] Restart equivalence restored from committed canonical state.
- [ ] Nonce replay rejection after restart.
- [ ] Crash safety confirms no leakage from uncommitted blocks.
- [ ] Cross-node deterministic reconstruction convergence.
- [ ] Contract + DAO lifecycle replay convergence across nodes.
- [ ] DAO proposal and vote transaction integration paths valid.

## Operational Sign-off

- [ ] Primary implementation PRs merged for DAO-READY epic items.
- [ ] Project board statuses moved to `Done` for merged items.
- [ ] Residual risk document reviewed: `docs/release/DAO_READY_RESIDUAL_RISKS.md`.
- [ ] Rollback owner identified and rollback path verified.
