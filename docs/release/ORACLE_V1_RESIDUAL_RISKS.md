# Oracle v1 Residual Risks and Rollback

## Residual Risks

1. Committee liveness risk
   - If fewer than threshold validators are online, price finalization stalls and graduation remains blocked.

2. Source quality risk at operator edge
   - External price source quality/outage can increase abstentions and delay finalization.

3. Governance misconfiguration risk
   - Incorrect updates to committee, staleness, or deviation parameters can unintentionally block graduation.

4. Operational blast radius of strict gating
   - Any regression in oracle finalization path blocks graduation rather than allowing unsafe fallback.

## Mitigations in Oracle v1

- Threshold signatures with committee membership checks.
- First-threshold-wins and immutable per-epoch finalization.
- Replay/idempotency checks on attestations and slashing evidence.
- No runtime wall-clock mutation path for graduation.
- Explicit staleness checks in graduation gate.

## Rollback Strategy

1. Immediate containment
   - Pause rollout and hold merge/deploy of Oracle v1 changes if any determinism gate fails.

2. Safe code rollback
   - Revert Oracle v1 branch changes as a unit (oracle runtime/API removal + gate wiring + docs).
   - Keep prior stable consensus branch as deploy target.

3. Governance-level fallback (if needed)
   - Adjust committee/threshold/timing parameters only at epoch boundary, with explicit change review.

4. Verification before resume
   - Re-run `./scripts/validate-oracle-v1-gates.sh` and confirm green on rollback target.
