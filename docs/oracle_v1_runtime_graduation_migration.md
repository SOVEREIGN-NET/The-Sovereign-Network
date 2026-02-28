# Oracle v1 Migration: Runtime Auto-Graduation Removal

## What Changed

Runtime/background auto-graduation has been removed.

- Removed `zhtp` runtime service that periodically scanned and mutated bonding-curve token phase.
- Removed API buy-path auto-graduation side effect in `/api/v1/curve/buy`.
- Removed `auto_graduated` field from `/api/v1/curve/buy` response (was previously always `true` when threshold met).
- Graduation state mutation now occurs only through canonical consensus block execution (`BondingCurveGraduate` transaction path).

## API Changes

### `POST /api/v1/curve/buy` Response

The `auto_graduated` field has been removed from the response.

**Migration:** Clients should query `GET /api/v1/curve/{token_id}` to check the token's `phase` field to detect graduation.

## Why

Consensus state must not be mutated by wall-clock runtime loops or handler side effects.
Oracle-gated graduation is deterministic and enforced in consensus execution.

## Node Migration Behavior

For nodes previously running auto-graduation service:

- After upgrade, runtime no longer performs background graduation writes.
- Existing token phases remain unchanged until a canonical `BondingCurveGraduate` transaction is included in a block.
- `curve/buy` no longer transitions token phase even if threshold conditions are met.

## Operational Notes

- If a token appears eligible, submit the canonical graduation transaction instead of relying on runtime automation.
- Deterministic oracle gating and staleness checks are enforced in blockchain execution, not in runtime timers.
