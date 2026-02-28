# Oracle v1 Migration: Runtime Auto-Graduation Removal

## What Changed

Runtime/background auto-graduation has been removed.

- Removed `zhtp` runtime service that periodically scanned and mutated bonding-curve token phase.
- Removed API buy-path auto-graduation side effect in `/api/v1/curve/buy`.
- Graduation state mutation now occurs only through canonical consensus block execution (`BondingCurveGraduate` transaction path).

## API Response Changes

### `POST /api/v1/curve/buy`

The `auto_graduated` field in the response now always returns `false` (previously it could return `true` when a token auto-graduated as a side effect of the buy operation).

**Before:**
```json
{
  "success": true,
  "token_id": "abc...",
  "stable_paid": 1000000,
  "tokens_received": 500000,
  "auto_graduated": true,
  "tx_status": "confirmed"
}
```

**After:**
```json
{
  "success": true,
  "token_id": "abc...",
  "stable_paid": 1000000,
  "tokens_received": 500000,
  "auto_graduated": false,
  "tx_status": "confirmed"
}
```

**Migration Note:** Clients should not rely on `auto_graduated` to detect graduation. Instead, query the token status endpoint (`GET /api/v1/curve/{token_id}`) to check the `phase` field, or wait for a `BondingCurveGraduate` transaction to be confirmed.

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
