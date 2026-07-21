# Legacy fixup removal gate (#1985 / #2000)

Startup/replay still contains a few **non-canonical repair** paths. They are
instrumented so operators can prove they are idle before Phase 5 deletes them.

## Instrumented paths

| Path | Code | Log target / fields |
|------|------|---------------------|
| SOV key→wallet balance migrate | `migrate_sov_key_balances_to_wallets` | `target=legacy_fixup` `path=migrate_sov_key_balances_to_wallets` |
| Backfill inflation repair | `repair_backfill_inflation` | `target=legacy_fixup` `path=repair_backfill_inflation` |
| Contract blob → `token_balances` | `backfill_token_balances_from_contract` | `target=legacy_fixup` `path=backfill_token_balances_from_contract` |
| Identity projection rebuild (canonical) | `rebuild_identity_projections_from_registry` | `target=legacy_fixup` `path=rebuild_identity_projections` |

Identity rebuild is **not** a ghost-mint path; it only rewrites projections from
block-derived registry. Track it to confirm rebuild frequency after upgrades.

## How to measure (validators g1–g3)

```bash
# Last 14 days of fixup firings (any non-zero entity counts matter)
for h in zhtp-g1 zhtp-g2 zhtp-g3; do
  echo "=== $h ==="
  ssh "$h" "journalctl -u zhtp --since '14 days ago' --no-pager \
    | grep 'legacy_fixup' \
    | grep -E 'migrate_sov_key_balances|repair_backfill_inflation|backfill_token_balances' \
    | wc -l"
done
```

Parse structured fields when present:

- `amount_atomic` / `entries_written` / `wallets_corrected` — **must be 0** for
  the removal window (or log lines must not appear at all).

## Removal gate (Phase 5)

**Ready to remove** a fixup when **all** of:

1. **Zero firings** of that path with non-zero effect for **≥ 14 consecutive days**
   on every GENESIS-3 validator (g1–g3).
2. Restart/replay suites green:
   - `identity_projection_restart_tests`
   - `wallet_projection_restart_tests`
   - `token_snapshot_restart_tests`
3. No open incident requiring the fixup as a recovery tool.
4. Parent epic checklist updated (#1988).

Until then: leave the path in place; do not “delete because it looks unused”
without the two-week evidence window.
