# ZHTP AUTH Phase 5 Validation Template

Use this template for `#2014` after `#2011` is unblocked and the legacy fixups have been removed on the target branch.

## Preconditions

- `#2011` is complete and the legacy fixups are removed from the target branch.
- Observation-window evidence is attached or linked, showing zero firings for:
  - `repair_backfill_inflation`
  - `migrate_sov_key_balances_to_wallets`
  - `backfill_token_balances_from_contract`
- `#2012` and `#2013` are complete.

## Validation Checklist

- [ ] Observation-window evidence reviewed and attached.
- [ ] Standard startup verified without `blockchain.dat` fallback.
- [ ] Emergency restore behavior reviewed and still explicitly gated.
- [ ] Restart equivalence suite passed on target branch.
- [ ] Replay determinism suite passed on target branch.
- [ ] Crash-safety / last-committed-block recovery suite passed on target branch.
- [ ] No startup path depends on removed legacy fixups.
- [ ] No standard startup path depends on `blockchain.dat`.
- [ ] Residual risks and rollback notes reviewed.
- [ ] Release recommendation recorded.

## Suggested Commands

Run only the relevant gate commands for the target branch and record the exact branch/commit:

```bash
cargo check -p zhtp -p lib-blockchain
```

```bash
cargo test -p lib-blockchain test_load_from_store_restart_replay_equivalence_for_identity_wallet_and_sov_state -- --nocapture
```

```bash
cargo test -p lib-blockchain --test wallet_projection_restart_tests -- --nocapture
```

```bash
cargo test -p zhtp reconstruct_identity_manager_from_blockchain_state_rebuilds_identity_and_wallets -- --nocapture
```

Add any additional final gate commands required by the branch state here before sign-off.

## Comment Template

```text
Final Phase 5 validation run completed on <branch> @ <commit>.

Observation-window evidence:
- <link or artifact>

Gate results:
- Standard startup without blockchain.dat fallback: PASS/FAIL
- Emergency restore remains explicit and operator-invoked: PASS/FAIL
- Restart equivalence: PASS/FAIL
- Replay determinism: PASS/FAIL
- Crash safety to last committed block: PASS/FAIL
- No dependency on removed legacy fixups: PASS/FAIL

Commands run:
- <command 1>
- <command 2>
- <command 3>

Residual risks:
- <risk 1>
- <risk 2>

Rollback notes:
- <note 1>
- <note 2>

Release recommendation:
- GO / NO-GO
```
