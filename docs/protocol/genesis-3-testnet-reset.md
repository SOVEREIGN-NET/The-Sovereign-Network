# GENESIS-3 Testnet Reset Runbook

**Issue:** [#2731 GENESIS-3](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2731)  
**Epic:** [#2727 GENESIS](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727)  
**Status:** Draft — execute only after GENESIS-2 gates are green  
**Audience:** Testnet operators (validators g1–g5, gateways)

---

## Purpose

Retire bulk `[[allocations.sov_balances]]` from active `genesis.toml` and align testnet with v2 clean-slate SOV policy (`[sov] initial_supply = 0`). DAO tokens (CBE, BUBL, …) enter via founding block txs (GENESIS-6), not genesis rows.

This is a **coordinated wipe-and-restart**, not an in-place `genesis.toml` edit on a live chain.

---

## Prerequisites (blockers)

Do **not** reset until every item is checked:

- [ ] **GENESIS-1 merged** — `project_chain_bootstrap_to_store()` at h=0 ([#2741](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/pull/2741))
- [ ] **GENESIS-2 CI green** — `./scripts/validate-genesis-replay-gate.sh`
- [ ] **Pagination sync fix deployed** — `ChainSync::import_blocks` uses canonical runtime on page 2+ (fixes g4 @ h=74010 wipe failure)
- [ ] **Manual g4 fixture green** — export from live sled, replay to checkpoint:
  ```bash
  cargo run --release -p tools --bin export_replay_fixture -- \
    <source-sled> /tmp/g4-fixture --to-height 74010
  G4_REPLAY_BLOCKS_PATH=/tmp/g4-fixture/blocks.v1.bin \
  G4_REPLAY_SNAPSHOT_PATH=/tmp/g4-fixture/checkpoint.json \
    cargo test --release -p lib-blockchain --test g4_replay_acceptance_tests \
      test_g4_checkpoint_replay_acceptance -- --ignored --nocapture
  # Paginated mirror of production initial sync (optional; 3–6h): test_g4_checkpoint_paginated_replay_acceptance
  ```
- [ ] **Binary built and recorded** — `cargo build --release -p zhtp` on reset commit; SHA-256 logged
- [ ] **Operators notified** — ≥48h notice; reset datetime in UTC recorded below

---

## Reset datetime

```
GENESIS-3 reset_time (UTC):  2026-07-02T12:00:00Z   (Wednesday — adjust if needed)
halt_lead_time:              T-30 minutes (stop accepting user txs / announce maintenance)
```

---

## Validator inventory

| Host | IP | sudo | Role |
|------|-----|------|------|
| zhtp-g1 | 77.42.37.161 | no | bootstrap leader |
| zhtp-g2 | 77.42.74.80 | no | validator |
| zhtp-g3 | 51.75.62.133 | no | validator |
| zhtp-g4 | 148.113.140.176 | yes | validator |
| zhtp-g5 | 178.105.9.247 | yes | validator |

Data path (all nodes): `/opt/zhtp/.zhtp/data/testnet/sled`

---

## Phase 0 — Pre-reset snapshot (T-24h)

1. On **g1** (canonical tip), export forensic snapshot:
   ```bash
   cargo run --release -p tools --bin export_replay_fixture -- \
     /opt/zhtp/.zhtp/data/testnet/sled /tmp/pre-genesis3-fixture --to-height 74010
   ```
2. Archive sled backup on each validator (do not delete until reset verified):
   ```bash
   sudo systemctl stop zhtp
   sudo cp -a /opt/zhtp/.zhtp/data/testnet/sled \
     /opt/zhtp/.zhtp/data/testnet/sled.pre-genesis3.$(date +%s)
   sudo systemctl start zhtp
   ```
3. Record chain tip height + hash from g1 logs or API.

---

## Phase 1 — Halt (T-30m)

Run **simultaneously** on all validators:

```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4 zhtp-g5; do
  ssh $node 'sudo systemctl stop zhtp' &
done
wait
```

Verify all stopped:

```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4 zhtp-g5; do
  ssh $node 'sudo systemctl is-active zhtp || echo stopped'
done
```

---

## Phase 2 — Deploy binary (T-0)

From dev machine with built binary:

```bash
./scripts/deploy-validators.sh target/release/zhtp
```

Or per-node rsync (g4/g5 need sudo):

```bash
rsync -az target/release/zhtp zhtp-g1:/opt/zhtp/zhtp
# repeat for g2–g5
```

---

## Phase 3 — Wipe sled (T+0)

**All validators together** — empty sled triggers peer catch-up from block 0:

```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4 zhtp-g5; do
  ssh $node 'sudo rm -rf /opt/zhtp/.zhtp/data/testnet/sled && sudo mkdir -p /opt/zhtp/.zhtp/data/testnet/sled'
done
```

Do **not** use `recover-fork.sh` for this reset — it assumes fork recovery, not genesis replay.

---

## Phase 4 — Start bootstrap leader (T+2m)

```bash
ssh zhtp-g1 'sudo systemctl start zhtp'
sleep 30
ssh zhtp-g1 'sudo journalctl -u zhtp -n 30 --no-pager | grep -iE "genesis|height|Loaded blockchain"'
```

Confirm g1 loads genesis and begins producing blocks.

---

## Phase 5 — Start followers (T+5m)

Stagger 30s apart to reduce handshake storms:

```bash
for node in zhtp-g2 zhtp-g3 zhtp-g4 zhtp-g5; do
  ssh $node 'sudo systemctl start zhtp'
  sleep 30
done
```

Watch for:
- `Caught up` / catch-up sync completing
- `5/5` validators in consensus (no `PARTITION`)
- No `Insufficient token balance` during initial sync

---

## Phase 6 — Verification (T+30m)

| Check | Command / signal |
|-------|------------------|
| All services active | `systemctl is-active zhtp` on each node |
| Heights aligned | API tip or logs within 1 block |
| g4 caught up | g4 logs show commit at peer height, not stuck at 74009 |
| Replay gate (optional) | Re-export fixture at h=74010 post-reset; manual gate green |

---

## Phase 7 — Post-reset seeding (GENESIS-6 follow-up)

After shrunk genesis is live:

1. **CBE / BUBL** — founding `TokenCreation` + contract deploy txs in blocks 1..k (not genesis rows)
2. **Wallets** — `WalletRegistration` / UBI / coinbase in early blocks ([#2733](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2733))
3. **Domains** — `./scripts/replay-domains.sh` if domain snapshot exists
4. **Sites** — redeploy per ops checklist

---

## Rollback

If reset fails (consensus partition, replay errors, mass crash-loop):

1. Stop all validators
2. Restore `sled.pre-genesis3.*` backup on each node
3. Redeploy **previous** known-good binary
4. Start g1, then followers
5. File incident on [#2727](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727) with height + error line

**Peer sled transplant** (g1 → g4 relay) is a valid recovery if a single node fails catch-up — do not wipe that node's sled again until pagination fix is confirmed on deployed binary.

---

## genesis.toml changes (GENESIS-3 scope)

On reset commit:

- Remove bulk `[[allocations.sov_balances]]` from active `genesis.toml`
- Set `[sov] initial_supply = 0`
- Archive migrated allocations to `archive/genesis-v1-pre-cutover.toml` (forensic only)
- Retire `[cbe_curve]` / block-0 CBE seed when GENESIS-6 lands

---

## Related docs

- [`docs/arch/genesis-bootstrap-surface.md`](../arch/genesis-bootstrap-surface.md) — genesis vs on-chain boundary
- [`scripts/validate-genesis-replay-gate.sh`](../../scripts/validate-genesis-replay-gate.sh) — CI replay gate
- [`scripts/reset-testnet.sh`](../../scripts/reset-testnet.sh) — legacy EPIC-001 script (update node list before use)