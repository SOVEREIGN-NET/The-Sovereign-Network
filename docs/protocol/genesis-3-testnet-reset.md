# GENESIS-3 Testnet Reset Runbook

**Issue:** [#2731 GENESIS-3](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2731)  
**Epic:** [#2727 GENESIS](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727)  
**Status:** Scheduled — execute only after prerequisites below are checked
**Audience:** Testnet operators (validators g1–g3 only; gateways retired)

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
- [ ] **Pre-reset g4 fixture documents divergence class** — manual gate is **expected red** on pre-reset chain (replay cannot reproduce h=73982 write-path history). Re-run after reset; gate must be **green** on post-reset chain before declaring success:
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
GENESIS-3 reset_time (UTC):  2026-07-07T12:00:00Z   (Monday)
operator_notice_deadline:    2026-07-05T12:00:00Z   (≥48h before reset — announce maintenance now)
halt_lead_time:              T-30 minutes → 2026-07-07T11:30:00Z
```

| Phase | UTC | Local hint (Europe/London, BST) |
|-------|-----|----------------------------------|
| Operator notice sent | by 2026-07-05T12:00:00Z | Sat 05 Jul, 13:00 |
| Phase 0 snapshot (optional) | 2026-07-06T12:00:00Z | Sun 06 Jul, 13:00 |
| Phase 1 halt | 2026-07-07T11:30:00Z | Mon 07 Jul, 12:30 |
| Phase 2–3 deploy + wipe | 2026-07-07T12:00:00Z | Mon 07 Jul, 13:00 |
| Phase 4 bootstrap g1 | 2026-07-07T12:02:00Z | Mon 07 Jul, 13:02 |
| Phase 5 start followers | 2026-07-07T12:05:00Z | Mon 07 Jul, 13:05 (30s stagger) |
| Phase 6 verification | from 2026-07-07T12:30:00Z | allow up to **T+3h** for catch-up |

**Slip rule:** if #2744 is not merged and deployed by 2026-07-06T12:00:00Z, postpone one week (2026-07-14T12:00:00Z) and re-announce.

---

## Topology (post-reset)

| Host (SSH alias) | IP | sudo | Role |
|------------------|-----|------|------|
| zhtp-g1 | 77.42.37.161 | no | bootstrap leader |
| zhtp-g2 | 77.42.74.80 | no | validator |
| zhtp-g3 | 178.105.9.247 | no | validator |

**Retired (decommission at reset — do not restart):**

| Host | IP | Former role |
|------|-----|-------------|
| zhtp-g4 | 148.113.140.176 | validator |
| zhtp-g5 | 51.75.62.133 | validator |
| zhtp-gateway | 91.98.113.188 | observer gateway |
| zhtp-gateway-2 | 57.128.30.74 | observer gateway |

BFT quorum with **3 validators** requires **3/3** votes (`(n×2/3)+1` = 3). All three nodes must be active for commits.

Clients connect to validators directly (`<ip>:9334`). No gateway layer.

Config source of truth: `tools/node-configs/shared.toml` (3 `bootstrap_peers`, 3 `bootstrap_validators`).

Data path (active validators): `/opt/zhtp/.zhtp/data/testnet/sled`

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

## Phase 1 — Halt + decommission (T-30m)

### 1a — Stop active validators (g1–g3)

```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3; do
  ssh $node 'sudo systemctl stop zhtp --wait-timeout 120' &
done
wait
```

### 1b — Decommission retired nodes (g4, g5, gateways)

Stop and **disable** so they do not rejoin after reboot:

```bash
for node in zhtp-g4 zhtp-g5 zhtp-gateway zhtp-gateway-2; do
  ssh $node 'sudo systemctl stop zhtp --wait-timeout 120; sudo systemctl disable zhtp' &
done
wait
```

Optional: take final sled backup on g4/g5 before power-down. Do **not** deploy new binary or wipe sled on retired hosts.

Verify all stopped:

```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4 zhtp-g5 zhtp-gateway zhtp-gateway-2; do
  ssh $node 'sudo systemctl is-active zhtp 2>/dev/null || echo stopped'
done
```

---

## Phase 2 — Deploy binary + config (T-0)

From dev machine with built binary. **Do not use** full `deploy-validators.sh` for wipe-reset (it restarts nodes) — rsync binary only, then wipe, then staggered start.

```bash
# Binary to g1–g3 only
BINARY=target/release/zhtp
for node in zhtp-g1 zhtp-g2 zhtp-g3; do
  scp -q "$BINARY" "$node:/tmp/zhtp.new"
  ssh "$node" 'cp /opt/zhtp/zhtp /opt/zhtp/zhtp.bak.$(date +%Y%m%d-%H%M%S) && mv /tmp/zhtp.new /opt/zhtp/zhtp && chmod +x /opt/zhtp/zhtp'
done

# Trimmed 3-validator mesh config (bootstrap_peers + bootstrap_validators)
./tools/deploy-config.sh zhtp-g1 zhtp-g2 zhtp-g3
```

Rolling upgrades on a live chain (no wipe): `./scripts/deploy-validators.sh target/release/zhtp` (g1–g3 table only).

---

## Phase 3 — Wipe sled (T+0)

**All validators together** — empty sled triggers peer catch-up from block 0.

Wipe canonical sled **and** legacy sidecar state under the testnet data dir:

```bash
DATA=/opt/zhtp/.zhtp/data/testnet
for node in zhtp-g1 zhtp-g2 zhtp-g3; do
  ssh $node "sudo rm -rf \
    $DATA/sled \
    $DATA/blockchain.dat \
    $DATA/rewards.sled \
    $DATA/rewards.dat \
    $DATA/notifications.sled \
    $DATA/storage \
    && sudo mkdir -p $DATA/sled"
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

Confirm g1 loads genesis and **creates block proposals**. g1 alone cannot **commit** blocks — BFT needs **3/3** with the trimmed set. Expect **no committed blocks** until g2 and g3 join (Phase 5). Proposals waiting for votes is normal; do not panic on "height stuck at 0" for the first few minutes.

---

## Phase 5 — Start followers (T+5m)

Stagger 30s apart to reduce handshake storms:

```bash
for node in zhtp-g2 zhtp-g3; do
  ssh $node 'sudo systemctl start zhtp'
  sleep 30
done
```

**Catch-up duration:** after a **wipe**, all nodes rebuild from genesis locally — minutes, not hours. (Long catch-up only applies if you restore old sled without wipe.)

Watch for:
- `Caught up` / catch-up sync completing
- `3/3` validators in consensus (no sustained `PARTITION`)
- No `Insufficient token balance` during initial sync
- Network directory shows **0 gateways**

**Partition noise:** ignore `PARTITION SUSPECTED` in the first **60 seconds** after start on any node — handshake window false positives are common during healthy startups.

---

## Phase 6 — Verification (T+30m)

| Check | Command / signal |
|-------|------------------|
| All services active | `systemctl is-active zhtp` on each node |
| Heights aligned | API tip or logs within 1 block |
| Validator count | Exactly 3 active in logs / `node status` |
| No gateway peers | Retired gateways not in bootstrap_peers |
| Replay gate (optional) | Re-export fixture at new tip post-reset; manual gate green |

Allow extra time (up to T+3h) if followers are still catching up from genesis.

---

## Phase 7 — Post-reset seeding (GENESIS-6 follow-up)

After shrunk genesis is live:

1. **CBE / BUBL** — founding `AssetLaunch` txs (+ CBE curve contract deploy) in blocks 1..k (not genesis rows). Historical chains may replay `TokenCreation` below block 80,000 only.
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

**Peer sled transplant** (g1 → follower) is valid if a single validator fails catch-up — do not wipe that node's sled again until pagination fix is confirmed on deployed binary.

---

## genesis.toml changes (GENESIS-3 scope)

On reset commit:

- Remove bulk `[[allocations.sov_balances]]` from active `genesis.toml`
- Set `[sov] initial_supply = 0`
- Archive migrated allocations to `archive/genesis-testnet-sov-balances-pre-genesis3.toml` (forensic only)
- Retire `[cbe_curve]` / block-0 CBE seed when GENESIS-6 lands

---

## Related docs

- [`docs/arch/genesis-bootstrap-surface.md`](../arch/genesis-bootstrap-surface.md) — genesis vs on-chain boundary
- [`scripts/validate-genesis-replay-gate.sh`](../../scripts/validate-genesis-replay-gate.sh) — CI replay gate
- [`scripts/reset-testnet.sh`](../../scripts/reset-testnet.sh) — legacy EPIC-001 script (update node list before use)