# Testnet Reset Checklist

**Date**: TBD
**Reason**: EPIC-001 merge — decimals unification (SOV 18), CBE removal from protocol, event-driven on-ramp
**PR**: #2105

---

## Pre-reset snapshot (DONE)

- [x] `docs/testnet/testnet_snapshot_2026-04-13.json` — 14 identities, 403 wallets, 15 CBE transfers
- [x] `docs/testnet/testnet_snapshot_2026-04-14.json` — 16 identities, 409 wallets, 15 CBE transfers (latest)
- [x] `docs/testnet/cbe_transactions_snapshot_2026-04-13.json` — all 15 CBE transfers with amounts/recipients
- [x] Current chain: height 106,570, 16 identities, 3 validators

## Data to preserve

### Identities (16 on-chain)
All identity DIDs and public keys are in the snapshot. These need to be re-registered after reset via the app or genesis config.

### Wallets (403+)
Wallet IDs and owner mappings are in the snapshot. Wallets are created during identity registration (3 per identity: Primary, UBI, Savings).

### CBE transfers (15 total, 5,930,842 CBE distributed)
These used the old pre-mint model. They will NOT be replayed — CBE enters via on-ramp only in the new model.

### Domain registrations (454 legacy + on-chain)
Legacy domains live in sled DomainRegistry. On-chain domains are in `blockchain.domain_registry`. Both will be lost. Need to re-register after reset.

---

## Pre-reset code changes required

### Governance bootstrap
- [ ] Set `genesis.toml` `[bootstrap_council]` threshold=1, add council member DID + wallet
- [ ] Council member identity must be registered on new chain first (or via genesis allocations)

### SOV amount constants (8-decimal → 18-decimal values)
All SOV amounts in the codebase are still 8-decimal values. With SOV_DECIMALS=18, they need multiplying by 10^10:
- [ ] `mint_sov_for_pouw` reward amounts (`zhtp/src/pouw/rewards.rs`)
- [ ] Validator rewards (`lib-consensus/src/rewards/reward_calculator.rs`)
- [ ] Welcome bonus — `SOV_WELCOME_BONUS` (`lib-identity/src/constants.rs`)
- [ ] UBI monthly amount (`lib-identity/src/constants.rs`)
- [ ] Domain registration fee (`zhtp/src/api/handlers/web4/domains.rs` — already fixed)
- [ ] Wallet `initial_balance` in identity registration handler

### CBE bonding curve
- [ ] `initialize_cbe_genesis()` still runs at startup — verify it works without `cbe_token`
- [ ] `BondingCurveEconomicState` defaults to zeros (correct — no pre-mint)
- [ ] First BUY_CBE triggers 20/32/48 split (verify with test)

## Reset procedure

### 1. Stop all nodes simultaneously
```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3; do
    ssh $node "systemctl stop zhtp" &
done
wait
# Verify all stopped
for node in zhtp-g1 zhtp-g2 zhtp-g3; do
    ssh $node "systemctl is-active zhtp" && echo "$node: STILL RUNNING" || echo "$node: stopped"
done
```

### 2. Merge EPIC-001 PR to development
```bash
# On local machine
gh pr merge 2105 --merge
git checkout development && git pull
```

### 3. Build release binary
```bash
cargo build --release -p zhtp
cargo build --release -p zhtp-cli
```

### 4. Clear chain data on all nodes
```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3; do
    ssh $node "rm -rf /opt/zhtp/data/testnet/sled && echo '$node: sled cleared'"
done
```

### 5. Deploy new binary to all nodes
```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3; do
    rsync -az target/release/zhtp $node:/opt/zhtp/zhtp
    ssh $node "chmod +x /opt/zhtp/zhtp"
done
```

### 6. Deploy updated CLI to all nodes
```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3; do
    scp target/release/zhtp-cli $node:/opt/zhtp/zhtp-cli
done
```

### 7. Start bootstrap leader (g1)
```bash
ssh zhtp-g1 "systemctl start zhtp && sleep 5 && systemctl is-active zhtp"
ssh zhtp-g1 "journalctl -u zhtp -n 20 --no-pager" | grep -i "genesis\|height\|started\|error"
```
Verify: genesis block created, height=0 or 1, no crash.

### 8. Start follower nodes
```bash
ssh zhtp-g2 "systemctl start zhtp && sleep 5 && systemctl is-active zhtp"
ssh zhtp-g3 "systemctl start zhtp && sleep 5 && systemctl is-active zhtp"
```
Verify: nodes sync genesis from g1, consensus starts.

### 9. Verify chain is advancing
```bash
ssh zhtp-g3 "journalctl -u zhtp -n 10 --no-pager" | grep "Block committed\|height"
```

---

## Post-reset verification

### Chain state
- [ ] SOV total supply = 0 (no pre-mint)
- [ ] CBE total supply = 0 (no pre-mint, enters via on-ramp only)
- [ ] `BondingCurveEconomicState`: s_c=0, reserve_balance=0, sov_treasury_cbe_balance=0, liquidity_pool_balance=0
- [ ] TokenContract uses u128 balances with 18-decimal SOV
- [ ] No `cbe_token` field on Blockchain struct
- [ ] No `[cbe_token]` in genesis

### Consensus
- [ ] All 3 validators producing blocks
- [ ] Finalization happening (3/3 commits)
- [ ] No crash loops on any node

### Identity registration
- [ ] New identity via app creates 3 wallets + SOV welcome bonus
- [ ] No "Failed to persist SOV token" warnings
- [ ] No 409 for observed→citizen upgrade

### Bonding curve
- [ ] BUY_CBE transaction produces 20/32/48 split
- [ ] SOV mints on deposit
- [ ] Floor price computable: `reserve_balance / s_c`

### Domains
- [ ] Domain registration works (requires identity + wallet + SOV)
- [ ] Legacy domains need re-registration

---

## Identity replay

After reset, users need to re-register via the app. The snapshot has all 16 DIDs for reference. Genesis config can pre-seed validator identities.

**Do NOT replay:**
- CBE transfers (old pre-mint model)
- Old wallet balances (SOV welcome bonus is re-credited on registration)

---

## Rollback plan

If the reset fails:
1. Stop all nodes
2. Re-deploy the old (pre-EPIC-001) binary from development HEAD~1
3. Sled data is already gone — restore from the snapshot or accept data loss
4. The snapshot has all identities/wallets/CBE transfers for manual replay if needed

**Note**: There is no automatic rollback. The reset is a one-way operation.

---

## Node details

| Node | IP | Role | SSH |
|------|-----|------|-----|
| zhtp-g1 | 77.42.37.161:9334 | Validator | `ssh zhtp-g1` |
| zhtp-g2 | 77.42.74.80:9334 | Validator | `ssh zhtp-g2` |
| zhtp-g3 | 178.105.9.247:9334 | Validator | `ssh zhtp-g3` |
