# Operations Guide

## Genesis

Genesis runs **once, ever** — on the founding node when a new network is created.

It will run once on testnet (already done). It will run once on mainnet. It must never
run again under any other circumstance unless a catastrophic fork forces a full chain reset.

When a node starts with an empty store and no peers have chain data, genesis is created
from the genesis configuration. Every other node — whether joining fresh or restarting
after an update — either loads its own saved state from disk or syncs missing blocks
from peers. No genesis code runs on restart or sync.

See: #1907 (CBE-0), #1909 (GENESIS-1)

---

## Rolling Update Procedure

Validators cannot all be updated simultaneously. BFT consensus requires 2/3 of validators
online to commit blocks. With 4 validators, at most 1 may be offline at any time.

### Binary Update

1. **Deploy and restart the founder node first (zhtp-g1)**

   ```bash
   rsync -az target/release/zhtp zhtp-g1:/opt/zhtp/zhtp
   rsync -az target/release/zhtp-cli zhtp-g1:/opt/zhtp/zhtp-cli
   ssh zhtp-g1 "chmod +x /opt/zhtp/zhtp /opt/zhtp/zhtp-cli && systemctl restart zhtp"
   ```

2. **Wait for g1 to reach tip** — confirm it is producing/committing blocks before proceeding:

   ```bash
   ssh zhtp-g1 "journalctl -u zhtp -n 20 --no-pager"
   ```

3. **Update remaining nodes one at a time** (g2, g3, g4 — any order):

   ```bash
   for node in zhtp-g2 zhtp-g3 zhtp-g4; do
     rsync -az target/release/zhtp $node:/opt/zhtp/zhtp
     rsync -az target/release/zhtp-cli $node:/opt/zhtp/zhtp-cli
     ssh $node "chmod +x /opt/zhtp/zhtp /opt/zhtp/zhtp-cli && systemctl restart zhtp"
     # Wait for the node to sync back to tip before updating the next one
     sleep 30
     ssh $node "journalctl -u zhtp -n 10 --no-pager"
   done
   ```

   Each restarted node:
   - Loads its saved state from disk (no genesis runs)
   - If behind: syncs missing blocks from peers, then joins consensus
   - If at tip: joins consensus immediately

4. **Never take more than 1 of 4 validators offline simultaneously.**

### Storage Format Change

Same procedure as binary update. New fields added to `BlockchainStorageV6` use
`#[serde(default)]` — the loading node deserializes the old format, restores in-memory
state, and persists in the new format on the next `save_to_file()`. No manual migration
required.

### Server Reference

| Node     | IP              | Port |
|----------|-----------------|------|
| zhtp-g1  | 77.42.37.161    | 9334 |
| zhtp-g2  | 77.42.74.80     | 9334 |
| zhtp-g3  | 91.98.113.188   | 9334 |
| zhtp-g4  | 77.42.77.183    | 9334 |

All nodes use SSH alias from `~/.ssh/config` with `IdentityFile ~/.ssh/kode_ocr.pem`.

### Checking logs after deploy

```bash
ssh zhtp-g1 "journalctl -u zhtp -n 50 --no-pager"
```

---

## This procedure is the single source of truth. It must never be violated.
