# Genesis Configuration and Key Ceremony

## Overview

Genesis ran once on testnet. It will run once on mainnet. It must never run again.

`genesis.toml` is the permanent source of truth for the founding state of the
Sovereign Network. Any node with the same file produces bit-for-bit identical block 0.
The founding node has no special status after genesis is committed.

See: #1909 (GENESIS-1), OPERATIONS.md

---

## Key Ceremony Procedure (Mainnet — One Time)

Before mainnet launch, a key ceremony must be performed to generate the real
cryptographic keys and lock the genesis configuration.

### Prerequisites

- Air-gapped machine (or HSM)
- At least 3 bootstrap council members present
- `zhtp-cli` binary available

### Step 1 — Generate Pool Keypairs (CBE Token)

Generate 4 Dilithium5 keypairs for the CBE token pools:

```bash
zhtp-cli wallet create --type compensation-pool
zhtp-cli wallet create --type operational-treasury
zhtp-cli wallet create --type performance-incentives
zhtp-cli wallet create --type strategic-reserves
```

Record the **public keys only** from each wallet.

### Step 2 — Generate Treasury Keypairs (Entity Registry)

Generate 2 Dilithium5 keypairs for entity registry:

```bash
zhtp-cli wallet create --type cbe-treasury
zhtp-cli wallet create --type nonprofit-treasury
```

### Step 3 — Generate Bootstrap Council Keypairs

Generate one keypair per council member. Each member registers a DID.

### Step 4 — Fill genesis.toml

Edit `genesis.toml` and set all public keys:

```toml
[cbe_token]
compensation_pool_key  = "<hex pubkey>"
operational_pool_key   = "<hex pubkey>"
performance_pool_key   = "<hex pubkey>"
strategic_pool_key     = "<hex pubkey>"

[entity_registry]
cbe_treasury_key       = "<hex pubkey>"
nonprofit_treasury_key = "<hex pubkey>"

[bootstrap_council]
threshold = 3
[[bootstrap_council.members]]
did    = "did:zhtp:<council-member-1>"
wallet = "<wallet-id>"
# ...repeat for each member
```

Set `genesis_time` to the agreed mainnet launch date.

### Step 5 — Build Block 0 and Record Hash

```bash
zhtp-cli genesis build --config genesis.toml
```

This outputs the deterministic hash of block 0.

### Step 6 — Lock CANONICAL_GENESIS_HASH

Set the hash in `lib-blockchain/src/genesis/mod.rs`:

```rust
pub const CANONICAL_GENESIS_HASH: &str = "<block-0-hash-from-step-5>";
```

Rebuild the binary.

### Step 7 — Commit and Tag

```bash
git add genesis.toml lib-blockchain/src/genesis/mod.rs
git commit -m "chore(genesis): lock mainnet genesis configuration"
git tag mainnet-genesis-v1
git push origin mainnet-genesis-v1
```

`genesis.toml` contains **public keys only**. Private keys are distributed to
their holders via a separate secure channel and must never be committed.

### Step 8 — Deploy

Follow the rolling update procedure in `OPERATIONS.md`.

---

## Testnet State Migration

Block history is throwaway on testnet. The following preserves:
- Wallet keys and IDs
- SOV balances
- Identities / DIDs
- Web4 sites and domains

### 1. Export current testnet state

From any running node:

```bash
# Export from the node's blockchain.dat
zhtp-cli genesis export-state \
  --dat-file /opt/zhtp/data/testnet/blockchain.dat \
  --output state-snapshot.json
```

### 2. Merge into genesis.toml

```bash
zhtp-cli genesis migrate-state \
  --snapshot state-snapshot.json \
  --config genesis.toml \
  --output genesis-final.toml
```

### 3. Verify block 0 hash

```bash
zhtp-cli genesis build --config genesis-final.toml
```

### 4. Rolling testnet reset (ops decision on timing)

```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4; do
  ssh $node "systemctl stop zhtp && rm -rf /opt/zhtp/data/"
  scp genesis-final.toml $node:/opt/zhtp/genesis.toml
  ssh $node "systemctl start zhtp"
done
```

After restart, all nodes boot from the new block 0. Wallets, balances, identities,
and domains are intact. Block history starts clean.

---

## Invariants

- `genesis.toml` is the only source of truth for genesis state
- `CANONICAL_GENESIS_HASH` is hardcoded in the binary — a different block 0 = different chain
- No genesis initialization runs during normal restart or peer sync
- The founder node has no special status after genesis is committed
