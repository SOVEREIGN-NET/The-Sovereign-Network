# DAO Launch — Operator Bootstrap (interim)

**Epic:** [#2799](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2799) · **Story:** [#2823](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2823)

This runbook covers **Phase 1** operator steps until chain-native rewards activation lands ([#2813](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2813) / N3).

End-user path (CLI `dao launch`) is tracked in [#2816](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2816).

---

## Prerequisites

1. Coordinated testnet reset if needed: `./scripts/effective-reset-testnet.sh`
2. Validators running current `zhtp` binary: `./scripts/deploy-validators.sh --skip-halt target/dev-release/zhtp`
3. Creator identity registered on-chain with Primary wallet funded (SOV for fees)

### Chain ID (must match genesis)

Embedded genesis (`genesis.toml` v2) sets `chain_id = 2` (Sovereign Network v2 testnet).
All signed txs and validator env **must** use that byte (`0x02`), not the legacy development
default `0x03`.

| Context | Value |
|---------|-------|
| `genesis.toml` `[chain].chain_id` | `2` |
| `seed_founding_dao --chain-id` | `2` |
| `ZHTP_CHAIN_ID` on validators | `2` |

v1 testnet used `chain_id = 1`; do not reuse those values on v2.

---

## Step 1 — Creator keystore

### CLI wizard (preferred)

```bash
zhtp-cli identity init --display-name "My DAO Creator"
```

Creates `~/.zhtp/keystore/` (`user_identity.json` + `user_private_key.json`) and registers on-chain (identity + Primary/UBI/Savings wallets + SOV welcome bonus).

### Manual (operators / validators)

On the operator host (or validator), create a directory:

```bash
mkdir -p /opt/zhtp/keystores/bubl-creator
```

Populate with:

| File | Purpose |
|------|---------|
| `user_identity.json` | ZHTP identity (DID, public keys) |
| `user_private_key.json` | Dilithium5 + Kyber private material |

The creator identity becomes:

- `TokenCreation` / `AssetLaunch` signer
- Launch signer only (creator key stays cold after handoff)

Rewards spending uses a dedicated hot delegate bound via `node configure-rewards` (SA-4).

---

## Step 2 — Build signed token launch tx

### BUBL (AssetLaunch — canonical path, SA-3)

```bash
cargo run -p tools --bin seed_asset_launch -- \
  --keystore-dir /opt/zhtp/keystores/bubl-creator \
  --token bubl \
  --supply-atoms 1000000000000000000000000000 \
  --chain-id 2 \
  --fee 0
```

Copy the `signed_tx` hex from JSON output.

> **Legacy note:** testnet BUBL deployed before SA-3 may still exist via historical
> `TokenCreation`. New launches must use `AssetLaunch` only. `TokenCreation` is
> rejected by `POST /api/v1/token/create` and sunset at block **80,000** in consensus
> (`TOKEN_CREATION_SUNSET_HEIGHT`).

---

## Step 3 — Broadcast launch tx

Prefer the sovereign-asset API (QUIC on testnet validators):

```bash
# Option A: zhtp-cli (recommended)
./target/dev-release/zhtp-cli -s <host>:9334 dao launch \
  --template fp-starter --keystore-dir /opt/zhtp/keystores/bubl-creator

# Option B: broadcast pre-signed hex from seed_asset_launch
./target/dev-release/zhtp-cli -s <host>:9334 blockchain broadcast-raw \
  --tx-hex "<signed_tx_hex>"

# Option C: POST /api/v1/assets/launch (same payload as Option A)
```

`POST /api/v1/token/create` accepts `AssetLaunch` only during migration shim;
`TokenCreation` returns **400 deprecated**.

Record outputs:

- `token_id` / `asset_id` (32-byte hex)
- Creator allocation (80% of supply)
- Treasury allocation (20%, unsignable `treasury_key_id`)

---

## Step 4 — Enable rewards on validators (SA-4)

SA-4 splits **activation** (no private key on disk; enables read endpoints) from
**delegate keystore** (hot wallet; required only for claim POSTs). This is strictly
better key exposure than the pre-SA-4 posture (creator/treasury key on one box via env
var): the spendable delegate key stays on **one** validator; the other validators serve
mobile read traffic without holding signing material.

### Keystore posture (do not put the hot wallet on every box)

| Validator | `rewards_activation.toml` | Hot delegate keystore (`bubl-rewards-hot`) |
|-----------|---------------------------|---------------------------------------------|
| g1 | yes | **yes** — only node that signs `RewardClaim` txs |
| g2 | yes (copy from g1) | **no** — reads only; claim POSTs return 503 |
| g3 | yes (copy from g1) | **no** — reads only; claim POSTs return 503 |

The activation file records `asset_id` and a `delegate_keystore_dir` path. Read
endpoints (`/status`, `/balance`, `/history`) need only `asset_id` in the file.
Claim endpoints additionally require the keystore directory to exist locally, the
signer `key_id` to match on-chain `spend_delegate_key_id`, and delegate balance &gt; 0.

### Rollout order (load-bearing — do not invert)

Without `rewards_activation.toml`, **every** `/api/v1/rewards/*` route — including
reads the mobile app calls — returns **503**. The safe sequence:

1. **Activation first (while the current binary is still running)** — on **all**
   validators, materialise `rewards_activation.toml` *before* deploying the SA-4
   binary that drops `ZHTP_REWARDS_TREASURY_KEYSTORE`:
   - **g1:** run `configure-rewards` (writes toml + validates keystore against chain)
   - **g2 / g3:** copy g1's `rewards_activation.toml` into each node's data dir (do
     **not** copy the hot keystore)
2. **Verify reads on all three** — `curl …/api/v1/rewards/status/<did>` must not be 503
   on g1, g2, and g3.
3. **Deploy SA-4 binary second** — env-var fallback is gone; nodes missing the toml
   lose all rewards routes immediately on restart.

> **Pre-merge check:** confirm whether g1/g2/g3 systemd units still set
> `ZHTP_REWARDS_TREASURY_KEYSTORE`. If yes, step 1 can lag until the env path is
> retired; if no, step 1 is mandatory before any SA-4 deploy.

### g1 — write activation + attach keystore

```bash
./target/dev-release/zhtp-cli node configure-rewards \
  --asset-id <launch_tx_hash_hex> \
  --delegate-keystore /opt/zhtp/keystores/bubl-rewards-hot
export ZHTP_CHAIN_ID=2
```

### g2 / g3 — activation file only

```bash
# After g1 step succeeds, copy the toml (not the keystore):
scp g1:/var/lib/zhtp/rewards_activation.toml /var/lib/zhtp/rewards_activation.toml
systemctl restart zhtp   # or your deploy script
```

Env-var overrides (`ZHTP_REWARDS_TREASURY_KEYSTORE`, `ZHTP_REWARDS_TOKEN_ID`) are
removed in SA-4 — `rewards_activation.toml` is required.

### Verify

```bash
# Reads — must succeed on g1, g2, g3 once toml is present
curl -s "https://<validator>:9334/api/v1/rewards/status/<did>"

# Claims — only g1 (or whichever node holds the hot keystore)
curl -s -X POST "https://g1:9334/api/v1/rewards/claim" …
```

503 on reads → missing or invalid `rewards_activation.toml`. 503 on claims on a
read-only replica → expected (no local keystore).

---

## Step 5 — Rewards policy (D1)

Publish canonical BUBL policy to DHT before AssetLaunch migration:

- Schema: `schemas/zhtp/rewards-policy/v1.schema.json`
- Example: `schemas/zhtp/rewards-policy/examples/bubl-v1.json`
- Validate: `lib-blockchain::rewards_policy::validate_rewards_policy`
- Hash: `policy_hash()` → store on-chain in `RewardsModuleState` (Phase 2 / P3)

Replace `asset_id` placeholder in the example with launch tx hash after migration.

---

## Related

- `tools/seed_asset_launch.rs` — canonical `AssetLaunch` + rewards delegate builder
- `tools/seed_founding_dao.rs` — **deprecated** `TokenCreation` builder (replay only)
- `scripts/effective-reset-testnet.sh` — wipe + post-reset checklist
- Epic child issues: P3–P5, N2–N4, D3 BUBL migration