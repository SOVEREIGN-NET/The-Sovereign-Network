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
- Interim rewards spender (`ZHTP_REWARDS_TREASURY_KEYSTORE`)

**Future (N3):** rewards spend moves to a dedicated hot delegate keystore; creator key leaves validators.

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

## Step 4 — Enable rewards on validators

On **each** validator (`zhtp-g1`, `g2`, `g3`), bind the on-chain spend delegate:

```bash
./target/dev-release/zhtp-cli node configure-rewards \
  --asset-id <launch_tx_hash_hex> \
  --delegate-keystore /opt/zhtp/keystores/bubl-rewards-hot
export ZHTP_CHAIN_ID=2
```

Writes `rewards_activation.toml` under the node data dir. Validators scan
`asset_rewards/` (pure `AssetLaunch`) plus legacy `token_contracts` rows.

**Deprecated fallback** (historical `TokenCreation` BUBL only):

```bash
export ZHTP_REWARDS_TREASURY_KEYSTORE=/opt/zhtp/keystores/bubl-creator
```

Handler activates when the configured keystore matches the on-chain spend delegate
and delegate balance is positive.

Verify:

```bash
curl -s "https://<validator>:9334/api/v1/rewards/status/<did>"
```

503 means keystore unset, wrong signer, or zero balance.

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