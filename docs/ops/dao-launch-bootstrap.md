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

### BUBL (TokenCreation — current testnet)

```bash
cargo run -p tools --bin seed_founding_dao -- \
  --keystore-dir /opt/zhtp/keystores/bubl-creator \
  --token bubl \
  --supply-atoms 1000000000000000000000000000 \
  --chain-id 2 \
  --fee 0
```

Copy the `signed_tx` hex from JSON output.

> **Do not use `seed_asset_launch` for Phase 1 BUBL bootstrap.** That path emits
> `AssetLaunch` txs (SA-3 / N3) and is incompatible with interim Phase 1 rewards,
> which expect a `TokenCreation` signer and `ZHTP_REWARDS_TREASURY_KEYSTORE`.
> Reserve `tools/seed_asset_launch.rs` for the N3 chain-native activation migration
> ([#2813](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2813)).

---

## Step 3 — Broadcast launch tx

**Phase 1 (current): use Option B.** `zhtp-cli token create` still hardcodes
`chain_id = 0x03` in `zhtp-cli/src/commands/token.rs`; txs signed that way are
rejected on v2 testnet (`genesis.toml` `chain_id = 2`). Broadcast the
`signed_tx` from `seed_founding_dao` (with `--chain-id 2`) until the CLI gains
explicit chain-id selection.

```bash
# Option A: zhtp-cli (NOT for Phase 1 v2 testnet — chain_id hardcoded 0x03)
# zhtp-cli token create --name Bubble --symbol BUBL \
#   --supply 1000000000000000000000000000 --decimals 18 \
#   --treasury-recipient <32-byte-hex-key_id>

# Option B: POST pre-signed tx from seed_founding_dao (required for Phase 1)
curl -s -X POST "https://<validator>:9334/api/v1/token/create" \
  -H "Content-Type: application/json" \
  -d '{"signed_tx":"<hex>"}'
```

Record outputs:

- `token_id` / `asset_id` (32-byte hex)
- Creator allocation (80% of supply)
- Treasury allocation (20%, unsignable `treasury_key_id`)

---

## Step 4 — Enable rewards on validators (interim)

On **each** validator (`zhtp-g1`, `g2`, `g3`), set environment and restart:

```bash
export ZHTP_REWARDS_TREASURY_KEYSTORE=/opt/zhtp/keystores/bubl-creator
# Optional override (defaults to deterministic BUBL token_id):
# export ZHTP_REWARDS_TOKEN_ID=<hex>
export ZHTP_CHAIN_ID=2
```

Handler activates when:

1. Keystore loads successfully
2. Signer is the on-chain token **creator**
3. Creator holds positive token balance

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

## Migration to chain-native activation (N3)

When [#2813](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2813) ships:

1. Remove `ZHTP_REWARDS_TREASURY_KEYSTORE` from validator env
2. Fund `spend_delegate_key_id` on-chain
3. Validators scan assets with `rewards` module bit + delegate balance > 0
4. Use `zhtp-cli node configure-rewards --asset-id <hex> --delegate-keystore ...` (interim CLI)
5. Build launch via `seed_asset_launch` (not `seed_founding_dao`):

```bash
cargo run -p tools --bin seed_asset_launch -- \
  --keystore-dir /opt/zhtp/keystores/bubl-creator \
  --token bubl \
  --supply-atoms 1000000000000000000000000000 \
  --chain-id 2 \
  --rewards-delegate-dir /opt/zhtp/keystores/bubl-rewards-hot
```

---

## Related

- `tools/seed_founding_dao.rs` — TokenCreation builder
- `tools/seed_asset_launch.rs` — AssetLaunch + rewards delegate
- `scripts/effective-reset-testnet.sh` — wipe + post-reset checklist
- Epic child issues: P3–P5, N2–N4, D3 BUBL migration