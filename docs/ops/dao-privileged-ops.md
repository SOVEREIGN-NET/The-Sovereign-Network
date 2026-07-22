# DAO privileged operations (P6 / P10 / P11)

**Epic:** [#2799](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2799)  
**Stories:** [#2805](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2805) · [#2809](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2809) · [#2810](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2810)

This runbook lists on-chain privileged sovereign-asset ops, who may sign them, and the CLI surface after DAO Launch v1.

---

## Authority model

| Phase | `SovereignAsset.authority` | Proof on privileged txs |
|-------|----------------------------|-------------------------|
| Pre-handoff | `Creator` | `AssetAuthorityProof::CreatorSig` (tx signature = creator) |
| Post-handoff | `Governance` | `AssetAuthorityProof::Governance` (multisig over action message hash) |

Handoff: `AssetAuthorityTransfer` → `pending_transfer` → activates at height ≥ **80,000** (`activate_pending_authority_transfers`).

---

## Privileged ops (GovernanceProof after handoff)

| Op | Tx type | Message payload hash input | CLI |
|----|---------|----------------------------|-----|
| Rewards policy update | `AssetRewardsPolicyUpdate` | policy_hash | `zhtp-cli dao governance propose/vote --submit` |
| Rewards delegate rotate | `AssetRewardsDelegateRotate` | new_delegate_key_id | `zhtp-cli asset rewards rotate-delegate [--governance]` |
| Manifest update | `AssetManifestUpdate` | manifest hash | governance tooling / protocol |
| Module upgrade | `AssetModuleUpgrade` | module payload | `tools` `seed_bubl_pre80k` / protocol |
| Authority transfer | `AssetAuthorityTransfer` | new verifier digest | `seed_bubl_pre80k authority-transfer` |
| Burn bps update | burn-bps path | new burn_bps digest | protocol |
| Elastic mint (post-80k) | mint path | class split | governance signer required |

Pre-handoff rotate:

```bash
zhtp-cli --server <host>:9334 asset rewards rotate-delegate \
  --asset-id <64hex> \
  --new-keystore /path/to/new-delegate \
  --keystore /path/to/creator \
  --chain-id 2
```

Post-handoff rotate (single governance signer = local keystore):

```bash
zhtp-cli --server <host>:9334 asset rewards rotate-delegate \
  --asset-id <64hex> \
  --new-keystore /path/to/new-delegate \
  --keystore /path/to/governance-signer \
  --governance \
  --threshold 1 \
  --chain-id 2
```

Multisig: collect Dilithium signatures over
`governance_action_message_hash(asset_id, "rewards_delegate_rotate", new_delegate_key_id)`
and pass each as `--approval <key_id_hex>:<sig_hex>`.

---

## Treasury (P10)

### Default treasury key at launch

CLI default when `--treasury-recipient` is omitted:

```text
treasury_key_id = blake3("SOV_DAO_TREASURY_V1")
# hex: 6adb0279d2af625f4d292bafe0fcfe3e2020436478b0f90d98adaf820cac1547
```

Must be **non-zero** and **≠ creator** `key_id`. Operators may pass a dedicated treasury keystore public key hex instead.

### Legacy BUBL

If `treasury_key_id` is unset on a pre-SA-3 projection, bind once with creator authority:

```bash
cargo run -p tools --bin seed_bubl_pre80k -- treasury-bind \
  --keystore-dir /opt/zhtp/keystores/bubl-creator \
  --treasury-dir /opt/zhtp/keystores/bubl-treasury \
  --asset-id <bubl_asset_id> \
  --chain-id 2
# then broadcast signed_tx via zhtp-cli
```

Fund rewards spend delegate (Q3) — explicit transfer, not auto-carved:

```bash
zhtp-cli asset rewards fund-delegate \
  --asset-id <asset_id> \
  --amount <atoms> \
  --delegate-keystore /opt/zhtp/keystores/bubl-treasury \
  --keystore /opt/zhtp/keystores/bubl-creator \
  --chain-id 2
```

### Settlement API liquidity error (M6)

When the spend delegate is underfunded at height ≥ 80,000, claim responses include:

```json
{
  "awarded": false,
  "amount": "0",
  "reason": "InsufficientRewardLiquidity",
  "have": "<atoms>",
  "need": "<atoms>"
}
```

Do **not** treat this as generic 503 (503 is reserved for missing `rewards_activation.toml` / no hot keystore).

---

## Domain claim fee (P11 / Q10)

Domain is a **separate** `DomainRegistration` after `AssetLaunch` (not embedded).

| Rule | Value |
|------|-------|
| Fee | **100 SOV** (`DEFAULT_DOMAIN_REGISTRATION_FEE_ATOMS`) |
| Sink | Protocol treasury `blake3("SOV_DAO_TREASURY_V1")` |
| DAO bind | Optional `--asset-id` (V3 payload) |
| Failure | Domain fail does **not** roll back launch |

Sequence:

```bash
# 1) Launch
zhtp-cli dao launch --template fp-starter --name "My DAO" --symbol MYDAO --chain-id 2
# record asset_id from response

# 2) Wait for finality (asset visible)
zhtp-cli # GET /api/v1/assets/<asset_id> shows dao_class + treasury_key_id

# 3) Claim domain bound to asset
zhtp-cli domain register \
  --domain mydao.sov \
  --asset-id <asset_id> \
  --chain-id 2
```

Smoke (no UI): `./scripts/dao-launch-smoke-test.sh` (#2879).

---

## Related

- [`economic-rules-activation-80k.md`](./economic-rules-activation-80k.md)
- [`dao-launch-bootstrap.md`](./dao-launch-bootstrap.md)
- [`../arch/dao-launch-decision-register.md`](../arch/dao-launch-decision-register.md)
