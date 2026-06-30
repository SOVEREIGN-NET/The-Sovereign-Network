# Genesis Bootstrap Surface Area

**Epic:** [#2727 GENESIS](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727)  
**Status:** Draft (GENESIS-0)  
**Companion:** [`state-unification.md`](./state-unification.md)

---

## 1. Rule of thumb

| Layer | Height | What | Grows when DAO mints? |
|-------|--------|------|------------------------|
| **Genesis (native)** | h=0 | SOV policy + shell, chain params, council | No |
| **On-chain txs** | h≥1 | All tokens, contracts, transfers, payroll | Yes — every DAO launch |
| **Node-local** | N/A | rewards.sled, keystores, OPAQUE runtime | Per node |

**Only SOV is native.** CBE, BUBL, and every other ticker are DAO tokens created via `TokenCreation`. CBE is special only in **economics**: its bonding-curve contract bootstraps SOV liquidity — not in **genesis shape**.

---

## 2. Token taxonomy

| Token | Class | Genesis? | Bootstrap role |
|-------|-------|----------|------------------|
| **SOV** | Native (sole) | Policy + contract shell at h=0 | Fees, payroll, internal settlement |
| **CBE** | DAO | No | Bonding-curve **contract** + `TokenCreation`; on-ramp buys mint SOV |
| **BUBL** | DAO | No | Rewards `TokenCreation` |
| **Others** | DAO | No | 20% treasury per `TokenCreationPayloadV1` |

Curve **parameters** and `BondingCurveEconomicState` are **DAO contract state** (sled), initialized by founding deploy/init txs — not `[cbe_curve]` in `genesis.toml`. Immutable protocol **math** (band formula, debt ceiling rules) may remain in `canonical.rs`; deploy-time config and live economic state belong on-chain.

---

## 3. Inventory (current → target; bucket = §4)

| State | Current writer | Sled on replay? | Target (§4) |
|-------|----------------|-----------------|-------------|
| `chain_id`, `genesis_time` | `genesis.toml` | N/A | A — genesis config |
| SOV native shell | `build_block0()` in-mem only | Yes (#2741 `project_chain_bootstrap`) | A — h=0 projection |
| `[[allocations.sov_balances]]` | `build_block0()` in-mem; #2725/#2741 sled | Yes | A — testnet legacy (see §8) |
| CBE `TokenCreation` + balances | Should be founding tx | Partial (block-0 patch) | B — on-chain txs |
| CBE curve params | `genesis.toml` + `canonical.rs` + `build_block0()` deploy | No | B — DAO contract state |
| `BondingCurveEconomicState` | Executor block-0 special case (deprecated) | Yes | B — contract init tx |
| BUBL / custom tokens | `TokenCreation` in chain | Yes if executor path | B — on-chain txs |
| Wallets / identities | `[[allocations.*]]`, `apply_genesis_state` | Partial | B — registration txs |
| Bootstrap council | `genesis.toml` | In-mem only | A — governance sled TBD |
| `[opaque]` | `apply_genesis_state` | No | C — node-local |
| `GenesisFundingService` welcome SOV | Bootstrap leader only | No | C — retire |
| Reward streaks | `rewards.sled` | N/A | C — node-local |

---

## 4. Buckets

### A — Native genesis (h=0, fixed at reset)

- Chain params (`chain_id`, `genesis_time`)
- SOV native token contract record (zero supply on v2)
- SOV policy (`[sov] initial_supply = 0` on clean testnet)
- Bootstrap council, treasury **addresses** (not DAO balances)
- Testnet-only: migrated `sov_balances` until GENESIS-3 reset

**API:** `GenesisConfig::project_chain_bootstrap_to_store()` (GENESIS-1, #2729) — SOV-native scope only. Installs SOV contract shell + credits `[allocations.sov_balances]` during executor block-0 `begin_block`.

### B — On-chain transactions (unbounded)

- `TokenCreation` — CBE, BUBL, all DAO tokens (20% treasury)
- CBE bonding-curve contract deploy + economic state init
- `TokenTransfer`, payroll, CBE buy/sell, coinbase
- `WalletRegistration`, `IdentityRegistration`, `ValidatorRegistration`

### C — Node-local (never consensus)

- `rewards.sled`, treasury signer keystore, per-node welcome bonus
- OPAQUE server setup blob (runtime auth)

---

## 5. Never in genesis

- CBE, BUBL, or any DAO token **balances**
- CBE curve **deploy config** (belongs in contract state)
- Per-DAO allocations that grow with each launch
- Reward policy / streak state
- Treasury private keys

`genesis.toml` may retain **chain** and **SOV policy** sections only after testnet reset. `[cbe_curve]` / `[bonding_curve]` are retired in favour of founding contract txs (GENESIS-6).

---

## 6. Replay acceptance (GENESIS-2)

After wipe + replay to height `H`:

1. SOV native balances match live node at `H` (sample wallets)
2. CBE treasury balance from **DAO tx replay**, not native h=0 patch
3. BUBL treasury from `TokenCreation` replay if deployed before `H`
4. No `Insufficient token balance` in executor at g4 checkpoint (~74010)

### CI gate (synthetic — does not replace g4 fixture)

```bash
./scripts/validate-genesis-replay-gate.sh
```

Regression-tests replay **mechanics** on a short synthetic chain. A green CI badge does **not** prove empirical g4 parity at 74k+.

| Test | Scope |
|------|-------|
| `test_genesis_bootstrap_checkpoint_balances` | Block-0 SOV shell, ≥3 `sov_balances`, legacy CBE 20B treasury |
| `test_sov_native_wipe_replay_parity` | SOV transfers — #2725/#2741 fix class |
| `test_dao_token_creation_wipe_replay_parity` | `TokenCreation` + custom-token transfer (BUBL class) |

Failures print `token_id`, `address`, `have`, `need` via `common/replay_gate.rs`.

**Who runs CI:** every PR touching `lib-blockchain` execution/sync/genesis (CI or `./scripts/validate-genesis-replay-gate.sh` locally).

### Manual g4 fixture (≥ `G4_CHECKPOINT_HEIGHT_FLOOR` = 74_010)

Empirical gate for the live chain shape. **Who:** testnet maintainer / validator operator with sled SSH access. **When:** before each testnet binary deploy that touches genesis, replay, or executor paths; mandatory before GENESIS-7 (delete seed-sled). **On failure:** block deploy, file issue on [#2727](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727) / [#2730](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2730) with height + `Insufficient token balance` line (token/address/have/need).

Export (versioned fixture — `blocks.v1.bin` + `checkpoint.json`):

```bash
cargo run -p tools --bin export_replay_fixture -- \
  /opt/zhtp/data/testnet/sled /tmp/g4-fixture --to-height 74010
```

Replay:

```bash
export G4_REPLAY_BLOCKS_PATH=/tmp/g4-fixture/blocks.v1.bin
export G4_REPLAY_SNAPSHOT_PATH=/tmp/g4-fixture/checkpoint.json
cargo test -p lib-blockchain --test g4_replay_acceptance_tests \
  test_g4_checkpoint_replay_acceptance -- --ignored --nocapture
```

Large chains: use `--to-height` to cap memory (full `export_all_blocks` on 177k+ blocks materialises the window). Bump `REPLAY_BLOCKS_FIXTURE_VERSION` if the wrapper layout changes.

---

## 7. Implementation order

See [#2727](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727): GENESIS-0 → GENESIS-1 (SOV h=0) → GENESIS-6 (CBE contract + DAO tokens) → GENESIS-2 (gate) → GENESIS-7+ (state unification).

Do **not** land GENESIS-7 (delete seed-sled) until GENESIS-2 passes.

---

## 8. Migration / retirement plan (testnet)

Retiring `[[allocations.sov_balances]]` (GENESIS-3 / #2731) requires a **coordinated testnet reset**, not a silent genesis.toml edit on a live chain:

1. **Snapshot** current sled + document wallet balances to verify replay parity (GENESIS-2).
2. **Reset** all validators together with shrunk `genesis.toml` (`[sov] initial_supply = 0`, no bulk allocations).
3. **Re-seed** wallets via early-block `WalletRegistration` / UBI / coinbase — not genesis rows.
4. **DAO tokens** (CBE, BUBL): founding `TokenCreation` + contract deploy txs in blocks 1..k (GENESIS-6).

Mainnet uses a one-shot ceremony; testnet may repeat resets until GENESIS-2 gate is green.

**Operator runbook:** [`docs/protocol/genesis-3-testnet-reset.md`](../protocol/genesis-3-testnet-reset.md)