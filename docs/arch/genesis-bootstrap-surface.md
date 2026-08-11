# Genesis Bootstrap Surface — Authoritative Boundary

**Part of:** [#2727 GENESIS epic](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727) — chain bootstrap, replay determinism, and state unification  
**Status:** Active (Phase 0 — documentation)  
**Companion:** [`state-unification.md`](./state-unification.md), [`sovereign-asset.md`](./sovereign-asset.md)  
**Supersedes:** ad-hoc per-token sled patches ([#2725](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2725) SOV-only)

---

## 1. Rule of thumb

Every state fact in the system belongs to exactly one of three buckets. The rule:

| Bucket | Height | Scope | Mnemonic |
|--------|--------|-------|----------|
| **A** | h=0 | Native-only SOV shell + chain params | "Genesis = birth certificate" |
| **B** | h≥1 | Token creation, curve economics, transfers, payroll, validator registration — ALL tokens | "Txs = economic life" |
| **C** | node-local | Keystores, reward DBs, OPAQUE runtime, per-node welcome bonus | "Node = private runtime" |

**Consequence:** If a state fact appears in a bucket it does not belong to, that is a **bug** — not a configuration choice.

---

## 2. Token taxonomy

The chain recognizes exactly one native token. Every other token is a DAO token that enters the system through on-chain transactions.

### 2.1 Classification table

| Token | Class | Enters via | Treasury | Native? | Notes |
|-------|-------|------------|----------|---------|-------|
| **SOV** | Native L1 currency | Genesis h=0 shell + policy; balances via block txs (coinbase, transfers) | N/A (native unit) | **Yes** | Only token whose contract record is written at h=0 |
| **CBE** | DAO token (bonding-curve class) | `TokenCreation` tx (target); currently seeded ad-hoc at h=0 executor (tech debt) | 20% per canonical payload, 20B off-curve treasury allocation | **No** | Bootstraps SOV economics via bonding curve; must not appear in genesis.toml as balances |
| **BUBL** | DAO token (rewards class) | `TokenCreation` tx | 20% per canonical payload | **No** | Fixed supply; rewards module; per-node welcome bonus is node-local (Bucket C) |
| **All other DAO tokens** | DAO token | `TokenCreation` tx | 20% per canonical payload | **No** | `SovereignAsset` primitive (future); uniform launch path |

### 2.2 CBE is NOT native

CBE is a DAO token whose bonding-curve economics bootstrap SOV demand. It is **not** a chain-native asset:

- CBE balances **must not** appear in [`genesis.toml`](../../genesis.toml) under any `[allocations]` section.
- CBE economic state (curve phase, reserve balance, treasury allocation) enters via on-chain transactions, not genesis projection.
- The current executor block-0 CBE seed ([`executor.rs:789-829`](../../lib-blockchain/src/execution/executor.rs#L789)) is **deprecated** tech debt — tracked as GENESIS-6 ([#2734](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2734)).

---

## 3. Full inventory: who writes what, and where

### 3.1 Bucket A — h=0 native only (genesis.toml → build_block0 + project_chain_bootstrap_to_store)

These are the **only** state facts that may appear at height 0. Every item listed here must produce identical sled state on every node that replays block 0.

| # | State fact | Current writer(s) | Written to sled on replay? | Target |
|---|-----------|-------------------|---------------------------|--------|
| A1 | Chain params (chain_id, genesis_time, name) | [`build_block0()`](../../lib-blockchain/src/genesis/mod.rs#L408) → block 0 header | ✅ yes (via `append_block`) | Stay in genesis |
| A2 | SOV native token contract record (name="SOV", symbol="SOV", decimals) | [`project_chain_bootstrap_to_store()`](../../lib-blockchain/src/genesis/mod.rs#L727) → `ensure_sov_native_contract_in_store()` | ✅ yes (GENESIS-1 #2729) | Stay in genesis |
| A3 | Bootstrap council (members, threshold) | [`build_block0()`](../../lib-blockchain/src/genesis/mod.rs#L504-L520) → in-memory `council_members` | ❌ in-memory only (no sled tree) | Add sled tree (deferred) |
| A4 | Entity registry treasury addresses (cbe_treasury_key, nonprofit_treasury_key) | [`build_block0()`](../../lib-blockchain/src/genesis/mod.rs#L487-L502) → in-memory `entity_registry` | ❌ in-memory only (no sled tree) | Add sled tree (deferred) |
| A5 | OPAQUE server setup (lobby-auth) | [`build_block0()`](../../lib-blockchain/src/genesis/mod.rs#L529) → in-memory `opaque_server_setup` | ❌ in-memory only | Node-local runtime (consider Bucket C) |
| A6 | CBE curve canonical params (p_start_0, reserve_ratio_ppm, graduation_threshold) | [`build_block0()`](../../lib-blockchain/src/genesis/mod.rs#L424-L485) → in-memory `bonding_curve_registry` | ❌ in-memory only | Move to Bucket B (curve contract deploy tx) |
| A7 | Identity/wallet/web4 allocations (migration) | [`apply_allocations()`](../../lib-blockchain/src/genesis/mod.rs#L535) → in-memory registries | ❌ in-memory only (no sled trees for most) | Retire; fold into founding txs |
| A8 | SOV balance allocations (bulk) | [`apply_allocations()`](../../lib-blockchain/src/genesis/mod.rs#L535) → in-memory `token_contracts`; [`project_chain_bootstrap_to_store()`](../../lib-blockchain/src/genesis/mod.rs#L727) → sled | ✅ yes (but GENESIS-3 retired bulk SOV) | **Retired** (GENESIS-3 #2731); empty in current genesis.toml |

### 3.2 Bucket B — on-chain transactions (h≥1)

These state facts **must not** be written at h=0. They enter via transactions in blocks 1+.

| # | State fact | Current writer(s) | Written to sled? | Target |
|---|-----------|-------------------|-----------------|--------|
| B1 | CBE treasury allocation (20B off-curve) | **TECH DEBT**: [`executor.rs` block-0 special case](../../lib-blockchain/src/execution/executor.rs#L804-L824) → sled `cbe_economic_state` + `token_balances` | ✅ yes (wrong height) | **Fold into founding `TokenCreation` + curve deploy txs at h=1** (GENESIS-6 #2734) |
| B2 | CBE bonding curve economic state (phase, reserve, treasury, S_c) | **TECH DEBT**: [`executor.rs` block-0 special case](../../lib-blockchain/src/execution/executor.rs#L804-L810) → sled | ✅ yes (wrong height) | **Fold into founding txs** (GENESIS-6 #2734) |
| B3 | TokenCreation (CBE, BUBL, all DAO tokens) | Valid `TokenCreation` tx in block 1+ | ✅ yes (via `StateMutator::apply`) | Normal tx path |
| B4 | Token transfers, burns, mints | Valid tx in block 1+ | ✅ yes | Normal tx path |
| B5 | Payroll (CBE operator, etc.) | Valid tx in block 1+ | ✅ yes | Normal tx path |
| B6 | Validator registration | `ValidatorRegistration` tx in block 1+ | ❌ in-memory only (no sled tree) | Add sled tree; move to normal tx path |
| B7 | DAO governance (proposals, votes, stake) | Governance tx in block 1+ | ⚠️ partial (stakes=sled, index=in-mem) | Complete sled wiring |
| B8 | Domain registration, NFT minting, web4 deploy, gateway registration, credential issuance | Respective tx in block 1+ | ❌ in-memory only | Add sled trees |

### 3.3 Bucket C — node-local runtime

These state facts are **never** part of consensus state. They differ per node by design and must not be written to sled trees that are expected to be identical across nodes.

| # | State fact | Current writer | Persisted? | Notes |
|---|-----------|---------------|-----------|-------|
| C1 | Reward streak DB | Node-local DB (not chain state) | Node-local disk | Per-validator reward tracking |
| C2 | Treasury signer keystore | Operator config (`/opt/zhtp/keystores/`) | Filesystem | Cold/hot wallet keys; never on chain |
| C3 | Per-node welcome bonus | [`GenesisFundingService`](../../zhtp/src/runtime/services/genesis_funding.rs) → in-memory SOV mint | In-memory only | Non-deterministic: depends on per-node wallet ID |
| C4 | GenesisFundingService UTXO mutation | [`GenesisFundingService::create_genesis_funding()`](../../zhtp/src/runtime/services/genesis_funding.rs#L28) → in-memory `utxo_set` + block 0 mutation | In-memory only | **Must be retired** — produces different block 0 hash per node |
| C5 | OPAQUE runtime auth state | [`opaque_server_setup`](../../lib-blockchain/src/genesis/mod.rs#L529) → in-memory | In-memory only | Server setup is consensus (Bucket A); runtime auth state is node-local |
| C6 | Mempool | [`pending_transactions`](../../lib-blockchain/src/blockchain.rs#L160) | ⚠️ sled trees exist but unused | Per-node; not consensus |

---

## 4. Three-bucket boundary diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      h=0 (genesis block)                     │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Bucket A — Native SOV shell + chain params           │  │
│  │  • Chain ID, genesis_time, name                       │  │
│  │  • SOV token contract record (name, symbol, decimals) │  │
│  │  • Bootstrap council members + threshold              │  │
│  │  • Entity registry treasury addresses                 │  │
│  │  • OPAQUE server setup blob                           │  │
│  │  • CBE curve canonical params (⚠️ moving to Bucket B) │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  BUG: Executor block-0 CBE seed (tech debt)           │  │
│  │  • 20B CBE treasury allocation → sled                 │  │
│  │  • CBE economic zero-state → sled                     │  │
│  │  • GENESIS-6 #2734: fold into founding txs            │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  BUG: GenesisFundingService (non-deterministic)       │  │
│  │  • UTXO set mutation post-build_block0()              │  │
│  │  • Per-node welcome bonus SOV mint                    │  │
│  │  • Different block 0 hash per node                    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    h≥1 (on-chain transactions)               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Bucket B — Economic life                             │  │
│  │  • TokenCreation: CBE, BUBL, all DAO tokens           │  │
│  │  • CBE curve contract deploy (20B treasury, curve ops)│  │
│  │  • All transfers, burns, mints                        │  │
│  │  • Validator registration                             │  │
│  │  • Governance: proposals, votes, stake                 │  │
│  │  • Domain, NFT, web4, gateway, credential txs         │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                 Node-local runtime (any height)              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Bucket C — Private per-node state                    │  │
│  │  • Reward streak DB                                   │  │
│  │  • Treasury signer keystores (filesystem)             │  │
│  │  • Per-node welcome bonus                             │  │
│  │  • OPAQUE runtime auth state                          │  │
│  │  • Mempool (per-node view)                            │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. "Never in genesis" list

The following **must never** appear in [`genesis.toml`](../../genesis.toml) or be written at h=0 by any code path:

| # | Item | Reason | Current status |
|---|------|--------|---------------|
| N1 | CBE token balances (any address) | CBE is a DAO token, not native | **VIOLATED**: executor block-0 writes 20B CBE to treasury sled balance (GENESIS-6 #2734) |
| N2 | CBE `BondingCurveEconomicState` | Curve economics are on-chain tx state | **VIOLATED**: executor block-0 writes zero-state (GENESIS-6 #2734) |
| N3 | BUBL token contract or balances | DAO token; enters via TokenCreation | ✅ Compliant (not in genesis.toml) |
| N4 | Any DAO-issued token (future `SovereignAsset`) | All DAO tokens enter via `AssetLaunch` tx | ✅ Compliant (not yet implemented) |
| N5 | Validator registration records | Validators register via tx, not genesis | ⚠️ Partial: `[[allocations.identities]]` can seed identities but not validators |
| N6 | Per-node wallet welcome bonus | Non-deterministic; depends on node-local wallet ID | **VIOLATED**: GenesisFundingService writes per-node SOV mint |

---

## 6. Testnet legacy to retire

The following code paths exist in the current testnet but **must be removed** to achieve replay determinism:

### 6.1 `[[allocations.sov_balances]]` — RETIRED (GENESIS-3 #2731)

- **Status:** Empty in current [`genesis.toml`](../../genesis.toml#L113-L114). Forensic snapshot archived at [`archive/genesis-testnet-sov-balances-pre-genesis3.toml`](../../archive/genesis-testnet-sov-balances-pre-genesis3.toml).
- **Remaining work:** Remove the `sov_balances` field from [`GenesisAllocations`](../../lib-blockchain/src/genesis/mod.rs#L169), [`GenesisStateSnapshot`](../../lib-blockchain/src/genesis/mod.rs#L253), `apply_allocations()`, `credit_sov_allocations_to_store()`, and `credit_sov_allocations_in_open_transaction()`.
- **Blocked by:** All testnet resets must use on-chain SOV distribution only.

### 6.2 Executor block-0 CBE ad-hoc seed — DEPRECATED (GENESIS-6 #2734)

- **Code:** [`executor.rs:789-829`](../../lib-blockchain/src/execution/executor.rs#L789) — writes CBE economic zero-state + 20B treasury allocation to sled inside the `block_height == 0` special case.
- **Replacement:** Founding `TokenCreation` + curve contract deploy transactions at height 1 (or earliest block with txs).
- **Risk:** Until removed, CBE is incorrectly treated as chain-native. Any replay that skips this block-0 path will miss the CBE economic state.

### 6.3 GenesisFundingService UTXO mutation — NON-DETERMINISTIC

- **Code:** [`genesis_funding.rs`](../../zhtp/src/runtime/services/genesis_funding.rs) — called after [`build_block0()`](../../lib-blockchain/src/genesis/mod.rs#L408), mutates the genesis block's UTXO set and transactions, then [`replace_block`](../../zhtp/src/runtime/services/genesis_funding.rs#L331) re-persists block 0.
- **Non-determinism source:** Validator identity IDs and user wallet IDs are per-node configuration. Even with deterministic sorting ([`genesis_funding.rs:73`](../../zhtp/src/runtime/services/genesis_funding.rs#L73)), different node configs produce different genesis block hashes.
- **Replacement:** Founding validators must register via on-chain `ValidatorRegistration` transactions at h≥1. Welcome bonuses move to Bucket C (node-local, not chain state).

### 6.4 Bulk wallet/identity allocations — RETIRED (GENESIS-4)

- **Status:** Empty in current [`genesis.toml`](../../genesis.toml#L116-L119). Forensic snapshot archived at [`archive/genesis-testnet-wallets-identities-pre-genesis4.toml`](../../archive/genesis-testnet-wallets-identities-pre-genesis4.toml).
- **Remaining work:** Remove the `wallets` and `identities` fields from [`GenesisAllocations`](../../lib-blockchain/src/genesis/mod.rs#L163-L166) and `apply_allocations()` once all testnet identities enter via block txs.

---

## 7. Current write-path inventory (who writes what to which store)

Understanding why engineers cannot diagnose state gaps requires mapping all four write paths:

| Write path | In-memory | Sled | Called by | Deterministic? |
|------------|-----------|------|-----------|---------------|
| [`build_block0()`](../../lib-blockchain/src/genesis/mod.rs#L408) | ✅ chain params, council, entity registry, CBE curve, OPAQUE, allocations | ❌ (sled not attached) | `Blockchain::new()` | ✅ yes (same genesis.toml → same result) |
| [`GenesisFundingService`](../../zhtp/src/runtime/services/genesis_funding.rs#L28) | ✅ UTXOs, SOV welcome bonus, validator funding | ❌ (then `replace_block` to sled) | Runtime startup (founding node) | ❌ **no** — per-node config |
| [`executor.rs` block-0 special case](../../lib-blockchain/src/execution/executor.rs#L775-L869) | ❌ | ✅ CBE economic state, CBE treasury balance, SOV contract shell, SOV balances (if any) | `apply_block(block_0)` during replay/sync | ✅ yes (but writes wrong-bucket data) |
| [`project_chain_bootstrap_to_store()`](../../lib-blockchain/src/genesis/mod.rs#L727) | ❌ | ✅ SOV contract shell + SOV allocations | Called from executor block-0 path | ✅ yes |

**The gap-producing scenario:**

1. Founding node calls `build_block0()` → in-memory has council, curve, entity registry, etc.
2. Founding node calls `GenesisFundingService` → mutates in-memory UTXO set, blocks[0]
3. Peer replays block 0 via `executor.apply_block()` → sled gets CBE economic state + SOV shell, but **in-memory maps are not populated**
4. Handler reads in-memory `bonding_curve_registry` → **empty** (never populated during replay)
5. Reconciliation step in [`process_and_commit_block`](../../lib-blockchain/src/blockchain.rs#L962) back-syncs some fields — but not all; gaps remain

---

## 8. Acceptance checklist for g4 / post-reset replay parity

- [ ] `build_block0()` writes **only** Bucket A items (no CBE balances, no curve economic state)
- [ ] Executor block-0 special case removed (GENESIS-6 #2734)
- [ ] CBE 20B treasury allocation + economic zero-state folded into founding `TokenCreation` + curve deploy txs at h=1
- [ ] `GenesisFundingService` retired; validator registration and welcome bonuses move to h≥1 txs or node-local runtime
- [ ] All `[allocations.*]` sections empty and code paths removed
- [ ] `project_chain_bootstrap_to_store` scoped to SOV contract shell only (no SOV balances)
- [ ] Two nodes with different configs replaying the same genesis.toml produce identical block 0 hash and identical sled state
- [ ] Divergence detector ([`state-unification.md` §5](./state-unification.md#5-divergence-detector--design-spec)) reports zero mismatches for all DELETE/CACHE pairs after 100-block soak
- [ ] `state-unification.md` §6 transition-window protocol satisfied for consensus-critical fields

---

## 9. Cross-references

| Document | Relationship |
|----------|-------------|
| [`state-unification.md`](./state-unification.md) | Catalogs the dual-store pairs this boundary isolates; §6 transition-window protocol for cutover |
| [`sovereign-asset.md`](./sovereign-asset.md) | Future `SovereignAsset` primitive — all DAO tokens (CBE, BUBL, …) become uniform Bucket B entries |
| [`docs/ops/dao-launch-bootstrap.md`](../ops/dao-launch-bootstrap.md) | Operational procedure for founding DAO token launches |
| [`docs/protocol/genesis-3-testnet-reset.md`](../protocol/genesis-3-testnet-reset.md) | GENESIS-3 reset runbook (retired bulk SOV) |
| [`docs/ops/legacy-fixup-removal-gate.md`](../ops/legacy-fixup-removal-gate.md) | Gates for removing legacy fixup code paths |

### Related GitHub issues

| Issue | Title | Role |
|-------|-------|------|
| [#2727](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727) | GENESIS epic | Parent tracker |
| [#2729](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2729) | GENESIS-1: SOV-native shell projection | Installed SOV contract record in sled at h=0 |
| [#2731](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2731) | GENESIS-3: retire bulk SOV allocations | Removed `[[allocations.sov_balances]]` |
| [#2734](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2734) | GENESIS-6: fold CBE seed into founding txs | Remove executor block-0 CBE special case |
| [#2725](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2725) | SOV-only token balance fix | Per-token patch — superseded by this boundary doc |

---

## 10. Revision history

| Date | Change | Author |
|------|--------|--------|
| 2026-08-10 | Initial draft: taxonomy + inventory + three buckets + legacy retirement list | GENESIS Phase 0 |
