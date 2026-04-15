# EPIC-001: Event-Driven Token Architecture Migration

**Status**: Planning
**Branch**: `epic/EPIC-001-event-driven-token-architecture`
**Canonical Spec**: `docs/architecture/token-architecture.md`
**Testnet Snapshot**: `docs/testnet/testnet_snapshot_2026-04-13.json`

---

## Context

The codebase treats CBE as a system token (hardcoded in Blockchain struct, special validation, pre-minted at genesis). The canonical spec says CBE is a DAO that enters via on-ramp only. Additionally, there's a decimals divergence: `lib-types` says CBE=18/SOV=18, but runtime uses CBE=8/SOV=8. The bonding curve uses 18 decimals internally. We're resetting testnet, so no backwards compatibility needed.

### CBE Hardcoding Audit
- **1,810 references across 84 files**
- CBE has a dedicated `cbe_token: CbeToken` field on the Blockchain struct
- Separate `cbe_accounts` sled tree for bonding curve account states
- Special validation, execution, oracle, pricing, and genesis paths
- 100B CBE pre-minted at genesis in 40/30/20/10 pool split

### Gap Analysis vs Spec
| Area | Spec | Current Code | Verdict |
|------|------|-------------|---------|
| On-ramp split | 20/32/48 | 20/80 binary | GAP |
| SOV minting | Event-driven on deposit | No mint on BUY_CBE | GAP |
| CBE floor price | reserve/supply | Piecewise linear formula | GAP |
| SOVRN token | Mints+burns audit token | Doesn't exist | GAP |
| Pre-minting | Rejected | 100B at genesis | GAP |
| Graduation | AMM from liquidity pool | AMM from reserve only | PARTIAL |
| Bonding curve pricing | Piecewise linear 5-band | Correctly implemented | MATCH |
| Payroll | On-ramp event | No-op in executor | GAP |

---

## Phase Ordering

```
Phase 0 (Constants + u128) → Phase 1 (CBE Removal) → Phase 2 (Event-Driven) → Phase 3 (Reset)
```

---

## Phase 0: Decimals Unification + u128 Widening

**Goal**: One decimal standard per token, no conflicting constants, u128 balances everywhere.

### Decisions
- **SOV = 18 decimals** everywhere (lib-types is correct, runtime constants are wrong)
- **CBE = 8 decimals** for display, but bonding curve keeps 18-decimal internal math (already working)
- **Remove CBE constants from lib-types** (CBE is a DAO, not protocol)
- **Widen TokenContract balances from u64 to u128** (sled already uses u128 via `Amount`)

### Changes

**A) lib-types/src/tokenomics.rs** — Remove CBE constants, keep SOV only:
- Delete `CBE_DECIMALS`, `CBE_TOTAL_SUPPLY_TOKENS`, `CBE_MAX_SUPPLY`
- Keep `SOV_DECIMALS = 18`, `SOV_MAX_SUPPLY`, `TOKEN_SCALE_18`

**B) lib-blockchain/src/contracts/tokens/constants.rs** — Unify SOV:
- Change `SOV_TOKEN_DECIMALS` from 8 to 18
- Change `SOV_TOKEN_MAX_SUPPLY` to use `TOKEN_SCALE_18`

**C) lib-identity/src/constants.rs** — Widen SOV amounts:
- `SOV_ATOMIC_UNITS: u128 = 1_000_000_000_000_000_000` (was u64 = 100_000_000)
- Update `SOV_WELCOME_BONUS`, `SOV_UBI_MONTHLY` to u128 math

**D) lib-blockchain/src/contracts/tokens/core.rs** — Widen TokenContract:
- `balances: HashMap<PublicKey, u64>` -> `u128`
- `total_supply: u64` -> `u128`
- `max_supply: u64` -> `u128`
- `locked_balances`, `allowances` -> `u128`

**E) Fix all callers** — Ripple u128 through:
- `lib-blockchain/src/blockchain/contracts.rs` (balance_of, mint, transfer)
- `lib-blockchain/src/execution/executor.rs` (token creation, generic transfers)
- `zhtp/src/api/handlers/token/mod.rs` (API responses)
- `lib-blockchain/src/blockchain/persistence.rs` (bump storage version)
- All tests

**F) Remove dead legacy pricing** — `lib-blockchain/src/contracts/bonding_curve/pricing.rs` uses 8-decimal constants. Audit and remove or route through canonical.

**Test gate**: `cargo test --workspace` passes. Bonding curve integration tests pass.

---

## Phase 1: Remove CBE from Protocol Layer

**Goal**: No `CbeToken` struct, no `cbe_token` field on Blockchain, no special CBE code paths. CBE balances go through standard `token_balances` sled tree.

### Changes

**A) Blockchain struct** (`lib-blockchain/src/blockchain.rs`):
- Remove `pub cbe_token: CbeToken` field
- Remove `pub cbe_dao_id: Option<[u8; 32]>` (move to DAO registry)
- Remove CBE account seeding/sync logic (lines 906-1001, 1049-1063)
- Remove `process_init_cbe_token_transactions()` method
- Remove `process_payroll_transactions()` CBE-specific logic

**B) Executor** (`lib-blockchain/src/execution/executor.rs`):
- Unify CBE transfer path: remove special `cbe_account_state` branch, route CBE through `apply_token_transfer()` with fee_bps=0
- Keep `apply_buy_cbe()` / `apply_sell_cbe()` but change them to use `credit_token()`/`debit_token()` on standard `token_balances` tree

**C) Storage** (`lib-blockchain/src/storage/sled_store.rs`):
- Remove `cbe_accounts` tree
- Remove `get_cbe_account_state()`, `put_cbe_account_state()`, `backfill_cbe_account_states()`

**D) Validation** (`lib-blockchain/src/transaction/validation.rs`):
- Remove special CBE balance checks
- Remove `InitCbeToken` validation (keep enum variant for repr(u8) stability)

**E) Persistence** (`lib-blockchain/src/blockchain/persistence.rs`):
- Create `BlockchainStorageV10` that omits `cbe_token` and `cbe_dao_id`

**F) Genesis** (`lib-blockchain/src/genesis/mod.rs`, `lib-blockchain/src/blockchain/init.rs`):
- Remove `CbeTokenConfig`, `initialize_cbe_genesis()`, `initialize_cbe_token_genesis()`
- Remove `[cbe_token]` section from `genesis.toml`

**G) Delete CbeToken module**:
- `lib-blockchain/src/contracts/tokens/cbe_token.rs` — delete
- `lib-economy/src/tokens/cbe_token.rs` — delete

**H) Entity registry** (`lib-blockchain/src/contracts/governance/entity_registry.rs`):
- Generalize `cbe_treasury: PublicKey` to generic for-profit treasury

**I) Oracle** (`lib-blockchain/src/oracle/mod.rs`):
- Generalize `cbe_usd_price` to generic `dao_token_prices: HashMap<[u8;32], u128>`

**Test gate**: `cargo test --workspace`. Bonding curve buy/sell works through standard token_balances.

---

## Phase 2: Event-Driven Minting

**Goal**: Implement the 20/32/48 on-ramp split, SOV minting on deposit, SOVRN audit token.

### Changes

**A) On-ramp split** (executor.rs `apply_buy_cbe`):
```
20% -> SOV treasury (held as CBE tokens)
32% -> CBE strategic reserve (locked, backs floor price)
48% -> CBE liquidity pool (accumulates toward graduation)
```
Add `liquidity_pool_balance` and `sov_treasury_cbe_balance` to `BondingCurveEconomicState`.

**B) SOV event-driven minting**:
- On every BUY_CBE: `sov_to_mint = treasury_cbe_credit * cbe_price / sov_price`
- Mint SOV via `credit_token(&sov_token_id, &treasury_address, sov_to_mint)`
- SOV genesis price = $0.10 (one-time constant)

**C) SOVRN audit token**:
- Create as non-transferable `TokenContract`
- Mint on every BUY_CBE: `sovrn_to_mint = liquidity_pool_credit * cbe_price`
- Burns at graduation

**D) Floor price formula**:
- `floor = strategic_reserve / circulating_cbe` (the 32% pool)
- Expose via API, used by sell-back redemption

**E) Payroll as on-ramp event** (Option A from spec):
- Compensation pool creation runs CBE through full on-ramp split
- Tokens go into unvested register (use `locked_balances` on TokenContract)
- ProcessPayroll moves from locked to available

**F) Graduation update**:
- AMM seeds from liquidity pool (48%) not from reserve
- SOVRN burns at graduation as proof of honest AMM price

**Test gate**: BUY_CBE produces correct 20/32/48 split. SOV mints. SOVRN tracks. Graduation works.

---

## Phase 3: Testnet Reset

**Goal**: Clean chain with replayed identities.

1. Stop all 3 validators simultaneously
2. Clear sled data: `rm -rf /opt/zhtp/data/testnet/sled` on all nodes
3. Deploy new binary to all 3 nodes
4. Start bootstrap leader (g1) — creates genesis block
5. Start g2, g3 — sync genesis
6. Replay 14 identity registrations (from genesis.toml allocations)
7. Replay 403 wallet registrations (from snapshot)
8. Do NOT replay CBE transfers (old pre-mint model)
9. Verify: SOV supply=0, CBE supply=0, bonding curve initialized, consensus holds

---

## Starting Point

**Phase 0A**: `lib-types/src/tokenomics.rs` — remove CBE constants. Smallest change that establishes the principle: CBE is not a protocol token.

## Critical Files (in order of touch)

1. `lib-types/src/tokenomics.rs` — remove CBE, keep SOV
2. `lib-blockchain/src/contracts/tokens/constants.rs` — SOV = 18
3. `lib-identity/src/constants.rs` — u128 SOV amounts
4. `lib-blockchain/src/contracts/tokens/core.rs` — u64->u128
5. `lib-blockchain/src/contracts/tokens/cbe_token.rs` — delete (Phase 1)
6. `lib-blockchain/src/blockchain.rs` — remove cbe_token field (Phase 1)
7. `lib-blockchain/src/execution/executor.rs` — unify CBE path, implement split (Phase 1+2)
8. `lib-blockchain/src/storage/sled_store.rs` — remove cbe_accounts tree (Phase 1)

## Verification

- `cargo test --workspace` after each phase
- Bonding curve integration tests specifically after Phase 0 and 1
- Local 3-node testnet before production deploy
- Smoke test: identity registration, wallet creation, BUY_CBE, check 20/32/48 split
