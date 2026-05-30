# State Unification — Phase 0 Inventory & Decisions

**Tracker:** [#2645](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2645) — `arch: unify state to single source of truth`
**This document delivers:** [#2634](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2634) — Phase 0
**Status:** Draft (Phase 0, no code changes)

---

## 1. Executive summary

`lib-blockchain` carries **two parallel state representations** that are written by separate code paths and reconciled by hand on every block:

| Representation | Where | Who writes | Used by |
|---|---|---|---|
| **In-memory** | `Blockchain` god-object's `HashMap`/`Vec`/`HashSet` fields (~80 of them) | Legacy `process_*_transactions` replay path | Every external handler in `zhtp`, `zhtp-cli`, `tools` (~218 access sites, 30 files) |
| **Sled-backed** | `BlockchainStore` trait, 92 methods, backed by `SledStore` | `BlockExecutor::apply_block` → `StateMutator` (45 primitives) | A handful of read-only chain/observer paths in `zhtp/runtime/` |

The codebase **documents Sled as the authoritative source of state** ([`blockchain.rs:227-229`](../../lib-blockchain/src/blockchain.rs#L227)):

> *"Phase 2 incremental storage backend (replaces monolithic serialization). When present, this store is the authoritative source of state."*

…but no public read API actually reads from it for most data types. Handlers read in-memory HashMaps that the executor never updates, and a 100-line manual reconciliation step in `process_and_commit_block` ([`blockchain.rs:962-1160`](../../lib-blockchain/src/blockchain.rs#L962)) re-applies each block's mutations to the HashMaps so the next handler call doesn't return zeros.

The handler that reproduces the BUBL-balance-zero bug class is the consequence, not the cause. The cause is that we have two stores.

This document catalogs the pairs and classifies the read sites that need migrating before privatization (#2640) can land safely.

---

## 2. Architecture today

### The intended pipeline (clean — partially built)

```
submit_tx → mempool.admit() → block builder
            → BlockExecutor::apply_block(block)
                 ├── validate_header / validate_block_resources
                 ├── store.begin_block(h)
                 │     for tx in block:
                 │         StateView::validate_stateful(tx)     [reads store]
                 │         StateMutator::apply(tx)              [writes store]
                 ├── store.append_block(block)
                 └── store.commit_block()                       [or rollback]
```

This pipeline is fully implemented in `lib-blockchain/src/execution/` and is the only place state should be mutated by transactions.

### The pipeline as actually run

```
Blockchain::process_and_commit_block(block)  [blockchain.rs:962]
  1. refresh_executor_token_creation_fee_if_needed()
  2. apply pending oracle protocol activation     [mutates in-mem oracle_state]
  3. validate_block_cbe_graduation_gating
  4. SEED-SLED dance [blockchain.rs:999-1045]
       for each token tx:
         if sled_balance == 0 && in_mem_balance != 0:
           backfill_token_balances_from_contract     ← reconcile (1) → store
  5. BlockExecutor::apply_block(block)              ← writes STORE
  6. BACK-SYNC dance [blockchain.rs:1056-1086]
       for each touched address:
         in_mem.token_contracts.set_balance(addr, store.get_token_balance) ← (2)
  7. self.push_block_windowed(block)                ← writes in-mem `blocks`
  8. self.height += 1                               ← writes in-mem height
  9. process_validator_registration_transactions    ← in-mem validator_registry
 10. process_gateway_transactions                   ← in-mem gateway_registry
 11. process_wallet_transactions                    ← in-mem wallet_registry
 12. process_employment_contract_transactions       ← in-mem employment_registry
 13. process_domain_transactions                    ← in-mem domain_registry
 14. process_nft_transactions                       ← in-mem nft_collections
 15. inline ValidatorRegistration mutation          ← in-mem (again)
 16. adjust_difficulty                              ← in-mem difficulty
```

Steps **4 and 6 are reconciliation** between the two stores. Steps **9–15 are the legacy replay path** re-applying mutations the executor never makes to the HashMaps that handlers actually read. The honest comment at [`blockchain.rs:1093-1098`](../../lib-blockchain/src/blockchain.rs#L1093) acknowledges this:

> *"The BlockExecutor handles SledStore state but does NOT update the in-memory wallet_registry or token_contracts mints. Without this call, after a restart from an old .dat file the in-memory balance stays at 0 for wallets whose registration block was applied in executor mode — making transfers fail the mempool balance check."*

---

## 3. Duplicate-state pair catalog

For each pair: in-memory location, sled trait method, live writer (executor / StateMutator), replay writer (legacy `process_*_transactions`), which is truth, and the decision to apply during the migration.

Decision codes: **DELETE** (drop in-memory; sled is sole truth), **CACHE** (keep as `pub(crate)` private read-through cache with explicit refresh contract), **DEFER** (large refactor, not in scope of this migration).

| # | Pair | In-memory (Blockchain god-object) | Sled (BlockchainStore) | Live writer (executor) | Replay writer (legacy) | Truth | Decision |
|---|---|---|---|---|---|---|---|
| 1 | **Blocks** | `blocks: Vec<Block>` ([blockchain.rs:133](../../lib-blockchain/src/blockchain.rs#L133)) — hot window only via `push_block_windowed` | `append_block` / `get_block_by_height` / `get_block_by_hash` / `latest_height` | `BlockExecutor::apply_block` → `store.append_block` ([executor.rs:539](../../lib-blockchain/src/execution/executor.rs#L539)) | `push_block_windowed` ([blockchain.rs:1089](../../lib-blockchain/src/blockchain.rs#L1089)) | **Sled** | **CACHE** — hot window stays as read-through; introduce `iter_blocks()` as canonical full-history iter (already exists) |
| 2 | **Token balances** | `TokenContract.balances: HashMap<PublicKey, u128>` (inside `token_contracts` HashMap) | `get_token_balance` / `set_token_balance` / `backfill_token_balances_from_contract` / `force_set_token_balances` | `StateMutator::credit_token` / `debit_token` / `transfer_token` ([tx_apply.rs:138-225](../../lib-blockchain/src/execution/tx_apply.rs#L138)) | `process_token_transactions` ([blockchain/contracts.rs:128](../../lib-blockchain/src/blockchain/contracts.rs#L128)) | **Sled** | **DELETE** in-mem; introduce `Blockchain::token_balance(token, addr)` facade (sled-first) |
| 3 | **Token nonces** | `token_nonces: HashMap<([u8;32], [u8;32]), u64>` ([blockchain.rs:158-ish](../../lib-blockchain/src/blockchain.rs)) | `get_token_nonce` / `set_token_nonce` / `increment_token_nonce` | `StateMutator::increment_token_nonce` ([tx_apply.rs:230](../../lib-blockchain/src/execution/tx_apply.rs#L230)) | Inline in `process_token_transactions` | **Sled** | **DELETE** in-mem; `bc.get_token_nonce` already has sled fallback but bypassed by direct HashMap reads |
| 4 | **Validators** | `validator_registry: HashMap<String, ValidatorInfo>` ([blockchain.rs:191](../../lib-blockchain/src/blockchain.rs#L191)); + `validator_blocks: HashMap<String, u64>` index | None on `BlockchainStore` today — **gap to close** | `process_validator_registration_transactions` (writes in-mem ONLY; no sled tree) | Same | **In-mem (no sled yet)** | **DEFER then DELETE** — add sled tree first, then migrate. Consensus-critical (vote verification reads this). |
| 5 | **Identities** | `identity_registry: HashMap<String, IdentityTransactionData>` ([blockchain.rs:162](../../lib-blockchain/src/blockchain.rs#L162)) + `identity_blocks` index | `get_identity` / `put_identity` / `delete_identity` / `get_identity_by_owner` / `get_identity_metadata` (DID-hash keyed) | `StateMutator::register_identity` / `update_identity` / `revoke_identity` ([tx_apply.rs:467-574](../../lib-blockchain/src/execution/tx_apply.rs#L467)) | `process_identity_transactions` ([blockchain/identity.rs:195](../../lib-blockchain/src/blockchain/identity.rs#L195)) | **Sled** | **DELETE** in-mem; route via `Blockchain::identity_by_did(did)` (DID→hash conversion via `did_to_hash`) |
| 6 | **Wallets** | `wallet_registry: HashMap<String, WalletTransactionData>` ([blockchain.rs:166](../../lib-blockchain/src/blockchain.rs#L166)) + `wallet_blocks` index | `get_wallet_projection` / `put_wallet_projection` / `delete_wallet_projection` / `iter_wallet_projections` / `replace_wallet_projections` | — *(no `StateMutator::register_wallet`; sled trees populated only via `replace_wallet_projections` startup recovery)* | `process_wallet_transactions` ([blockchain/wallets.rs:757](../../lib-blockchain/src/blockchain/wallets.rs#L757)) | **In-mem (replay-rebuilt)** | **DEFER then DELETE** — `WalletProjection` already a sled type, but executor doesn't write it during apply_block; need executor wiring before delete |
| 7 | **Token contracts metadata** | `token_contracts: HashMap<[u8;32], TokenContract>` ([blockchain.rs:171](../../lib-blockchain/src/blockchain.rs#L171)) — name/symbol/decimals/balances combined | `get_token_contract` / `iter_token_contracts` / `put_token_contract` | `StateMutator::put_token_contract` ([tx_apply.rs:244](../../lib-blockchain/src/execution/tx_apply.rs#L244)) | `process_token_transactions` (mints/transfers) ([blockchain/contracts.rs:128](../../lib-blockchain/src/blockchain/contracts.rs#L128)) | **Sled** | **CACHE** for metadata (name/symbol); **DELETE** for balances (covered by row 2) — split the type |
| 8 | **Pending transactions / mempool** | `pending_transactions: Vec<Transaction>` ([blockchain.rs:160](../../lib-blockchain/src/blockchain.rs#L160)) | `put_pending_transaction` / `iter_pending_transactions` / `delete_pending_transaction` | — *(not consensus state, no executor writer)* | `add_pending_transaction` ([blockchain.rs:3078](../../lib-blockchain/src/blockchain.rs#L3078)) → raw `Vec::push` ([blockchain.rs:3150](../../lib-blockchain/src/blockchain.rs#L3150)) | **In-mem (sled trees exist but unused)** | **DELETE** in-mem; wire `lib_mempool::admit()` + `put_pending_transaction`. Two adjacent dead alternatives exist: `lib-blockchain/src/mempool.rs::Mempool` and `lib-mempool` crate (both 0 callers). |
| 9 | **Oracle state** | `oracle_state: OracleState` ([blockchain.rs:308](../../lib-blockchain/src/blockchain.rs#L308)) | `get_oracle_state` / `save_oracle_state` (default no-op trait methods) | Direct mutation in `process_and_commit_block` ([blockchain.rs:968-971](../../lib-blockchain/src/blockchain.rs#L968)) — pending activation applied in-mem | `process_oracle_attestation_transactions` ([blockchain/oracle.rs:533](../../lib-blockchain/src/blockchain/oracle.rs#L533)) | **In-mem (trait save is no-op for default impls)** | **CACHE** — oracle state is small, mutated outside normal tx flow; needs sled durability story + read-through cache. High-touch (55 external sites) |
| 10 | **UTXO set** | `utxo_set: HashMap<Hash, TransactionOutput>` ([blockchain.rs:156](../../lib-blockchain/src/blockchain.rs#L156)) | `get_utxo` / `put_utxo` / `delete_utxo` + Merkle leaf methods | `StateMutator::spend_utxo` / `create_utxo` / `create_utxos_with_amounts` ([tx_apply.rs:51-137](../../lib-blockchain/src/execution/tx_apply.rs#L51)) | — *(no `process_utxo_transactions` — executor or genesis only)* | **Sled** | **DELETE** in-mem; introduce `Blockchain::utxo(outpoint)` facade |
| 11 | **Nullifier set** | `nullifier_set: HashSet<Hash>` ([blockchain.rs:158](../../lib-blockchain/src/blockchain.rs#L158)) | None on `BlockchainStore` today — **gap to close** | — | Inline in `process_and_commit_block` + tx validation | **In-mem (no sled tree)** | **DEFER then DELETE** — add sled tree first; double-spend protection is consensus-critical |
| 12 | **Domain registry** | `domain_registry: HashMap<String, OnChainDomainRecord>` ([blockchain.rs:182](../../lib-blockchain/src/blockchain.rs#L182)) | None on `BlockchainStore` today — **gap to close** (sled `DomainRegistry` is a separate DHT cache, comment at L180) | — | `process_domain_transactions` ([blockchain/contracts.rs:1052](../../lib-blockchain/src/blockchain/contracts.rs#L1052)) | **In-mem (DHT is cache, not truth)** | **DEFER then DELETE** — add sled tree first |
| 13 | **NFT collections** | `nft_collections: HashMap<[u8;32], NftContract>` ([blockchain.rs:177](../../lib-blockchain/src/blockchain.rs#L177)) | None on `BlockchainStore` today — **gap to close** | — | `process_nft_transactions` ([blockchain/contracts.rs:1133](../../lib-blockchain/src/blockchain/contracts.rs#L1133)) | **In-mem (no sled tree)** | **DEFER then DELETE** |
| 14 | **Web4 contracts** | `web4_contracts: HashMap<[u8;32], Web4Contract>` ([blockchain.rs:174](../../lib-blockchain/src/blockchain.rs#L174)) | None on `BlockchainStore` today — **gap to close** | — | `process_contract_transactions` ([blockchain/contracts.rs:5](../../lib-blockchain/src/blockchain/contracts.rs#L5)) | **In-mem (no sled tree)** | **DEFER then DELETE** |
| 15 | **Gateway registry** | `gateway_registry: HashMap<String, GatewayInfo>` ([blockchain.rs:197](../../lib-blockchain/src/blockchain.rs#L197)) + `gateway_blocks` index | None on `BlockchainStore` today — **gap to close** | — | `process_gateway_transactions` ([blockchain/gateways.rs:276](../../lib-blockchain/src/blockchain/gateways.rs#L276)) | **In-mem (no sled tree)** | **DEFER then DELETE** |
| 16 | **DAO registry** | `dao_registry_index: HashMap<[u8;32], DaoRegistryIndexEntry>` ([blockchain.rs:188](../../lib-blockchain/src/blockchain.rs#L188)) | `get_dao_stake` / `put_dao_stake` / `delete_dao_stake` / `iter_dao_stakes_for_dao` (stakes only — index not in store) | `StateMutator::put_dao_stake` ([tx_apply.rs:326](../../lib-blockchain/src/execution/tx_apply.rs#L326)) | `index_dao_registry_entry_from_tx` ([blockchain.rs:1109-ish](../../lib-blockchain/src/blockchain.rs#L1109)) | **Split (stakes=sled, index=in-mem)** | **CACHE** — derive index from `iter_dao_stakes_*` |
| 17 | **Credentials** | `credential_registry: HashMap<String, UserCredential>` ([blockchain.rs:226](../../lib-blockchain/src/blockchain.rs#L226)) | None on `BlockchainStore` today | — | `process_credential_transactions` ([blockchain/credentials.rs:22](../../lib-blockchain/src/blockchain/credentials.rs#L22)) | **In-mem (no sled tree)** | **DEFER then DELETE** |
| 18 | **Observer admission** | `observer_registry: HashMap<String, ObserverAdmissionRecord>` ([blockchain.rs:217](../../lib-blockchain/src/blockchain.rs#L217)) | `get_observer_record` / `put_observer_record` / `delete_observer_record` / `iter_observer_records_for_sponsor` / `get_observer_policy` / `save_observer_policy` | `StateMutator::put_observer_record` ([tx_apply.rs:354](../../lib-blockchain/src/execution/tx_apply.rs#L354)) | — *(executor path only)* | **Sled** | **DELETE** in-mem — already correctly wired through executor |
| 19 | **Welfare services + audit** | `welfare_services` / `welfare_audit_trail` / `service_performance` / `outcome_reports` | None on `BlockchainStore` today (audit trail moved partially behind store by BST-203) | — | Inline + processing methods | **In-mem (no canonical sled)** | **DEFER** — needs its own design; BST-203 was right shape but partial |
| 20 | **Treasury + governance state** | `treasury_*` / `governance_phase` / `council_members` / `voting_power_mode` / `vote_delegations` / `pending_cosigns` / `pending_vetoes` / `executed_dao_proposals` / `entity_registry` / `employment_registry` / `fee_router` / `phase_transition_config` / `emergency_*` (~30 fields) | None on `BlockchainStore` today | — | `process_entity_registry_transactions` / `process_employment_contract_transactions` + inline | **In-mem (no sled trees)** | **DEFER** — large governance domain; needs its own decomposition pass after #2641 |
| 21 | **Bonding curve / AMM** | `bonding_curve_registry` / `amm_pools` | `get_bonding_curve_token` / `put_bonding_curve_token` / `iter_bonding_curve_tokens` / `get_cbe_economic_state` / `put_cbe_economic_state` (bonding curve in sled; AMM not) | `StateMutator::put_bonding_curve_token` / `put_cbe_economic_state` | — | **Sled (bonding curve)**, **In-mem (AMM)** | **DELETE** bonding curve in-mem; **DEFER** AMM |
| 22 | **Contract code / storage** | `contract_states: HashMap<[u8;32], Vec<u8>>` ([blockchain.rs:255](../../lib-blockchain/src/blockchain.rs#L255)) + `contract_state_history` | `get_contract_code` / `put_contract_code` / `get_contract_storage` / `put_contract_storage` / `delete_contract_storage` | `StateMutator::put_contract_code` / `put_contract_storage` ([tx_apply.rs:391-411](../../lib-blockchain/src/execution/tx_apply.rs#L391)) | `process_contract_transactions` | **Sled** | **DELETE** in-mem |
| 23 | **PoUW mint index** | `pouw_mint_index: HashMap<[u8;32], Vec<PouwMintRecord>>` | None on `BlockchainStore` today | — | Inline | **In-mem (no sled)** | **CACHE** — derivable index, can be rebuilt from block scan |
| 24 | **UBI registry** | `ubi_registry: HashMap<String, UbiRegistryEntry>` + `ubi_blocks` | None on `BlockchainStore` today | — | `process_ubi_claim_transactions` ([blockchain.rs:6161](../../lib-blockchain/src/blockchain.rs#L6161)) | **In-mem (no sled)** | **DEFER then DELETE** |

### Counts

- **24 duplicate-state pairs** identified (initial 7 + 17 uncovered)
- **DELETE in-mem now (sled already truth and executor-wired):** 7 pairs (rows 2, 3, 5, 7-balances, 10, 18, 21-bonding-curve, 22)
- **CACHE (keep in-mem as private read-through cache):** 4 pairs (rows 1-blocks, 7-metadata, 9-oracle, 16-DAO-index, 23-pouw-index)
- **DEFER then DELETE (sled gap to close first):** 8 pairs (rows 4, 6, 11, 12, 13, 14, 15, 17, 21-AMM, 24)
- **DEFER (big refactor, separate epic):** 2 pairs (rows 19-welfare, 20-treasury+governance)

The 7 immediate-DELETE rows are the right scope for the read-migration phases #2636–#2639. The CACHE and DEFER rows are documented here so they don't get lost; they become follow-up issues or feed Phase 5 (#2642).

---

## 4. Read-site classification

### 4.1 Classification framework

Every read site falls into one of four categories. The classification determines which facade method (or sled access pattern) it should migrate to.

| Class | Symptom | Target API |
|---|---|---|
| **Recent only** | Caller iterates "the last N blocks" or just needs the tip | `latest_block()` / `iter_blocks().rev().take(N)` / private hot-window cache fine |
| **Full history** | Caller iterates "all blocks ever" or scans for historical events | `iter_blocks()` (sled-backed, full chain) — never `query_blocks()` |
| **Single key lookup** | Caller does `registry.get(&key)` or `.contains_key(&key)` | Facade method, sled-first: `bc.identity_by_did(did)`, `bc.token_balance(token, addr)`, etc. |
| **Aggregate** | Caller does `.len()`, `.values()`, `.iter().filter(...)` | Sled scan via existing iter trait methods (`iter_token_contracts`, `iter_wallet_projections`, etc.) |

### 4.2 External read-site inventory (zhtp + zhtp-cli + zhtp-daemon + tools)

**228 total external direct-field-access sites across 34 files** touching the duplicate-state fields enumerated in §3. (See [§4.4](#44-read-site-fine-classification-full-table) for the per-site CSV with class + sub-issue routing.)

Ranked by access density (combined reads + writes; the Phase 0 inventory splits direction per-site in §4.4):

| Sites | File | Primary fields touched | Migration urgency |
|---:|---|---|---|
| 37 | `zhtp/src/runtime/mod.rs` | `oracle_state`, `validator_registry`, `token_contracts`, `blocks` | **Critical** — runtime entry; routes many fields |
| 31 | `zhtp/src/api/handlers/oracle/mod.rs` | `oracle_state`, `token_contracts`, `validator_registry` | **Critical** — oracle handler hot path |
| 16 | `zhtp/src/runtime/components/oracle.rs` | `oracle_state` | High |
| 15 | `zhtp/src/runtime/services/genesis_funding.rs` | `blocks[0]`, `token_contracts`, `utxo_set` | Bootstrap-only |
| 14 | `zhtp/src/runtime/components/identity.rs` | `identity_registry`, `credential_registry` | High |
| 13 | `zhtp/src/runtime/components/blockchain.rs` | `blocks` (metrics) | Low — metrics, mostly `.len()` |
| 11 | `tools/chain_audit.rs` | `identity_registry`, `blocks` | Tool — easy to migrate |
| 9 | `zhtp/src/runtime/shared_blockchain.rs` | `blocks`, `pending_transactions`, `height` | **Critical** — shared service over blockchain |
| 7 | `zhtp/src/api/handlers/web4/domains.rs` | `token_contracts`, `domain_registry` | High |
| 7 | `zhtp/src/api/handlers/identity/mod.rs` | `identity_registry`, `credential_registry` | High |
| 7 | `tools/wallet_probe.rs` | Multiple | Tool — easy to migrate |
| 6 | `zhtp/src/runtime/components/consensus.rs` | `blocks`, `validator_registry` | **Critical** — consensus path |
| 6 | `zhtp/src/api/handlers/dao/mod.rs` | `validator_registry`, `blocks` | High |
| 5 | `zhtp/src/api/handlers/credentials/mod.rs` | `credential_registry` | Medium |
| 4 | `zhtp/src/unified_server.rs` | `identity_registry`, `validator_registry`, `blocks` | Medium |
| 4 | `zhtp/src/runtime/services/mining_service.rs` | `blocks`, `pending_transactions` | High |
| 4 | `zhtp/src/api/handlers/marketplace/mod.rs` | `token_contracts` | Medium |
| 4 | `zhtp/src/api/handlers/identity/backup_recovery.rs` | `token_contracts`, `validator_registry`, `identity_registry` | Medium |
| 4 | `zhtp/src/api/handlers/credentials/opaque.rs` | `credential_registry` | Medium |
| 4 | `zhtp/src/api/handlers/blockchain/mod.rs` | `blocks` (mostly `query_blocks`) | High — directly enumerated in #2636 |
| 4 | `zhtp-cli/src/commands/genesis.rs` | `blocks`, `token_contracts` | Tool |
| 3 | `zhtp/src/monitoring/metrics.rs` | `blocks` (counts) | Low |
| 3 | `zhtp/src/api/handlers/wallet/mod.rs` | `token_contracts` (balances), `blocks` | **Critical** — primary bug surface (BUBL balance) |
| 3 | `zhtp/src/api/handlers/nft/mod.rs` | `nft_collections` | Medium |
| 2 | `zhtp/src/runtime/components/protocols.rs` | `validator_registry` | High |
| 2 | `zhtp/src/messaging/inbound_stream.rs` | `identity_registry` | Medium |
| 2 | `tools/testnet_reset.rs` | Multiple | Tool |
| 1 | `zhtp/src/runtime/validator_ip.rs` | `validator_registry` | Medium |
| 1 | `zhtp/src/messaging/handler.rs` | `identity_registry` | Medium |
| 1 | `zhtp/src/api/server.rs` | `blocks` (count) | Low |

### 4.3 Per-field external access counts

> **Corrected (CR #2657).** The first cut of this table was produced with a
> binding-prefix grep (`bc | blockchain | b | …`) that **silently excluded real
> access sites** — counts were off by 4–17×. Regenerated by matching `.<field>`
> dot-access across `zhtp/`, `zhtp-cli/`, `zhtp-daemon/`, `tools/` with **no
> binding filter**, deduping shadow-struct fields (handlers that declare their
> own `domain_registry: Arc<…>`, etc.) into a separate `binding=shadow` column
> rather than dropping them. Counts below are **Blockchain-bound** sites only.
> Comment-only mentions are excluded (so e.g. `token/mod.rs` and `principal.rs`,
> which only *name* `identity_registry` in doc comments while resolving via a
> method, are not counted as direct reads).

**340 Blockchain-bound access sites + 36 shadow-struct sites = 376 total** (vs the original 228).

| Field | Sites | Files | Sub-issue |
|---|---:|---:|---|
| `oracle_state` | 67 | 4 | DEFER (no sled durability) |
| `identity_registry` | 51 | 21 | [#2639](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2639) — **incl. 1 BLOCKING gateway-auth site** |
| `blocks` | 38 | 13 | [#2636](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2636) (incl. internal lib-blockchain scans — see CR #2659) |
| `domain_registry` | 32 | 3 | DEFER (no sled tree) |
| `wallet_registry` | 31 | 11 | [#2639*](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2639) (blocked: executor sled wiring) |
| `token_contracts` | 28 | 9 | [#2637](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2637) |
| `validator_registry` | 24 | 9 | [#2639](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2639) (consensus-critical) |
| `pending_transactions` | 22 | 10 | [#2641](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2641) |
| `utxo_set` | 19 | 6 | [#2662](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2662) (facade — type impedance) |
| `credential_registry` | 12 | 4 | DEFER (no sled tree) |
| `web4_contracts` | 10 | 2 | DEFER (no sled tree) |
| `nft_collections` | 4 | 1 | DEFER (no sled tree) |
| `gateway_registry` | 2 | 2 | DEFER (no sled tree) |
| `token_nonces` | 0 | 0 | [#2638](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2638) — all reads already use `get_token_nonce()` facade |

Class breakdown (Blockchain-bound): 169 Reference, 94 Aggregate, 37 **Mutate** (= #2640 fuel), 36 Lookup, 4 Recent.

#### ⚠️ BLOCKING site — `identity_registry`

`zhtp/src/server/quic_handler.rs:896, 1547–1572` is the **gateway-admission identity fallback**: a gateway DID not found in `gateway_registry` is allowed if it exists in `identity_registry`. If #2639 drops the in-memory `identity_registry` field before this path reads the sled-backed identity store, **gateway authentication breaks** (exactly the regression class the MEMORY.md `feedback_*` rules warn against). This site is tagged `class=blocking` in spirit and **must** migrate to `identity_consensus_by_did()` (or an equivalent sled read) within #2639 — not be left for Phase 3 privatization to discover at compile-fail time.

### 4.4 Read-site fine classification (full table)

The line-by-line classification ships as a CSV — one row per external direct-field-access site, classified and routed to its target facade method and Phase 2 sub-issue:

**Spreadsheet:** [`docs/arch/state-unification-read-sites.csv`](./state-unification-read-sites.csv) — **376 rows** (340 Blockchain-bound + 36 shadow-struct) across the external roots.

Columns: `file, line, field, class, binding, sub_issue, target_facade, snippet`. Sorted by `sub_issue` then `field` then `file:line` so each Phase 2 PR can grep its rows. The `binding` column is `blockchain` (a real `Blockchain` field access — a migration target) or `shadow` (a handler struct that declares its own field of the same name — **not** a migration target, kept for visibility so the migration doesn't accidentally edit it).

#### How the CSV was built (CR #2657 — corrected)

1. Grep every external root (`zhtp/`, `zhtp-cli/`, `zhtp-daemon/`, `tools/`) for **`.<field>`** (dot-access) for each of the 14 duplicate-state fields. **No binding-prefix filter** — the original filter (`bc | blockchain | …`) silently dropped real sites (e.g. the gateway-auth fallback in `quic_handler.rs`).
2. Exclude comment-only lines. Flag shadow-struct files in the `binding` column instead of dropping them.
3. Classify each snippet by access pattern:
   - **Aggregate** — `.iter() / .values() / .keys() / .len() / .is_empty()`
   - **Recent** — `.last() / .first() / .back() / .front()`
   - **Lookup** — `.get() / .contains() / .field[k]`
   - **Mutate** — `.insert() / .remove() / .push() / .clear() / .field = … / .get_mut() / .set()`
   - **Reference** — bare `&x.field` / `x.field.clone()` / multiline continuation (downstream behavior not classified here)

> **Line-number caveat.** Line references in this doc and the catalog (§3) were captured against an earlier checkout and drift as `development` moves (e.g. `contract_states` is now ~`blockchain.rs:255`, not `:122`). Treat them as indicative; each migration PR must re-grep its field in the current tree before editing (every Phase 2 PR so far has found multiline sites the CSV line list alone missed). The CSV is regenerated from a fresh grep, so its line numbers are current as of this PR.

#### Mutate rows are #2640 fuel

**37 Mutate**-class rows are external paths writing directly into Blockchain maps — the privatization barrier #2640 must enforce. They are not migration targets for #2636–#2639 (which migrate reads); flagged so #2640 has a candidate list. Each #2640 PR must cite the Mutate rows it deletes and prove an equivalent BlockExecutor / StateMutator path exists — if a handler is the *only* writer of a piece of state, deleting it breaks that handler.

---

## 5. Divergence detector — design spec

### 5.1 Purpose

A background harness that runs in testnet (and optionally dev nodes) to:

- Detect any case where the in-memory representation disagrees with the sled-backed truth.
- Surface the disagreement before a handler returns stale data to a user.
- Lock in the invariant once Phase 4 (#2641) is complete: zero divergence in CI.

### 5.2 Activation

| Env var | Behavior |
|---|---|
| `ZHTP_DIVERGENCE_DETECT=1` | Spawn the detector task at runtime start. No-op if unset. |
| `ZHTP_DIVERGENCE_PANIC=1` | On mismatch, panic instead of logging (testnet enforcement / CI). |
| `ZHTP_DIVERGENCE_INTERVAL_SECS=N` | Override default sampling cadence (default: 30s). |
| `ZHTP_DIVERGENCE_SAMPLE_SIZE=N` | Number of keys sampled per cycle, per field (default: 100). |

### 5.3 Location

`lib-blockchain/src/divergence_detector.rs` (new file). Spawned by the runtime when the env var is set, given a clone of the `Arc<RwLock<Blockchain>>`.

### 5.4 Detection algorithm

For each pair classified DELETE or CACHE in §3, the detector runs one cycle per interval:

1. **Snapshot** a sample of keys from the in-memory representation (e.g. random 100 keys from `token_contracts.values()`, or random 100 `(token_id, address)` pairs with non-zero in-mem balance).
2. **Read** the same keys from `BlockchainStore`.
3. **Compare**:
   - Equality of value (balance, nonce, identity record).
   - In-mem-only or sled-only existence is also a divergence.
4. **On match**: emit DEBUG-level "ok" with sample size.
5. **On mismatch**:
   - ERROR-level structured log: `divergence_detected field=token_balance key=<token>:<addr> in_mem=<v1> sled=<v2> block_height=<h>`
   - Increment `divergence_total{field="…"}` Prometheus counter.
   - If `ZHTP_DIVERGENCE_PANIC=1`: panic with the same fields in the message.

### 5.5 Sampling strategy per pair

| Pair | Key universe | Sample technique |
|---|---|---|
| Token balances | `(token_id, address)` with non-zero balance in either source | Random sample from union of both key sets |
| Token nonces | Same keying as balances | Random sample where either source ≠ 0 |
| Identities | DID hashes | Random sample of `iter_identities` ∪ `identity_registry.keys()` |
| Blocks | Heights `0..latest` | Random heights + edge cases (0, latest, latest-1) |
| Token contracts | Token IDs | Iterate union, compare metadata fields (name/symbol/decimals); balances compared via the balance check (avoid double-counting) |
| Validators / wallets / observer | Registry keys | Random sample once sled tree exists |

> **Excluded from sampling (CR #2657).** Derived in-memory indexes that sled
> never stores — `pouw_mint_index` (row 23, `#[serde(skip)]`), `dao_registry_index`
> (row 16, derived from `iter_dao_stakes_*`), and any other CACHE-classified
> field rebuilt from a primary source — **must not** be sampled. Sled holds no
> counterpart, so every comparison would report a false divergence and, under
> `ZHTP_DIVERGENCE_PANIC=1`, panic spuriously. The implemented detector
> (Phase 1) samples only the four primary pairs: token balances, token nonces,
> identities, and block hashes. Derived caches are validated indirectly — if
> their source agrees with sled, the derived index is correct by construction.

### 5.6 Output

- **Logs**: `tracing::error!` at mismatch with structured fields.
- **Metrics** (Prometheus): `divergence_total{field}` counter; `divergence_samples_total{field}` counter; `divergence_last_mismatch_height{field}` gauge.
- **CI**: A targeted scenario test in `lib-blockchain/tests/divergence_smoke.rs` runs the detector against a deterministic 100-block scenario with `ZHTP_DIVERGENCE_PANIC=1`. Fails the build on any drift.

### 5.7 Not in scope (deferred to implementation in Phase 1 / #2635)

- Continuous integration of the detector into testnet observability — the runtime wiring lands with #2635.
- Auto-remediation: the detector reports; it does not "fix" divergences. Phase 4 (#2641) eliminates the source of drift entirely.

---

## 6. Transition-window protocol (CR #2657)

While a field's read sites are being migrated, some call sites read sled-first
(via a facade) and others still read the in-memory map. **If the two stores
disagree, concurrent requests get different answers for the duration of the
window.** The Phase 1 facades are written sled-first-with-in-mem-fallback, so a
*read* divergence only surfaces if sled and in-mem actually differ — which is
exactly what the divergence detector (§5) is for. But two field classes cannot
tolerate even a transient window and need an explicit cutover discipline:

### 6.1 Field-atomic cutover (required for consensus/mempool-critical fields)

For **`validator_registry`** (consensus: vote verification, proposer selection)
and **`pending_transactions`** (mempool admission / block proposal), a mixed
read state can change *consensus outcomes*, not just an HTTP response. These
fields must be cut over **atomically within a single PR**: every read site for
the field migrates in the same change, the in-memory field is privatized in the
same change, and there is no intermediate commit where some readers see sled and
others see in-mem. If a field-atomic cut is too large for one PR, it must be
gated behind a flag that flips all readers together, never per-site.

### 6.2 Detector-gated read-order flips

Changing a facade's *internal* read order (e.g. `get_token_nonce` from
HashMap-first to sled-first) is a behavior change even though the signature is
stable. Such flips are only safe **after** the divergence detector has run a
soak proving in-mem == sled for that field, and are batched into Phase 3 (where
sled becomes authoritative), never slipped into a read-migration PR.

### 6.3 Acceptable-drift fields (explicit)

For **non-consensus, non-mempool** fields (stats endpoints, explorer reads,
metadata listings), a transient read-divergence window **is acceptable** and is
not worth a field-atomic cut. These migrate incrementally per-PR. The accepted
reasoning: a stale stats number for one block interval is not a correctness
violation; a wrong validator set is. The divergence detector still watches them
so the window is observed, not blind.

### 6.4 The BLOCKING-site rule

Any read site classified **blocking** (currently `quic_handler.rs` gateway-auth,
§4.3) must migrate *before* its field is privatized, with a test proving the
sled path returns the same admission decision. Privatization (#2640) is not
allowed to discover a blocking site at compile-fail time and "fix" it with an
expedient stub.

---

## 7. Migration order rationale

Recap of the ordering as it now relates to the catalog:

| Phase | Issue | Catalog scope |
|---|---|---|
| 0 | #2634 | **This doc + read-site CSV** — no code change |
| 1 | #2635 | Add facade methods (sled-first) for the 7 immediate-DELETE pairs + the 4 CACHE pairs. Add divergence detector. Existing handlers untouched. |
| 2a | #2636 | Migrate `blocks` read sites (#3 row 1). 22+9 sites across 8 files. |
| 2b | #2637 | Migrate `token_contracts` balance read sites (row 2 + row 7-balances). 36 sites across ~12 files. |
| 2c | #2638 | Migrate `token_nonces` (row 3). 2 sites. |
| 2d | #2639 | Migrate `validator_registry`, `identity_registry`, `wallet_registry` (rows 4, 5, 6). 60 sites across ~10 files. Consensus-critical — requires soak. |
| 3 | #2640 | Privatize the in-memory fields once external readers are migrated. Compile-fail any remaining direct access. |
| 4 | #2641 | Delete the legacy `process_*_transactions` writers. Replay rebuilds caches lazily from sled, not by re-executing. |
| 5 | #2642 | Bench-justify each remaining CACHE. Document refresh contract. |
| 6 | #2643 | Snapshot/persistence: switch to sled-derived `SnapshotDto` instead of in-mem field serialization. |
| 7 | #2644 | Doc + clippy lint forbidding `pub Vec/HashMap/BTreeMap` on `Blockchain`. CI divergence-test gate. |

---

## 8. References

- Parent tracker: [#2645](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2645)
- Phase issues: [#2634](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2634) (this doc) through [#2644](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2644)
- Key code paths cited:
  - `lib-blockchain/src/execution/` — clean architecture (BlockExecutor + StateView + StateMutator)
  - `lib-blockchain/src/storage/mod.rs` — `BlockchainStore` trait (92 methods)
  - `lib-blockchain/src/blockchain.rs:131-370` — Blockchain god-object struct (~80 fields)
  - `lib-blockchain/src/blockchain.rs:962-1160` — `process_and_commit_block` (dual-write + reconciliation)
- Parked precursor branch (do not merge): `bst-203-finalized-oracle-welfare-cold-offload` — premature execution of #2640 before the read migration. Kept as a reference; commits do not land.
