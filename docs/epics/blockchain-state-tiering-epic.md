# EPIC — Blockchain State Tiering (`Blockchain` struct → hot working set + `BlockchainStore`)

**Status:** Approved — open questions resolved & decisions locked 2026-05-19; Phase 1 gated on PR #2589
**Owner:** TBD
**Date:** 2026-05-19
**Companion work:** PR #2589 (`storage_atomic_commit` — WAL crash-atomic block commits). Phase 1 of this epic supersedes and simplifies the `PendingBatch`/WAL structure introduced there; sequence accordingly.

**Decision context:** `Blockchain` (`lib-blockchain/src/blockchain.rs:114`) is an ~80-field monolithic in-memory database. It holds the chain-tip working set *and* all history — every block, every transaction receipt, per-height UTXO and contract-state snapshots, the fork audit trail, and economic event logs. The whole struct is cloned, `bincode`-serialized, and held under one `Arc<RwLock<>>`. Memory grows unbounded with chain length; a clone or save touches the entire history. This epic separates the **hot working set** (state needed to validate block `H+1`) from **cold state** (history / receipts / snapshots / archival blocks) and moves the cold tier behind `BlockchainStore`.

---

## Outcome (Definition of Done)

When this epic ships:

1. **`Blockchain` holds only the hot working set** — the indexes required to validate and apply the next block. Memory footprint is bounded by *state size*, not *chain length*.
2. **Cold state lives behind `BlockchainStore`** — receipts, `contract_state_history`, `utxo_snapshots`, `fork_points`, `economics_transactions`, and archival blocks are read through the store, not held in the struct.
3. **A generic `Table<K, V>` abstraction exists** — adding a persisted dataset is one `impl Table` declaration, not a `get/put/delete/iter` method quadruple plus wiring in six places.
4. **`PendingBatch` / WAL is table-driven** — the 24 hand-listed fields, the 24-arm `tree_by_name` match, and the per-tree `to_wal_record` lines collapse to iteration over a registry.
5. **Block access is a hot-window cache + store-backed cold reads** — recent blocks stay in memory; older blocks come from the store. Tip and recent-block access stay effectively infallible on consensus hot paths.
6. **No `bincode(Blockchain)` whole-history serialization on the live path** — the deprecated `.dat` format is drained into the store on load and retired.

---

## Principle: what is "hot" vs "cold"

> **Hot** = state read or mutated while validating/applying block `H+1`. **Cold** = historical, audit, or snapshot data read only by queries, recovery, or export.

| Tier | Fields (representative) | Rationale |
|---|---|---|
| **Hot — stays in `Blockchain`** | `height`, `total_work`, `difficulty*`, `tx_fee_config*`; `utxo_set`, `nullifier_set`, `pending_transactions`; all registries (`identity_*`, `wallet_*`, `validator_*`, `gateway_*`, `token_contracts`, `web4_contracts`, `nft_collections`, `domain_registry`, `dao_registry_index`, `credential_registry`, `did_to_username`, `token_nonces`, `ubi_*`, `observer_registry`, `welfare_services`, `bonding_curve_registry`, `amm_pools`, `contract_states`); DAO/treasury/governance state incl. `executed_dao_proposals`; `oracle_state`, `exchange_state`, `onramp_state`, `token_pricing_state`, `fee_router`; `#[serde(skip)]` runtime handles | Needed to validate the next block, or process-local handles |
| **Cold — moves behind `BlockchainStore`** | `blocks` (archival portion), `receipts`, `contract_state_history`, `utxo_snapshots`, `fork_points`, `economics_transactions`, `oracle_slash_events`, `welfare_audit_trail`, `finalized_blocks` | History / audit / per-height snapshots; grow with chain length; never read to validate `H+1` |

**Explicitly out of scope (future, Stage 4+):** the large mutable registries (`identity_registry`, `utxo_set`, …) are *hot* but also grow unbounded. Tiering them (e.g. an LRU index over a store-backed map) is a separate epic — this one stops at history/receipts/snapshots/blocks, matching the review finding.

**Deliberately kept hot — `executed_dao_proposals`:** although bounded-ish, governance execution reads it for replay protection, execution dedup, proposal-state transitions, and treasury-action idempotency. Moving it cold now would push store reads onto the governance execution hot path and couple consensus to the store prematurely, while governance is already the most stateful and dangerous subsystem. It stays hot until governance execution semantics and the proposal lifecycle are formally modelled; only *finalized/expired* governance history moves cold later, keeping the active-proposal index hot. `finalized_blocks`, by contrast, is pure consensus-audit history (never read to validate `H+1`) and moves cold in Phase 2.

---

## Phase Map

| Phase | Theme | Shippable as |
|---|---|---|
| 0 | Design lock (this document) | — |
| 1 | Generic `Table` abstraction; migrate existing store types; collapse `PendingBatch`/WAL repetition | 1 PR |
| 2 | Cold-state offload — receipts, snapshots, histories, fork points become `Table`s; removed from `Blockchain` | 1–2 PRs |
| 3 | Archival blocks — hot-window cache + store-backed cold reads; migrate the 123 `self.blocks` sites | 2–3 PRs |
| 4 | (future, not this epic) Registry tiering | separate epic |

Phases are strictly ordered: 2 depends on 1; 3 depends on 1 (and is independent of 2).

---

# Phase 0 — Decisions & Setup

## BST-001 · Lock the design

This document. Sign-off required before Phase 1 code.

## BST-002 · `store` becomes mandatory for cold access

Today `Blockchain.store: Option<Arc<dyn BlockchainStore>>`. Cold-state reads cannot be `Option`-gated on a hot path. Decision: cold-state accessors require a store; constructors that build a store-less `Blockchain` (`new_runtime_state`, test fixtures) either (a) attach an in-memory `SledStore` (`open_temporary`) by default, or (b) the cold accessors return a typed "no store" error. Phase 1 picks (a) — every `Blockchain` gets a store. Recorded as **AD-005**.

---

# Phase 1 — Generic `Table` abstraction

The current `BlockchainStore` is a fat trait: one `get_X`/`put_X`/`delete_X`/`iter_X` quadruple per dataset, each wired into a `SledStore` tree field, `from_db`, the 24-field `PendingBatch`, the 24-arm `tree_by_name`, `to_wal_record`, and `apply_post_image`. Adding a dataset means writing that boilerplate ~6 times. Phase 1 removes the multiplier.

## BST-101 · Introduce the `Table` trait

```rust
/// A typed, transactional key→value dataset backed by one storage keyspace.
pub trait Table {
    /// Stable on-disk keyspace name (sled tree). Protocol — never changes.
    const NAME: &'static str;
    /// Schema version of `Value`. Bumped on any incompatible change; drives
    /// the startup migration registry (BST-104 / AD-009).
    const VERSION: u32;
    type Key: AsKeyBytes;
    type Value: Serialize + DeserializeOwned;
}
```

Generic, written once on `BlockchainStore`:
`get<T: Table>(&T::Key) -> StorageResult<Option<T::Value>>`,
`stage<T: Table>(batch, &T::Key, &T::Value)`, `stage_delete<T: Table>(batch, &T::Key)`,
`iter<T: Table>() -> impl Iterator<Item = (T::Key, T::Value)>`.

## BST-102 · Migrate existing datasets to `Table` declarations

UTXOs, token contracts/supply, identities, wallet projections, pending transactions, observer records, etc. each become a zero-sized `struct XTable; impl Table for XTable`. The bespoke `get_utxo`/`put_utxo`/… methods are deleted or become thin shims during migration, then removed. Bespoke non-KV methods (UTXO Merkle root/proof) stay as-is.

## BST-103 · Make `PendingBatch` and the WAL table-driven

`PendingBatch` becomes `BTreeMap<&'static str, TreeBatch>` (tree name → ops). `commit_block`, `to_wal_record`, `apply_post_image`, and `tree_by_name` iterate the map — the 24 hand-listed fields, the 24 `add(...)` lines, and the 24-arm match all collapse. New tables require **no** edits to the WAL path. This directly simplifies the code added in PR #2589.

## BST-104 · Table schema versioning + startup migration registry

Removing `bincode(Blockchain)` (AD-006) also removes its implicit "free" whole-struct migration: once cold datasets are independent tables, each owns its own forward compatibility. Each `Table` declares `const VERSION`; a startup migration registry runs per-table upgrade hooks against on-disk data before first read and records the applied version in a `meta` key. Built **now**, while there are ~6 tables — retrofitting versioning across 50+ tables later is not viable. See AD-009.

**Exit criteria:** existing storage tests green; `BlockchainStore` trait surface reduced; adding a table touches one file; every table is version-tagged and the migration registry runs on open.

---

# Phase 2 — Cold-state offload

With `Table` in place, each cold dataset is one declaration.

## BST-201 · Receipts → `ReceiptsTable`

`receipts: HashMap<Hash, TransactionReceipt>` removed from `Blockchain`. `create_receipt` stages into the table; `get_receipt`/finality updates read/rewrite through it. ~6 call sites (`blockchain.rs:5599–5679`).

## BST-202 · Per-height snapshots — NOT naively moved (decision 2026-05-19)

`utxo_snapshots` and `contract_state_history` map each height to a **full clone** of the entire UTXO set / contract state. Moving those giant blobs behind the store as-is is explicitly **rejected** as a long-term design — it just relocates an O(state × height) footprint.

Short term: they stay in memory with the existing bounded-retention pruning (`prune_utxo_history` / `prune_contract_history`), now with an explicit size warning in `save_utxo_snapshot`. The real direction is **live state + an undo journal / checkpoints** (see Future Work), tracked as a separate epic — not a blob relocation.

## BST-203 · Audit logs & finalized-block history → tables

`fork_points` (~4 sites), `economics_transactions` (~9 sites), `finalized_blocks`, `oracle_slash_events`, and `welfare_audit_trail` become append/scan tables — they share one shape: monotonically-growing audit history. `finalized_blocks` is historical consensus-audit material — block `H+1` is validated from the tip, validator state, fork-choice, and the current finality frontier, never from ancient finalized metadata, so it belongs cold.

## BST-204 · Drain legacy `.dat` cold fields into the store on load

`load_from_file` currently rehydrates these fields into the struct. Instead, on load, drain them into the store, then leave the struct fields gone. `BlockchainStorageV3` keeps the fields for *reading* old files; `to_blockchain` writes them to the store. New saves no longer carry them.

**Exit criteria:** every Phase-2 cold field (receipts, the two per-height snapshot maps, fork points, economic log, finalized blocks, the audit logs) no longer exists on `Blockchain`; queries go through the store; `.dat` migration covered by a test.

---

# Phase 3 — Archival blocks

`blocks: Vec<Block>` has **123 call sites** and is on consensus hot paths. It is already mirrored into `BlockchainStore` (`append_block`/`get_block_by_height`), so the in-memory `Vec` is a redundant full copy.

## BST-301 · Hot-window block cache

`Blockchain` keeps a bounded window of the most recent `W` blocks in a `VecDeque<Block>`, where:

```
W = max(finality_depth * 2, MIN_WINDOW)   // MIN_WINDOW = 128
```

The size **derives from consensus rollback/finality guarantees, not an arbitrary constant** (AD-004). Older blocks are evicted; they remain in the store.

## BST-302 · Block access API

Introduce explicit accessors and migrate the 123 sites by category:

| Pattern | Today | After |
|---|---|---|
| tip | `self.blocks.last()` | `self.tip()` — always in-window, infallible |
| count | `self.blocks.len()` | `self.height + 1` |
| recent (`h ≥ height − W`) | `self.blocks[h]` | `self.recent_block(h)` — in-window, infallible |
| arbitrary historical | `self.blocks[h]` | `self.block_at(h) -> StorageResult<Option<Block>>` — window then store |
| full scan (replay/export) | `self.blocks.iter()` | `self.store.iter_blocks()` |

Consensus hot paths only ever touch tip + recent → stay infallible. Only genuine historical reads become fallible.

## BST-303 · Migrate call sites + delete the field

Convert all 123 sites, then remove `blocks: Vec<Block>` from `Blockchain`. `replay_from_store` and chain export switch to store iteration.

**Exit criteria:** `Blockchain` memory is bounded by `W` blocks + state size, independent of chain length.

---

## Architectural Decisions

- **AD-001 · Hot/cold split by next-block-validation.** A field is hot iff validating/applying block `H+1` reads or writes it. Everything else is cold.
- **AD-002 · One generic `Table` abstraction, not per-dataset trait methods.** Removes the `get/put/delete/iter`-quadruple multiplier and the six-place wiring.
- **AD-003 · `PendingBatch`/WAL is table-driven.** A name-keyed map replaces the 24 hand-listed fields and the `tree_by_name` match; new tables need no WAL edits.
- **AD-004 · Archival blocks via bounded hot-window + store cold reads.** Window `W = max(finality_depth * 2, 128)`. **Window size derives from consensus rollback/finality guarantees, not an arbitrary constant** — validation, mempool rebasing, rollback, and recovery paths routinely reach beyond strict finality depth, so the window must track `finality_depth` (the `*2` margin), and a future change (`finality_depth = 256`, optimistic-execution windows, delayed attestations, wider mesh-partition reconciliation) must not silently invalidate the cache assumption. A fixed `128` would become a latent consensus bug. Tip and recent access stay infallible; only historical reads return `Result<Option<Block>>`.
- **AD-005 · `store` is mandatory.** Every `Blockchain` carries a `BlockchainStore` (real or `open_temporary`); cold accessors do not branch on `Option`.
- **AD-006 · `.dat` is retired in this epic — store + WAL is the sole runtime authority.** The moment the WAL exists, the authoritative model is `sled + WAL`, never "`sled` + maybe `.dat` + maybe memory" — `.dat` as shadow authority cannot survive the transition. Cold fields drain into the store on load. `save_to_file` is removed from all runtime paths; new nodes never emit `.dat`. `load_from_file` survives **only** as read-only one-time migration / import / offline-recovery input — never as live persistence. No `bincode(Blockchain)` whole-history serialization remains on any live path.
- **AD-007 · Registry tiering is out of scope.** `identity_registry`, `utxo_set`, etc. are hot but unbounded; tiering them is a separate future epic.
- **AD-008 · Sequence after PR #2589.** Phase 1 rewrites the WAL `PendingBatch` structure; land #2589 first so Phase 1 *simplifies* it rather than colliding. The strict order is: (1) make commits crash-safe, (2) abstract storage, (3) move cold state, (4) shrink memory — never collapsed into one PR stream.
- **AD-009 · Tables are schema-versioned (BST-104).** Removing `bincode(Blockchain)` removes its implicit free whole-struct migration, so every table owns its forward compatibility: a `const VERSION`, optional per-table migration hooks, and a startup migration registry that upgrades on-disk data before first read. Established in Phase 1, *before* the table count grows — versioning is the difference between this storage layer being evolvable and being schema-by-copy-paste.

---

## Risks

| Risk | Mitigation |
|---|---|
| Block access becoming fallible leaks into consensus hot paths | AD-004 — window keeps tip/recent infallible; only historical reads are `Result` |
| Cold reads hitting sled add latency to queries | Cold data is query-path only, not consensus; acceptable. Window absorbs the hot case |
| Migration of existing on-disk data (`.dat` and current sled) | BST-204 drain + a migration test; sled cold tables are additive |
| Phase 1 conflicts with in-review PR #2589 | AD-008 — strict ordering; Phase 1 deletes #2589's repetition |
| 123-site `blocks` migration is large and consensus-adjacent | Phase 3 split into 2–3 PRs by call-site category (BST-302 table); each independently testable |
| Behavioral drift in receipts/snapshot semantics | Phase 2 keeps existing logic, only changes the backing store; covered by existing tests + `.dat` migration test |

---

## Sign-off — open questions resolved (2026-05-19)

1. **Hot-window size `W`** → `W = max(finality_depth * 2, 128)`. Derived from consensus guarantees, not a fixed constant — see AD-004.
2. **`executed_dao_proposals` / `finalized_blocks`** → `finalized_blocks` cold (Phase 2, BST-203); `executed_dao_proposals` stays **hot** until governance execution semantics are formally modelled — see the hot/cold note above.
3. **`.dat` format** → retired in this epic; `save_to_file` removed from runtime, `load_from_file` kept read-only for migration/import/recovery — see AD-006.

## Future work (explicitly not this epic)

Once archival blocks are cold (Phase 3), full `replay_from_store` becomes the bootstrap cost and grows with chain length — eventually multi-hour, making node bootstrap and federation nodes impractical. Before that bites, a follow-up epic must add:

- **Periodic canonical checkpoints / state snapshots** — a verifiable state root plus the serialized hot working set at epoch boundaries.
- **Fast-sync bootstrap** — new nodes load the latest checkpoint and replay only the tail, instead of replaying from genesis.
- **Pruning epochs** — bounded retention for cold tables that are pure audit history.

Also future (AD-007): tiering the large hot registries (`identity_registry`, `utxo_set`, …). Flagged here so they are designed *for*, not discovered later.

---

*This epic is not a bug fix — it converts the chain from monolithic process-state into a storage-backed blockchain architecture: composable, evolvable, and bounded in memory. The four ordered moves are: commits safe → storage abstracted → cold state moved → memory bounded.*
