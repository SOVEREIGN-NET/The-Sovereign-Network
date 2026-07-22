# Blockchain-Authoritative Registration — Implementation Plan

Parent epic: **#1982**. Phase 1 parent: **#1984**.

Goal: committed blocks are the only authority for identity, wallet, and token
state. API/runtime may only validate and enqueue; projections update after
block processing.

## Invariants

1. No canonical identity/wallet/token mutation outside block process/commit.
2. API success does not imply finality before inclusion (`queued` vs `confirmed`).
3. One registration path: system inject → mempool → block → process_* / executor.
4. Pending registration txs are durable (sled pending tree) and reloaded on restart.
5. DHT / identity_manager / local indexes are projections, rebuildable from chain.

## Ordered work (do not skip)

| Order | Work | Issue | Status in tree (pre-cutover) |
|------:|------|-------|------------------------------|
| 0 | Audit divergence | #1983 | Done historically; residual ghost paths remain |
| 1A | `register_wallet()` enqueue-only | #1989 | **Done in tree** — enqueue only; pending occupies id |
| 1B | Identity handler: no pre-block authority | #1990 | **Done in tree** — no shadow; events + wait option |
| 1C | Peer welcome uses same path | #1991 | **Done via 1A** (no direct registry insert in quic) |
| 1D | Pending tx durability + restart gates | #1992 | **Done** (`put_pending` + recover); unit coverage exists |
| B | Kill startup SOV backfill | #1993 | **Still present** (`collect_sov_backfill_entries`) |
| 2 | Replay rebuild identity projection | #1985 | **In progress** — rebuild + telemetry + restart tests |
| 3 | Wallet sled projection | #1986 | Partial (executor put_wallet_projection) |
| 4 | DHT post-confirmation only | #1987 | Listener exists; **events never emitted** |
| 5 | Cleanup legacy fixups | #1988 | Open |

## Phase 1 cutover design (this PR series)

### 1A — `register_wallet`

- Enqueue `WalletRegistration` only (`add_system_transaction`).
- Do **not** insert `wallet_registry` / `wallet_blocks`.
- Do **not** mint SOV (genesis or otherwise). Welcome SOV = separate `TokenMint`.
- Existence checks include **pending** wallet registrations (not only sled/shadow).

Canonical wallet materialization remains in:

- `process_wallet_transactions` (in-mem registry + height index)
- executor `put_wallet_projection` (sled)

### 1B — Identity register API

- Validate proof, username, conflicts (committed **or** pending).
- Enqueue identity + wallets + welcome mint only.
- Do **not** `insert_identity_shadow` / pre-fill `identity_blocks`.
- Return `status: "queued"` + `blockchain_tx` immediately by default.
- Optional `wait_for_inclusion` (body flag): poll until DID exists from committed
  state (or timeout → still `queued` with timeout note).
- Local `identity_manager` citizen create is a **provisional cache** for wallet
  id derivation only; roll back on enqueue failure. Not chain authority.
- DHT / storage identity index writes only from post-commit projection listener.

### Event emission (unlocks 1B projections / #1987)

Publish from block processing:

- `BlockchainEvent::IdentityRegistered` in `process_identity_transactions`
- `BlockchainEvent::WalletRegistered` in `process_wallet_transactions`

### 1D — Durability

Already: `add_system_transaction` → `store.put_pending_transaction`;
`set_store` → `recover_pending_transactions_from_store`.

Add regression tests: restart before mine keeps registration txs; after commit
they are gone and state matches process_*.

### Blocker after Phase 1

#1993 — remove `collect_sov_backfill_entries` / load-time mint paths so restart
cannot invent supply.

## Rollout

1. Land Phase 1 code + unit/integration tests.
2. Deploy to GENESIS-3 only after binary includes empty-sig fix **and** this cutover.
3. Clients: treat `queued` as pending; poll `GET /identity/get/{did}` or use
   `wait_for_inclusion` for sync UX.
4. Do not wipe chain unless explicitly ordered.

## Non-goals (this plan)

- BFT redesign, new tx types, rewriting BlockExecutor.
- Making DHT authoritative.
- Patch-only “return success and hope” behavior.
