# Ticket 459 — lib-network ⟷ lib-storage circular dependency removal

Persistent implementation plan. Each phase is a review checkpoint; I will pause after completing the items in that phase. Checkboxes will be marked as work proceeds.

- [x] Phase 0 — Ground rules & inventory
  - [x] Add `lib-types/README.md` documenting guardrails (no async/tokio/networking/storage/logging/feature-flags, only serde/blake3/hex, data-only, no behavior/policy).
  - [x] Inventory current usages of `NodeId`, DHT types, and chunk types across crates to size the import migration.

- [x] Phase 1 — Scaffold lib-types crate
  - [x] Create `lib-types` crate with minimal `Cargo.toml` (serde derive, blake3, hex).
  - [x] Add `src/lib.rs` exposing modules: `node_id`, `dht::{mod.rs, types.rs, message.rs, transport.rs}`, `chunk.rs`, `errors.rs`; re-export per spec.
  - [x] Add `lib-types/README.md` capturing hard rules and stability contract.

- [x] Phase 2 — Move primitives into lib-types
  - [x] Implement `node_id.rs` exactly as specified (frozen layout, data-only).
  - [x] Implement DHT data/message/transport modules per comment (traits only; no logic).
  - [x] Implement `chunk.rs` and `errors.rs` per comment.
  - [ ] Ensure `lib-types` builds standalone.

- [x] Phase 3 — Wire workspace dependencies
  - [x] Update root `Cargo.toml` to include `lib-types` (first).
  - [x] Add `lib-types` dependency to `lib-network` and `lib-storage` (others will be added as imports migrate).
  - [x] Confirm `lib-types` has no internal crate dependencies.

- [ ] Phase 4 — Decouple lib-network from storage/chain entirely
  - [ ] Remove `lib-blockchain` and `lib-storage` dependencies from `lib-network/Cargo.toml` (no feature flags for correctness).
  - [ ] Identify all lib-blockchain/lib-storage usages in lib-network and remove or replace them with data-only outputs/events.
  - [ ] Introduce a data output enum (e.g., `NetworkOutput` / `NetworkEvent`) to signal blockchain/storage intents upward; no traits, no async in the interface.
  - [ ] Ensure `cargo check -p lib-network` succeeds with zero knowledge of storage or chain.
  - [ ] Keep lib-types behavior-free (no new logic added).

- [ ] Phase 5 — Enable lib-storage → lib-network
  - [ ] Add `lib-network` dependency back into `lib-storage`.
  - [ ] Validate public API and call sites that rely on peer registry access.
  - [ ] Replace temporary stubs (storage/blockchain/DHT) with data-only `NetworkOutput` interface before wiring back dependencies. (Required: no hidden side-effects.)
  - [ ] Blocker noted 2024-XX-XX: `lib-protocols` depends on `lib-storage`, creating a cycle (`lib-storage -> lib-protocols -> lib-network -> lib-storage`). Safest approach: gate or remove `lib-protocols` → `lib-storage` during this phase; otherwise keep `lib-network` out of `lib-storage` until integration layer is ready.

- [ ] Phase 6 — Clean-up & verification
  - [ ] Run `cargo check --workspace` (plus package-level checks for network/storage).
  - [ ] Run `cargo test --workspace` (or targeted suites if needed).
  - [ ] Grep for stale imports to ensure old paths removed.
  - [ ] Final sanity: `lib-types/README.md` matches rules; public surface stable.

# Aggressive decouple plan (lib-network protocol-only)
- [ ] Commit 1 — Dependency cut & module relocation
  - [ ] Remove `lib-blockchain` and `lib-storage` from `lib-network/Cargo.toml`.
  - [ ] Move stateful modules out of lib-network into zhtp/lib-node: `web4/**`, `dht/**`, `blockchain_sync/**`, `zdns/**`, `client/**`.
  - [ ] Strip storage/chain/DHT/Web4/sync ownership from `lib-network/src/mesh/server.rs`; leave protocol-only routing/node shell.
  - [ ] Remove or move storage/chain-dependent tests from lib-network.
  - [ ] Ensure `cargo check -p lib-network` passes with no chain/storage deps.
- [ ] Commit 2 — NetworkOutput + side-effect removal
  - [ ] Add minimal data-only `NetworkOutput` enum (with `Web4Event`, `DhtEvent`, `BlockchainEvent` as needed).
  - [ ] Replace remaining storage/chain/DHT/Web4 side effects in lib-network with emitted outputs.
  - [ ] Expose a pull/queue API for outputs; keep interfaces sync/data-only.
  - [ ] Ensure `cargo check -p lib-network` passes.
- [ ] Commit 3 — Integration dispatcher wiring (zhtp/lib-node)
  - [ ] Add integration dispatcher in zhtp/lib-node to handle `NetworkOutput` and call relocated modules (`lib-storage`, `lib-blockchain`, Web4/DHT/sync).
  - [ ] Update zhtp imports to use relocated modules (replace `lib_network::web4` etc.).
  - [ ] Wire runtime/handlers/CLI to consume outputs and invoke dispatcher.
  - [ ] Move/restore integration tests in zhtp; keep lib-network tests protocol-only.
  - [ ] Ensure `cargo check --workspace` and relevant tests pass.
