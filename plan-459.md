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

- [ ] Phase 3 — Wire workspace dependencies
  - [ ] Update root `Cargo.toml` to include `lib-types` (first).
  - [ ] Add `lib-types` dependency to `lib-network`, `lib-storage`, and other consumers.
  - [ ] Confirm `lib-types` has no internal crate dependencies.

- [ ] Phase 4 — Migrate NodeId/DHT/chunk uses
  - [ ] Replace imports of moved types to use `lib_types::{...}` across crates.
  - [ ] Remove moved definitions from `lib-storage` and adjust re-exports.
  - [ ] Update `lib-network` re-exports/imports to rely on `lib-types` (or consumers import directly).
  - [ ] Keep lib-types behavior-free (no new logic added).

- [ ] Phase 5 — Enable lib-storage → lib-network
  - [ ] Add `lib-network` dependency back into `lib-storage`.
  - [ ] Validate public API and call sites that rely on peer registry access.

- [ ] Phase 6 — Clean-up & verification
  - [ ] Run `cargo check --workspace` (plus package-level checks for network/storage).
  - [ ] Run `cargo test --workspace` (or targeted suites if needed).
  - [ ] Grep for stale imports to ensure old paths removed.
  - [ ] Final sanity: `lib-types/README.md` matches rules; public surface stable.
