# DAO Registry (SOV-P0-2.3)

This module implements the Phase-0 DAO Registry contract referenced by SOV-P0-2.3.

Overview
- Stores DAO metadata and addresses in a gas-efficient registry.
- Primary storage: `HashMap<[u8;32], DAOEntry>` (dao_id -> DAOEntry).
- Secondary index: `HashMap<[u8;32], [u8;32]>` (token_addr -> dao_id) for O(1) lookup by token address.

Core functions
- `register_dao(token_addr, class, metadata_hash, treasury, owner) -> DaoId`
- `get_dao(token_addr) -> DAOMetadata`
- `list_daos() -> Vec<DAOEntry>` (sorted by creation date; consider pagination for production)
- `update_metadata(dao_id, metadata_hash)` (owner-only)

Events
- `DaoRegistered` emitted when a DAO is registered
- `DaoUpdated` emitted when DAO metadata is updated

WASM
- `wasm.rs` exposes simple wrappers for WASM runtimes to call into the contract logic.

Testing
- Comprehensive unit tests are included in `src/contracts/dao_registry/tests.rs`.
- A convenience script `scripts/run_dao_registry_tests.sh` runs the tests locally.

Notes
- The registry uses deterministic `dao_id` generation via blake3 over token, owner, and timestamp.
- The contract is intentionally lightweight for Phase-0; pagination and indexed storage for large-scale registries are recommended for future improvements.

License: MIT
