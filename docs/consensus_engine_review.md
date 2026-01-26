# Consensus Engine Review (Architecture)

File reviewed: `lib-consensus/src/engines/consensus_engine.rs`

## Scope
This document summarizes architectural issues in the consensus engine implementation after the security fixes were applied. It focuses on maintainability, separation of concerns, and auditability. No code changes are proposed in this document, only issues and improvement areas.

## Architectural / Maintainability Issues

1) Single file combines too many domains
- Consensus logic, network I/O, proof creation, DAO, reward calculation, liveness monitoring, and tests are all in one 4k LOC file.
- This increases audit cost and makes correctness reasoning fragile.
- Location: `lib-consensus/src/engines/consensus_engine.rs:174`

2) Tests in the production module
- Unit tests live in the same file as production code, inflating file size and mixing concerns.
- Location: `lib-consensus/src/engines/consensus_engine.rs:2664`

3) Demo/stub logic in core paths
- Example proof generation and demo-only flows are embedded in production paths rather than behind explicit dev flags or interfaces.
- Risk: behavior variance across environments; harder to reason about production semantics.
- Locations: `lib-consensus/src/engines/consensus_engine.rs:808`

## Testing Gaps (Architecture-Focused)
- No tests enforcing module boundaries or side-effect isolation (consensus logic independent of network/DAO/rewards).
- No tests for file-splitting or ownership boundaries once the module is split.

## Suggested Refactor Direction (no code changes here)
- Split into modules: `state_machine.rs`, `validation.rs`, `storage.rs`, `network.rs`, `liveness.rs`, `proofs.rs`, and `tests/consensus_engine.rs`.
- Enforce a boundary between deterministic consensus state machine and side-effect services (DAO, broadcaster, rewards).
- Make the “demo” implementations explicit via a feature flag or test-only plumbing.
