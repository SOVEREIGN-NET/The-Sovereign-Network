# MessagePack Compression Fixtures

Generated from existing Sovereign Network test fixtures for compression benchmarking.

## Files

- blockchain_transactions.msgpack — 1749085 bytes — source: blockchain_transactions.json
- network_mesh_messages.msgpack — 189357 bytes — source: network_mesh_messages.json
- governance_proposals.msgpack — 114446 bytes — source: governance_proposals.json
- witness_metadata.msgpack — 259731 bytes — source: witness_metadata.json
- token_economics.msgpack — 93292 bytes — source: token_economics.json
- identity_records.msgpack — 173894 bytes — source: identity_records.json
- mixed_workload.msgpack — 391366 bytes — source: synthetic mixed workload

## Notes

- Each `.msgpack` file contains a top-level envelope with `dataset`, `encoding`, `generated_at`, `source`, and `payload`.
- `mixed_workload.msgpack` combines slices of multiple Sovereign datasets to stress nested MessagePack structures.
