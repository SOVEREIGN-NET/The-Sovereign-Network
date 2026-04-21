# Block Sync Wire Compatibility V1

Status: Proposed  
Owners: Runtime + API + Blockchain  
Scope: Observer and bootstrap sync paths only (no validator consensus logic changes)

## 1. Problem Statement

Mac observer nodes connect and authenticate to bootstrap peers, but fail while deserializing `/api/v1/blockchain/blocks/{start}/{end}` responses.

Observed error:

- `invalid value: integer 4952893, expected variant index 0 <= i < 48`

The failure happens after successful QUIC/UHP authentication and while decoding a valid-looking bincode block page payload.

## 2. Evidence (Current Code + Runtime)

1. Block page endpoint serializes raw `&[Block]` with bincode:
- `zhtp/src/api/handlers/blockchain/mod.rs` (`handle_get_block_range`)

2. Observer sync decodes response body directly into `Vec<Block>`:
- `zhtp/src/runtime/components/blockchain.rs`

3. Current transaction model is V8 tagged payload:
- `lib-blockchain/src/transaction/core.rs`

4. V1-V7 transaction deserialization is intentionally unsupported in V8+:
- `lib-blockchain/src/transaction/core.rs` comments near `TX_VERSION_V8`

5. Runtime logs show schema-related warnings immediately before decode failure:
- legacy ZK proof shape warnings in `lib-proofs/src/types/zk_proof.rs`

Conclusion from evidence: this is a block transaction schema drift / wire-compat issue, not a transport failure.

## 3. Goals

1. Observer/bootstrapping nodes must sync block pages from current testnet peers.
2. Do not change validator consensus safety rules or commit logic.
3. Replace implicit bincode coupling with explicit negotiated wire versions.
4. Produce actionable errors when incompatibility remains.

## 4. Non-Goals

1. No consensus rule changes.
2. No validator voting/catch-up behavior change in this phase.
3. No retroactive rewrite of on-chain historical data.

## 5. Hard Invariants

1. Validator commit path remains byte-for-byte behavior-equivalent for accepted blocks.
2. Any observer compatibility decode path must never bypass block validation when blocks are committed to local chain state.
3. If wire version is unsupported, node must fail closed with explicit peer + version diagnostics.

## 6. Design Overview

## 6.1 Capability Negotiation (Explicit)

Add endpoint:

- `GET /api/v1/blockchain/sync-capabilities`

Response JSON:

```json
{
  "block_page_wire_versions": ["v1-bincode-raw", "v2-cbor-envelope"],
  "tx_wire_min_version": 8,
  "tx_wire_max_version": 8,
  "node_software_version": "..."
}
```

Client behavior:

1. Query capabilities before first page request.
2. Choose highest mutually supported block page wire version.
3. Pin choice for session and include it in every page request.
4. If no overlap: fail with `peer`, `local_supported`, `peer_supported`.

## 6.2 Versioned Block Page Endpoint

Keep current endpoint for backward compatibility:

- `GET /api/v1/blockchain/blocks/{start}/{end}` -> legacy behavior (`v1-bincode-raw`)

Add new endpoint:

- `GET /api/v2/blockchain/blocks/{start}/{end}`

Response is a typed envelope:

```json
{
  "wire_version": "v2-cbor-envelope",
  "block_encoding": "cbor",
  "tx_encoding": "v8-payload",
  "start": 123,
  "end": 222,
  "count": 100,
  "payload": "<bytes>"
}
```

Notes:

1. Envelope metadata is parsed first, before decoding payload.
2. Payload format is self-described by envelope fields.
3. Integrity fields (optional in v1 of this spec): `payload_hash`, `schema_id`.

## 6.3 Observer Compatibility Adapter (Scoped)

Introduce an observer-only adapter that can ingest legacy page formats into an intermediate model, then normalize into current `Block` shape for validation/import.

Key constraint:

1. Adapter is only invoked from observer/bootstrap sync components.
2. Consensus validator path is unchanged.

Recommended internal shape:

- `enum SyncBlockPage { V1Raw(Vec<Block>), V2Envelope(BlockPageEnvelopeV2), LegacyVx(LegacyBlockPage) }`

Normalization contract:

1. Every normalized block must pass existing block validation checks before persistence.
2. Unknown legacy transaction variant -> deterministic `IncompatibleLegacyTx` error with tx index + block height.
3. No silent dropping of transactions.

## 6.4 Error Model (Operator-Visible)

Standardize sync decode errors:

1. `UnsupportedPeerWireVersion`
2. `LegacyTxVariantUnsupported`
3. `BlockPageEnvelopeMalformed`
4. `PayloadDecodeFailed`

Every error log must include:

- peer address
- endpoint
- selected wire version
- start/end height
- first bytes hash/prefix

## 7. Rollout Plan

Phase 0 (instrumentation only):

1. Add sync capability endpoint.
2. Add wire-version negotiation logs and counters.
3. Keep existing page decode path active.

Phase 1 (dual-stack):

1. Add `/api/v2/blockchain/blocks/...` envelope endpoint.
2. Observers prefer v2, fallback to v1 only if peer lacks v2.
3. Record per-peer version usage metrics.

Phase 2 (strictness):

1. Disable implicit raw v1 fallback by default in new releases.
2. Keep explicit config flag for temporary fallback during migration window.

Phase 3 (deprecation):

1. Announce cutoff date for v1 raw page support.
2. Remove fallback after all validators/bootstraps report v2 capability.

## 8. Validation Plan

## 8.1 Unit Tests

1. Capability negotiation chooses highest mutual version.
2. Unsupported intersection produces deterministic error.
3. Envelope parser rejects malformed/partial metadata.
4. Legacy adapter rejects unknown tx variants with exact location metadata.

## 8.2 Integration Tests

1. Observer (new binary) syncing from v1-only peer.
2. Observer syncing from v2-capable peer.
3. Mixed peer list (v1 + v2) with deterministic selection and retry behavior.
4. Regression: validator consensus commit path unchanged (golden behavior test).

## 8.3 Field Verification

1. Start mac observer against current bootstrap peers.
2. Confirm negotiated version in logs.
3. Confirm height advances beyond previous stall point.
4. Confirm no repeated `expected variant index 0 <= i < 48` decode loop.

## 9. Risks and Mitigations

Risk: dual-stack complexity during migration.  
Mitigation: keep adapter scope narrow (observer/bootstrap only), add metrics and kill-switch.

Risk: silent semantic drift in normalized legacy transactions.  
Mitigation: fail closed on unknown legacy fields/variants; no best-effort partial mapping.

Risk: accidental consensus-path contamination.  
Mitigation: separate modules and compile-time boundaries for sync adapter vs consensus apply path.

## 10. Acceptance Criteria

1. A mac observer on current branch syncs from testnet bootstrap peers without deserialization loop.
2. Validator commit and consensus behavior are unchanged.
3. Incompatibility scenarios produce explicit negotiated-version errors, not opaque bincode enum panics.
4. Metrics expose per-peer wire version and decode failures.

