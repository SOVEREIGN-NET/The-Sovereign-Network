# Block Sync Wire Compatibility and Migration Plan (v1)

## Purpose
This document defines the staged migration from implicit v1 raw block pages to explicit negotiated sync wire versions.

Current implementation status:
- v2 envelope wire is implemented and preferred
- explicit negotiation is implemented (`/api/v1/blockchain/sync-capabilities`)
- v1 fallback remains enabled by default
- strict mode is available via runtime flag

## Wire Versions
- `v1-bincode-raw`: legacy raw `Vec<Block>` payload (`/api/v1/blockchain/blocks/{start}/{end}`)
- `v2-cbor-envelope`: self-describing envelope (`/api/v2/blockchain/blocks/{start}/{end}`)

## Rollout Phases
1. Phase 1 (current): Dual-stack default
- Default behavior: prefer v2, fallback to v1 when capabilities are missing/unavailable.
- Goal: keep mixed fleets syncable while rolling out v2 servers.

2. Phase 2: Strict mode default
- Default behavior: require successful capability negotiation; disable implicit v1 fallback.
- v1 fallback available only via explicit opt-in.

3. Phase 3: v1 deprecation/removal
- Remove v1 fallback code paths once bootstrap fleet readiness is confirmed.
- Keep explicit failure diagnostics for incompatible peers.

## Operator Flags
- `ZHTP_SYNC_WIRE_STRICT=1`
  - Enables strict mode.
  - Disables fallback when sync-capabilities endpoint is unavailable or fails.
  - Negotiation failures return `UnsupportedPeerWireVersion`.

Examples:
```bash
# Dual-stack default (Phase 1)
zhtp --testnet --config ~/.zhtp/config.toml --data-dir ~/.zhtp

# Strict mode (Phase 2 behavior)
ZHTP_SYNC_WIRE_STRICT=1 zhtp --testnet --config ~/.zhtp/config.toml --data-dir ~/.zhtp
```

## Failure Classes and Operations Signals
Observer/bootstrap sync decode paths classify errors as:
- `UnsupportedPeerWireVersion`
- `LegacyTxVariantUnsupported`
- `BlockPageEnvelopeMalformed`
- `PayloadDecodeFailed`

Every decode failure log includes:
- peer
- endpoint/path
- selected wire version
- requested range
- payload prefix (first bytes)
- payload hash

Counters are recorded per peer/wire:
- wire selection usage
- decode failure counts by error class

## Field Verification Checklist (Mac Observer)
Use this checklist after deployment to confirm observer sync progression beyond previous stall points.

1. Build and run observer node in dev profile.
2. Confirm negotiation logs show v2 selection against upgraded peers.
3. Confirm no repeated opaque decode loops; failures must emit structured class + context.
4. If strict mode is enabled, verify peers without sync-capabilities fail with explicit `UnsupportedPeerWireVersion`.
5. Confirm observer height advances beyond prior stall height and remains stable after restart.
6. Capture logs for one full bootstrap session and archive with:
- selected wire per peer
- any decode failures and class counts
- final synced height

## Deprecation Gate (Phase 3 Entry Criteria)
Do not remove v1 support until all are true:
- bootstrap peers serving current testnet expose sync-capabilities
- no production observers depend on v1 fallback for at least one full release cycle
- strict mode validation completed on macOS observer nodes under real bootstrap traffic
