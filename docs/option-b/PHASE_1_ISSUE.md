# Phase 1 Issue: Remove TCP from Bootstrap Gatekeepers (or Hard-Gate It)

## Goal
Default build boots over QUIC without any TCP capability requirements.

## Scope
1.1 Gate TCP bootstrap handshake path
- Change lib-network/src/bootstrap/handshake.rs
  - If QUIC bootstrap exists, make it the default.
  - Wrap with_required_capabilities(["tcp"]) and the TCP UHP adapter behind #[cfg(feature = "legacy_tcp")].
  - If feature is off, compilation should not include TCP bootstrap types.

1.2 Gate TCP protocol selection in peer discovery
- Change lib-network/src/bootstrap/peer_discovery.rs
  - Remove "select TCP" logic as the default.
  - If kept, only compile it under legacy_tcp.
  - Ensure peer discovery can return QUIC candidates even if TCP code is absent.

## Acceptance Test
- Build with default features: QUIC-only node can bootstrap; no code path demands TCP capability.
