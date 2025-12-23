# Phase 3 Issue: Treat WiFi Direct as Legacy (or Re-Home It)

## Goal
Default build does not open TCP streams for WiFi Direct.

## Scope
- Decision: WiFi Direct is legacy until rewritten to carry QUIC.
- Change lib-network/src/protocols/wifi_direct.rs
- Change lib-network/src/protocols/wifi_direct_handshake.rs
  - Put behind feature = "legacy_wifi_direct" (or delete).
  - Ensure it is not a default dependency of the mesh plane.

## Acceptance Test
- Default build does not open TCP streams for WiFi Direct.
