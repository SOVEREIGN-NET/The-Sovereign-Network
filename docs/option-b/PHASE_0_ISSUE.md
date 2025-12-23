# Phase 0 Issue: Make QUIC-Only Peers Not Fail

## Goal
Ensure QUIC-only nodes can discover peers and never assume TCP is available.

## Scope
0.1 Fix discovery advertisement (misleading today)
- Change lib-network/src/discovery/local_network.rs
  - Remove tcp from protocols list.
  - Only advertise quic (and any discovery-only tag if needed).
- Change lib-network/src/discovery/unified.rs
  - Ensure unified discovery output does not inject TCP defaults anywhere.

## Acceptance Test
- A QUIC-only node on a LAN sees peers and never learns/assumes TCP is available.

## Notes
- UDP multicast is permitted only for link-local discovery.
