# Phase 2 Issue: Kill TCP Preference in Routing and Type-Level Defaults

## Goal
Default build cannot select TCP for payload routing.

## Scope
2.1 Make QUIC highest priority everywhere
- Change lib-network/src/routing/message_routing.rs
  - Default must be QUIC, not TCP.
  - Priority list: QUIC > (optional UDP discovery-only, not for payload) > legacy TCP.

2.2 Stop prioritizing TCP/UDP in sync coordinator
- Change lib-network/src/blockchain_sync/sync_coordinator.rs
  - If sync uses transport, make it QUIC-only.
  - If legacy, gate coordinator behind a legacy_sync feature until rewritten.

2.3 Reduce protocol surface area in types (without huge churn)
- Change lib-network/src/protocols/mod.rs
  - Keep NetworkProtocol::TCP/UDP only if legacy_tcp/legacy_udp_payload is enabled.
  - Otherwise, compile-time remove them or make them unreachable.
- Change lib-network/src/types/node_address.rs
  - Keep TCP/UDP address variants only behind legacy features.
  - Or introduce NodeAddress::Quic(SocketAddr) as the only non-legacy payload address.
  - Keep discovery addresses separate (do not reuse payload address for discovery signaling).

## Acceptance Test
- In default build, you cannot accidentally create a TCP route.
- Routing cannot choose TCP because it is not in the build or not in the priority list.
