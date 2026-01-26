# Phase 5 Issue: Mesh Config Cleanup

## Goal
Config cannot imply TCP exists when it does not.

## Scope
- Change lib-network/src/mesh/config.rs
  - Remove TCP listen port from default config.
  - Introduce QUIC listen port as the primary bind.
  - If TCP exists, only under legacy feature.

## Acceptance Test
- Default config does not expose TCP listen settings.
