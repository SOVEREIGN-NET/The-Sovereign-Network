# Phase 4 Issue: UDP-Based Subsystems Get Explicit Status

## Goal
Make UDP dependencies explicit; QUIC-only build can run without DHT/ZDNS unless explicitly enabled.

## Scope
4.1 DHT
- If required: plan rewrite to "DHT over QUIC streams" (or QUIC-native overlay).
- If not required for alpha: feature-gate or disable by default.

4.2 ZDNS
- Either rewrite transport to QUIC or feature-gate and disable by default.

## Acceptance Test
- Default build can run without DHT/ZDNS and still does QUIC mesh + discovery.
