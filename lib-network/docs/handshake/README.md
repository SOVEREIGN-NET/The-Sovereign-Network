# Handshake (UHP/2.0)

## Purpose
UHP/2.0 defines the only boundary where a transport connection becomes a verified
peer identity. Discovery and transport do not grant trust.

## Trust Boundary
- Before handshake: peer is anonymous and hostile.
- After handshake: peer is verified and granted minimal authority only.

## Required Bindings
The signature must cover all of the following:
- Network identifier (domain separation)
- Protocol identifier + version
- Declared role (client/server/router/etc.)
- Purpose string (e.g. "zhtp-node-handshake")
- Channel binding (QUIC/TLS exporter)
- Nonce (and optional timestamp)

## Capability Rules
- Capabilities are trusted only if asserted inside the handshake.
- Required capabilities (e.g. "quic") are hard failures if missing.
- No silent downgrade or fallback.

## Discovery Integration
Discovery is hint-only:
- No state mutation before handshake completes.
- No identity inferred from IP, port, or discovery metadata.
- Discovery results must flow into the handshake, not around it.

## Failure Semantics
- Fail closed on any parse/verify error.
- Error responses must not reveal which invariant failed.

## Security Invariants (Checklist)
- Transport irrelevance (no pre-handshake trust)
- Explicit identity proof (signature under claimed key)
- Domain separation (network + protocol + purpose)
- Role binding (client/server/router/etc.)
- Channel binding (QUIC/TLS exporter)
- Anti-replay (nonce, optional timestamp)
- Capability assertions (no inference)
- Minimal authority after verification
