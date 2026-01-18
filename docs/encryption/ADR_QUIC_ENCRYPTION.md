# ADR: QUIC Transport-Only Encryption (Alpha)

## Status
Accepted (alpha)

## Decision
QUIC is transport-only. Identity, authentication, and post-quantum key agreement are handled exclusively by UHP v2.

## Rationale
- Eliminates downgrade paths and legacy state.
- Keeps cryptographic transcript at the protocol layer, not the transport layer.
- Aligns with the alpha objective: one handshake, one session key, one derivation.

## Consequences
- QUIC TLS uses the system TLS stack only.
- No Kyber negotiation occurs at the QUIC layer.
- UHP v2 uses Kyber1024 + Dilithium5 and produces the session key.
