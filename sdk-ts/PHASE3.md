# SDK TS Phase 3 (Alpha)

Status update:
- QUIC is transport-only.
- UHP v2 is the only handshake model.
- Post-quantum key agreement is handled in core UHP v2, not in QUIC.

Notes:
- The previous Kyber-based QUIC handshake has been removed from sdk-ts.
- Use the Rust core implementation for UHP v2 until a TS UHP v2 client exists.
