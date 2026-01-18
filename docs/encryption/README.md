# Encryption Documentation (Alpha)

This documentation covers the alpha encryption stance.

## Summary
- QUIC is transport-only.
- UHP v2 is the only handshake.
- Post-quantum algorithms: Kyber1024 + Dilithium5.
- Session keys derive from the UHP v2 transcript hash.
- No legacy or downgrade paths.
