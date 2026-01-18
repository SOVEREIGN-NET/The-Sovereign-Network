# QUIC Encryption Guide (Alpha)

This guide documents the alpha stance: QUIC is transport-only. All cryptographic identity and post-quantum key agreement lives in UHP v2.

## Key Points
- UHP v2 is the sole handshake model.
- Kyber1024 + Dilithium5 only.
- QUIC does not participate in key agreement or identity binding.
- Transcript hash is computed from UHP v2 messages, not transport packets.

## Operational Guidance
- Use QUIC for reliable, encrypted transport.
- Perform UHP v2 handshake over the QUIC stream.
- Derive all application keys from the UHP v2 session key.
