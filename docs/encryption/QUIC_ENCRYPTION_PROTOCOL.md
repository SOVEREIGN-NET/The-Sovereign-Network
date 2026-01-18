# QUIC Encryption Protocol (Alpha)

Status: QUIC is transport-only for alpha.

## Scope
- QUIC provides transport security and reliability only.
- Identity, authentication, and post-quantum key agreement are handled by UHP v2.

## Cryptographic Invariants
- UHP v2 is the only handshake.
- Post-quantum algorithms: Kyber1024 + Dilithium5.
- Session key derivation is based on the UHP v2 transcript hash.
- No legacy or downgrade paths.

## Transcript Hash
The cryptographic transcript is defined by UHP v2 only:
- ClientHello (version, capabilities, PQ public keys)
- ServerHello (selected params, server PQ public keys)
- Kyber encapsulation/decapsulation messages
- Dilithium signatures over the transcript so far
- Final handshake confirmation

`handshake_hash = HASH(transcript_bytes)` is used as the HKDF salt, session binding, and audit artifact.

## Notes
- QUIC TLS uses the system TLS stack (rustls or platform TLS).
- QUIC does not negotiate Kyber and does not participate in identity or key agreement.
