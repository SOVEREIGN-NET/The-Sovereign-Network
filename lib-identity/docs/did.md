# DID (did:zhtp) and Identity Anchor

This repository uses the `did:zhtp` method.

## Invariant (ADR-0004)

The DID is anchored to a deterministic **Root Signing public key** (Dilithium5).

- The DID MUST NOT be derived directly from raw seed/entropy material.
- A high-entropy Root Secret is used only as a derivation root.
- Operational keys (transport, KEM, device auth, storage, governance, etc.) are bound under the DID and may rotate without changing the DID.

## Derivation Overview

```text
RecoveryEntropy32 (32 bytes, mnemonic-encodable)
  -> RootSecret64 = HKDF(RecoveryEntropy32, info="zhtp:root-secret:v1", out=64)

RootSecret64
  -> RootSigningSeed32 = HKDF(RootSecret64, info="zhtp:root-signing-seed:v1", out=32)
  -> RootSigningKeypair = Dilithium5.KeyGen(RootSigningSeed32)

DID = "did:zhtp:" + hex(Blake3(RootSigningPublicKey))
```

## DID Document and Operational Keys

Operational keys MUST be authorized by the active Root Signing Key (RSK), typically by signing a DID Document update that:

- lists the operational public keys
- assigns explicit purposes
- revokes/replaces keys during rotation

## Migration (Seed-Only Re-Registration)

For a small set of trusted users affected by earlier broken invariants, the server supports a one-time migration endpoint:

- `POST /api/v1/identity/migrate`

Client responsibilities:

- derive the new Root Signing Key from the recovery phrase
- sign the migration payload with the new Root Signing private key
- send the JSON body produced by `build_migrate_identity_request_json()`

Server responsibilities:

- verify signature using the new public key (proves control of recovery phrase)
- transfer `display_name` + wallets to the new DID exactly once
- permanently mark the old identity as migrated

## Legacy Documentation

Older DID documentation (including seed-anchored DID narratives and non-`did:zhtp` methods) has been archived to `docs/archive/did_legacy.md` for reference only.
