# ADR-0004: Root-Key-Anchored DID (Identity Invariant Revision)

## Date
2026-02-07

## Status
Accepted

## Context

The system previously relied on a seed-anchored DID model (ADR-0001) due to limitations in some PQC libraries (non-seeded key generation). Over time, multiple implementations diverged and identity recovery became unreliable because different keypairs (and thus different DIDs) were produced from the same recovery phrase across client/server paths.

We are intentionally taking a breaking change to re-establish a single, enforceable invariant:

- The DID is anchored to a **root public signing key**.
- The DID MUST NOT be derived from raw seed/entropy bytes.
- All other keys are operational capabilities bound under the DID and can rotate independently.

## Decision

### 1. Identity Primitives

1. **Recovery Entropy (RE32)**:
   - 32 bytes random, mnemonic-encodable (e.g. 24-word phrase).
   - Used only to recover the Root Secret deterministically.

2. **Root Secret (RS64)**:
   - 64 bytes, high-entropy secret used exclusively as a derivation root.
   - RS MUST NEVER be directly encoded, hashed, or embedded in the DID.

3. **Root Signing Key (RSK)**:
   - Deterministic Dilithium5 signature keypair derived from RS using a domain-separated KDF.

4. **Decentralized Identifier (DID)**:
   - Deterministically derived from the Root Signing public key.

### 2. Canonical Derivations

```text
RE32 (32 bytes)
  -> RS64 = HKDF(RE32, info="zhtp:root-secret:v1", out=64)

RS64
  -> RSKSeed32 = HKDF(RS64, info="zhtp:root-signing-seed:v1", out=32)
  -> RSK = Dilithium5.KeyGen(RSKSeed32)

DID = "did:zhtp:" + hex(Blake3(RSK.public))
```

### 3. Key Hierarchy

- **Root Signing Key** anchors the identity and authorizes updates.
- **Operational Keys** (signing, KEM, transport, storage, device auth, governance, etc.) are:
  - derived from RS with strict domain separation, or
  - randomly generated and bound under the DID via a signed DID Document update.

Keys of different purposes MUST NOT be reused.

### 4. Rotation and Recovery

- Operational keys MAY rotate without changing the DID.
- Root Signing Key rotation is possible only via an explicit, method-defined recovery mechanism or authorized update chain.

### 5. Migration Strategy (Seed-Only Re-Registration)

For a small set of trusted users with broken DIDs:

- The server exposes a one-time `/api/v1/identity/migrate` flow.
- The client derives the **new** root signing key from the recovery phrase and signs the migration payload.
- The server transfers `display_name` and wallets to the new DID exactly once and permanently marks the old identity as migrated.

## Consequences

### Positive
- One enforceable anchor: DID is a function of a single public key.
- Consistent client/server recovery and DID derivation.
- Cryptographic agility: operational keys can change without identity churn.

### Negative
- Breaking change for any system assuming seed-hash-based DIDs.
- Requires a controlled migration flow for existing broken identities.

