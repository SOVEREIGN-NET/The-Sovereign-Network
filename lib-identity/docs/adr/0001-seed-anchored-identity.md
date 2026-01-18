# Architecture Decision: Seed-Anchored Identity

**Date**: 2025-11-29
**Status**: Accepted
**Context**: P1-7 Implementation - new_unified() Constructor

## Problem

Original design anchored identity on PQC keypairs:
```
seed → PQC keypair → key_id → DID → everything else
```

**Fatal flaw**: `pqcrypto-*` crates don't support seeded keypair generation.
- `dilithium2::keypair()` uses global `thread_rng()` (always random)
- No API to pass custom RNG or seed
- Same seed → **different Dilithium keypair** → **different DID** → **broken determinism**

This breaks:
- ❌ Deterministic identity recovery
- ❌ Multi-device identity sync
- ❌ Predictable DIDs, NodeIds, secrets
- ❌ Reproducible tests
- ❌ Sovereign identity model

## Decision

**Anchor identity on the seed, not on PQC keypairs.**

### New Architecture: Seed as Root of Trust

```
seed (root of trust)
 ├─ DID = did:zhtp:{Blake3(seed || "ZHTP_DID_V1")}
 ├─ IdentityId = Blake3(DID)
 ├─ zk_identity_secret = Blake3(seed || "ZHTP_ZK_SECRET_V1")
 ├─ wallet_master_seed = XOF(seed || "ZHTP_WALLET_SEED_V1") [64 bytes]
 ├─ dao_member_id = Blake3("DAO:" || DID)
 ├─ NodeIds = f(DID, device)
 └─ PQC keypairs (random, attached, rotatable)
      ├─ Dilithium2 (for signatures)
      └─ Kyber1024 (for KEM)
```

### Key Principles

1. **Seed defines identity**
   - Same seed → same DID (forever)
   - All secrets derive from seed deterministically
   - Identity survives across devices, backups, recoveries

2. **PQC keys are attachments, not anchors**
   - Generated randomly via `pqcrypto-*` APIs
   - Bound to DID via attestation/signature
   - Can be rotated, replaced, lost without breaking identity
   - Stored as credentials belonging to the DID

3. **Determinism where it matters**
   - ✅ DID (from seed)
   - ✅ All secrets (from seed)
   - ✅ NodeIds (from DID + device)
   - ✅ DAO membership (from DID)
   - ❌ PQC keypairs (random, by design)

## Implementation

### Signature
```rust
pub fn new_unified(
    identity_type: IdentityType,
    age: Option<u64>,
    jurisdiction: Option<String>,
    primary_device: &str,
    seed: Option<[u8; 64]>,  // NEW: optional seed for determinism
) -> Result<Self>
```

### Behavior
- **seed = Some(s)**: Deterministic identity (same seed → same DID/secrets)
- **seed = None**: Generate random seed via `OsRng` (new identity, exportable)

### Derivation Functions
All use domain-separated Blake3:

```rust
// DID from seed (not from PQC key_id)
fn derive_did_from_seed(seed: &[u8; 64]) -> String {
    let hash = Blake3(seed || "ZHTP_DID_V1");
    format!("did:zhtp:{}", hex::encode(hash))
}

// Secrets from seed
fn derive_zk_secret(seed: &[u8; 64]) -> [u8; 32] {
    Blake3(seed || "ZHTP_ZK_SECRET_V1")
}

fn derive_wallet_seed(seed: &[u8; 64]) -> [u8; 64] {
    Blake3_XOF(seed || "ZHTP_WALLET_SEED_V1", 64)
}
```

### PQC Key Handling
```rust
// Generate random PQC keypairs (not from seed)
let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
let (kyber_pk, kyber_sk) = kyber1024::keypair();

// Store as belonging to DID (not defining DID)
identity.public_key = PublicKey {
    dilithium_pk,
    kyber_pk,
    key_id: Blake3(dilithium_pk || kyber_pk), // For lookups only
};
```

## Consequences

### Positive
✅ **Deterministic recovery**: Same seed → same identity across devices
✅ **PQC API compatibility**: Works with current `pqcrypto-*` crates
✅ **Key rotation**: Can replace PQC keys without breaking DID
✅ **Future-proof**: Compatible with future seeded PQC (liboqs, etc.)
✅ **Testable**: Reproducible golden vectors for all derived fields
✅ **Clean separation**: Identity (seed-based) vs. Transport (PQC-based)

### Tradeoffs
⚠️ **PQC keys not deterministic**: Must be backed up separately
⚠️ **Key_id no longer defines DID**: Breaking change from old model

### Migration Path
- Old identities: `DID = did:zhtp:{key_id}` (from PQC)
- New identities: `DID = did:zhtp:{Blake3(seed)}` (from seed)
- Both can coexist with version markers

## Alternatives Considered

### Option 1: Accept broken determinism
**Rejected**: Defeats sovereign identity purpose

### Option 2: Switch to liboqs-rust immediately
**Deferred**:
- Large refactor, more dependencies
- PQC ecosystem still evolving
- Can adopt later without breaking this architecture

### Option 3: Seed-anchored identity (CHOSEN)
**Rationale**:
- Solves determinism without fighting PQC APIs
- Matches industry patterns (Signal, Tor, EUDI, Bitcoin HD)
- Enables recovery, multi-device, and testing
- Future-compatible with better PQC libraries

## References

- Issue #10: Update new_unified() Constructor
- P1-6: Cryptographic Derivation Functions
- ARCHITECTURE_CONSOLIDATION.md: Identity field specifications
- Similar patterns:
  - Signal: Seed → Identity Key (Ed25519) + Prekeys (random)
  - Tor: Seed → Ed25519 identity + Random circuit keys
  - Bitcoin HD Wallets: Seed → All keys via BIP32/44
  - EUDI Wallet: Seed + KDF → All credentials

## Status

**Accepted and implemented in P1-7.**

---

*This decision log captures the pivot from PQC-anchored to seed-anchored identity architecture, ensuring deterministic sovereign identity with current PQC library constraints.*
