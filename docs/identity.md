# ZHTP Identity Architecture - Single Root Invariant

## Core Invariant (LOCKED)

ZHTP has **one and only one cryptographic root**:

```
ZhtpIdentity.wallet_master_seed: [u8; 64]
```

### Derived Values (Not Roots)
All other identity material is **derived** from the single root with domain separation:

- **DID**: `derive_did_from_seed(wallet_master_seed)`
- **ZK Identity Secret**: `derive_zk_secret_from_seed(wallet_master_seed)`
- **Wallet Master Seed**: `derive_wallet_seed_from_seed(wallet_master_seed)`

### Recovery Material (UX, Not Cryptographic Root)

Recovery phrases exist **only to reconstruct the wallet_master_seed** during account recovery.

Recovery material is **UX data, not identity**. It must never contain:
- Signing material
- Secondary cryptographic roots
- Any value used for operations other than seed reconstruction

## Why This Matters

If a "seed-like" field exists and is initialized to zeros (or any deterministic value):

**Either:**
1. It's used for cryptographic operations → **silent collisions and invalid signatures**
2. It's not used → **dead code and design confusion**

Both outcomes create **non-local failures**: verification mismatches, ownership checks failing, inconsistent signatures across restarts.

These failures surface as random bugs in downstream systems (domain registration, Web4 operations, keystore persistence).

## Rules (Enforceable by Type)

1. `ZhtpIdentity` must not import any recovery modules
2. Recovery code lives in separate module (`identity::recovery`)
3. Only allowed recovery entry point: `recover_identity_from_recovery_data(IdentityRecoveryData) -> ZhtpIdentity`
4. Recovery reconstruction is **one-way only** (no back-channel to expose seed)
5. Any field named `seed` must either:
   - Be the root (`wallet_master_seed`)
   - Not exist
   - There is no third option

## Lifecycle

### Identity Creation
```
generate wallet_master_seed [u8; 64]
  ↓
create ZhtpIdentity with wallet_master_seed
  ↓
optionally: export recovery phrases (user consent)
  ↓
persist: encrypted wallet_master_seed (HSM/OS keystore)
persist: optionally encrypted IdentityRecoveryData (if user opts in)
```

### Identity Recovery
```
user provides recovery phrases
  ↓
BIP-39 decode
  ↓
PBKDF (memory-hard)
  ↓
wallet_master_seed [u8; 64]
  ↓
create ZhtpIdentity
  ↓
verify DID matches (proof of correct recovery)
```

### Identity Verification
```
signature operation: sign with private key derived from wallet_master_seed
  ↓
verification: verify against public key derived from wallet_master_seed
  ↓
deterministic result (no ambiguity, no zero-seed collisions)
```

## Non-Compliance Indicators

If you see:
- `[0u8; 32]` or any hardcoded seed value
- A `seed` field that is initialized but never used
- Multiple paths that construct identity without going through canonical root
- Recovery material passed into signing/verification logic
- A "PrivateIdentityData" that contains more than recovery phrases

**These are bugs. Report them.**
