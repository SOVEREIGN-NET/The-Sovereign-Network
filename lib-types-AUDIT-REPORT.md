# lib-types Deep Audit Report
## Branch: development (commit 0d7245d3)
## Date: 2026-02-28
## Scope: Type architecture compliance - are types properly centralized?

---

## Executive Summary

| Category | Count | Assessment |
|----------|-------|------------|
| Types in lib-types | ~15 | Core primitives defined |
| Duplicate type definitions | 9+ | ❌ Architecture violation |
| Missing consensus types | Many | ❌ Types scattered across crates |
| Architecture compliance | POOR | ❌ Types NOT centralized |

**Overall Assessment:** The architecture is **NOT being respected**. Types are scattered and duplicated across crates instead of being centralized in lib-types.

---

## 🔴 CRITICAL FINDINGS

### 1. NodeId Defined in TWO Places (Different Implementations!)

**Location 1:** `lib-types/src/node_id.rs` (lines 1-19)
```rust
pub struct NodeId(pub [u8; 32]);
```

**Location 2:** `lib-identity/src/types/node_id.rs` (lines 122-132)
```rust
pub struct NodeId {
    bytes: [u8; 32],
    creation_nonce: [u8; 32],
    network_genesis: [u8; 32],
}
```

**Problem:** Two different types with the same name! This causes:
- Compilation errors when both are imported
- Confusion about which to use
- Potential security issues (simple vs enhanced version)

**Impact:** HIGH - This is a fundamental type used across the entire system.

---

### 2. Core Primitive Types Duplicated

**BlockHash defined in:**
- `lib-types/src/primitives.rs` (lines 32-55)
- `lib-blockchain/src/storage/mod.rs` (duplicated!)

**TxHash defined in:**
- `lib-types/src/primitives.rs` (lines 82-105)
- `lib-blockchain/src/storage/mod.rs` (duplicated!)

**Address defined in:**
- `lib-types/src/primitives.rs` (lines 136-159)
- `lib-blockchain/src/storage/mod.rs` (duplicated!)

**TokenId defined in:**
- `lib-types/src/primitives.rs` (lines 190-216)
- `lib-blockchain/src/storage/mod.rs` (duplicated!)

**Problem:** Same types defined in multiple places. Violates DRY principle.

---

### 3. Type Aliases Redefined

**BlockHeight defined in:**
- `lib-types/src/primitives.rs` (line 19)
- `lib-blockchain/src/contracts/root_registry/types.rs` (line 1)

**Problem:** Type aliases should be defined once in lib-types.

---

### 4. PeerId Defined Outside lib-types

**Location:** `lib-storage/src/dht/transport.rs`
```rust
pub enum PeerId {
    Node(NodeId),
    Socket(SocketAddr),
}
```

**Problem:** PeerId is a core networking type but defined in lib-storage.

---

## 🟡 HIGH FINDINGS

### 5. Missing Core Consensus Types

These types should be in lib-types but are scattered:

**In lib-consensus/src/types/mod.rs:**
- `ConsensusType`
- `ValidatorStatus`
- `VoteType`
- `ConsensusStep`
- `ConsensusRound`
- `ConsensusProposal`
- `ConsensusVote`
- `SlashType`

**In lib-blockchain/src/transaction/core.rs:**
- `Transaction` (core type!)
- `TransactionInput`
- `TransactionOutput`
- `TransactionStatus` (in receipts/types.rs)

**Problem:** Core consensus and transaction types not in lib-types.

---

### 6. Missing Economic Types

**In lib-economy:**
- `TreasuryFund`
- `FeeDistribution`
- Various stats/metrics types

**Problem:** Economic primitives not centralized.

---

### 7. Missing Fee Types

**In lib-fees/src/model_v2.rs:**
- `TxKind` (transaction classification)
- `SigScheme` (signature scheme)
- `FeeInput`
- `FeeParams`

**Problem:** Fee model types not in lib-types.

---

### 8. Missing Mempool Types

**In lib-mempool:**
- `MempoolConfig`
- `MempoolState`
- `AdmitTx`
- `AdmitResult`

**Problem:** Mempool types not centralized.

---

## 🟢 POSITIVE FINDINGS

### 9. lib-types Design is Good

The types that ARE in lib-types are well-designed:
- Fixed-size arrays (no dynamic allocation)
- Deterministically serializable
- Efficient Copy and comparison
- Proper Display/Debug implementations

---

## 📊 ARCHITECTURE COMPLIANCE ANALYSIS

### Rule: "All shared types go in lib-types"

| Type | Location | Should Be In | Status |
|------|----------|--------------|--------|
| NodeId | lib-types, lib-identity | lib-identity (canonical) | ❌ DUPLICATE |
| BlockHash | lib-types, lib-blockchain | lib-types | ❌ DUPLICATE |
| TxHash | lib-types, lib-blockchain | lib-types | ❌ DUPLICATE |
| Address | lib-types, lib-blockchain | lib-types | ❌ DUPLICATE |
| TokenId | lib-types, lib-blockchain | lib-types | ❌ DUPLICATE |
| BlockHeight | lib-types, lib-blockchain | lib-types | ❌ DUPLICATE |
| PeerId | lib-storage | lib-types | ❌ WRONG LOCATION |
| Transaction | lib-blockchain | lib-types | ❌ MISSING |
| ConsensusRound | lib-consensus | lib-types | ❌ MISSING |
| ValidatorStatus | lib-consensus | lib-types | ❌ MISSING |
| TxKind | lib-fees | lib-types | ❌ MISSING |
| SigScheme | lib-fees | lib-types | ❌ MISSING |
| TreasuryFund | lib-economy | lib-types | ❌ MISSING |

---

## 🎯 RECOMMENDATIONS

### Critical Priority

1. **Merge NodeId implementations**
   - Remove simple NodeId from lib-types
   - Keep enhanced NodeId from lib-identity
   - Re-export from lib-types for convenience

2. **Remove duplicate primitives from lib-blockchain**
   - Remove BlockHash, TxHash, Address, TokenId from storage/mod.rs
   - Import from lib-types instead

3. **Move core transaction types to lib-types**
   - Move Transaction, TransactionInput, TransactionOutput
   - Move TransactionStatus

### High Priority

4. **Move consensus types to lib-types**
   - Move all consensus primitive types
   - Keep consensus logic in lib-consensus

5. **Move fee types to lib-types**
   - Move TxKind, SigScheme, FeeInput, FeeParams
   - Keep fee calculation logic in lib-fees

6. **Move economic primitives to lib-types**
   - Move TreasuryFund, FeeDistribution types
   - Keep economic logic in lib-economy

### Medium Priority

7. **Move mempool types to lib-types**
   - Move MempoolConfig, MempoolState
   - Keep mempool logic in lib-mempool

8. **Move PeerId to lib-types**
   - Relocate from lib-storage

9. **Add documentation**
   - Document the type architecture rule
   - Add contribution guidelines

---

## CORRECTED ARCHITECTURE

```
lib-types/                    <- All shared types here
├── primitives.rs             <- BlockHash, TxHash, Address, TokenId, Amount
├── node_id.rs                <- Re-export from lib-identity
├── consensus.rs              <- ConsensusRound, ValidatorStatus, VoteType, etc.
├── transaction.rs            <- Transaction, TransactionInput, TransactionOutput
├── fees.rs                   <- TxKind, SigScheme, FeeInput, FeeParams
├── economy.rs                <- TreasuryFund, economic primitives
├── mempool.rs                <- MempoolConfig, MempoolState
└── peer.rs                   <- PeerId, NodeId wrappers

lib-blockchain/               <- Uses types from lib-types
├── NO duplicate type definitions
├── Import everything from lib-types
└── Only blockchain logic here

lib-consensus/                <- Uses types from lib-types
├── NO duplicate type definitions
├── Import consensus types from lib-types
└── Only consensus logic here

(same for all other crates)
```

---

## CONCLUSION

**The type architecture is currently NOT being respected.** 

- ❌ Multiple duplicate type definitions
- ❌ Core types scattered across crates
- ❌ Two different NodeId implementations
- ❌ lib-types is underutilized

**Required Actions:**
1. Consolidate all duplicate types
2. Move core primitives to lib-types
3. Document and enforce the architecture rule
4. Add CI check to prevent future duplicates

---

*Report generated by traversal analysis of type definitions across all crates*
