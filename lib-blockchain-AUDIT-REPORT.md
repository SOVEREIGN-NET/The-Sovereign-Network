# lib-blockchain Deep Audit Report
## Branch: development (commit 0d7245d3)
## Date: 2026-02-28
## Scope: Hardcoded values, stubs, TODOs, bugs, garbage code

---

## Executive Summary

| Category | Count | Critical | High | Medium |
|----------|-------|----------|------|--------|
| Hardcoded Magic Numbers | 45+ | 8 | 15 | 22 |
| TODO/FIXME Comments | 50+ | 5 | 12 | 33 |
| Stub Implementations | 15 | 4 | 6 | 5 |
| Dangerous unwrap/expect | 35+ | 3 | 10 | 22 |
| Deprecated Code | 20+ | 3 | 8 | 9 |
| Performance Issues (Clone) | 10 | 2 | 5 | 3 |

**Overall Assessment:** The codebase has significant technical debt with critical issues in consensus safety, economic parameters, and state management. Many "TODO" items are in consensus-critical paths.

---

## 🔴 CRITICAL ISSUES (Fix Immediately)

### 1. MISSING SIGNATURE VERIFICATION (Consensus Security Gap)
**File:** `validation/tx_validate.rs:233`
```rust
// TODO: Verify signature matches UTXO owner
// This requires access to the signature verification logic
```
**Risk:** UTXO inputs are not having their signatures verified. Critical security vulnerability.
**Fix:** Implement signature verification before accepting transactions.

### 2. VALIDATOR REGISTRY PANIC RISK (Consensus Crash)
**File:** `blockchain.rs:4692`
```rust
let mut validator_info = self.validator_registry.get(identity_id).unwrap().clone();
```
**Risk:** TOCTOU race condition can cause node panic if validator removed between check and access.
**Fix:** Use `ok_or_else()` to return proper error instead of unwrap.

### 3. WALL-CLOCK TIME IN CONSENSUS (Determinism Violation)
**File:** `utils.rs:56`
```rust
std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs()
```
**Risk:** Violates AGENTS.md consensus determinism rules. Can fail if clock before Unix epoch.
**Fix:** Use block timestamp instead of wall clock time.

### 4. ZK PROOFS NOT CRYPTOGRAPHICALLY VERIFIED
**File:** `contracts/root_registry/namespace_policy.rs:125`
```rust
// TODO: In production, verify the ZK proof cryptographically.
// For now, trust the provided level if proof structure is valid.
```
**Risk:** ZK proofs are accepted without cryptographic verification. Security vulnerability.
**Fix:** Implement proper ZK proof verification.

### 5. DIRECT BALANCE MUTATION BYPASSES TREASURY KERNEL
**File:** `blockchain.rs:2639, 2656`
```rust
// Note: Direct balance mutation for backward compatibility.
// SOV token operations go through TreasuryKernel for new transactions,
// but this historical fee deduction maintains existing behavior.
```
**Risk:** Dual execution paths (Kernel and direct) risk consensus divergence.
**Fix:** Remove legacy path, route all through TreasuryKernel.

### 6. BLOCKCHAIN STRUCT HAS DERIVE(CLONE) - MEMORY EXPLOSION
**File:** `blockchain.rs:87`
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]  // ⚠️ Clone is dangerous!
pub struct Blockchain {
    pub blocks: Vec<Block>,          // ALL blocks
    pub utxo_set: HashMap<...>,      // ALL UTXOs
    // ... 50+ more fields
}
```
**Risk:** Cloning the entire blockchain state causes OOM crashes.
**Fix:** Remove `Clone`, use `Arc<Blockchain>` for shared ownership.

### 7. SNAPSHOT STATE HASH CLONES ENTIRE STATE
**File:** `sync/snapshot.rs:169-186`
```rust
let mut utxos_sorted = self.utxos.clone();      // CLONES ALL UTXOs
let mut accounts_sorted = self.accounts.clone(); // CLONES ALL ACCOUNTS
let mut balances_sorted = self.token_balances.clone(); // CLONES ALL BALANCES
```
**Risk:** Every snapshot operation clones entire state - massive memory/CPU hit.
**Fix:** Use Merkle tree approach instead of sorting cloned vectors.

### 8. TREASURY KERNEL TOKEN MINT BYPASS
**File:** `contracts/executor/mod.rs:866`
```rust
#[allow(deprecated)] // TODO(#852): Route through TreasuryKernel
crate::contracts::tokens::functions::mint_tokens(...)
```
**Risk:** Token minting bypasses TreasuryKernel governance checks.
**Fix:** Route through TreasuryKernel as the TODO says.

---

## 🟡 HIGH PRIORITY ISSUES

### Hardcoded Economic Parameters (Should be Governance-Configurable)

| Line | Code | Issue |
|------|------|-------|
| 61 | `10_080` (~1 week) | Treasury epoch length assumes 10s blocks |
| 66 | `8_640` (~1 day) | Veto window assumes 10s blocks |
| 71 | `10` | Max executions per epoch arbitrary |
| 4510 | `1_000 / 100_000` | Validator min stake hardcoded |
| 4561 | `10_737_418_240` | Min storage 10GB not configurable |
| 6333 | `5 / 100` | Treasury spend cap 5% hardcoded |
| 7553 | `100_000_000` | SOV atomic units conversion |

### Inconsistent Defaults

| Concept | Value A | Value B | Location |
|---------|---------|---------|----------|
| Finality depth | 12 | 6 | `new()` vs `default_finality_depth()` |
| Epoch length | 10,080 | 100 | Treasury vs Treasury Kernel |
| Update fee | 100 | 50 | Identity vs Validator |

### Deprecated Code Still in Production Paths

1. **Legacy block processing path** (`blockchain.rs:2057-2195`) - logs deprecation warning but still active
2. **PoW mining stubs** (`block/creation.rs:124-155`) - full implementations marked deprecated
3. **Direct token mint/burn** - bypass governance, marked deprecated but used with `#[allow(deprecated)]`

---

## 📋 COMPLETE FINDINGS BY CATEGORY

### 1. TODO/FIXME in Critical Paths

| Priority | File | Line | Description |
|----------|------|------|-------------|
| 🔴 | validation/tx_validate.rs | 233 | UTXO signature verification not implemented |
| 🔴 | root_registry/namespace_policy.rs | 125 | ZK proofs not cryptographically verified |
| 🔴 | treasury_kernel/ubi_engine.rs | 154 | UBI mint unwraps kernel/token state |
| 🟡 | transaction/validation.rs | 278 | AMM/Token validation not implemented |
| 🟡 | blockchain.rs | 7630 | Vote delegation returns 0 (not implemented) |
| 🟡 | blockchain.rs | 7735 | Blockchain state recovery not implemented |
| 🟡 | employment/employment_registry.rs | 162 | No caller authorization |
| 🟡 | root_registry/core.rs | 477 | No governance verification |

### 2. Stub Implementations

| File | Function | Current Behavior |
|------|----------|------------------|
| blockchain.rs:7628 | get_delegated_voting_power | Returns 0 |
| transaction/core.rs:1834 | compute_claim_id | Returns Hash::default() |
| ubi_distribution/core.rs:637 | has_claimed_this_epoch | Returns false |
| bonding_curve/event_indexer.rs:238 | get_latest_event | Returns None |

### 3. Dangerous unwrap/expect Patterns

| File | Line | Risk |
|------|------|------|
| blockchain.rs:4692 | Validator registry unwrap | TOCTOU panic risk |
| utils.rs:56 | SystemTime unwrap | Clock failure panic |
| transaction/hashing.rs:30 | Serialization expect | Future-proofing issue |
| execution/tx_apply.rs:798 | Address conversion | Silent zero address |
| treasury_kernel/cap_types.rs:79 | Overflow expect | Kernel panic |

### 4. Performance Killers (Clone)

| File | Line | Issue |
|------|------|-------|
| blockchain.rs:87 | #[derive(Clone)] on Blockchain | Can clone 50K+ blocks |
| sync/snapshot.rs:169 | Clones all UTXOs for hashing | O(n) memory |
| blockchain.rs:892-999 | Storage V3 conversion clones everything | Migration overhead |
| shared_provider.rs:8 | Global Arc<RwLock<Blockchain>> | Encourages cloning |

---

## 🗑️ GARBAGE CODE (Should be Removed)

### 1. Dead PoW Mining Code
```rust
// block/mod.rs:26-27
mine_block,  // Deprecated stub - BFT-A-935
mine_block_with_config,  // Deprecated stub - BFT-A-935
```
BFT consensus doesn't use mining. 30+ lines of dead code.

### 2. Legacy File-Based Storage
```rust
// blockchain.rs:9077, 9138
#[deprecated(since = "0.2.0", note = "Use Phase 2 incremental storage...")]
pub fn load_from_file(...)  // Still exported, tests use it
```
Deprecated since 0.2.0 but still in codebase.

### 3. Time-Based Expiration (Replaced by Block Height)
```rust
// root_registry/types.rs:1080-1189
#[deprecated(note = "Use expires_at_height for on-chain logic")]
pub expires_at: u64,
```
Multiple deprecated time fields kept for "display only".

### 4. Contract Execution V1 Legacy
```rust
// transaction/contract_execution.rs:4
V1 (legacy): b"ZHTP"
```
Old memo format kept for "read compatibility" but adds complexity.

---

## 📊 CODE QUALITY METRICS

| Metric | Value | Assessment |
|--------|-------|------------|
| Total Lines | 50,465 | Large codebase |
| TODO Comments | 45+ | High technical debt |
| Deprecated Items | 20+ | Migration in progress |
| unsafe blocks | 0 | ✅ Good |
| unwrap/expect | 200+ | ⚠️ Needs audit |
| Clone on large structs | 10+ | ⚠️ Performance risk |

---

## 🎯 RECOMMENDATIONS

### Immediate (This Sprint)
1. **Fix UTXO signature verification** - Critical security gap
2. **Remove Clone from Blockchain** - Prevents OOM crashes
3. **Fix validator registry unwrap** - Prevents consensus crash
4. **Route token mint through TreasuryKernel** - Complete TODO(#852)

### Short-term (Next 2 Sprints)
5. **Remove legacy block processing path** - Reduce dual-path risk
6. **Fix snapshot state hashing** - Use Merkle trees
7. **Audit all hardcoded economic params** - Make governance-configurable
8. **Implement ZK proof verification** - Close security gap

### Medium-term (Next Quarter)
9. **Break up Blockchain god object** - Separate concerns
10. **Remove deprecated code** - PoW stubs, file storage, time-based expiration
11. **Standardize mutex types** - Use tokio::sync consistently
12. **Add recursion/stack depth limits** - Already mostly done, verify coverage

---

## CONCLUSION

The lib-blockchain crate has substantial technical debt with several critical issues:

**Blockers for Production:**
- UTXO signature verification missing
- Validator registry panic risk
- TreasuryKernel bypass for token minting
- ZK proof verification not implemented

**Performance Risks:**
- Blockchain::Clone can OOM
- Snapshot hashing clones entire state
- Inefficient storage patterns

**Code Quality:**
- 45+ TODOs in consensus paths
- 20+ deprecated items still in use
- Inconsistent defaults
- Hardcoded economic parameters

The codebase would benefit from a focused refactoring sprint addressing the critical issues before any production deployment.

---

*Report generated by automated analysis of lib-blockchain/src/*
