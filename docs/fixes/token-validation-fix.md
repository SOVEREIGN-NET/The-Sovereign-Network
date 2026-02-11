# Token Creation Validation Fix

**Date:** 2026-01-31
**Issue:** iOS token creation failing with "Transaction validation failed: InvalidTransaction"
**Status:** RESOLVED

---

## Problem Summary

iOS clients attempting to create custom tokens via `POST /api/v1/token/create` received:
```
Transaction validation failed: InvalidTransaction
```

Server logs showed:
```
Transaction type: ContractExecution
Transaction validation failed: InvalidTransaction
Transaction details: inputs=0, outputs=0, fee=1200, type=ContractExecution, system=true
```

---

## Root Causes

### 1. Memo Size Limit Too Small (CRITICAL)

**Location:** `lib-blockchain/src/transaction/validation.rs:1228`

**Problem:** The `MAX_MEMO_SIZE` was set to 1024 bytes. Token transactions include:
- 4-byte `ZHTP` marker
- Bincode-serialized `ContractCall` struct
- Bincode-serialized `Signature` containing Dilithium5 public key (2592 bytes)

Total memo size: ~3000+ bytes, exceeding the 1024 byte limit.

**Fix:**
```rust
const MAX_MEMO_SIZE: usize = 8192; // 8 KB - increased for post-quantum signatures (Dilithium5 pubkey = 2592 bytes)
```

### 2. Empty Outputs Rejected for Contract Transactions

**Location:** `lib-blockchain/src/transaction/validation.rs:338-362`

**Problem:** `validate_contract_transaction()` required non-empty outputs for all contract transactions. However, token contract calls (`create_custom_token`, `mint`, `transfer`, `burn`) don't produce UTXO outputs - they modify token state in the contract storage.

**Fix:** Added `is_token_contract_execution()` detection function and bypass:
```rust
fn validate_contract_transaction(&self, transaction: &Transaction) -> ValidationResult {
    // Token contract executions don't require outputs
    let is_token = is_token_contract_execution(transaction);

    if transaction.outputs.is_empty() && !is_token {
        return Err(ValidationError::InvalidOutputs);
    }

    Ok(())
}
```

---

## The Fix: `is_token_contract_execution()` Function

**Location:** `lib-blockchain/src/transaction/validation.rs:874-917`

This function detects token contract calls by parsing the transaction memo:

```rust
fn is_token_contract_execution(transaction: &Transaction) -> bool {
    // 1. Must be ContractExecution type
    if transaction.transaction_type != TransactionType::ContractExecution {
        return false;
    }

    // 2. Memo must start with "ZHTP" marker
    if transaction.memo.len() <= 4 || &transaction.memo[0..4] != b"ZHTP" {
        return false;
    }

    // 3. Deserialize the ContractCall from memo[4..]
    let call_data = &transaction.memo[4..];
    let (call, _sig): (ContractCall, Signature) = bincode::deserialize(call_data)?;

    // 4. Must be Token contract type
    if call.contract_type != ContractType::Token {
        return false;
    }

    // 5. Must be a recognized token method
    matches!(
        call.method.as_str(),
        "create_custom_token" | "mint" | "transfer" | "burn"
    )
}
```

---

## Complete Flow: Frontend to Backend

### 1. iOS Client (Frontend)

```
User taps "Create Token" in app
         │
         ▼
┌─────────────────────────────────────┐
│  Build ContractCall:                │
│  - contract_type: Token             │
│  - method: "create_custom_token"    │
│  - params: {name, symbol, decimals} │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  Build Transaction:                 │
│  - type: ContractExecution          │
│  - inputs: [] (empty)               │
│  - outputs: [] (empty)              │
│  - fee: 1200                        │
│  - memo: "ZHTP" + bincode(call,sig) │
│  - signature: Dilithium5 signed     │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  Serialize & Hex-encode:            │
│  signed_tx = hex(bincode(tx))       │
└─────────────────────────────────────┘
         │
         ▼
POST /api/v1/token/create
Body: { "signed_tx": "..." }
```

### 2. SOV Server (Backend)

```
POST /api/v1/token/create arrives
         │
         ▼
┌─────────────────────────────────────┐
│  TokenHandler::handle_create_token  │
│  (zhtp/src/api/handlers/token/)     │
│                                     │
│  1. Decode hex → bincode → Tx       │
│  2. Extract ContractCall from memo  │
│  3. Verify method = create_custom   │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  TokenHandler::submit_to_mempool    │
│                                     │
│  blockchain.add_pending_transaction │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  Blockchain::verify_and_enqueue     │
│  (lib-blockchain/src/blockchain.rs) │
│                                     │
│  → verify_transaction()             │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  StatefulTransactionValidator       │
│  ::validate_transaction_with_state  │
│  (lib-blockchain/src/transaction/   │
│   validation.rs:925+)               │
│                                     │
│  Checks:                            │
│  1. validate_basic_structure        │
│     - memo.len <= MAX_MEMO_SIZE     │  ← FIX: 8192 bytes
│  2. validate_contract_transaction   │
│     - outputs can be empty IF       │
│       is_token_contract_execution   │  ← FIX: Added detection
│  3. validate_signature              │
│     - Dilithium5 verification       │
└─────────────────────────────────────┘
         │
         ▼
Transaction added to pending_transactions
         │
         ▼
Mining interval (30s) includes tx in next block
         │
         ▼
Token created in contract storage
```

---

## Files Modified

| File | Change |
|------|--------|
| `lib-blockchain/src/transaction/validation.rs` | Increased `MAX_MEMO_SIZE` to 8192, added `is_token_contract_execution()` function, updated `validate_contract_transaction()` to allow empty outputs for token calls |
| `lib-blockchain/src/blockchain.rs` | Added trace logging for debugging |

---

## Verification

After deploying the fix to `zhtp-prod`:
- iOS token creation: **SUCCESS**
- Server logs show: `is_token_contract_execution: VALID token contract call, method=create_custom_token`
- Transaction accepted to mempool and included in next block

---

## Key Learnings

1. **Post-quantum signatures are large**: Dilithium5 public keys are 2592 bytes, signatures are 4627 bytes. Any size limits must account for this.

2. **Token transactions are stateful, not UTXO-based**: Unlike transfers that consume and produce UTXOs, token operations modify contract state. Empty inputs/outputs are valid for token calls.

3. **Memo format for contract calls**: `"ZHTP" + bincode(ContractCall, Signature)` - the 4-byte marker identifies ZHTP contract transactions.
