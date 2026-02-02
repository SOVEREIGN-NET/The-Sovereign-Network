# Phase 2 Implementation Checklist

**Purpose**: Deterministic, crash-safe block execution pipeline on BlockchainStore with Fee Model v2 minimum fee enforcement.

**Scope Lock**: Anything not in this checklist is out of scope for Phase 2.

---

## Hard Rules (Non-Negotiable)

- [ ] R1: Authoritative state is BlockchainStore only. No in-memory state is canonical.
- [ ] R2: Every block uses single lifecycle: prechecks → begin_block → apply txs → append_block → commit_block
- [ ] R3: All state mutation occurs only through tx_apply primitives
- [ ] R4: Fee Model v2 enforced as minimum fee constraint: `tx.fee < min_fee_v2(tx)` → reject → rollback
- [ ] R5: Phase-2 tx kinds limited to: NativeTransfer, TokenTransfer, Coinbase (all others rejected)
- [ ] R6: Genesis applied through BlockExecutor::apply_block like any other block

---

## Module Creation

### lib-blockchain/src/execution/

- [x] mod.rs - module exports
- [x] executor.rs - BlockExecutor, ApplyOutcome, StateChangesSummary
- [x] errors.rs - BlockApplyError, TxApplyError
- [x] state_view.rs - read-only helpers
- [x] tx_apply.rs - StateMutator + apply_* functions
- [ ] tx_validate.rs - stateless/stateful validation (includes min fee check)
- [ ] tx_types.rs - Phase-2 parsing: OutPoint, token transfer payload extraction

### lib-blockchain/src/fees/ (NEW)

- [ ] mod.rs - module exports
- [ ] model_v2.rs - compute_fee_v2 (pure, deterministic)
- [ ] types.rs - FeeInput, TxKind, SigScheme, byte classification, FeeParamsV2

### lib-blockchain/src/blockchain.rs modifications

- [x] Add `store: Option<Arc<dyn BlockchainStore>>` field
- [x] Add `new_with_store()` constructor
- [x] Deprecate `save_to_file` / `load_from_file`
- [ ] Remove authoritative Vec<Block>, HashMaps for utxo/registries from runtime usage
- [ ] Route all block application through BlockExecutor only

---

## Execution Lifecycle (Canonical)

### Step 0: Determine expected height
- [ ] `expected_height = if store initialized: store.get_latest_height() + 1 else 0`
- [ ] `block.header.height` must equal `expected_height`

### Step 1: Prechecks (no begin_block yet)
- [x] Height check
- [ ] Previous hash check if height > 0 (optimize: use `get_block_hash_by_height`)
- [ ] Block structural checks:
  - [ ] `header.transaction_count == block.transactions.len()`
  - [x] `block.size() <= config.max_block_size`
  - [x] if `!allow_empty_blocks`: block.transactions not empty
  - [ ] Merkle root validation (if merkle_root is consensus field)

### Step 2: begin_block
- [x] `store.begin_block(block.height)`

### Step 3: Apply txs in order
- [x] For each tx at index i:
  - [x] `validate_stateless(tx)`
  - [ ] `validate_stateful(tx, ctx=view+fee_engine)` - needs fee integration
  - [x] `apply(tx)` using StateMutator
  - [x] Accumulate StateChangesSummary + fees_collected
- [x] If any fails: `store.rollback_block()`, return `BlockApplyError::TxFailed { index, reason }`

### Step 4: Append block
- [x] `store.append_block(block)`

### Step 5: Commit
- [x] `store.commit_block()`
- [x] Return ApplyOutcome

### Step 6: Panic safety
- [x] Executor must guarantee rollback on panic after begin_block
- [x] Use scope guard OR catch_unwind wrapper with rollback in unwind path

---

## Transaction Support (Locked)

### Supported TransactionType values:
- [x] Transfer (native UTXO)
- [ ] TokenTransfer (balances) - **INCOMPLETE: needs real implementation**
- [x] Coinbase

### All other tx types:
- [x] Error in validate_stateless as UnsupportedType

---

## Fee Model v2 Integration

### fees/types.rs definitions:

#### TxKind enum:
- [x] NativeTransfer (Phase-2 extension)
- [x] TokenTransfer
- [x] ContractCall
- [x] DataUpload
- [x] Governance
- [x] Staking

#### SigScheme enum:
- [x] Ed25519
- [x] Dilithium5
- [x] Hybrid

#### FeeInput struct:
- [x] tx_kind: TxKind
- [x] sig_scheme: SigScheme
- [x] sig_count: u8
- [x] envelope_bytes: u32
- [x] payload_bytes: u32
- [x] witness_bytes: u32
- [x] state_reads: u16
- [x] state_writes: u16
- [x] state_write_bytes: u32

#### FeeParamsV2 struct:
- [x] base_tx_fee: u64
- [x] price_exec_unit: u64
- [x] price_state_read: u64
- [x] price_state_write: u64
- [x] price_state_write_byte: u64
- [x] price_payload_byte: u64
- [x] price_witness_byte_numer: u64 (rational: numer/denom)
- [x] price_witness_byte_denom: u64
- [x] price_verify_unit: u64
- [x] exec_units: map TxKind -> u32
- [x] verify_units_per_sig: map SigScheme -> u32
- [x] witness_cap_bytes: map TxKind -> u32
- [x] max_witness_bytes: map TxKind -> u32
- [x] max_sigs: map TxKind -> u16
- [x] block_max_payload_bytes: u32
- [x] block_max_witness_bytes: u32
- [x] block_max_verify_units: u32
- [x] block_max_state_write_bytes: u32
- [x] block_max_txs: u32

### fees/model_v2.rs:

#### compute_fee_v2 function:
- [x] Pure function (no store access, no global state)
- [x] Deterministic
- [x] u128 arithmetic internally, final u64
- [x] Formula implementation:
  ```
  charged_witness_bytes = min(witness_bytes, witness_cap_bytes[tx_kind])
  verify_units = sig_count * verify_units_per_sig[sig_scheme]
  exec_units = exec_units[tx_kind]
  fee = base_tx_fee
      + exec_units * price_exec_unit
      + state_reads * price_state_read
      + state_writes * price_state_write
      + state_write_bytes * price_state_write_byte
      + payload_bytes * price_payload_byte
      + charged_witness_bytes * price_witness_byte (rational, round up)
      + verify_units * price_verify_unit
  ```

### Byte classification (consensus rule):
- [x] envelope_bytes: fixed header fields and type tags (constant per tx type)
- [x] payload_bytes: intent fields (inputs/outputs, amounts, token transfer payload)
- [x] witness_bytes: signature bytes + public key bytes + zk proof bytes

### Byte classifiers for Phase-2 tx types:
- [x] Transfer classifier
- [x] TokenTransfer classifier
- [x] Coinbase classifier

### TxKind mapping for Phase-2:
- [x] Add TxKind::NativeTransfer with params:
  - [x] exec_units[NativeTransfer] = 5
  - [x] witness_cap_bytes[NativeTransfer] = 1_536
  - [x] max_witness_bytes[NativeTransfer] = 16_384
  - [x] max_sigs[NativeTransfer] = 2

---

## Transaction Validation Requirements

### validate_stateless(tx):
- [x] Reject unsupported tx type
- [ ] For Transfer:
  - [x] inputs not empty
  - [x] outputs not empty
  - [x] no duplicate OutPoints within tx
- [ ] For Coinbase:
  - [x] inputs empty
  - [x] outputs non-empty
  - [ ] must be first tx in block (block-level precheck)
  - [ ] at most one coinbase per block
- [ ] For TokenTransfer:
  - [ ] must contain token payload (token_id, from, to, amount)
  - [ ] amount > 0

### validate_stateful(tx, view):
- [ ] Transfer:
  - [x] every input OutPoint exists in store.utxos
  - [ ] nullifier uniqueness (if available)
- [ ] TokenTransfer:
  - [ ] sender balance >= amount (fee is 0 per locked choice)
- [ ] Coinbase:
  - [ ] only one per block
  - [ ] reward amount exactly config.block_reward
  - [ ] no non-Phase-2 fields set (identity_data, wallet_data, dao_*, ubi_*, profit_declaration_data must be None)
- [x] Fee minimum check:
  - [x] Build FeeInput from tx + classification
  - [x] Compute state_reads/writes/write_bytes deterministically:
    - [x] NativeTransfer: reads=inputs.len, writes=outputs.len+inputs.len, write_bytes estimated
    - [x] TokenTransfer: reads=2, writes=2, write_bytes=2*BALANCE_ENTRY_SIZE_EST
    - [x] Coinbase: reads=0, writes=outputs.len, write_bytes estimated
  - [x] Compute min_fee_v2
  - [x] Require tx.fee >= min_fee_v2

### Fee payment rule (Phase-2 lock):
- [x] NativeTransfer: fee paid by input-output difference
- [x] TokenTransfer: tx.fee must be 0
- [x] Coinbase: tx.fee must be 0

---

## Transaction Apply Requirements

### NativeTransfer apply:
- [x] Spend each input: load UTXO, delete it
- [x] Create outputs: insert new UTXOs at OutPoints (tx_hash, output_index)
- [ ] Enforce conservation: total_in >= total_out + fee
- [x] Update summary

### Coinbase apply:
- [x] Create outputs as UTXOs
- [ ] Enforce output amount equals block_reward
- [ ] Reject if any non-Phase-2 fields are set

### TokenTransfer apply:
- [ ] Parse payload (token_id, from, to, amount) from token_transfer_data
- [ ] Debit sender balance
- [ ] Credit receiver balance
- [ ] Enforce no underflow
- [ ] Update summary

---

## Block-Level Resource Limits

### Precheck aggregates (before begin_block):
- [x] total_payload_bytes <= block_max_payload_bytes
- [x] total_witness_bytes <= block_max_witness_bytes
- [x] total_verify_units <= block_max_verify_units
- [x] total_state_write_bytes <= block_max_state_write_bytes
- [x] tx_count <= block_max_txs (via BlockValidateConfig.max_transactions)

---

## Storage Optimizations

- [x] Add `get_block_hash_by_height(height) -> Option<BlockHash>` to BlockchainStore
- [x] Implement in SledStore (default implementation via get_block_by_height)
- [x] Use for previous-hash validation (avoid full block deserialization)

---

## Genesis Requirements

- [ ] Genesis is block at height 0
- [ ] Genesis must include enough state to fund tests:
  - [ ] At least one coinbase tx OR predefined UTXO outputs
- [ ] Genesis applied by BlockExecutor with same lifecycle
- [ ] Create proper genesis block for testing with fundable UTXOs

---

## Authorization Invariant (Document Explicitly)

- [ ] Document chosen approach:
  - [ ] Option A: Ownership enforced via ZK/nullifiers in executor
  - [ ] Option B: Ownership enforced earlier, executor assumes validity
  - [ ] Option C: Executor rejects spends without proof
- [ ] Add invariant comment to executor.rs

---

## Required Tests

### A) Execution lifecycle
- [x] Apply genesis
- [x] Apply sequential blocks

### B) Rollback
- [x] Block with invalid tx: height unchanged and state unchanged

### C) Double spend across blocks
- [ ] Fund via genesis/coinbase through executor (not manual store mutation)
- [ ] Spend once succeeds
- [ ] Spend again fails and rolls back

### D) Token underflow
- [ ] Token transfer with insufficient balance fails and rolls back

### E) Fee model golden vectors
- [x] compute_fee_v2 matches PQ vectors exactly (rational witness pricing)
- [x] At least one Dilithium vector for regression (using PQ crypto, not Ed25519)
- [x] Test rounding rule explicitly

### F) Persistence across restart
- [x] Apply N blocks, reopen store, continue

### G) Coinbase rule enforcement
- [ ] Test: only one coinbase per block
- [ ] Test: coinbase must be first tx
- [ ] Test: coinbase reward amount validation

### H) Fee minimum enforcement
- [x] Test: tx with fee < min_fee_v2 rejected
- [x] Test: tx with fee >= min_fee_v2 accepted

---

## Definition of Done

Phase 2 is complete when:

- [ ] All stateful writes flow through StateMutator and BlockchainStore
- [ ] No monolithic in-memory chain struct is required for correctness
- [ ] TokenTransfer is fully implemented with deterministic rules
- [ ] Coinbase is fully implemented with all rules enforced
- [ ] Fee Model v2 minimum fee enforcement is in place
- [ ] Golden fee vectors pass in CI
- [ ] Rollback tests prove no partial effects
- [ ] Restart test proves persistence
- [ ] Tests use executor for all state mutation (no direct store manipulation)
- [ ] Authorization invariant is documented
- [ ] Block structural validation is complete
- [ ] Panic-safe rollback is implemented

---

## Current Status Summary

### Completed:
- Storage module (BlockchainStore trait, SledStore, keys)
- Basic execution module structure
- Basic validation module structure
- Blockchain struct updated with store field
- Basic tests for genesis, sequential blocks, persistence

### In Progress:
- TokenTransfer implementation (has token_transfer_data field but executor incomplete)

### Not Started:
- Fee Model v2 module (fees/)
- Complete coinbase rule enforcement
- Block structural validation completion
- Panic-safe rollback
- Fee minimum validation
- Block resource limits
- Genesis funding path
- Test fixes to use executor
- Authorization invariant documentation
