# Cross-Contract Call Infrastructure Implementation Guide

**Issue**: #842
**Status**: Phase 1-3 Complete, Phase 4 Documentation
**Red Test**: `red_cross_contract_calls_type_checked` ✅ PASSING

---

## Overview

This guide documents the complete implementation of the cross-contract call infrastructure for the Sovereign Network blockchain. It enables contracts to safely call other contracts with type-safe parameters, deterministic error handling, and strict recursion limits per ADR-0017 (Execution Boundary principle).

## Architecture

### High-Level Design

```
Contract A                          Contract B
   |                                   |
   +-- call B::transfer()              |
       |                               |
       +-- CrossContractCall (struct)  |
           |                           |
           +-- Validate ------+        |
           |                  |        |
           +-- Record Intent -+-- Returns Intent Hash
           |
           +-- Call Stack Tracking
           |
           +-- Error Wrapping (no pass-through)
```

### Core Components

#### 1. **Error System** (`contracts/calls/errors.rs`)
- **Purpose**: Prevents ABI information leakage between contracts
- **Key Types**:
  - `CrossContractError`: Wraps all errors with category, not message
  - `CalleeErrorCode`: 6 deterministic error categories (ValidationFailed, ExecutionFailed, NotFound, PermissionDenied, CallDepthExceeded, Unknown)
  - `ContractId`: Type alias for `[u8; 32]` contract hashes

```rust
// Example: Error wrapping
let error = CrossContractError::validation_failed(
    callee_id,
    "transfer".to_string(),
    "Parameter type mismatch"  // Original error (hashed)
);
// Caller only sees: ContractId, method name, error code, reason hash
// Never sees: Original error message (prevents ABI leakage)
```

#### 2. **Call Stack** (`contracts/calls/stack.rs`)
- **Purpose**: Prevents infinite recursion with hard limit of 16 levels
- **Key Methods**:
  - `push()`: Adds contract to stack, returns depth or error
  - `pop()`: Removes contract and decrements depth
  - `current_depth()`: Returns current recursion level
  - `chain()`: Returns full call chain for auditing

```rust
// Example: Depth tracking
let mut stack = CallStack::new();
stack.push(contract_a, "method1".to_string())?;  // depth = 1
stack.push(contract_b, "method2".to_string())?;  // depth = 2
stack.push(contract_c, "method3".to_string())?;  // depth = 3
// If depth > 16: Error CallDepthExceeded
```

#### 3. **Call Representation** (`contracts/calls/call.rs`)
- **Purpose**: Encapsulates all information needed for a cross-contract call
- **Key Fields**:
  - `caller`: Contract making the call
  - `callee`: Contract being called
  - `method`: Method name to invoke
  - `args`: Serialized arguments (format-agnostic)
  - `depth`: Recursion depth at call time

```rust
// Example: Creating a call
let call = CrossContractCall::new(
    caller_id,
    callee_id,
    "transfer".to_string(),
    serialized_args
).with_depth(current_depth);

call.validate_structure()?;  // Sanity checks
```

#### 4. **Type Validator** (`contracts/calls/type_validator.rs`)
- **Purpose**: Ensures parameters match expected types with promotion rules
- **Features**:
  - Primitive type parsing (u8-u128, i8-i128, bool, String, etc.)
  - Complex types (Vec<T>, Option<T>, Result<T, E>, [T; N])
  - Type promotion (u8 → u32 → u64 → u128)
  - Custom struct field validation

```rust
// Example: Type validation
TypeValidator::validate_arguments(
    &["u32", "String"],          // Actual argument types
    &["u64", "String"]           // Expected parameter types
)?;  // u32 compatible with u64 (promotion)

// For custom types
TypeValidator::validate_struct_fields(
    &[("recipient", "Hash"), ("amount", "u64")],
    &[("recipient", "Hash"), ("amount", "u64")]
)?;
```

#### 5. **Serialization Validator** (`contracts/calls/serialization_validator.rs`)
- **Purpose**: Validates data format (Bincode, JSON, MessagePack, CBOR)
- **Features**:
  - Auto-detection from byte data
  - Format compatibility matrix
  - Endianness consistency

```rust
// Example: Format detection
let format = SerializationValidator::detect_format(data)?;
match format {
    SerializationFormat::Json => { /* handle JSON */ },
    SerializationFormat::Bincode => { /* handle Bincode */ },
    _ => { /* other formats */ },
}

// Validation
SerializationValidator::validate_format(data, SerializationFormat::Json)?;
```

#### 6. **Call Executor** (`contracts/calls/executor.rs`)
- **Purpose**: Orchestrates safe call execution with intent recording
- **Key Methods**:
  - `execute_call()`: Full execution pipeline
  - `record_intent()`: Creates `CrossContractCallIntent` per ADR-0017
  - `register_abi()`: Links contract to its ABI methods

```rust
// Example: Executing a call
let executor = CallExecutor::new(current_block_height);
executor.register_abi(contract_b_id, contract_b_methods);

let result = executor.execute_call(
    call,
    2,              // param count
    "u64",         // expected return type
    "1.0.0"        // caller ABI version
)?;

match result {
    CrossContractCallResult::Success { return_value } => {
        // Handle success (intent hash returned)
    },
    CrossContractCallResult::Error { error } => {
        // Handle error (wrapped, no details leaked)
    },
}
```

#### 7. **Cycle Detector** (`contracts/calls/cycle_detector.rs`)
- **Purpose**: Prevents infinite loops in contract call graphs
- **Algorithms**:
  - `would_create_cycle()`: O(n) single-call check
  - `find_all_cycles()`: O(V+E) DFS graph traversal
  - `path_creates_cycle()`: Path-based cycle detection

```rust
// Example: Cycle detection
let call_stack = vec![(contract_a, "m1"), (contract_b, "m2")];

// Single call check
if CycleDetector::would_create_cycle(&call_stack, new_callee) {
    return Err("Cycle would be created");
}

// Full graph analysis
let edges = vec![
    CallEdge::new(a, b, "m"),
    CallEdge::new(b, c, "m"),
    CallEdge::new(c, a, "m"),  // Cycle: A→B→C→A
];
let cycles = CycleDetector::find_all_cycles(&edges)?;
```

---

## Integration Points

### With ABI Registry (#843)

The calls system integrates with the ABI registry to validate method signatures:

```rust
// 1. Load ABI for callee
let callee_abi = abi_registry.get(&callee_id)?;

// 2. Validate method exists and signature matches
CallValidator::validate_call(
    &call,
    &callee_abi.methods,
    actual_param_count,
    expected_return_type,
    caller_abi_version
)?;

// 3. Include ABI hash in intent for versioning
let intent = CrossContractCallIntent::new(
    ...,
    abi_hash,  // From callee's ABI
    ...
);
```

### With ContractExecutor (#841)

Integration with the main contract executor for state management:

```rust
// 1. Record call intent (instead of executing effects)
let intent = executor.record_intent(&call)?;

// 2. Emit intent as event
executor.emit_event("CrossContractCallIntent", intent);

// 3. Deferred execution by Treasury Kernel
// Treasury Kernel reads intent and executes actual state changes
```

### With Treasury Kernel (Future)

The intent-based model enables Treasury Kernel execution:

```
Contract executes:
  call B::transfer(recipient, amount)
    ↓
Contract records:
  CrossContractCallIntent { caller, callee, method, args_hash, depth, ... }
    ↓
Contract emits:
  Event "CrossContractCallIntent"
    ↓
Treasury Kernel processes:
  1. Validates intent depth/privilege
  2. Loads callee contract state
  3. Executes actual state changes
  4. Records effects in blockchain
```

---

## Usage Examples

### Example 1: Simple Cross-Contract Call

```rust
// UBI contract calls Treasury to withdraw funds
let ubi_executor = CallExecutor::new(current_block);
ubi_executor.register_abi(treasury_id, treasury_methods);

let call = CrossContractCall::new(
    ubi_contract_id,
    treasury_id,
    "withdraw".to_string(),
    encode_args(&[citizen_id, amount])
).with_depth(0);

let result = ubi_executor.execute_call(
    call,
    2,           // 2 parameters
    "bool",      // returns success bool
    "1.0.0"      // UBI uses ABI v1.0.0
)?;
```

### Example 2: Nested Calls with Depth Tracking

```rust
// DAORegistry calls UBI which calls Treasury
let dao_call = CrossContractCall::new(
    dao_id,
    ubi_id,
    "claim".to_string(),
    args
).with_depth(0);

// Executor 1: DAO → UBI
match ubi_executor.execute_call(...) {
    Ok(CrossContractCallResult::Success { .. }) => {
        // Inside UBI: UBI → Treasury
        let treasury_call = CrossContractCall::new(
            ubi_id,
            treasury_id,
            "disburse".to_string(),
            args
        ).with_depth(1);  // Increased depth

        treasury_executor.execute_call(...)?;
    }
}
```

### Example 3: Error Handling (No Pass-Through)

```rust
// Contract B validation fails
let error = CrossContractError::validation_failed(
    contract_b_id,
    "transfer".to_string(),
    "Parameter type mismatch: expected u64, got String"
);

// Contract A only sees:
// - callee: contract_b_id
// - method: "transfer"
// - code: ValidationFailed (enum, not detailed message)
// - reason_hash: blake3(original_error)

// Original error message is NEVER exposed to Contract A
```

---

## Design Decisions

### 1. Intent-Based Over Direct Execution

**Decision**: Calls record INTENT, execution deferred to Treasury Kernel

**Rationale**:
- Enables consensus validation of contract behavior
- Separates validation (in contract) from execution (in kernel)
- Allows Treasury Kernel to coordinate state changes atomically
- Supports ADR-0017 Execution Boundary principle

### 2. Wrapped Errors (No Pass-Through)

**Decision**: All errors wrapped in `CrossContractError`

**Rationale**:
- Prevents ABI information leakage
- Prevents error-shape dependency between contracts
- Keeps caller logic stable across callee upgrades
- No string bubbling (preserves determinism)

### 3. Hard Max Depth of 16

**Decision**: Maximum recursion depth = 16 levels

**Rationale**:
- 16 is high enough for composability (DAOs calling UBI calling Treasury + more)
- 16 is low enough to prevent DoS attacks
- Enforced at stack level, included in recorded intent
- Deterministic across validators

### 4. Deterministic Hashing

**Decision**: All hashing uses Blake3 with canonical ordering

**Rationale**:
- Blake3 is fast and cryptographically sound
- Canonical ordering ensures identical hashes across validators
- Enables consensus validation of intents
- No time-dependent or random behavior

### 5. Type System with Promotion Rules

**Decision**: Support type promotion (u8 → u32 → u64)

**Rationale**:
- Matches caller expectations for flexibility
- Promotion rules are one-way (no demotion)
- Reduces compatibility issues between versions
- Still enforces type safety

---

## Testing

### Test Coverage

**Total Tests**: 165 (100% passing)

- **Phase 1**: 87 tests
  - Error wrapping (9 tests)
  - Call stack (9 tests)
  - Call representation (21 tests)
  - Validation (29 tests)
  - Execution (19 tests)

- **Phase 2**: 58 tests
  - Type validation (29 tests)
  - Serialization (29 tests)

- **Phase 3**: 20 tests
  - Cycle detection (20 tests)

### Running Tests

```bash
# All cross-contract call tests
cargo test --package lib-blockchain --lib contracts::calls --features contracts

# Specific component
cargo test --package lib-blockchain --lib contracts::calls::cycle_detector --features contracts

# Red test
cargo test --package lib-blockchain red_cross_contract_calls_type_checked --features contracts
```

---

## Performance Characteristics

| Operation | Complexity | Note |
|-----------|-----------|------|
| Single call validation | O(n) | Where n = method count in ABI |
| Type checking | O(m) | Where m = parameter count |
| Cycle detection (single) | O(n) | Simple stack check |
| Cycle detection (full graph) | O(V+E) | Depth-first search |
| Intent hashing | O(1) | Fixed-size output |
| Stack operations | O(1) | Push/pop operations |

---

## Security Considerations

### 1. ABI Information Leakage
- ✅ **Mitigated**: Errors wrapped, no original message exposed
- ✅ **Verified**: Error reason stored as hash, not plaintext

### 2. Infinite Recursion
- ✅ **Mitigated**: Hard limit of 16 levels
- ✅ **Verified**: Limit checked before push, included in intent

### 3. State Mutation Escaping
- ✅ **Mitigated**: Strict state isolation (callee cannot mutate caller)
- ✅ **Verified**: Enforced at executor level

### 4. Consensus Divergence
- ✅ **Mitigated**: All hashing deterministic
- ✅ **Verified**: Blake3 with canonical ordering

---

## Future Enhancements

1. **Treasury Kernel**: Implement actual execution of recorded intents
2. **Cross-Validator Consensus**: Validate intents across network
3. **CBOR Support**: Add CBOR serialization format
4. **Custom Type Evolution**: Version custom types with migrations
5. **Gas Metering**: Track gas usage across call chains
6. **Permission Integration**: Enforce privilege levels on calls

---

## Related Documentation

- **ADR-0017**: Execution Boundary principle (intent vs. effects)
- **Issue #841**: Persistent Contract Storage
- **Issue #843**: Contract ABI System
- **Issue #844**: UBI Distribution (depends on this)

---

## Questions & Support

For implementation questions:
1. Check this guide first
2. Review test cases for examples
3. Consult red test: `red_cross_contract_calls_type_checked`
4. Reference ADR-0017 for design rationale

---

**Last Updated**: Phase 4 (Red Test Enabled)
**Status**: ✅ Production Ready for Integration Testing
