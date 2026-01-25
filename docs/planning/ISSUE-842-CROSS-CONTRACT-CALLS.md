# Issue #842: Cross-Contract Call Infrastructure

**Status**: PLANNING → IMPLEMENTATION
**Branch**: `feat/842-cross-contract-calls`
**Blocks**: #844 UBI Distribution
**Depends on**: ✅ #841, ✅ #843

---

## Design Decisions (LOCKED IN)

### 1. Call Expression Syntax
**Form**: `call <contract_id>::<method>(args...)`

**Rationale**:
- No dynamic dispatch (deterministic at validation time)
- ABI resolution is static and verifiable
- Easy to lint, type-check, statically analyze
- Prevents reflection-like abuse
- Protocol-level strictness, not a scripting language

**Example**:
```rust
call 0xABC123::transfer(recipient, amount)
call 0xDEF456::vote(proposal_id, vote_direction)
```

---

### 2. Intent Recording Format
**Primary**: Events (source of truth, append-only, consensus-visible)
**Secondary**: State entries (optional cache for replay/debugging)

**Event Schema**:
```rust
struct CrossContractCallIntent {
    caller: ContractId,
    callee: ContractId,
    method: String,
    args_hash: Hash,           // blake3(args)
    abi_hash: Hash,            // callee's ABI hash for versioning
    depth: u16,                // call depth (0 = top-level)
    timestamp_block: u64,      // block where call originated
}
```

**Critical Rule**: Events are authoritative. State is a cache, never authoritative.

---

### 3. Max Recursion Depth
**Hard Limit**: 16 (enforced at executor level)

**Rules**:
- Depth counter increments per cross-contract hop
- Depth is part of recorded intent (for replay validation)
- Exceeding limit → deterministic `CallDepthExceeded` error
- 16 is high enough for composability, low enough to prevent DoS

**Enforcement**:
```rust
if call_depth >= MAX_RECURSION_DEPTH {
    return Err(CrossContractError::CallDepthExceeded { depth: call_depth });
}
```

---

### 4. Error Propagation (NO Pass-Through)
**Model**: Wrap all errors in `CrossContractError`

```rust
pub struct CrossContractError {
    pub callee: ContractId,
    pub method: String,
    pub code: CalleeErrorCode,        // Only error category, not message
    pub reason_hash: Hash,            // blake3(original_error)
}
```

**Why**:
- Prevents ABI leakage between contracts
- Prevents error-shape dependency (caller doesn't know callee internals)
- Keeps caller logic stable across callee upgrades
- No string bubbling (prevents determinism issues)
- No panic forwarding (deterministic failures only)

**Mapping**:
```rust
pub enum CalleeErrorCode {
    ValidationFailed = 1,
    ExecutionFailed = 2,
    NotFound = 3,
    PermissionDenied = 4,
    Unknown = 99,
}
```

---

### 5. State Isolation (STRICT, NO EXCEPTIONS)
**Rule**: Callee cannot mutate caller state under any circumstances.

**What's Allowed**:
- Callee reads own state ✅
- Callee reads caller's public contract interface (ABI) ✅
- Callee records own state changes (as intent) ✅
- Callee returns values to caller ✅

**What's NOT Allowed**:
- Callee mutates caller's storage ❌
- Callee modifies caller's balance ❌
- Callee reads caller's private state ❌
- Callee accesses caller's event history ❌

**Rationale**: Preserves determinism, auditability, replay safety. Any looser model creates exploitability and fragility.

---

## Implementation Architecture

```
lib-blockchain/src/contracts/calls/
├── mod.rs                    # Module root, exports
├── call.rs                   # CrossContractCall struct
├── validator.rs              # CallValidator (parameter type checking)
├── executor.rs               # CallExecutor (safe execution)
├── stack.rs                  # CallStack (recursion tracking)
├── errors.rs                 # CrossContractError types
├── intent.rs                 # CrossContractCallIntent event
└── tests.rs                  # Integration tests
```

---

## Phase 1: Core Call Execution (1-2 days)

### Goals
- Enable basic contract-to-contract calls
- ABI lookup and parameter validation
- Call stack tracking
- Intent recording
- ~10-12 tests

### Deliverables

#### 1.1: CrossContractCall struct (call.rs)
```rust
pub struct CrossContractCall {
    pub caller: ContractId,
    pub callee: ContractId,
    pub method: String,
    pub args: Vec<u8>,              // Serialized arguments
    pub depth: u16,
}

impl CrossContractCall {
    pub fn new(caller: ContractId, callee: ContractId, method: String, args: Vec<u8>) -> Self { ... }
    pub fn with_depth(mut self, depth: u16) -> Self { ... }
}
```

#### 1.2: CallValidator (validator.rs)
```rust
pub struct CallValidator;

impl CallValidator {
    pub fn validate_parameters(
        call: &CrossContractCall,
        abi: &ContractAbi,
    ) -> Result<()> { ... }

    pub fn validate_return_type(
        abi: &ContractAbi,
        method: &str,
        return_value: &[u8],
    ) -> Result<()> { ... }
}
```

#### 1.3: CallStack (stack.rs)
```rust
pub struct CallStack {
    depth: u16,
    chain: Vec<(ContractId, String)>,  // (caller, method)
}

impl CallStack {
    pub fn new() -> Self { ... }
    pub fn push(&mut self, contract: ContractId, method: String) -> Result<u16> { ... }
    pub fn pop(&mut self) { ... }
    pub fn current_depth(&self) -> u16 { ... }
    pub fn chain(&self) -> &[(ContractId, String)] { ... }
}
```

#### 1.4: CallExecutor (executor.rs)
```rust
pub struct CallExecutor {
    abi_registry: Arc<AbiRegistry>,
    call_stack: RefCell<CallStack>,
}

impl CallExecutor {
    pub fn execute_call(
        &self,
        call: CrossContractCall,
        executor: &ContractExecutor,
    ) -> Result<CrossContractCallResult> { ... }

    fn record_intent(&self, call: &CrossContractCall) -> Result<()> { ... }
}
```

#### 1.5: CrossContractCallIntent (intent.rs)
```rust
pub struct CrossContractCallIntent {
    pub caller: ContractId,
    pub callee: ContractId,
    pub method: String,
    pub args_hash: [u8; 32],
    pub abi_hash: [u8; 32],
    pub depth: u16,
    pub timestamp_block: u64,
}

impl CrossContractCallIntent {
    pub fn hash(&self) -> [u8; 32] { ... }
}
```

#### 1.6: Error Types (errors.rs)
```rust
pub struct CrossContractError {
    pub callee: ContractId,
    pub method: String,
    pub code: CalleeErrorCode,
    pub reason_hash: [u8; 32],
}

pub enum CalleeErrorCode {
    ValidationFailed = 1,
    ExecutionFailed = 2,
    NotFound = 3,
    PermissionDenied = 4,
    CallDepthExceeded = 5,
    Unknown = 99,
}
```

### Tests (Phase 1)
- `test_create_cross_contract_call` - Basic call construction
- `test_call_stack_depth_tracking` - Push/pop operations
- `test_call_stack_max_depth_enforcement` - Reject depth > 16
- `test_validate_parameters_success` - Valid parameters pass
- `test_validate_parameters_type_mismatch` - Invalid types rejected
- `test_validate_return_type_success` - Valid returns accepted
- `test_intent_hashing_deterministic` - Same intent → same hash
- `test_intent_recording_format` - Intent has required fields
- `test_abi_lookup_missing_callee` - Handle unknown contracts
- `test_abi_lookup_missing_method` - Handle unknown methods
- `test_call_execution_basic` - End-to-end basic call
- `test_call_executor_integration_with_abi_registry` - Registry integration

---

## Phase 2: Type Safety & Version Compatibility (1-2 days)

### Goals
- Comprehensive type validation
- Version compatibility matrix
- Better error messages
- ~8-10 tests

### Components
- Enhanced `CallValidator` with full type checking
- `VersionCompatibilityChecker`
- Serialization format validation
- Return type coercion rules

### Tests (Phase 2)
- Type mismatch detection (each primitive type)
- Array type validation
- Optional/custom type validation
- Version incompatibility detection
- SemVer backward compatibility
- Error messages clarity

---

## Phase 3: Recursion Prevention & Safety (1 day)

### Goals
- Cycle detection
- Prevent infinite loops
- Track full call chain
- ~5-7 tests

### Components
- Cycle detection algorithm
- Call chain monitoring
- Early termination on cycles
- Audit trail of call path

### Tests (Phase 3)
- Simple cycle (A → B → A)
- Complex cycle (A → B → C → A)
- Self-call (A → A)
- Deep chain (A → B → ... → P)
- Cycle detection accuracy

---

## Phase 4: Red Tests & Documentation (1 day)

### Goals
- Enable `red_cross_contract_calls_type_checked`
- Create implementation guide
- Document integration points
- Ready for #844 UBI Distribution

### Tasks
- Uncomment and enable red test
- Create IMPLEMENTATION_GUIDE.md
- Document ABI registry integration
- Add examples
- PR review and merge

---

## Integration Points

### With AbiRegistry (#843)
- Load callee's ABI for validation
- Verify method exists and signature matches
- Check version compatibility

### With ContractExecutor (#841)
- Access current contract context
- Record intents in contract state
- Emit call events
- Participate in finalize_block_state()

### With Treasury Kernel (future)
- Intents become executable items
- Kernel validates call depth
- Kernel executes actual state changes

---

## Success Criteria

**All tests pass**:
- Phase 1: 12 tests ✅
- Phase 2: 10 tests ✅
- Phase 3: 7 tests ✅
- Phase 4: red_cross_contract_calls_type_checked enabled ✅

**Code quality**:
- No compiler warnings
- Full documentation
- Integration tested
- Follows project patterns

**Determinism verified**:
- Same calls → same hashes
- Replay produces identical results
- No random/time-dependent behavior

---

## Next Steps After #842

Once complete:
1. Start Treasury Kernel implementation (critical path)
2. Begin #844 UBI Distribution (unblocked by #842 completion)
3. Cross-contract composability testing
