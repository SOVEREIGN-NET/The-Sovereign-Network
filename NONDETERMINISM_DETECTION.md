# Fail-Fast Nondeterminism Detection

This document describes the nondeterminism detection system implemented to prevent chain splits and consensus failures in the ZHTP blockchain.

## Problem Statement

Blockchain consensus requires **deterministic execution** across all validators. When different validators execute the same block but arrive at different results due to nondeterministic inputs, chain splits occur.

Common sources of nondeterminism:
- **Wall-clock time**: `SystemTime::now()`, `chrono::Utc::now()`
- **Random number generation**: `rand::random()`, `OsRng`
- **Thread scheduling and timing**
- **Network timing and ordering**
- **Floating-point arithmetic** (hardware-dependent)

## Solution: Runtime Guards

This implementation adds **fail-fast runtime detection** that immediately panics when nondeterministic operations are attempted during consensus-critical sections.

### Architecture

#### 1. Consensus Engine Guards (`lib-consensus/src/engines/consensus_engine/validation.rs`)

The consensus engine defines a `determinism_guard` module that tracks when consensus-critical operations are active:

```rust
pub(super) mod determinism_guard {
    static CONSENSUS_ACTIVE: AtomicBool = AtomicBool::new(false);

    pub fn enter_consensus_scope();
    pub fn exit_consensus_scope();
    pub fn is_consensus_active() -> bool;

    #[track_caller]
    pub fn assert_no_nondeterminism(operation: &str);
}
```

#### 2. Scoped Guards (`lib-consensus/src/engines/consensus_engine/state_machine.rs`)

Critical consensus operations wrap their execution with scope guards:

```rust
pub(super) async fn on_prevote(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
    // GUARD: Enter consensus-critical section
    determinism_guard::enter_consensus_scope();
    let _guard = scopeguard::guard((), |_| {
        determinism_guard::exit_consensus_scope();
    });

    // ... consensus validation logic ...
}
```

Protected operations:
- `on_prevote()` - PreVote processing
- `on_precommit()` - PreCommit processing
- `on_commit_vote()` - Commit vote processing

#### 3. Blockchain Utility Guards (`lib-blockchain/src/utils.rs`)

Time and randomness utilities include runtime assertions:

```rust
pub fn current_timestamp() -> u64 {
    if is_consensus_validation_active() {
        panic!(
            "FATAL: current_timestamp() called during consensus validation at {}. \
            This is a nondeterministic operation that can cause chain splits.",
            std::panic::Location::caller()
        );
    }
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn random_hash() -> Hash {
    if time::is_consensus_validation_active() {
        panic!(
            "FATAL: random_hash() called during consensus validation at {}. \
            This is a nondeterministic operation that can cause chain splits.",
            std::panic::Location::caller()
        );
    }
    // ... random generation ...
}
```

## Usage Guidelines

### Safe Operations During Consensus

These operations are **safe** during consensus validation:
- Reading block timestamps from validated blocks
- Deterministic hash computations
- Signature verification
- State machine transitions based on validated inputs
- Database reads of committed state

### Unsafe Operations During Consensus

These operations will **panic** if attempted during consensus validation:
- `crate::utils::time::current_timestamp()` - wall-clock time
- `crate::utils::hash::random_hash()` - random generation
- Any operation that depends on system time or randomness

### Adding New Protected Operations

To protect new consensus-critical code:

```rust
use super::validation::determinism_guard;

pub async fn my_consensus_operation(&mut self) -> Result<()> {
    determinism_guard::enter_consensus_scope();
    let _guard = scopeguard::guard((), |_| {
        determinism_guard::exit_consensus_scope();
    });

    // Your consensus logic here
    // Any nondeterministic calls will panic

    Ok(())
}
```

## Testing

The implementation includes comprehensive tests:

### Consensus Engine Tests
- `lib-consensus/src/engines/consensus_engine/nondeterminism_tests.rs`
- Tests guard activation/deactivation
- Tests panic behavior during violations
- Tests cleanup with scope guards

### Blockchain Utility Tests
- `lib-blockchain/src/utils/nondeterminism_tests.rs`
- Tests time utility guards
- Tests random hash guards
- Tests integration with consensus validation state

Run tests:
```bash
cargo test --package lib-consensus nondeterminism
cargo test --package lib-blockchain nondeterminism
```

## Implementation Notes

### Why Fail-Fast?

The system panics immediately on nondeterminism violations rather than logging warnings because:

1. **Chain splits are catastrophic** - They can't be automatically recovered
2. **Early detection is critical** - Finding issues in testing, not production
3. **Clear failure modes** - Panic location shows exactly what went wrong
4. **Forces correct patterns** - Developers must use deterministic alternatives

### Performance Impact

The guards use atomic operations with `SeqCst` ordering to ensure correct behavior across threads. The performance impact is minimal:
- Single atomic read per protected operation
- No lock contention
- No allocation
- Negligible overhead compared to consensus operations

### Safe Time Usage

For operations that legitimately need time (logging, metrics, expiry checks):

```rust
// SAFETY: This time access is for Byzantine detection logging, not consensus logic
let current_time = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs();
```

Add a `SAFETY` comment explaining why the time access is acceptable.

## Future Enhancements

Potential improvements:
1. **Compile-time enforcement** - Use type system to prevent nondeterministic calls
2. **Audit logging** - Track all time/random accesses for analysis
3. **Configurable guards** - Enable/disable in different build modes
4. **Additional protected ops** - Extend to cover more operations
5. **Integration tests** - End-to-end scenarios testing guard behavior

## Related Issues

- Issue #953: Fail-fast nondeterminism detection
- CONSENSUS-NET-4.2: Vote validation determinism
- CONSENSUS-NET-4.3: Height-scoped validator membership

## References

- [Byzantine Fault Tolerance](https://en.wikipedia.org/wiki/Byzantine_fault)
- [Deterministic execution in blockchains](https://ethereum.org/en/developers/docs/evm/)
- [Consensus safety properties](https://decentralizedthoughts.github.io/2019-06-01-2019-5-31-models/)
