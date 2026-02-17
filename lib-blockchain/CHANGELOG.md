# Changelog

All notable changes to the `lib-blockchain` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed - BREAKING CHANGES

#### Fork Detection and Chain Reorganization Logic (Issue #936)

As part of the BFT-A consensus implementation, all fork detection and chain reorganization (reorg) logic has been removed from the blockchain core. BFT consensus prevents forks through validator agreement, eliminating the need for fork recovery mechanisms.

**Breaking API Changes:**

The following types and functions have been **removed** from the public API:

- `ForkDetector` - Fork detection state and analysis
- `ForkPoint` - Fork divergence point information
- `ForkAnalysis` - Fork evaluation results
- `detect_fork()` - Fork detection function
- `evaluate_fork()` - Fork evaluation function
- `resolve_fork()` - Fork resolution/reorg function
- All fork-related configuration and state in `Blockchain`

**Migration Guide:**

If your code previously imported these types from `lib-blockchain`:

```rust
// OLD CODE - No longer works
use lib_blockchain::{ForkDetector, ForkPoint, ForkAnalysis};
let detector = ForkDetector::new();
```

**Remove these imports and related fork handling logic.** Under BFT consensus:

1. **Forks cannot occur** - Validator consensus ensures a single canonical chain
2. **Block conflicts are rejected** - If a different block already exists at a height, new proposals at that height are rejected
3. **No reorganization needed** - The chain progresses linearly through consensus

If you were using fork detection for diagnostic purposes, consider using the new block conflict detection in consensus integration, which logs when conflicting blocks are rejected.

**New Behavior:**

- When a block proposal arrives for a height where a different block already exists, the proposal is immediately rejected with an error
- The blockchain maintains a single linear chain through BFT validator consensus
- No fork evaluation or chain reorganization logic executes

For questions or migration assistance, please refer to Issue #936 or the BFT-A epic (#933).
