# Difficulty Parameter Governance System

> **Version:** 1.0.0  
> **Last Updated:** January 2026  
> **Status:** Production

This document describes the architecture, governance flow, and operational procedures for the adaptive difficulty adjustment system in The Sovereign Network.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Design Principles](#design-principles)
4. [System Components](#system-components)
5. [Governance Flow](#governance-flow)
6. [Default Parameters](#default-parameters)
7. [Governance Guide](#governance-guide)
8. [API Reference](#api-reference)
9. [Examples](#examples)
10. [Troubleshooting](#troubleshooting)
11. [Safety Considerations](#safety-considerations)

---

## Overview

The Difficulty Parameter Governance System enables DAO-controlled adjustment of blockchain mining difficulty parameters. Unlike traditional blockchains with hardcoded difficulty rules, The Sovereign Network allows validators and token holders to propose and vote on difficulty parameter changes through decentralized governance.

### Key Features

- **DAO-Controlled**: All parameter changes require community voting
- **Deterministic**: Calculations depend only on chain data, not wall-clock time
- **Safe**: Built-in clamping prevents extreme difficulty swings
- **Auditable**: All changes tracked on-chain with block height timestamps
- **Backward Compatible**: Default parameters match Bitcoin-style behavior

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DIFFICULTY GOVERNANCE ARCHITECTURE                │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   lib-blockchain │     │   lib-consensus  │     │    lib-proofs    │
│                  │     │                  │     │                  │
│ ┌──────────────┐ │     │ ┌──────────────┐ │     │ ┌──────────────┐ │
│ │DifficultyConf│◄├─────┤►│DifficultyMgr │ │     │ │ ZK Proofs    │ │
│ │   (state)    │ │     │ │  (policy)    │ │     │ │ (validation) │ │
│ └──────────────┘ │     │ └──────────────┘ │     │ └──────────────┘ │
│                  │     │                  │     │                  │
│ ┌──────────────┐ │     │ ┌──────────────┐ │     └──────────────────┘
│ │ Blockchain   │ │     │ │  DaoEngine   │ │
│ │adjust_diff() │◄├─────┤►│(proposals)   │ │
│ └──────────────┘ │     │ └──────────────┘ │
└──────────────────┘     └──────────────────┘

        │                        │
        └────────────┬───────────┘
                     ▼
            ┌────────────────┐
            │  Governance    │
            │    Flow        │
            │                │
            │ 1. Propose     │
            │ 2. Vote        │
            │ 3. Execute     │
            │ 4. Apply       │
            └────────────────┘
```

### Component Responsibilities

| Component | Package | Responsibility |
|-----------|---------|----------------|
| `DifficultyConfig` | lib-blockchain | Stores active parameters, validation |
| `DifficultyManager` | lib-consensus | Owns difficulty policy, calculations |
| `DaoEngine` | lib-consensus | Manages proposals, voting |
| `Blockchain` | lib-blockchain | Applies updates, uses config |
| `BlockchainConsensusCoordinator` | lib-blockchain | Bridges blockchain ↔ consensus |

---

## Design Principles

### 1. Separation of Concerns

**Consensus Owns Policy**: The difficulty adjustment policy (when to adjust, how much to change) is owned by `lib-consensus`. The blockchain layer stores state and delegates calculations.

```
lib-consensus (policy)     lib-blockchain (state)
        │                         │
        ▼                         ▼
  DifficultyManager ──────► DifficultyConfig
  - calculate_new_difficulty()    - target_timespan
  - should_adjust()               - adjustment_interval
  - apply_governance_update()     - last_updated_at_height
```

### 2. Determinism

All difficulty calculations depend **only on chain data**:
- Block timestamps (from chain)
- Current difficulty (from chain state)
- Configuration parameters (from governance state)

**No wall-clock time is used**. This ensures:
- Identical results when replaying from genesis
- Reproducible calculations from any block height
- Auditable difficulty history

### 3. Governance Integration

Parameter changes flow through the standard DAO governance system:
1. Proposals require minimum voting power to create
2. Voting period allows community deliberation
3. Timelock delay prevents rushed changes
4. Execution is transparent and on-chain

### 4. State Persistence

Configuration state is:
- Serialized with blockchain state
- Tracked with `last_updated_at_height` for audit
- Recoverable from any blockchain snapshot

---

## System Components

### DifficultyConfig (lib-blockchain)

Stores the active difficulty adjustment parameters.

```rust
pub struct DifficultyConfig {
    /// Target time for adjustment interval (seconds)
    /// Default: 1,209,600 (14 days)
    pub target_timespan: u64,

    /// Blocks between difficulty adjustments
    /// Default: 2016 blocks
    pub adjustment_interval: u64,

    /// Max factor difficulty can decrease per adjustment
    /// Default: 4 (difficulty can quarter)
    pub max_difficulty_decrease_factor: u64,

    /// Max factor difficulty can increase per adjustment
    /// Default: 4 (difficulty can quadruple)
    pub max_difficulty_increase_factor: u64,

    /// Block height when config was last updated
    /// Used for governance tracking
    pub last_updated_at_height: u64,
}
```

### DifficultyParameterUpdateData (lib-blockchain)

Data structure for governance proposals.

```rust
pub struct DifficultyParameterUpdateData {
    pub target_timespan: u64,
    pub adjustment_interval: u64,
    pub min_adjustment_factor: Option<u64>,
    pub max_adjustment_factor: Option<u64>,
}
```

### DifficultyManager (lib-consensus)

Owns the difficulty policy and performs calculations.

```rust
pub struct DifficultyManager {
    config: DifficultyConfig,
}

impl DifficultyManager {
    pub fn should_adjust(&self, height: u64) -> bool;
    pub fn calculate_new_difficulty(&self, current: u32, actual_timespan: u64) -> Result<u32>;
    pub fn apply_governance_update(&mut self, ...) -> Result<()>;
}
```

---

## Governance Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     DIFFICULTY PARAMETER GOVERNANCE FLOW                 │
└─────────────────────────────────────────────────────────────────────────┘

    ┌─────────────┐
    │  PROPOSAL   │  User creates DifficultyParameterUpdate proposal
    │  CREATION   │  - Requires 50,000+ CBE voting power
    │             │  - Validates target_timespan > 0
    │             │  - Validates adjustment_interval > 0
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │   VOTING    │  Community votes on proposal
    │   PERIOD    │  - Duration: 7-14 days (configurable)
    │             │  - Quorum required: 30%
    │             │  - Simple majority (>50% yes) to pass
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │  TIMELOCK   │  Mandatory delay before execution
    │   DELAY     │  - Duration: 7 days
    │             │  - Allows emergency intervention
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │  EXECUTION  │  Blockchain::apply_difficulty_parameter_update()
    │             │  - Decodes proposal parameters
    │             │  - Validates all values
    │             │  - Updates DifficultyConfig
    │             │  - Syncs with consensus coordinator
    │             │  - Records last_updated_at_height
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │   ACTIVE    │  New parameters take effect
    │             │  - Next adjust_difficulty() uses new config
    │             │  - All validators use updated parameters
    └─────────────┘
```

### Quorum and Voting Requirements

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Quorum Required | 30% | Same as protocol upgrades (high-impact change) |
| Approval Threshold | >50% | Simple majority |
| Min Voting Power to Propose | 50,000 CBE | Prevents spam proposals |
| Timelock Delay | 7 days | Time for validators to prepare |
| Voting Period | 7-14 days | Adequate deliberation time |

---

## Default Parameters

### Bitcoin-Compatible Defaults

| Parameter | Default Value | Rationale |
|-----------|--------------|-----------|
| `target_timespan` | 1,209,600 sec (14 days) | Bitcoin compatibility, proven stability |
| `adjustment_interval` | 2016 blocks | ~2 weeks at 10-min blocks |
| `max_difficulty_increase_factor` | 4 | Prevents >4x difficulty jump |
| `max_difficulty_decrease_factor` | 4 | Prevents >75% difficulty drop |
| `target_block_time` | 600 sec (10 min) | Derived: 1,209,600 / 2016 |

### Validation Limits

| Parameter | Minimum | Maximum | Rationale |
|-----------|---------|---------|-----------|
| `target_timespan` | 1 second | 1 year | Practical bounds |
| `adjustment_interval` | 1 block | 1,000,000 blocks | Practical bounds |
| `max_difficulty_*_factor` | 1 | 100 | Safety limits |

---

## Governance Guide

### How to Propose Difficulty Parameter Changes

#### Step 1: Prepare the Proposal

```rust
use lib_blockchain::types::DifficultyParameterUpdateData;

// Create proposal data
let update = DifficultyParameterUpdateData::new(
    7 * 24 * 60 * 60,  // 1 week target_timespan
    1008,              // 1008 blocks adjustment_interval
).expect("Valid parameters");

// Or with custom factors
let update = DifficultyParameterUpdateData::new_with_factors(
    7 * 24 * 60 * 60,
    1008,
    Some(2),  // min_adjustment_factor (limits decrease)
    Some(8),  // max_adjustment_factor (allows larger increase)
).expect("Valid parameters");
```

#### Step 2: Submit Through DAO

```rust
use lib_consensus::DaoProposalType;

// Create the proposal through consensus
let proposal_id = blockchain.create_dao_proposal(
    proposer_identity,
    "Reduce adjustment interval for faster responsiveness",
    "This proposal reduces the difficulty adjustment interval from 2016 to 1008 blocks...",
    DaoProposalType::DifficultyParameterUpdate,
).await?;
```

#### Step 3: Monitor Voting

```rust
// Check proposal status
let proposal = blockchain.get_dao_proposal(&proposal_id)?;
let (yes, no, abstain, total) = blockchain.tally_dao_votes(&proposal_id);

println!("Votes: {} yes, {} no, {} abstain", yes, no, abstain);
println!("Quorum needed: 30% of {}", total);
```

### How to Vote on Difficulty Proposals

```rust
use lib_consensus::DaoVoteChoice;

// Cast a vote
blockchain.cast_dao_vote(
    voter_identity,
    proposal_id,
    DaoVoteChoice::Yes,  // or No, Abstain
).await?;

// Verify your vote was recorded
let votes = blockchain.get_dao_votes_for_proposal(&proposal_id);
```

### Safety Considerations

1. **Test on Testnet First**: Always test parameter changes on testnet before mainnet proposals

2. **Consider Mining Economics**: Faster adjustment intervals can destabilize mining rewards

3. **Gradual Changes**: Prefer incremental changes over dramatic shifts

4. **Coordinate with Validators**: Ensure validators are prepared for the change

5. **Monitor After Activation**: Watch block times and difficulty for unexpected behavior

---

## API Reference

### DifficultyConfig Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new()` | `fn new() -> Self` | Create with defaults |
| `with_params()` | `fn with_params(...) -> Result<Self>` | Create with validation |
| `validate()` | `fn validate(&self) -> Result<()>` | Validate all parameters |
| `target_block_time()` | `fn target_block_time(&self) -> u64` | Calculate target block time |
| `clamp_timespan()` | `fn clamp_timespan(&self, actual: u64) -> u64` | Clamp timespan to safe range |

### Blockchain Methods

| Method | Description |
|--------|-------------|
| `get_difficulty_config()` | Get current difficulty configuration |
| `set_difficulty_config()` | Update configuration (validates first) |
| `apply_difficulty_parameter_update()` | Apply passed governance proposal |
| `adjust_difficulty()` | Perform difficulty adjustment using config |

### DifficultyParameterUpdateData Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new()` | `fn new(target_timespan, adjustment_interval) -> Result<Self>` | Create with required fields |
| `new_with_factors()` | `fn new_with_factors(...) -> Result<Self>` | Create with all fields |
| `validate()` | `fn validate(&self) -> Result<()>` | Validate all parameters |
| `target_block_time_secs()` | `fn target_block_time_secs(&self) -> u64` | Calculate target block time |
| `with_min_factor()` | `fn with_min_factor(self, factor: u64) -> Self` | Builder: set min factor |
| `with_max_factor()` | `fn with_max_factor(self, factor: u64) -> Self` | Builder: set max factor |

---

## Examples

### Example 1: Create a Difficulty Parameter Update Proposal

```rust
use lib_blockchain::types::DifficultyParameterUpdateData;

// Prepare the parameter update
let update = DifficultyParameterUpdateData::new(
    7 * 24 * 60 * 60,  // Reduce to 1 week target
    1008,              // Reduce to 1008 blocks
).expect("Valid parameters");

// Verify the proposal is valid
assert!(update.validate().is_ok());

// Calculate new target block time
let block_time = update.target_block_time_secs();
println!("New target block time: {} seconds", block_time);  // 600 seconds

// Submit proposal through DAO
let proposal_id = blockchain.create_dao_proposal(
    proposer_id,
    "Faster difficulty adjustments",
    "Proposal to reduce adjustment interval...",
    DaoProposalType::DifficultyParameterUpdate,
).await?;

println!("Proposal created: {:?}", proposal_id);
```

### Example 2: Process a Governance Vote

```rust
use lib_consensus::DaoVoteChoice;

// Cast votes from multiple validators
for validator in active_validators {
    blockchain.cast_dao_vote(
        validator.identity_id,
        proposal_id,
        DaoVoteChoice::Yes,
    ).await?;
}

// Check if proposal passed
let passed = blockchain.has_proposal_passed(&proposal_id, 30)?;
if passed {
    println!("Proposal passed! Will execute after timelock.");
}

// After timelock, apply the update
if passed {
    blockchain.apply_difficulty_parameter_update(proposal_id)?;
    println!("Difficulty parameters updated!");
}
```

### Example 3: Verify Parameter Changes Applied

```rust
// Before the update
let old_config = blockchain.get_difficulty_config().clone();

// Apply the update
blockchain.apply_difficulty_parameter_update(proposal_id)?;

// After the update
let new_config = blockchain.get_difficulty_config();

// Verify changes
assert_ne!(old_config.target_timespan, new_config.target_timespan);
assert_eq!(new_config.last_updated_at_height, blockchain.height);

println!("target_timespan: {} → {}", 
    old_config.target_timespan, 
    new_config.target_timespan
);
println!("Updated at block height: {}", new_config.last_updated_at_height);
```

---

## Troubleshooting

### How to Detect if Parameters Changed

```rust
// Check last_updated_at_height
let config = blockchain.get_difficulty_config();
if config.last_updated_at_height > 0 {
    println!("Parameters were updated at block {}", config.last_updated_at_height);
}

// Compare with defaults
let defaults = DifficultyConfig::default();
if config.target_timespan != defaults.target_timespan {
    println!("target_timespan differs from default: {} vs {}", 
        config.target_timespan, defaults.target_timespan);
}
if config.adjustment_interval != defaults.adjustment_interval {
    println!("adjustment_interval differs from default: {} vs {}",
        config.adjustment_interval, defaults.adjustment_interval);
}
```

### How to Audit Parameter Change History

```rust
// Get all executed governance proposals
let executed_proposals = &blockchain.executed_dao_proposals;

// Filter for difficulty parameter updates
for proposal_id in executed_proposals {
    if let Some(proposal) = blockchain.get_dao_proposal(proposal_id) {
        // Check proposal type (requires parsing proposal data)
        println!("Executed proposal: {:?}", proposal_id);
        println!("  Title: {}", proposal.title);
        println!("  Description: {}", proposal.description);
    }
}

// Current config shows when it was last updated
let config = blockchain.get_difficulty_config();
println!("Current config last updated at block: {}", config.last_updated_at_height);
```

### How to Rollback Bad Parameter Changes

**Important**: There is no automatic rollback mechanism. To revert parameter changes, you must create a new governance proposal with the desired (original) parameters.

```rust
use lib_blockchain::types::DifficultyParameterUpdateData;

// Create a rollback proposal with original values
let rollback_update = DifficultyParameterUpdateData::new(
    14 * 24 * 60 * 60,  // Restore 2-week target (default)
    2016,               // Restore 2016 blocks (default)
).expect("Valid parameters");

// Submit as new proposal
let rollback_proposal_id = blockchain.create_dao_proposal(
    proposer_id,
    "ROLLBACK: Restore original difficulty parameters",
    "This proposal restores the original Bitcoin-compatible difficulty parameters...",
    DaoProposalType::DifficultyParameterUpdate,
).await?;

// The rollback proposal goes through normal voting process
// Coordinate with community for expedited voting if urgent
```

### Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| "InvalidProposal: Proposal not found" | Invalid or non-existent proposal_id | Verify proposal exists with `get_dao_proposal()` |
| "InvalidProposal: Proposal has not passed voting" | Insufficient votes or quorum not met | Wait for more votes or check voting status |
| "ParameterValidationError: target_timespan cannot be zero" | Invalid parameter value | Use a value > 0 |
| "ParameterValidationError: adjustment_interval cannot be zero" | Invalid parameter value | Use a value > 0 |
| Parameters not taking effect | Proposal not yet executed | Call `apply_difficulty_parameter_update()` after timelock expires |
| Double-execution attempt | Proposal already applied | Safe to ignore - method returns `Ok(())` for idempotency |

---

## Safety Considerations

### Clamping Mechanism

The difficulty adjustment is clamped to prevent extreme changes:

```
                    min_timespan                max_timespan
                         │                           │
                         ▼                           ▼
    ◄────────────────────┼───────────┼───────────────┼────────────────────►
                         │           │               │
                    target/4    target_timespan   target*4
                         │           │               │
                         │     (no clamping)         │
                         │           │               │
    Difficulty can       │           │               │    Difficulty can
    increase by max 4x   │           │               │    decrease by max 4x
```

**Example with default config:**
- `target_timespan` = 1,209,600 seconds (14 days)
- `max_difficulty_increase_factor` = 4
- `max_difficulty_decrease_factor` = 4
- **min_timespan** = 1,209,600 / 4 = 302,400 seconds (3.5 days)
- **max_timespan** = 1,209,600 × 4 = 4,838,400 seconds (56 days)

If blocks come faster than 3.5 days for 2016 blocks, difficulty increases by max 4x.
If blocks come slower than 56 days for 2016 blocks, difficulty decreases by max 4x.

### Validation Rules

All parameters are validated before being applied:

1. **target_timespan**: Must be > 0 and ≤ 31,536,000 (1 year in seconds)
2. **adjustment_interval**: Must be > 0 and ≤ 1,000,000 blocks
3. **max_difficulty_decrease_factor**: Must be > 0 and ≤ 100
4. **max_difficulty_increase_factor**: Must be > 0 and ≤ 100
5. **max_adjustment_factor ≥ min_adjustment_factor**: If both specified in proposal

### Historical Precedents

| Network | target_timespan | adjustment_interval | target_block_time | Notes |
|---------|-----------------|---------------------|-------------------|-------|
| Bitcoin | 2 weeks | 2016 blocks | 10 min | Original design, proven stable since 2009 |
| Litecoin | 3.5 days | 2016 blocks | 2.5 min | 4x faster blocks |
| Dogecoin | 4 hours | 240 blocks | 1 min | Very fast adjustment |
| **ZHTP (default)** | 2 weeks | 2016 blocks | 10 min | Bitcoin-compatible |

### Recommendations for Parameter Changes

1. **Don't reduce `adjustment_interval` below 100 blocks** without extensive testing
   - Very frequent adjustments can cause oscillation

2. **Don't increase factors above 8x** to maintain mining stability
   - Extreme swings can discourage miners

3. **Test all changes on testnet** for at least one full adjustment period
   - Observe actual behavior before mainnet

4. **Document the rationale** thoroughly in proposal description
   - Future governance participants need context

5. **Consider economic impact** on miners and validators
   - Sudden changes affect profitability

---

## Related Documentation

- [NETWORK_RULES.md](NETWORK_RULES.md) - Network consensus rules
- [NODE_CONNECTION_GUIDE.md](NODE_CONNECTION_GUIDE.md) - Node operation guide
- [CONSENSUS_BLOCKCHAIN_INTEGRATION.md](CONSENSUS_BLOCKCHAIN_INTEGRATION.md) - Consensus layer integration

---

## Glossary

| Term | Definition |
|------|------------|
| **target_timespan** | The desired total time for `adjustment_interval` blocks |
| **adjustment_interval** | Number of blocks between difficulty recalculations |
| **target_block_time** | Derived value: `target_timespan / adjustment_interval` |
| **clamping** | Limiting timespan to prevent extreme difficulty changes |
| **quorum** | Minimum percentage of votes required for proposal validity |
| **timelock** | Mandatory delay between proposal passing and execution |

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | January 2026 | Initial documentation for Issue #605 |
