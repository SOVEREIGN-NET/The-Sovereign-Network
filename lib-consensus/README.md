# ZHTP Consensus Package

A modularized, multi-layered consensus system combining Proof of Stake, Proof of Storage, Proof of Useful Work, and Byzantine Fault Tolerance for the ZHTP blockchain network.

## Features

###Modular Architecture

- **Consensus Engines**: Pluggable consensus mechanisms (PoS, PoStorage, PoUW, Hybrid, BFT)
- **Validator Management**: Comprehensive validator registration, slashing, and lifecycle management
- **DAO Governance**: Integrated decentralized governance with proposals, voting, and treasury management
- **Byzantine Fault Tolerance**: Advanced fault detection and automatic remediation
- **Reward System**: Fair and transparent reward calculation and distribution
- **Proof Systems**: Cryptographic proofs for stake, storage, and useful work

###  Security Features

- **Post-Quantum Cryptography**: Integration with CRYSTALS-Dilithium signatures
- **ZK Proof Integration**: Zero-knowledge proofs for privacy and efficiency
- **Byzantine Fault Detection**: Automatic detection of double-signing, liveness violations, and invalid proposals
- **Slashing Mechanisms**: Economic penalties for misbehavior
- **Validator Jailing**: Temporary suspension for repeated violations

###  DAO Governance

- **Proposal System**: Create and manage governance proposals
- **Voting Mechanisms**: Weighted voting based on stake and reputation
- **Treasury Management**: Secure fund allocation and spending controls
- **Quorum Requirements**: Configurable participation thresholds
- **Execution Engine**: Automatic execution of passed proposals

### Economic Incentives

- **Multi-Type Rewards**: Rewards for validation, useful work, and participation
- **Dynamic Multipliers**: Adjustable reward rates for different work types
- **Delegation Support**: Stake delegation with commission rates
- **UBI Integration**: Universal Basic Income distribution through governance

## Architecture

```
lib-consensus/
├── src/
│   ├── engines/           # Consensus engine implementations
│   │   ├── consensus_engine.rs
│   │   ├── bft_engine.rs
│   │   └── hybrid_engine.rs
│   ├── validators/        # Validator management
│   │   ├── validator.rs
│   │   └── validator_manager.rs
│   ├── dao/              # DAO governance system
│   │   ├── dao_engine.rs
│   │   ├── dao_types.rs
│   │   ├── proposals.rs
│   │   ├── voting.rs
│   │   └── treasury.rs
│   ├── proofs/           # Cryptographic proof systems
│   │   ├── work_proof.rs
│   │   ├── stake_proof.rs
│   │   └── storage_proof.rs
│   ├── byzantine/        # Byzantine fault tolerance
│   │   ├── fault_detector.rs
│   │   └── bft_types.rs
│   ├── rewards/          # Reward calculation
│   │   ├── reward_calculator.rs
│   │   └── reward_types.rs
│   ├── types/            # Core data types
│   │   └── mod.rs
│   └── lib.rs
├── examples/
│   └── consensus_demo.rs
├── tests/
└── Cargo.toml
```

## Quick Start

### Basic Usage

```rust
use lib_consensus::{ConsensusEngine, ConsensusConfig, ConsensusType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize consensus with hybrid PoS + PoStorage
    let config = ConsensusConfig {
        consensus_type: ConsensusType::Hybrid,
        min_stake: 1000 * 1_000_000, // 1000 ZHTP
        min_storage: 100 * 1024 * 1024 * 1024, // 100 GB
        max_validators: 100,
        block_time: 10,
        ..Default::default()
    };

    let mut consensus = ConsensusEngine::new(config)?;

    // Register as validator
    consensus.register_validator(
        identity,
        stake_amount,
        storage_capacity,
        consensus_key,
        commission_rate,
        false, // not genesis
    ).await?;

    // Start consensus
    consensus.start_consensus().await?;

    Ok(())
}
```

### DAO Governance

```rust
// Create a proposal
let proposal_id = consensus.dao_engine_mut().create_dao_proposal(
    proposer_id,
    "Increase Validator Rewards".to_string(),
    "Proposal to increase base validator rewards by 20%".to_string(),
    DaoProposalType::EconomicParams,
    7, // 7 days voting period
).await?;

// Cast a vote
consensus.dao_engine_mut().cast_dao_vote(
    voter_id,
    proposal_id,
    DaoVoteChoice::Yes,
    Some("Supporting increased validator incentives".to_string()),
).await?;
```

### Validator Management

```rust
// Get validator statistics
let stats = consensus.validator_manager().get_validator_stats();
println!("Active validators: {}", stats.active_validators);
println!("Total stake: {} ZHTP", stats.total_stake);

// Check Byzantine threshold
let threshold = consensus.validator_manager().get_byzantine_threshold();
println!("Byzantine threshold: {} voting power", threshold);
```

## Consensus Types

### Proof of Stake (PoS)
- Validators are selected based on staked tokens
- Economic security through slashing
- Energy efficient

### Proof of Storage (PoStorage)
- Validators provide storage capacity to the network
- Storage challenges verify actual capacity
- Incentivizes decentralized storage

### Proof of Useful Work (PoUW)
- Rewards for actual network contributions
- Network routing, computation, and storage
- Balanced work distribution scoring

### Hybrid Consensus
- Combines PoS and PoStorage
- Validators need both stake and storage
- Enhanced security and utility

### Byzantine Fault Tolerance (BFT)
- 2/3+ majority required for decisions
- Immediate finality
- Handles up to 1/3 malicious validators

## Governance Features

### Proposal Types
- **Treasury Allocation**: Fund distribution decisions
- **Protocol Upgrades**: Network parameter changes
- **UBI Distribution**: Universal Basic Income parameters
- **Validator Updates**: Validator set modifications
- **Economic Parameters**: Fee structures and rewards
- **Emergency Actions**: Critical protocol fixes

### Voting Mechanisms
- **Weighted Voting**: Based on stake and reputation
- **Quorum Requirements**: Minimum participation thresholds
- **Time-Bounded**: Proposals have voting deadlines
- **Transparent**: All votes are recorded on-chain

### Treasury Management
- **Multi-Signature Security**: Requires consensus for spending
- **Budget Allocations**: Annual budget planning
- **Transaction History**: Complete audit trail
- **Reserve Management**: Emergency fund protection

## Security Model

### Byzantine Fault Detection
- **Double-Signing Detection**: Automatic identification of conflicting signatures
- **Liveness Monitoring**: Tracking validator participation
- **Invalid Proposal Detection**: Identifying malicious proposals

### Slashing Mechanisms
- **Double-Sign Slashing**: 5-10% stake penalty
- **Liveness Slashing**: 1-3% stake penalty for inactivity
- **Graduated Penalties**: Increasing severity for repeat offenses
- **Validator Jailing**: Temporary suspension from consensus

### Economic Security
- **Stake Requirements**: Minimum stake to participate
- **Commission Limits**: Maximum validator commission rates
- **Delegation Security**: Protected stake delegation
- **Reward Distribution**: Fair and transparent incentives

## Dependencies

- `lib-crypto`: Post-quantum cryptography and hashing
- `lib-identity`: Identity management and verification
- `lib-storage`: Distributed storage integration
- `lib-network`: Network communication protocols
- `lib-proofs`: Zero-knowledge proof systems

## Development

### Running Examples

```bash
# Run the consensus demo
cargo run --example consensus_demo --features="full"

# Run with DAO features only
cargo run --example consensus_demo --features="dao"
```

### Testing

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test validators::tests
cargo test dao::tests
cargo test byzantine::tests
```

### Features

- `default`: Full consensus system with all features
- `dao`: DAO governance functionality only
- `byzantine`: Byzantine fault tolerance only
- `rewards`: Reward calculation system only
- `ubi`: Universal Basic Income features
- `testing`: Additional testing utilities

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- ZHTP development team
- Post-quantum cryptography research community
- Blockchain consensus research community
