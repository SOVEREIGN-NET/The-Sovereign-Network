# ZHTP Consensus Documentation

Welcome to the ZHTP Consensus documentation. This directory contains comprehensive documentation about the ZHTP consensus mechanism.

## Documentation Structure

### Core Documentation

- **[CONSENSUS_MECHANISM.md](CONSENSUS_MECHANISM.md)** - Complete documentation of the ZHTP consensus mechanism
  - Architecture overview
  - Consensus process details
  - Security features
  - DAO governance
  - Reward system
  - Configuration and monitoring

- **[DIFFICULTY_GOVERNANCE.md](DIFFICULTY_GOVERNANCE.md)** - Comprehensive difficulty parameter governance documentation
  - Adaptive difficulty adjustment for PoUW consensus
  - Governance flow and DAO integration
  - Parameter validation and configuration
  - API reference and examples

### API Reference

- **[API_REFERENCE.md](api-reference.md)** - API documentation for consensus components
  - Consensus engine interfaces
  - Validator management APIs
  - DAO governance APIs
  - Reward calculation APIs

### Architecture

- **[ARCHITECTURE.md](architecture/)** - Detailed architecture documentation
  - Component diagrams
  - Data flow diagrams
  - Module interactions
  - Design patterns

### Modules

#### Byzantine Fault Tolerance
- **[bft_types.md](modules/bft_types.md)** - Byzantine fault types and detection
- **[evidence.md](modules/evidence.md)** - Evidence production and handling
- **[fault_detector.md](modules/fault_detector.md)** - Fault detection algorithms

#### DAO Governance
- **[dao_engine.md](modules/dao_engine.md)** - DAO engine implementation
- **[dao_types.md](modules/dao_types.md)** - DAO data structures
- **[proposals.md](modules/proposals.md)** - Proposal management
- **[voting.md](modules/voting.md)** - Voting mechanisms
- **[treasury.md](modules/treasury.md)** - Treasury management

#### Engines
- **[consensus_engine.md](modules/consensus_engine.md)** - Main consensus engine
- **[bft_engine.md](modules/bft_engine.md)** - BFT engine
- **[hybrid_engine.md](modules/hybrid_engine.md)** - Hybrid consensus engine
- **[enhanced_bft_engine.md](modules/enhanced_bft_engine.md)** - Enhanced BFT with ZK

#### Proofs
- **[stake_proof.md](modules/stake_proof.md)** - Proof of Stake implementation
- **[storage_proof.md](modules/storage_proof.md)** - Proof of Storage implementation
- **[work_proof.md](modules/work_proof.md)** - Proof of Useful Work implementation

#### Rewards
- **[reward_calculator.md](modules/reward_calculator.md)** - Reward calculation algorithms
- **[reward_types.md](modules/reward_types.md)** - Reward data structures

#### Validators
- **[validator.md](modules/validator.md)** - Validator implementation
- **[validator_manager.md](modules/validator_manager.md)** - Validator management
- **[validator_discovery.md](modules/validator_discovery.md)** - Validator discovery
- **[validator_protocol.md](modules/validator_protocol.md)** - Validator protocols

#### Network
- **[liveness_monitor.md](modules/liveness_monitor.md)** - Liveness monitoring
- **[heartbeat.md](modules/heartbeat.md)** - Heartbeat tracking

## Getting Started

### Quick Start

1. **Read the main documentation**: Start with [CONSENSUS_MECHANISM.md](CONSENSUS_MECHANISM.md) for a complete overview
2. **Explore the API**: Check [API_REFERENCE.md](api-reference.md) for integration details
3. **Understand the architecture**: Review the [architecture documentation](architecture/) for system design

### Key Concepts

- **Hybrid Consensus**: Combining PoS, PoStorage, and BFT
- **Byzantine Fault Tolerance**: Security against malicious validators
- **Post-Quantum Cryptography**: Future-proof security
- **DAO Governance**: Decentralized decision making
- **Reward System**: Incentive mechanisms for validators

### Example Usage

```rust
use lib_consensus::{ConsensusEngine, ConsensusConfig, ConsensusType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize consensus with hybrid PoS + PoStorage
    let config = ConsensusConfig {
        consensus_type: ConsensusType::Hybrid,
        min_stake: 1000 * 1_000_000,           // 1000 ZHTP
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

## Development

### Building the Documentation

To build the documentation:

```bash
# Generate API documentation
cargo doc --no-deps --open

# Build markdown documentation
# (requires additional tools)
```

### Contributing

Contributions to the documentation are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b docs/feature-name`
3. **Make your changes** and update documentation
4. **Commit your changes**: `git commit -m 'Add documentation for feature'`
5. **Push to the branch**: `git push origin docs/feature-name`
6. **Open a Pull Request**

### Documentation Standards

- Use clear, concise language
- Include code examples where appropriate
- Keep diagrams up-to-date
- Document all public APIs
- Include security considerations

## Support

For questions or issues with the documentation:

- **GitHub Issues**: Report documentation issues
- **Community Forum**: Discuss documentation improvements
- **Developer Chat**: Get help with documentation questions

## License

This documentation is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.