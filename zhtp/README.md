# ZHTP - Zero-Knowledge Hypertext Transfer Protocol

<div align="center">

[![Rust](https://img.shields.io/badge/rust-nightly-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/zhtp/zhtp)

**Internet Replacement System**

*Complete  • Zero-Knowledge Privacy • Universal Basic Income • Post-Quantum Security*

</div>

##  Overview

ZHTP is a network node that orchestrates a complete internet replacement system. It coordinates 9 specialized library packages to provide  through mesh networking, zero-knowledge privacy for all communications, universal basic income distribution, and quantum-resistant cryptographic security.

### Key Features

- **Complete ISP Replacement** - Pure mesh networking with Bluetooth LE, WiFi Direct, and LoRaWAN
-  **Zero-Knowledge Privacy** - All communications protected with ZK proofs and post-quantum cryptography  
- **Universal Basic Income** - 33 SOV daily, 1000 SOV monthly for all verified citizens
-  **Decentralized Governance** - DAO-based decision making with liquid democracy
-  **Web4 Protocol Stack** - Next-generation internet protocols
-  **Real-time Monitoring** - Comprehensive system health and performance metrics

##Architecture

ZHTP operates as a **Level 1 Orchestrator** that coordinates **Level 2 Components**:

```
┌─────────────────────────────────────────────────────────┐
│                    ZHTP Orchestrator                    │
│                    (Level 1 - Main)                     │
└─────────────────────┬───────────────────────────────────┘
                      │
          ┌───────────┼───────────┐
          │           │           │
    ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
    │Protocols  │ │Network│ │Blockchain │
    │           │ │       │ │           │
    └───────────┘ └───────┘ └───────────┘
          │           │           │
    ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
    │Storage    │ │Economy│ │Consensus  │
    │           │ │       │ │           │
    └───────────┘ └───────┘ └───────────┘
          │           │           │
    ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
    │Identity   │ │Proofs │ │Crypto     │
    │           │ │       │ │           │
    └───────────┘ └───────┘ └───────────┘
```

##  Core Modules

### Required ZHTP Library Dependencies

The ZHTP node requires all 9 specialized libraries to function:

| Library | Purpose  | Status |
|---------|---------|--------|
| **lib-crypto** | Post-quantum cryptography (CRYSTALS-Dilithium/Kyber) | - | Required |
| **lib-proofs** | Zero-knowledge system (Plonky2)  | Required |
| **lib-identity** | Privacy-preserving identity management  | Required |
| **lib-storage** | Distributed storage with encryption  | Required |
| **lib-network** | Mesh networking (BLE, WiFi Direct, LoRaWAN)  | Required |
| **lib-blockchain** | Blockchain layer with UBI support  | Required |
| **lib-consensus** | Consensus mechanism  | Required |
| **lib-economy** | Economic incentives and DAO governance  | Required |
| **lib-protocols** | High-level protocol implementations  | Required |

### Internal Modules

The ZHTP orchestrator contains sophisticated internal systems:

#### Configuration System (`src/config/`)
- **aggregation.rs** - Cross-package configuration coordination
- **validation.rs** - Configuration conflict detection and resolution
- **environment.rs** - Environment-specific settings (dev/staging/prod)
- **mesh_modes.rs** - Mesh networking mode management
- **security.rs** - Security level configurations

#### 🖥️ CLI Interface (`src/cli/`)
- **argument_parsing.rs** - Command-line argument processing
- **command_execution.rs** - Command handling and orchestration
- **interactive_shell.rs** - Interactive shell with auto-completion
- **commands/** - Specialized command handlers for each subsystem

####  Runtime Orchestration (`src/runtime/`)
- **components.rs** - Component lifecycle management
- **blockchain_provider.rs** - Blockchain integration layer
- **shared_blockchain.rs** - Shared blockchain state management

#### Monitoring System (`src/monitoring/`)
- **metrics.rs** - Real-time system metrics collection
- **health_check.rs** - Component health monitoring
- **alerting.rs** - Alert management and notifications
- **dashboard.rs** - Web dashboard with live visualization

#### Integration Layer (`src/integration/`)
- **service_container.rs** - Dependency injection container
- **event_bus.rs** - Inter-component messaging system
- **component_manager.rs** - Component startup and shutdown coordination
- **dependency_injection.rs** - Advanced dependency resolution

#### API Server (`src/api/`)
- **server.rs** - HTTP API server for external integration
- **endpoints.rs** - RESTful API endpoint definitions
- **handlers/** - Request handlers for each functional area

##  Getting Started

### Prerequisites

1. **Rust nightly** - Install from [rustup.rs](https://rustup.rs/) (repository uses `rust-toolchain.toml`)
2. **All ZHTP Libraries** - Ensure all 9 lib-* packages are available in parent directory
3. **System Requirements** - 4GB RAM, 10GB storage minimum

### Installation

1. **Clone the ZHTP repository structure:**
```bash
git clone https://github.com/SOVEREIGN-NET/SOVEREIGN_NET.git
cd SOVEREIGN_NET/zhtp
```

2. **Verify dependencies are available:**
```bash
# Check that all required libraries exist
ls -la ../lib-*
# Should show: lib-blockchain, lib-consensus, lib-crypto, lib-economy, 
#              lib-identity, lib-network, lib-proofs, lib-protocols, lib-storage
```

3. **Build the ZHTP node:**
```bash
cargo build --release
```

4. **Run initial setup:**
```bash
# Create default configuration
cargo run -- --config zhtp/configs/dev-node.toml
```

### Quick Start

#### Method 1: Interactive CLI Mode (Recommended)
```bash
# Start the interactive ZHTP shell
cargo run

# Available commands in the shell(not all of them work):
zhtp> help                    # Show all available commands
zhtp> node start --port 9334  # Start the orchestrator node
zhtp> node status             # Check node health
zhtp> monitor system          # View system metrics
zhtp> wallet create --name "MyWallet" --type citizen
zhtp> dao info                # Check DAO status
zhtp> identity create TestUser # Create new DID identity
zhtp> network status          # Check mesh network status
```

#### Method 2: Direct Commands
```bash
# Execute single commands directly
cargo run -- --config config.toml
cargo run -- wallet balance <address>
cargo run -- dao claim-ubi
cargo run -- network peers
```

## 📖 Usage Examples

### Starting a Complete ZHTP Node

```bash
# Start with default settings
cargo run -- --config zhtp/configs/dev-node.toml

# Start with custom configuration
cargo run -- --config custom.toml --mesh-port 9334

# Start in pure mesh mode (no TCP/IP fallback)
cargo run -- --config zhtp/configs/edge-node.toml --pure-mesh
```

### Identity Management

```bash
# Create a new Zero-Knowledge DID identity
cargo run -- identity create-did Alice \
  --type human \
  --recovery-options "phrase1,phrase2"

# Verify an existing identity
cargo run -- identity verify <identity_id>

# List all identities
cargo run -- identity list
```

### Wallet Operations

```bash
# Create a new citizen wallet
cargo run -- wallet create --name "CitizenWallet" --type citizen

# Check wallet balance
cargo run -- wallet balance <wallet_address>

# Transfer funds between wallets
cargo run -- wallet transfer \
  --from <from_wallet> \
  --to <to_wallet> \
  --amount 1000

# View transaction history
cargo run -- wallet history <wallet_address>
```

### DAO Governance

```bash
# Get DAO information
cargo run -- dao info

# Create a new proposal
cargo run -- dao propose \
  --title "Network Upgrade" \
  --description "Implement new features"

# Vote on a proposal
cargo run -- dao vote --proposal-id <id> --choice yes

# Claim your Universal Basic Income
cargo run -- dao claim-ubi
```

### Network Operations

```bash
# Check network status
cargo run -- network status

# View connected peers
cargo run -- network peers

# Test network connectivity
cargo run -- network test
```

### Monitoring and Diagnostics

```bash
# View system metrics
cargo run -- monitor system

# Check component health
cargo run -- monitor health

# View performance metrics
cargo run -- monitor performance

# Check system logs
cargo run -- monitor logs
```

### Component Management

```bash
# List all components
cargo run -- component list

# Start a specific component
cargo run -- component start lib-blockchain

# Check component status
cargo run -- component status lib-network

# Restart a component
cargo run -- component restart lib-consensus
```

## Configuration

### Default Configuration File (`lib-node.toml`)

```toml
[node]
name = "zhtp-node"
mesh_port = 9334
environment = "development"
data_dir = "./data"

[protocols_config]
api_port = 9333

[mesh]
mode = "pure-mesh"              # pure-mesh, offline
enable_bluetooth = true
enable_wifi_direct = true
enable_lorawan = false

[security]
level = "enhanced"           # basic, enhanced, paranoid
quantum_resistant = true
zero_knowledge = true

[economy]
ubi_enabled = true
dao_participation = true
daily_ubi_amount = 33000000000000000000    # 33 SOV tokens
monthly_ubi_amount = 1000000000000000000000 # 1000 SOV tokens

[monitoring]
enable_dashboard = true
dashboard_port = 9334
metrics_interval = 30
health_check_interval = 60

[logging]
level = "info"
output = "console"
file_path = "./logs/zhtp.log"
```

### Environment Variables

```bash
export ZHTP_CONFIG_PATH="./config.toml"
export ZHTP_DATA_DIR="./data"
export ZHTP_LOG_LEVEL="info"
export ZHTP_MESH_PORT="9334"
export ZHTP_ENVIRONMENT="development"
```

## Monitoring & Debugging

### Web Dashboard

Access the live monitoring dashboard at `http://127.0.0.1:9334` when the node is running:

- **System Metrics** - CPU, memory, network usage
- **Component Health** - Status of all 9 SOV libraries
- **Network Statistics** - Mesh network connectivity and performance
- **Economic Metrics** - UBI distribution, transaction volumes
- **Security Status** - Cryptographic operations, threat detection

### Log Files

Logs are written to `./logs/zhtp.log` by default:

```bash
# View real-time logs
tail -f ./logs/zhtp.log

# Filter for specific components
grep "lib-network" ./logs/zhtp.log

# View error logs only
grep "ERROR" ./logs/zhtp.log
```

### Health Checks

Health checks are performed via the CLI:
```bash
zhtp-cli network status
```

## Development

### Building from Source

```bash
# Development build
cargo build

# Release build with optimizations
cargo build --release

# Build with specific features
cargo build --features "pure-mesh,development"
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test integration_tests

# Run with verbose output
cargo test -- --nocapture
```

### Development Mode

```bash
# Start in development mode with enhanced logging
cargo run -- --config zhtp/configs/dev-node.toml

# Use custom configuration for development
cargo run -- --config dev-config.toml
```

## Security Features

### Post-Quantum Cryptography
- **CRYSTALS-Dilithium** - Digital signatures
- **CRYSTALS-Kyber** - Key encapsulation
- **Quantum-resistant** - Protection against future quantum computers

### Zero-Knowledge Privacy
- **Plonky2 Proofs** - Privacy-preserving transaction validation
- **Selective Disclosure** - Reveal only necessary information
- **Anonymous Communications** - No metadata leakage

### Economic Security
- **Anti-Spam** - Economic incentives prevent network abuse
- **Quality Rewards** - Better service providers earn more
- **Decentralized Governance** - Community-driven security decisions

## Network Modes

### Hybrid Mode (Default)
- Uses mesh networking with TCP/IP fallback
- Gradual transition from traditional internet
- Best compatibility with existing systems

### Pure Mesh Mode
- Complete  using only mesh protocols
- Maximum privacy and decentralization
- Requires multiple ZHTP nodes in area

### Offline Mode
- Local-only operations without external connectivity
- Useful for development and testing
- Complete functionality simulation

## Roadmap

### Phase 1: Foundation (Current)
- Core orchestrator implementation
- Configuration management system
- CLI interface and interactive shell
- Monitoring and health checks
- API server with REST endpoints

### Phase 2: Network Integration
-  Complete mesh networking implementation
-   functionality
-  Multi-protocol support (BLE, WiFi Direct, LoRaWAN)
-  Network topology optimization

### Phase 3: Economic System
- 📅 UBI distribution implementation
- 📅 DAO governance mechanics
- 📅 Economic incentive algorithms
- 📅 Quality-based reward system

### Phase 4: Production Deployment
- 📅 Production security hardening
- 📅 Scalability optimizations
- 📅 Mobile device support
- 📅 Global network coordination

## Contributing

We welcome contributions to the ZHTP project! Please see:

- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development setup and practices

### Quick Contribution Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/SOVEREIGN_NET.git
cd SOVEREIGN_NET/zhtp

# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes and test
cargo test
cargo fmt
cargo clippy

# Submit a pull request
git push origin feature/your-feature-name
```

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- **Complete Documentation**: [docs/README.md](docs/README.md) - Start here for comprehensive documentation
- **API Reference**: [docs/api-reference.md](docs/api-reference.md) - Complete API endpoint documentation
- **CLI Reference**: [docs/cli-reference.md](docs/cli-reference.md) - Command-line interface guide
- **Configuration Guide**: [docs/configuration-guide.md](docs/configuration-guide.md) - Setup and configuration
- **Deployment Guide**: [docs/deployment-guide.md](docs/deployment-guide.md) - Production deployment
- **Architecture Overview**: [docs/architecture.md](docs/architecture.md) - System architecture
- **Module Analysis**: [docs/module-analysis.md](docs/module-analysis.md) - Detailed code analysis

### Community
- **GitHub Issues**: [Report bugs and request features](https://github.com/SOVEREIGN-NET/SOVEREIGN_NET/issues)
- **Discussions**: [Community discussions and Q&A](https://github.com/SOVEREIGN-NET/SOVEREIGN_NET/discussions)

### Getting Help

```bash
# Built-in help system
cargo run -- help
cargo run -- node --help
cargo run -- wallet --help

# Interactive help in shell mode
zhtp> help
zhtp> help wallet
zhtp> help dao
```

---

<div align="center">

**ZHTP - Revolutionizing Internet Infrastructure**

*Building the foundation for Web4 and true digital sovereignty*

[Website](https://zhtp.org) • [Documentation](https://docs.zhtp.org) • [Community](https://community.zhtp.org)

</div>
