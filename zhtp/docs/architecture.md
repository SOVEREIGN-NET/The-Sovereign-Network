# ZHTP Architecture Documentation

## Overview

The ZHTP (Zero-Knowledge Hypertext Transfer Protocol) node is a comprehensive orchestrator system that coordinates multiple blockchain and networking components to create a complete ISP replacement and Web4 implementation. This document provides a detailed architectural overview of the ZHTP system.

## System Architecture

### Hierarchical Component Structure

ZHTP follows a four-level architectural hierarchy:

- **Level 1: ZHTP Orchestrator** - Central coordination and management
- **Level 2: Core Services** - Protocols, blockchain, and network services  
- **Level 3: Infrastructure** - Consensus, storage, and economic systems
- **Level 4: Foundation** - Proofs, identity, and cryptographic utilities

### Component Dependencies

```
Level 1: zhtp (orchestrator)
    ├── CLI Interface
    ├── API Server
    ├── Runtime Orchestrator
    └── Configuration Management

Level 2: Core Services
    ├── lib-protocols (ZHTP server with handlers)
    ├── lib-blockchain (blockchain operations)
    └── lib-network (mesh networking)

Level 3: Infrastructure  
    ├── lib-consensus (consensus mechanisms)
    ├── lib-storage (distributed storage)
    └── lib-economy (economic incentives)

Level 4: Foundation
    ├── lib-proofs (zero-knowledge proofs)
    ├── lib-identity (identity management)
    └── lib-crypto (cryptographic primitives)
```

## Core Modules

### 1. Main Entry Points

#### main.rs
- Primary executable entry point
- Initializes logging and tracing
- Routes to CLI or server mode based on arguments
- Version: 0.1.0

#### lib.rs  
- Library interface for external integration
- Re-exports key types and components
- Defines core constants (ZHTP_MAGIC, DEFAULT_MESH_PORT)
- Error type definitions (ZhtpError)

### 2. API Module (`src/api/`)

#### Server Architecture
- **ZhtpServer**: Main server implementation using lib-protocols Router
- **Handler System**: Modular handlers for different API domains
- **Middleware Stack**: Request/response processing pipeline
- **Routing**: ZHTP protocol-based routing with economic requirements

#### API Handlers
- **NetworkHandler**: Network peer management and statistics
- **IdentityHandler**: Identity creation and verification
- **BlockchainHandler**: Blockchain operations and queries
- **StorageHandler**: Distributed storage operations
- **ProtocolHandler**: Protocol-level operations
- **WalletHandler**: Wallet and transaction operations
- **DaoHandler**: DAO governance operations
- **DhtHandler**: DHT operations
- **Web4Handler**: Web4 protocol operations
- **DnsHandler**: DNS resolution

#### Key Features
- ZHTP protocol compliance with ZhtpRequest/ZhtpResponse
- Economic requirements and access controls
- Comprehensive monitoring and metrics
- Type-safe routing with parameter extraction

### 3. CLI Module (`src/cli/`)

#### Command Structure
The CLI provides comprehensive orchestration commands:

```rust
zhtp [OPTIONS] <COMMAND>

Commands:
  node         Node lifecycle management
  wallet       Wallet operations (orchestrated)
  dao          DAO operations (orchestrated)  
  identity     Identity operations (orchestrated)
  network      Network operations (orchestrated)
  blockchain   Blockchain operations (orchestrated)
  monitor      System monitoring and status
  component    Component management
  interactive  Interactive shell
  server       Server management
  isolation    Network isolation management
```

#### Key Features
- Structured argument parsing with clap
- Multiple output formats (JSON, YAML, table)
- Interactive shell support
- Server orchestration capabilities

### 4. Configuration System (`src/config/`)

#### Multi-Package Configuration
- **Aggregation**: Combines configurations from all 11 SOV packages
- **Validation**: Cross-package configuration consistency checks
- **Environment Management**: Development, production, pure-mesh modes
- **Mesh Modes**: Pure mesh (ISP-free) vs hybrid configurations
- **Security Levels**: Configurable security and isolation settings

#### Configuration Files
- Primary config: `lib-node.toml`
- Environment-specific overrides
- CLI argument integration
- Validation and error reporting

### 5. Runtime System (`src/runtime/`)

#### RuntimeOrchestrator
The central coordination system managing all components:

```rust
pub struct RuntimeOrchestrator {
    config: NodeConfig,
    components: Arc<RwLock<HashMap<ComponentId, Arc<dyn Component>>>>,
    component_health: Arc<RwLock<HashMap<ComponentId, ComponentHealth>>>,
    message_bus: Arc<Mutex<mpsc::UnboundedSender<(ComponentId, ComponentMessage)>>>,
    // ... additional fields
}
```

#### Component Management
- **Lifecycle Management**: Start, stop, restart components in correct order
- **Health Monitoring**: Continuous health checks and status tracking
- **Message Bus**: Inter-component communication system
- **Shared Resources**: Blockchain and DHT service sharing

#### Component Types
```rust
pub enum ComponentId {
    Crypto, ZK, Identity, Storage, Network,
    Blockchain, Consensus, Economics, Protocols, Api,
}
```

#### Startup Sequence
1. Crypto → ZK → Identity → Storage → Network
2. Blockchain → Consensus → Economics → Protocols
3. Shared service initialization
4. Health monitoring activation

### 6. Integration System (`src/integration/`)

#### Service Container
- Dependency injection for components
- Service lifecycle management
- Cross-component resource sharing

#### Event Bus
- Pub/sub messaging between components
- Event filtering and routing
- Asynchronous event processing

#### Component Manager
- Dynamic component loading/unloading
- Component dependency resolution
- Resource allocation and cleanup

### 7. Monitoring System (`src/monitoring/`)

#### Comprehensive Monitoring
- **MetricsCollector**: System and application metrics
- **HealthMonitor**: Component health and status
- **AlertManager**: Threshold-based alerting
- **DashboardServer**: Web-based monitoring interface

#### Key Metrics
- Component status and health
- Network connectivity and peer counts
- Blockchain operations and statistics
- System resource usage
- Economic model metrics

## Integration Patterns

### Inter-Component Communication

#### Message Bus System
```rust
pub enum ComponentMessage {
    // Lifecycle messages
    Start, Stop, Restart, HealthCheck,
    
    // Network messages  
    PeerConnected(String), PeerDisconnected(String),
    
    // Blockchain messages
    BlockMined(String), TransactionReceived(String),
    
    // Identity messages
    IdentityCreated(String), IdentityUpdated(String),
    
    // Custom messages
    Custom(String, Vec<u8>),
}
```

#### Shared Resources
- **SharedBlockchainService**: Cross-component blockchain access
- **SharedDhtService**: Distributed hash table operations
- **GlobalProviders**: Singleton access patterns

### Component Lifecycle

#### Startup Process
1. Configuration loading and validation
2. Component registration in dependency order
3. Sequential component initialization
4. Shared service establishment
5. Health monitoring activation
6. Main operational loop

#### Shutdown Process
1. Graceful shutdown signal
2. Reverse-order component shutdown
3. Resource cleanup and finalization
4. Timeout handling for hung components
5. Force termination if necessary

## Network Architecture

### Mesh Networking
- **Pure Mesh Mode**: Complete  using only mesh protocols
- **Hybrid Mode**: Mesh networking with TCP/IP fallback
- **Network Isolation**: Optional isolation for pure mesh operation

### Protocol Stack
- **ZHTP Protocol**: Zero-knowledge hypertext transfer protocol
- **Economic Routing**: Payment-based packet routing
- **Mesh Coordination**: Peer discovery and network formation
- **Quality Assurance**: Network stability and performance monitoring

## Security Model

### Zero-Knowledge Privacy
- All communications use zero-knowledge proofs
- Identity protection through lib-identity integration
- Cryptographic security via lib-crypto

### Economic Incentives
- Universal Basic Income for network participation
- Quality-based routing payments
- DAO governance for network decisions

### Network Isolation
- Configurable network isolation levels
- Pure mesh operation without TCP/IP dependency
- Security-focused operational modes

## Deployment Modes

### Development Mode
- Full logging and debugging
- Local testing configurations
- Development-friendly defaults

### Production Mode
- Optimized performance settings
- Security-hardened configuration
- Operational monitoring

### Pure Mesh Mode
- Complete ISP replacement
- Mesh-only networking
- Maximum privacy and decentralization

### Raspberry Pi Mode
- Memory-optimized compilation
- Reduced feature set for embedded deployment
- Basic blockchain without WASM runtime

## Error Handling

### Comprehensive Error Types
```rust
pub enum ZhtpError {
    Configuration(String),
    ComponentInit(String),
    Runtime(String),
    Integration(String),
    Monitoring(String),
    Network(String),
    // Standard error integration
    Io(#[from] std::io::Error),
    Serialization(#[from] serde_json::Error),
}
```

### Recovery Strategies
- Automatic component restart on failure
- Graceful degradation for non-critical components
- Timeout handling for network operations
- Health-based component management

## Performance Characteristics

### Memory Management
- Arc/RwLock for shared state
- Async/await for non-blocking operations
- Configurable resource limits
- Garbage collection for temporary resources

### Concurrency Model
- Tokio async runtime
- Component isolation
- Message-passing concurrency
- Lock-free where possible

### Scalability Features
- Horizontal peer scaling
- Distributed storage
- Economic load balancing
- Modular component architecture

## Future Extensions

### Planned Features
- Additional protocol handlers
- Enhanced monitoring capabilities
- Advanced economic models
- Extended Web4 functionality

### Architecture Evolution
- Plugin system for custom components
- Dynamic configuration updates
- Advanced routing algorithms
- Improved zero-knowledge implementations

This architecture provides a robust foundation for the ZHTP system's goal of creating a complete Internet replacement with zero-knowledge privacy, economic incentives, and decentralized governance.