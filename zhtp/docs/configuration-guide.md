# ZHTP Configuration Guide

## Overview

The ZHTP node orchestrator uses a comprehensive configuration system that aggregates settings from all 11 SOV packages. This guide covers configuration options, deployment scenarios, and best practices.

## Configuration Architecture

### Multi-Package Configuration
ZHTP aggregates configurations from:
- **Level 4 Packages**: lib-crypto, lib-proofs, lib-identity
- **Level 3 Packages**: lib-consensus, lib-storage, lib-economy  
- **Level 2 Packages**: lib-protocols, lib-blockchain, lib-network
- **Level 1 Package**: zhtp (orchestrator)

### Configuration Sources
1. **Default Settings**: Built-in defaults for each package
2. **Configuration Files**: TOML-based configuration files
3. **Environment Variables**: Runtime environment overrides
4. **Command Line Arguments**: Highest priority overrides

## Main Configuration File

### Default Location
- Primary: `lib-node.toml` (current directory)
- Custom: Specified via `--config` flag

### Basic Structure
```toml
[node]
# Node identification and basic settings
node_id = "zhtp-node-001"
data_dir = "./data"
log_level = "info"

[network]
# Mesh networking configuration
mesh_port = 33444
pure_mesh = false
hybrid_mode = true
bootstrap_peers = [
    "192.168.1.100:33444",
    "10.0.0.50:33444"
]

[api]
# API server configuration
server_port = 9333
bind_address = "127.0.0.1"
enable_cors = true
max_connections = 1000

[security]
# Security and cryptography settings
security_level = "high"
enable_encryption = true
key_rotation_interval = 86400

[mesh]
# Mesh networking modes
mode = "hybrid"
isolation_level = "none"

[integration]
# Cross-package integration settings
health_check_interval_ms = 30000
component_startup_timeout = 30000
cross_package_timeouts = { shutdown = 30000, startup = 60000 }

[economics]
# Economic model configuration
enable_ubi = true
base_routing_rate = 0.01
quality_multiplier = 1.5

[blockchain]
# Blockchain-specific settings
enable_contracts = true
wasm_runtime = true
genesis_funding = 1000000

[storage]
# Distributed storage configuration
max_storage_size = 1073741824  # 1GB
enable_compression = true
enable_encryption = true
default_tier = "hot"

[consensus]
# Consensus mechanism settings
algorithm = "proof_of_stake"
block_time = 10
max_validators = 100

[identity]
# Identity management settings
enable_did = true
enable_zero_knowledge = true
identity_expiration = 31536000  # 1 year

[protocols]
# Protocol layer configuration
enable_zhtp = true
enable_web4 = true
enable_dns = true

[monitoring]
# System monitoring configuration
enable_metrics = true
health_check_interval = 30
dashboard_port = 8081
prometheus_export = false

[logging]
# Logging configuration
level = "info"
format = "json"
file_rotation = true
max_file_size = "100MB"
```

## Environment-Specific Configurations

### Development Environment
**File**: `configs/dev-node.toml`

```toml
[node]
log_level = "debug"
data_dir = "./dev-data"

[network]
mesh_port = 33445
pure_mesh = false

[api]
server_port = 9334
enable_cors = true

[security]
security_level = "medium"

[blockchain]
wasm_runtime = true
genesis_funding = 10000

[monitoring]
enable_metrics = true
dashboard_port = 8082

[logging]
level = "debug"
format = "pretty"
```

### Production Environment
**File**: `configs/full-node.toml`

```toml
[node]
log_level = "info"
data_dir = "/var/lib/zhtp"

[network]
mesh_port = 33444
pure_mesh = false
bootstrap_peers = [
    "bootstrap1.zhtp.network:33444",
    "bootstrap2.zhtp.network:33444"
]

[api]
server_port = 9333
bind_address = "0.0.0.0"
max_connections = 5000

[security]
security_level = "maximum"
enable_encryption = true
key_rotation_interval = 43200  # 12 hours

[blockchain]
enable_contracts = true
wasm_runtime = true
genesis_funding = 1000000

[monitoring]
enable_metrics = true
dashboard_port = 8081
prometheus_export = true
prometheus_port = 9090

[logging]
level = "info"
format = "json"
file_rotation = true
```

### Pure Mesh Environment
**File**: `configs/pure-mesh.toml`

```toml
[node]
log_level = "info"

[network]
mesh_port = 33444
pure_mesh = true
hybrid_mode = false

[mesh]
mode = "pure"
isolation_level = "complete"

[security]
security_level = "maximum"

[network_isolation]
block_tcp_ip = true
allow_mesh_only = true
firewall_rules = [
    "BLOCK INPUT tcp",
    "BLOCK OUTPUT tcp", 
    "ALLOW MESH_PROTOCOL"
]

[api]
# API only available via mesh
server_port = 9333
bind_address = "mesh://0.0.0.0"
```

### Edge Node Environment
**File**: `configs/edge-node.toml`

```toml
[node]
node_type = "edge"
data_dir = "./edge-data"

[network]
mesh_port = 33444
edge_mode = true
relay_traffic = false

[blockchain]
sync_mode = "light"
wasm_runtime = false

[storage]
max_storage_size = 104857600  # 100MB
cache_only = true

[economics]
participate_routing = false
relay_payments = false
```

### Validator Node Environment
**File**: `configs/validator-node.toml`

```toml
[node]
node_type = "validator"

[blockchain]
validator_mode = true
stake_amount = 10000
enable_mining = true

[consensus]
validator_key = "path/to/validator.key"
min_stake = 1000

[storage]
max_storage_size = 10737418240  # 10GB
enable_full_history = true

[economics]
validator_rewards = true
commission_rate = 0.05
```

### Storage Node Environment
**File**: `configs/storage-node.toml`

```toml
[node]
node_type = "storage"

[storage]
max_storage_size = 107374182400  # 100GB
enable_compression = true
enable_deduplication = true
storage_tiers = ["hot", "warm", "cold"]

[economics]
storage_payments = true
storage_rate = 0.001  # SOV per MB per day

[network]
advertise_storage = true
max_storage_connections = 500
```

## Mesh Networking Modes

### Hybrid Mode (Default)
```toml
[network]
pure_mesh = false
hybrid_mode = true

[mesh]
mode = "hybrid"
tcp_ip_fallback = true
mesh_priority = true
```

**Characteristics:**
- Uses mesh networking as primary
- Falls back to TCP/IP when needed
- Gradual ISP replacement
- Best for transition period

### Pure Mesh Mode
```toml
[network]
pure_mesh = true
hybrid_mode = false

[mesh]
mode = "pure"
tcp_ip_fallback = false

[network_isolation]
block_tcp_ip = true
mesh_only = true
```

**Characteristics:**
- Complete 
- Mesh-only networking
- Maximum privacy and decentralization
- Requires sufficient mesh density

### Development Mode
```toml
[network]
pure_mesh = false
development_mode = true

[mesh]
mode = "development"
simulate_mesh = true
local_testing = true
```

## Security Levels

### Security Level Configuration
```toml
[security]
security_level = "maximum"  # minimum, medium, high, maximum

[crypto]
encryption_algorithm = "AES-256-GCM"
key_derivation = "Argon2id"
signature_algorithm = "Ed25519"

[zero_knowledge]
proof_system = "Groth16"
circuit_size = "large"
verification_timeout = 30000
```

### Security Level Details

#### Minimum Security
- Basic encryption (AES-128)
- Standard key derivation
- Reduced proof verification
- Faster performance

#### Medium Security  
- AES-192 encryption
- Enhanced key rotation
- Standard zero-knowledge proofs
- Balanced security/performance

#### High Security
- AES-256 encryption
- Frequent key rotation
- Enhanced proof systems
- Strong authentication

#### Maximum Security
- AES-256-GCM encryption
- Continuous key rotation
- Advanced zero-knowledge circuits
- Multiple verification layers
- Complete network isolation options

## Economic Model Configuration

### Universal Basic Income
```toml
[economics.ubi]
enabled = true
daily_amount = 10.0
qualification_period = 86400  # 24 hours
max_backlog_days = 7

[economics.routing]
base_rate = 0.01
quality_multiplier = 1.5
payment_threshold = 1.0

[economics.storage]
storage_rate = 0.001  # SOV per MB per day
bandwidth_rate = 0.0001  # SOV per MB transferred
```

### DAO Governance
```toml
[dao]
enabled = true
voting_period = 604800  # 7 days
quorum_threshold = 0.33
proposal_threshold = 1000  # ZHTP required to propose

[dao.treasury]
initial_supply = 1000000
inflation_rate = 0.02  # 2% annual
treasury_allocation = 0.1  # 10% to treasury
```

## Platform-Specific Configurations

### Windows Configuration
```toml
[platform.windows]
enable_bluetooth = true
bluetooth_features = ["windows-gatt"]
data_dir = "C:\\ProgramData\\ZHTP"

[network.windows]
firewall_auto_config = true
```

### Linux Configuration
```toml
[platform.linux]
enable_bluetooth = true
bluetooth_service = "bluez"
data_dir = "/var/lib/zhtp"

[network.linux]
use_netlink = true
```

### Raspberry Pi Configuration
```toml
[platform.rpi]
memory_optimized = true
reduced_features = true

[blockchain.rpi]
wasm_runtime = false
sync_mode = "light"

[storage.rpi]
max_storage_size = 1073741824  # 1GB
compression_aggressive = true
```

## Monitoring and Logging

### Monitoring Configuration
```toml
[monitoring]
enable_metrics = true
health_check_interval = 30
metrics_retention = 86400  # 24 hours

[monitoring.dashboard]
enabled = true
port = 8081
bind_address = "127.0.0.1"

[monitoring.prometheus]
enabled = false
port = 9090
metrics_path = "/metrics"

[monitoring.alerting]
enabled = true
alert_webhook = "http://localhost:8080/alerts"
thresholds = { cpu = 80.0, memory = 85.0, disk = 90.0 }
```

### Logging Configuration
```toml
[logging]
level = "info"
format = "json"  # json, pretty, compact
output = "stdout"  # stdout, file, both

[logging.file]
enabled = true
path = "./logs/zhtp.log"
rotation = "daily"
max_size = "100MB"
max_files = 7

[logging.tracing]
enabled = true
sample_rate = 0.1
jaeger_endpoint = "http://localhost:14268"
```

## Environment Variables

### Core Environment Variables
```bash
# Configuration
export ZHTP_CONFIG="/path/to/config.toml"
export ZHTP_DATA_DIR="/var/lib/zhtp"
export ZHTP_LOG_LEVEL="info"

# Network
export ZHTP_MESH_PORT="33444"
export ZHTP_PURE_MESH="false"
export ZHTP_API_PORT="9333"

# Security
export ZHTP_SECURITY_LEVEL="high"
export ZHTP_API_KEY="your-api-key-here"

# Economics
export ZHTP_ENABLE_UBI="true"
export ZHTP_UBI_AMOUNT="10.0"

# Monitoring
export ZHTP_ENABLE_METRICS="true"
export ZHTP_DASHBOARD_PORT="8081"
```

### Development Environment Variables
```bash
export ZHTP_ENVIRONMENT="development"
export ZHTP_LOG_LEVEL="debug"
export ZHTP_API_CORS="true"
export ZHTP_UNSAFE_MODE="true"
```

### Production Environment Variables
```bash
export ZHTP_ENVIRONMENT="production"
export ZHTP_SECURITY_LEVEL="maximum"
export ZHTP_LOG_LEVEL="info"
export ZHTP_ENABLE_MONITORING="true"
```

## Validation and Testing

### Configuration Validation
```bash
# Validate configuration file
zhtp config validate --config production.toml

# Test configuration without starting
zhtp config test --config production.toml

# Show effective configuration
zhtp config show --format json
```

### Network Connectivity Testing
```bash
# Test mesh connectivity
zhtp network test --config pure-mesh.toml

# Test hybrid mode
zhtp network test --config hybrid.toml

# Validate isolation
zhtp isolation test --config pure-mesh.toml
```

## Best Practices

### Configuration Management
1. **Version Control**: Keep configuration files in version control
2. **Environment Separation**: Use separate configs for dev/staging/prod
3. **Secret Management**: Use environment variables for secrets
4. **Validation**: Always validate configurations before deployment

### Security Considerations
1. **Key Management**: Rotate keys regularly
2. **Access Control**: Limit API access with authentication
3. **Network Isolation**: Use pure mesh for maximum privacy
4. **Monitoring**: Enable comprehensive monitoring

### Performance Optimization
1. **Resource Limits**: Set appropriate memory and storage limits
2. **Connection Limits**: Configure connection pools properly
3. **Caching**: Enable caching for frequently accessed data
4. **Compression**: Use compression for storage and network

### Deployment Strategies
1. **Gradual Rollout**: Start with hybrid mode, migrate to pure mesh
2. **Load Balancing**: Distribute load across multiple nodes
3. **High Availability**: Configure redundant infrastructure
4. **Backup Strategy**: Regular configuration and data backups

## Troubleshooting

### Common Configuration Issues

#### Port Conflicts
```toml
[network]
mesh_port = 33444  # Ensure port is available

[api]  
server_port = 9333  # Check for conflicts with other services
```

#### Permission Issues
```bash
# Fix data directory permissions
sudo chown -R zhtp:zhtp /var/lib/zhtp
sudo chmod 750 /var/lib/zhtp
```

#### Memory Configuration
```toml
[storage]
max_storage_size = 1073741824  # Adjust based on available RAM

[blockchain]
wasm_runtime = false  # Disable WASM on low-memory systems
```

#### Network Connectivity
```toml
[network]
bootstrap_peers = [
    "working.peer.address:33444"  # Ensure bootstrap peers are reachable
]
```

### Configuration Debugging
```bash
# Enable debug logging
export ZHTP_LOG_LEVEL="debug"

# Validate configuration
zhtp config validate

# Check component status
zhtp component list
zhtp monitor health
```

This comprehensive configuration guide ensures proper setup and operation of ZHTP nodes across various deployment scenarios, from development testing to production pure mesh networks.