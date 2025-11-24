# ZHTP Node Configuration Templates

This directory contains pre-configured templates for different types of ZHTP nodes. Each configuration is optimized for specific use cases and roles within the SOVEREIGN_NET ecosystem.

## Available Node Types

### 1. **Full Node** (`full-node.toml`)
**Purpose**: Complete blockchain functionality with all ZHTP components
**Best for**: API servers, blockchain explorers, dApps, general-purpose nodes

**Features**:
- All 9 ZHTP components enabled
- Complete blockchain copy and validation
- API endpoints for serving data
- Moderate storage provision (500GB)
- High peer connectivity (150 peers)
- Hybrid mesh + TCP/IP networking

**Resources**: 4GB RAM, 12 CPU threads, 1TB storage

### 2. **Validator Node** (`validator-node.toml`)  
**Purpose**: Consensus participation and block validation
**Best for**: Stakers, consensus participants, block producers

**Features**:
- **Validator consensus ENABLED**
- Maximum security (Dilithium-5, Kyber-1024)
- High storage provision (1TB)
- Enhanced peer connectivity (200 peers)
- Hardware security key support
- Higher staking requirements (10,000 ZHTP)

**Resources**: 8GB RAM, 16 CPU threads, 2TB storage

### 3. **Storage Node** (`storage-node.toml`)
**Purpose**: Distributed storage services and DHT participation  
**Best for**: Storage providers, -like services, data availability

**Features**:
- **Large storage capacity (5TB)**
- Cold storage tier optimization
- High storage reward multipliers (3x)
- Erasure coding for data integrity
- Smart contracts disabled (resource conservation)
- Extended timeout for storage operations

**Resources**: 2GB RAM, 8 CPU threads, 10TB storage

### 4. **Edge Node** (`edge-node.toml`)
**Purpose**: Mesh networking and 
**Best for**: Mesh relays, rural connectivity, censorship resistance

**Features**:
- **Pure mesh mode ()**
- Mesh protocols only (Bluetooth, WiFi Direct, LoRaWAN)
- Long-range relay support (satellite/LoRaWAN)
- High routing reward multipliers (2x)
- Minimal resource requirements
- No internet fallback (true mesh independence)

**Resources**: 1GB RAM, 4 CPU threads, 200GB storage

### 5. **Development Node** (`dev-node.toml`)
**Purpose**: Testing and development
**Best for**: Development, testing, local experiments

**Features**:
- Relaxed security settings
- Fast block times (2 seconds)
- Lower resource requirements
- Simplified configuration
- TCP-only networking
- Local bootstrap peers

**Resources**: 512MB RAM, 2 CPU threads, 50GB storage

## Usage

### Quick Start Commands

```bash
# Using node type shortcuts (recommended)
zhtp --node-type full      # Full node
zhtp --node-type validator # Validator node  
zhtp --node-type storage   # Storage node
zhtp --node-type edge      # Edge node
zhtp --node-type dev       # Development node

# Using explicit config files
zhtp node start --config ./configs/full-node.toml
zhtp node start --config ./configs/validator-node.toml
zhtp node start --config ./configs/storage-node.toml
zhtp node start --config ./configs/edge-node.toml
zhtp node start --config ./configs/dev-node.toml

# Using helper scripts
./start-node.sh    # Interactive node type selection (Linux/Mac)
./start-node.bat   # Interactive node type selection (Windows)
```

### Advanced Usage

```bash
# Override specific settings
zhtp node start --config ./configs/validator-node.toml --validator --port 8081

# Pure mesh mode
zhtp node start --config ./configs/edge-node.toml --pure-mesh

# Development with custom data directory
zhtp node start --config ./configs/dev-node.toml --data-dir ./my-test-data
```

## Configuration Customization

### Environment Variables
You can override configuration values using environment variables:

```bash
export ZHTP_MESH_PORT=33445
export ZHTP_STORAGE_CAPACITY_GB=2000
export ZHTP_MAX_PEERS=300
zhtp node start --config ./configs/full-node.toml
```

### Custom Configurations
Copy any template and modify it for your specific needs:

```bash
cp configs/full-node.toml configs/my-custom-node.toml
# Edit my-custom-node.toml

# Validate your configuration
./configs/validate-config.sh configs/my-custom-node.toml

# Start with custom configuration
zhtp node start --config ./configs/my-custom-node.toml
```

## Node Role Requirements

### Validator Node Requirements
- **Minimum stake**: 10,000 ZHTP tokens
- **Identity**: Registered human identity (`did:zhtp:person:*`)
- **Hardware**: Dedicated server recommended
- **Network**: Stable, high-bandwidth connection
- **Uptime**: 99%+ availability expected

### Storage Node Requirements  
- **Storage**: Large disk capacity (1TB+ recommended)
- **Network**: Good upload bandwidth for serving data
- **Reliability**: Consistent availability for data retrieval

### Edge Node Requirements
- **Hardware**: Can run on Raspberry Pi or similar
- **Location**: Areas with poor internet connectivity
- **Protocols**: Bluetooth, WiFi Direct, or LoRaWAN capability

## Security Considerations

### Production Deployment
- Always use `environment = "Mainnet"` for production
- Set `security_level = "Maximum"` for validators
- Enable `post_quantum_enabled = true` for security
- Use hardware security modules for validator keys

### Network Security
- Configure firewall rules for required ports
- Use VPN or secure channels for bootstrap peers
- Monitor for unusual network activity

## Monitoring and Maintenance

### Health Checks
All nodes expose health endpoints:
- `http://localhost:8080/health` - Overall node health
- `http://localhost:8080/metrics` - Detailed metrics
- `http://localhost:8080/peers` - Network connectivity

### Log Monitoring
Monitor logs for:
- Consensus participation (validators)
- Storage operations (storage nodes)
- Mesh connectivity (edge nodes)
- API request patterns (full nodes)

## Troubleshooting

### Common Issues
1. **Port conflicts**: Ensure mesh_port, dht_port, and api_port are available
2. **Storage space**: Monitor disk usage, especially for storage nodes
3. **Peer connectivity**: Check firewall and network configuration
4. **Stake requirements**: Validators need sufficient ZHTP tokens staked

### Configuration Validation
Before starting a node, validate your configuration:

```bash
# Validate any configuration file
./configs/validate-config.sh ./configs/full-node.toml
./configs/validate-config.sh ./configs/my-custom-node.toml
```

### Support
- Check logs in `./data/[node-type]/logs/`
- Use `zhtp node status` for quick diagnostics
- Validate configurations with `./configs/validate-config.sh`
- Monitor system resources and network connectivity

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Full Node     │    │  Validator Node │    │  Storage Node   │
│                 │    │                 │    │                 │
│ • All Components│    │ • Consensus    │    │ • Large Storage │
│ • API Endpoints │    │ • High Security │    │ • DHT Focus     │
│ • Moderate Store│    │ • Block Creation│    │ • Data Serving  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Edge Node     │
                    │                 │
                    │ • Pure Mesh     │
                    │ •     │
                    │ • Low Resources │
                    │ • Rural Connect │
                    └─────────────────┘
```

Each node type is optimized for its specific role while maintaining compatibility with the broader ZHTP ecosystem.