# ZHTP CLI Reference

## Overview

The ZHTP Command Line Interface (CLI) provides comprehensive control over the ZHTP node orchestrator. The CLI allows you to manage components, monitor system health, perform blockchain operations, and coordinate network activities.

## Installation and Setup

### Basic Usage
```bash
zhtp [OPTIONS] <COMMAND>
```

### Global Options
- `-s, --server <ADDRESS>` - API server address (default: 127.0.0.1:9333)
- `-v, --verbose` - Enable verbose output
- `-f, --format <FORMAT>` - Output format: json, yaml, table (default: table)
- `-c, --config <FILE>` - Configuration file path
- `--api-key <KEY>` - API key for authentication  
- `--user-id <ID>` - User ID for authenticated requests

## Commands

### Node Management

Manage the ZHTP orchestrator node lifecycle.

```bash
zhtp node <ACTION>
```

#### Start Node
Start the ZHTP orchestrator node.

```bash
zhtp node start [OPTIONS]

Options:
  -c, --config <FILE>     Configuration file
  -p, --port <PORT>       Port to bind to (default: 9333)
  --dev                   Enable development mode
  --pure-mesh             Enable pure mesh mode (ISP-free networking)
```

**Example:**
```bash
# Start in development mode
zhtp node start --dev --port 9333

# Start in pure mesh mode (no TCP/IP)
zhtp node start --pure-mesh --config production.toml
```

#### Stop Node
```bash
zhtp node stop
```

#### Get Node Status
```bash
zhtp node status
```

**Example Output:**
```
Node Status: Running
Uptime: 2h 15m 30s
Components: 10/10 running
Network Mode: Hybrid
API Server: http://127.0.0.1:9333
```

#### Restart Node
```bash
zhtp node restart
```

### Wallet Operations

Manage wallets and perform transactions (orchestrated through the node).

```bash
zhtp wallet <ACTION>
```

#### Create Wallet
```bash
zhtp wallet create --name <NAME> [--wallet-type <TYPE>]

Options:
  -n, --name <NAME>           Wallet name (required)
  -t, --wallet-type <TYPE>    Wallet type (default: citizen)
```

**Example:**
```bash
zhtp wallet create --name "MyMainWallet" --wallet-type citizen
```

#### Check Balance
```bash
zhtp wallet balance <ADDRESS>
```

**Example:**
```bash
zhtp wallet balance zhtp1abc123def456...
```

**Output:**
```
Wallet Balance
==============
Address: zhtp1abc123def456...
Balance: 1,500 ZHTP
Pending: 50 ZHTP
Total Available: 1,550 ZHTP
```

#### Transfer Funds
```bash
zhtp wallet transfer --from <FROM> --to <TO> --amount <AMOUNT>

Options:
  -f, --from <ADDRESS>     Source wallet address
  -t, --to <ADDRESS>       Destination wallet address
  -a, --amount <AMOUNT>    Amount to transfer
```

**Example:**
```bash
zhtp wallet transfer \
  --from zhtp1sender123... \
  --to zhtp1receiver456... \
  --amount 100
```

#### Transaction History
```bash
zhtp wallet history <ADDRESS>
```

#### List Wallets
```bash
zhtp wallet list
```

### DAO Operations

Interact with the Decentralized Autonomous Organization governance system.

```bash
zhtp dao <ACTION>
```

#### DAO Information
```bash
zhtp dao info
```

**Output:**
```
DAO Status
==========
Total Members: 500
Active Proposals: 3
Treasury Balance: 100,000 ZHTP
Voting Power Distributed: 45,000
Current Period: Voting Phase
```

#### Create Proposal
```bash
zhtp dao propose --title <TITLE> --description <DESC>

Options:
  -t, --title <TITLE>           Proposal title
  -d, --description <DESC>      Proposal description
```

**Example:**
```bash
zhtp dao propose \
  --title "Increase UBI Rate" \
  --description "Proposal to increase UBI from 10 to 15 ZHTP per day"
```

#### Vote on Proposal
```bash
zhtp dao vote --proposal-id <ID> --choice <CHOICE>

Options:
  -p, --proposal-id <ID>     Proposal ID
  -c, --choice <CHOICE>      Vote choice: yes, no, abstain
```

**Example:**
```bash
zhtp dao vote --proposal-id prop_123 --choice yes
```

#### Claim UBI
```bash
zhtp dao claim-ubi
```

**Output:**
```
UBI Claim Result
================
Amount Claimed: 10 ZHTP
Next Claim Available: 2025-10-11 12:00:00 UTC
Total Claimed (All Time): 300 ZHTP
```

### Identity Management

Manage zero-knowledge DID identities.

```bash
zhtp identity <ACTION>
```

#### Create Identity
```bash
zhtp identity create <NAME>
```

#### Create DID Identity
```bash
zhtp identity create-did <NAME> [OPTIONS]

Options:
  -t, --identity-type <TYPE>    Identity type (default: human)
  -r, --recovery-options <OPT>  Recovery options (can be used multiple times)
```

**Identity Types:**
- `human` - Human identity
- `organization` - Organizational identity
- `device` - Device/IoT identity
- `service` - Service identity

**Example:**
```bash
zhtp identity create-did "Alice" \
  --identity-type human \
  --recovery-options email \
  --recovery-options phone
```

#### Verify Identity
```bash
zhtp identity verify <IDENTITY_ID>
```

#### List Identities
```bash
zhtp identity list
```

**Output:**
```
Identities
==========
ID: did:zhtp:abc123...
Name: Alice
Type: Human
Status: Active
Created: 2025-10-10 10:30:00 UTC
```

### Network Operations

Monitor and manage network connectivity and peers.

```bash
zhtp network <ACTION>
```

#### Network Status
```bash
zhtp network status
```

**Output:**
```
ZHTP Mesh Network Status
========================
Internet Connected: Yes
Mesh Connected: Yes
Connectivity: 85.5%
Active Peers: 15
  • Local: 8
  • Regional: 5  
  • Global: 2
  • Relays: 0
Coverage: 72.3%
Stability: 94.2%
```

#### Connected Peers
```bash
zhtp network peers
```

**Output:**
```
Connected Peers
===============
ID            Type       Status      Connection Time
peer_1        local      connected   2025-10-10 10:00:00
peer_2        regional   connected   2025-10-10 09:45:00
peer_3        global     connected   2025-10-10 09:30:00
```

#### Test Network Connectivity
```bash
zhtp network test
```

### Blockchain Operations

Interact with the blockchain layer.

```bash
zhtp blockchain <ACTION>
```

#### Blockchain Status
```bash
zhtp blockchain status
```

**Output:**
```
Blockchain Status
=================
Status: Active
Height: 12,345 blocks
Pending Transactions: 8
Total Identities: 150
Last Block: 2025-10-10 11:45:00 UTC
Network Hash Rate: 1.5 TH/s
```

#### Transaction Information
```bash
zhtp blockchain transaction <TX_HASH>
```

**Output:**
```
Transaction Details
===================
Hash: 0xabc123def456...
Block: 12,340
From: did:zhtp:sender...
To: did:zhtp:receiver...
Amount: 100 ZHTP
Fee: 1 ZHTP
Status: Confirmed (5 confirmations)
Timestamp: 2025-10-10 11:30:00 UTC
```

#### Blockchain Statistics
```bash
zhtp blockchain stats
```

### System Monitoring

Monitor system health and performance.

```bash
zhtp monitor <ACTION>
```

#### System Overview
```bash
zhtp monitor system
```

**Output:**
```
System Monitoring
=================
Uptime: 2h 15m 30s
CPU Usage: 45%
Memory Usage: 2.1GB / 8GB (26%)
Disk Usage: 15GB / 100GB (15%)
Network: ↑ 1.2 MB/s ↓ 2.1 MB/s
Active Connections: 15
```

#### Component Health
```bash
zhtp monitor health
```

**Output:**
```
Component Health Status
=======================
Component     Status    Uptime       Restarts  Errors
crypto        Running   2h 15m       0         0
identity      Running   2h 14m       0         0  
storage       Running   2h 14m       0         0
network       Running   2h 13m       1         0
blockchain    Running   2h 13m       0         0
consensus     Running   2h 12m       0         0
economics     Running   2h 12m       0         0
protocols     Running   2h 11m       0         0
api          Running   2h 10m       0         0
```

#### Performance Metrics
```bash
zhtp monitor performance
```

#### System Logs
```bash
zhtp monitor logs [--lines <N>] [--follow]

Options:
  --lines <N>    Number of lines to show (default: 50)
  --follow       Follow log output (like tail -f)
```

### Component Management

Manage individual system components.

```bash
zhtp component <ACTION>
```

#### List Components
```bash
zhtp component list
```

#### Start Component
```bash
zhtp component start <NAME>
```

#### Stop Component  
```bash
zhtp component stop <NAME>
```

#### Restart Component
```bash
zhtp component restart <NAME>
```

#### Component Status
```bash
zhtp component status <NAME>
```

**Available Components:**
- `crypto` - Cryptographic operations
- `identity` - Identity management
- `storage` - Distributed storage
- `network` - Mesh networking
- `blockchain` - Blockchain operations
- `consensus` - Consensus mechanisms
- `economics` - Economic incentives
- `protocols` - ZHTP protocols
- `api` - API server

### Interactive Shell

Start an interactive shell for exploratory operations.

```bash
zhtp interactive [--command <CMD>]

Options:
  -c, --command <CMD>    Initial command to run
```

**Interactive Commands:**
- All standard CLI commands available
- Tab completion for commands and parameters
- Command history
- Built-in help system

**Example:**
```bash
zhtp interactive
ZHTP> network status
ZHTP> wallet list  
ZHTP> exit
```

### Server Management

Manage the API server component.

```bash
zhtp server <ACTION>
```

#### Start Server
```bash
zhtp server start
```

#### Stop Server
```bash
zhtp server stop
```

#### Restart Server
```bash
zhtp server restart
```

#### Server Status
```bash
zhtp server status
```

#### Server Configuration
```bash
zhtp server config
```

### Network Isolation

Manage network isolation for pure mesh operation.

```bash
zhtp isolation <ACTION>
```

#### Apply Isolation
Enable network isolation to prevent TCP/IP usage.

```bash
zhtp isolation apply
```

#### Check Isolation Status
```bash
zhtp isolation check
```

#### Remove Isolation
```bash
zhtp isolation remove
```

#### Test Connectivity
```bash
zhtp isolation test
```

## Output Formats

### JSON Format
```bash
zhtp --format json network status
```

**Output:**
```json
{
  "status": "success",
  "mesh_status": {
    "internet_connected": true,
    "mesh_connected": true,
    "connectivity_percentage": 85.5,
    "active_peers": 15
  }
}
```

### YAML Format
```bash
zhtp --format yaml network status
```

**Output:**
```yaml
status: success
mesh_status:
  internet_connected: true
  mesh_connected: true
  connectivity_percentage: 85.5
  active_peers: 15
```

### Table Format (Default)
```bash
zhtp network status
```

**Output:**
```
Network Status
==============
Internet Connected: Yes
Mesh Connected: Yes
Connectivity: 85.5%
Active Peers: 15
```

## Configuration

### Configuration File
Default location: `lib-node.toml`

```toml
[network]
mesh_port = 33444
pure_mesh = false

[api]
server_port = 9333
enable_cors = true

[logging]
level = "info"
format = "json"
```

### Environment Variables
- `ZHTP_CONFIG` - Configuration file path
- `ZHTP_API_KEY` - Default API key
- `ZHTP_SERVER` - Default server address
- `ZHTP_LOG_LEVEL` - Logging level

## Examples

### Complete Node Setup
```bash
# Start node in development mode
zhtp node start --dev --config dev.toml

# Create identity and wallet
zhtp identity create-did "MyIdentity" --identity-type human
zhtp wallet create --name "MainWallet"

# Check system status
zhtp monitor system
zhtp network status
zhtp blockchain status
```

### Network Debugging
```bash
# Check network connectivity
zhtp network status
zhtp network peers
zhtp network test

# Monitor network in real-time
zhtp monitor logs --follow
```

### DAO Participation
```bash
# Check DAO status and proposals
zhtp dao info

# Vote on active proposals
zhtp dao vote --proposal-id prop_123 --choice yes

# Claim daily UBI
zhtp dao claim-ubi
```

## Error Handling

### Common Exit Codes
- `0` - Success
- `1` - General error
- `2` - Configuration error
- `3` - Network error
- `4` - Authentication error
- `5` - Component error

### Troubleshooting
```bash
# Check component health
zhtp monitor health

# View detailed logs
zhtp monitor logs --lines 100

# Restart problematic components
zhtp component restart network

# Full system restart
zhtp node restart
```

The ZHTP CLI provides comprehensive control over all aspects of the ZHTP node orchestrator, enabling efficient management of the decentralized network infrastructure with zero-knowledge privacy and economic incentives.