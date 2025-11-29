# ZHTP CLI Documentation

## Overview

The ZHTP CLI provides a command-line interface for interacting with the Zero-Knowledge Hypertext Transfer Protocol network. It serves as the primary orchestrator for coordinating all ZHTP components.

## Installation & Setup

Build and run the ZHTP CLI from the source:

```bash
cd zhtp
cargo build
cd target/debug
./zhtp.exe --help
```

## Global Options

All commands support these global options:

- `-s, --server <SERVER>`: API server address (default: 127.0.0.1:9333)
- `-v, --verbose`: Enable verbose output with full response details
- `-f, --format <FORMAT>`: Output format - json, yaml, table (default: table)
- `-c, --config <CONFIG>`: Configuration file path
- `--api-key <API_KEY>`: API key for authentication
- `--user-id <USER_ID>`: User ID for authenticated requests
- `-h, --help`: Print help information
- `-V, --version`: Print version

## Commands Overview

```
ZHTP Network Node - Complete Internet Replacement and Web4 Orchestrator

Usage: zhtp.exe [OPTIONS] <COMMAND>

Commands:
  node         Start the ZHTP orchestrator node
  wallet       Wallet operations (orchestrated)
  dao          DAO operations (orchestrated)
  identity     Identity operations (orchestrated)
  network      Network operations (orchestrated)
  blockchain   Blockchain operations (orchestrated)
  monitor      System monitoring and status
  component    Component management
  interactive  Interactive shell
  server       Server management
  help         Print this message or the help of the given subcommand(s)
```

## Identity Commands

### Create DID Identity

Create a new Zero-Knowledge Decentralized Identifier with full Web4 citizen onboarding.

**Basic Usage**:
```bash
./zhtp.exe identity create <NAME>
```

**Example**:
```bash
./zhtp.exe identity create TestUser
```

**Output**:
```
Creating new ZHTP DID identity: TestUser
DID Created Successfully!
DID: did:zhtp:81b3eefad482f2f6a2621d0c10c5c4b2340e81e86c3be637cd4a60df48cf8285
Identity ID: 81b3eefad482f2f6a2621d0c10c5c4b2340e81e86c3be637cd4a60df48cf8285
Primary Wallet: 82fcaa64469b576b51f04d0344f97e3e5649cbbceefceb1547a61d3f4e4eb75c
Blockchain TX: e12958e1d46f15cec4dd6b43787f66ab16bf72d5de10c946c76421fb02cbea3b
Status: transaction_created
```

**What Gets Created**:
- **Quantum-Resistant DID**: `did:zhtp:...` identifier
- **Multiple Wallets**: Primary, UBI, and Savings wallets
- **DAO Voting Rights**: 1 voting power granted automatically
- **UBI Registration**: 33 ZHTP daily, 1000 ZHTP monthly eligibility
- **Welcome Bonus**: 5000 ZHTP tokens credited immediately
- **Blockchain Registration**: Identity mined into blockchain block
- **Web4 Access**: Full access to 10 Web4 services
- **Privacy Credentials**: 2 ZK credentials for selective disclosure

### Create Advanced DID Identity

Create a DID with custom identity type and recovery options.

**Usage**:
```bash
./zhtp.exe identity create-did [OPTIONS] <NAME>
```

**Options**:
- `--identity-type <TYPE>`: Identity type (human, organization, service) [default: human]
- `--recovery-options <OPTIONS>...`: Custom recovery phrases

**Example**:
```bash
./zhtp.exe identity create-did Alice --identity-type human --recovery-options "my secret phrase" "backup phrase 123"
```

**Output**:
```
Creating zero-knowledge DID identity: Alice
🔖 Identity Type: human
Recovery options configured: 2 phrases
Zero-Knowledge DID Created Successfully!
DID: did:zhtp:...
Identity ID: ...
Primary Wallet: ...
🎁 UBI Wallet: ...
🏦 Savings Wallet: ...
 DAO Voting Power: 1
Daily UBI: 33 ZHTP
Blockchain TX: ...
Registration Status: transaction_created
 Full Web4 citizen onboarding completed!
```

### Verify Identity

Verify an existing ZHTP identity and check its status.

**Usage**:
```bash
./zhtp.exe identity verify <IDENTITY_ID>
```

**Example**:
```bash
./zhtp.exe identity verify 81b3eefad482f2f6a2621d0c10c5c4b2340e81e86c3be637cd4a60df48cf8285
```

**Output**:
```
Verifying ZHTP identity: 81b3eef...
Identity verification successful!
Verification Score: 95
 Security Level: Standard
```

### List Identities

View blockchain identity information and statistics.

**Usage**:
```bash
./zhtp.exe identity list
```

**Output**:
```
Listing ZHTP identities from blockchain...
Blockchain Identity Status:
Latest Block: 1
To see created identities, check the server logs for DID creation events
   or use 'zhtp blockchain stats' to see blockchain statistics
```

## Node Operations

### Start Node

Start the complete ZHTP orchestrator node with all services.

**Usage**:
```bash
./zhtp.exe node start [OPTIONS]
```

**Options**:
- `--mode <MODE>`: Node mode (full, light, validator) [default: full]
- `--network <NETWORK>`: Network type (mainnet, testnet, local) [default: local]
- `--port <PORT>`: API server port [default: 9333]

**Example**:
```bash
./zhtp.exe node start --mode full --network local --port 9333
```

## Wallet Operations

### Create Wallet

**Usage**:
```bash
./zhtp.exe wallet create <WALLET_NAME>
```

### Transfer Tokens

**Usage**:
```bash
./zhtp.exe wallet transfer <FROM> <TO> <AMOUNT>
```

### Check Balance

**Usage**:
```bash
./zhtp.exe wallet balance <WALLET_ID>
```

## DAO Operations

### View DAO Information

**Usage**:
```bash
./zhtp.exe dao info
```

### Create Proposal

**Usage**:
```bash
./zhtp.exe dao proposal create <TITLE> <DESCRIPTION>
```

### Vote on Proposal

**Usage**:
```bash
./zhtp.exe dao proposal vote <PROPOSAL_ID> <VOTE>
```

## Network Operations

### Check Network Status

**Usage**:
```bash
./zhtp.exe network status
```

###  Status

**Usage**:
```bash
./zhtp.exe network isp-bypass
```

### Mesh Discovery

**Usage**:
```bash
./zhtp.exe network mesh discover
```

## Blockchain Operations

### Blockchain Statistics

**Usage**:
```bash
./zhtp.exe blockchain stats
```

### Get Block Information

**Usage**:
```bash
./zhtp.exe blockchain block <BLOCK_HEIGHT>
```

### Get Transaction

**Usage**:
```bash
./zhtp.exe blockchain transaction <TX_HASH>
```

## Monitoring Commands

### System Status

**Usage**:
```bash
./zhtp.exe monitor status
```

### Health Check

**Usage**:
```bash
./zhtp.exe monitor health
```

### Component Status

**Usage**:
```bash
./zhtp.exe component list
./zhtp.exe component status <COMPONENT_NAME>
```

## Interactive Shell

Start an interactive ZHTP shell with command completion.

**Usage**:
```bash
./zhtp.exe interactive
```

**Features**:
- Tab completion for commands and options
- Command history
- Built-in help system
- Real-time status updates

## Server Management

### Start API Server

Start the ZHTP API server in standalone mode.

**Usage**:
```bash
./zhtp.exe server start [OPTIONS]
```

**Options**:
- `--port <PORT>`: Server port [default: 9333]
- `--host <HOST>`: Server host [default: 127.0.0.1]

### Server Status

**Usage**:
```bash
./zhtp.exe server status
```

## Configuration

### Default Configuration

The ZHTP CLI uses these default settings:

- **API Server**: `127.0.0.1:9333`
- **Output Format**: `table`
- **Network Mode**: `local` (for development)
- **Logging Level**: `info`

### Custom Configuration

Create a configuration file (TOML format):

```toml
[server]
host = "127.0.0.1"
port = 9333

[network]
mode = "local"
mesh_enabled = true

[identity]
default_type = "human"
auto_ubi = true

[economy]
default_priority = "Normal"
auto_dao_fee = true
```

Use with `--config` option:
```bash
./zhtp.exe --config config.toml identity create Alice
```

## Verbose Output

Use `-v` flag to see complete API responses:

```bash
./zhtp.exe -v identity create TestUser
```

**Additional Output**:
```
Full Response:
{
  "did": "did:zhtp:...",
  "identity_id": "...",
  "primary_wallet_id": "...",
  "dao_registration": {...},
  "ubi_registration": {...},
  "blockchain": {...}
}
```

## Output Formats

### Table Format (Default)

Clean, human-readable output with emojis and colors.

### JSON Format

```bash
./zhtp.exe --format json identity create TestUser
```

**Output**:
```json
{
  "status": "success",
  "data": {
    "did": "did:zhtp:...",
    "identity_id": "..."
  }
}
```

### YAML Format

```bash
./zhtp.exe --format yaml identity create TestUser
```

## Error Handling

The CLI provides clear error messages and suggestions:

```bash
./zhtp.exe identity create
# Error: Missing required argument: <NAME>
# 
# Usage: zhtp.exe identity create <NAME>
```

**Network Errors**:
```bash
./zhtp.exe identity create TestUser
# Error: Connection refused (server not running)
# 
# Suggestion: Start the ZHTP node first:
#   ./zhtp.exe node start
```

## Integration Examples

### Shell Scripts

```bash
#!/bin/bash
# Create multiple identities
for name in Alice Bob Charlie; do
    ./zhtp.exe identity create $name
done

# Check their DIDs
./zhtp.exe identity list
```

### PowerShell Scripts

```powershell
# Create identity and capture DID
$result = ./zhtp.exe --format json identity create "TestUser" | ConvertFrom-Json
$did = $result.data.did
Write-Host "Created DID: $did"

# Use DID for verification
./zhtp.exe identity verify $result.data.identity_id
```

## Development & Testing

### Local Development

1. Start the node:
   ```bash
   ./zhtp.exe node start
   ```

2. In another terminal, run CLI commands:
   ```bash
   ./zhtp.exe identity create TestUser
   ```

### Testing Suite

Run the built-in test commands:
```bash
./zhtp.exe monitor health  # Check all components
./zhtp.exe blockchain stats  # Verify blockchain
./zhtp.exe network status   # Check network connectivity
```

## Troubleshooting

### Common Issues

**"Connection refused"**:
- Ensure ZHTP node is running: `./zhtp.exe node start`
- Check if port 9333 is available

**"Invalid HTTP version"**:
- This has been fixed in the current version
- Rebuild if using older version: `cargo build`

**"Identity creation failed"**:
- Check server logs for details
- Verify blockchain component is running

### Debug Mode

Enable debug logging:
```bash
RUST_LOG=debug ./zhtp.exe identity create TestUser
```

### Help System

Get help for any command:
```bash
./zhtp.exe identity --help
./zhtp.exe wallet transfer --help
./zhtp.exe dao proposal create --help
```

## Production Usage

For production deployment:

1. Configure proper security:
   ```bash
   ./zhtp.exe --api-key <secure-key> node start --network mainnet
   ```

2. Use configuration files for consistent settings
3. Monitor system health regularly
4. Set up proper logging and alerting

The ZHTP CLI provides a complete interface to the Web4 internet replacement system, enabling users to participate in a post-scarcity digital economy while maintaining quantum-resistant security and zero-knowledge privacy.
