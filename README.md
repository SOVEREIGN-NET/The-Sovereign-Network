# SOVEREIGN_NET

A distributed post-quantum blockchain network with advanced privacy features and zero-knowledge proofs.

## Project Structure

This repository contains multiple interconnected libraries and services:

### node download

git clone --recurse-submodules https://github.com/SOVEREIGN-NET/The-Sovereign-Network.git

### Core Libraries
- **`lib-blockchain/`** - Core blockchain implementation with UTXO model and smart contracts
- **`lib-consensus/`** - Byzantine fault-tolerant consensus mechanisms with DAO governance
- **`lib-crypto/`** - Post-quantum cryptography (CRYSTALS-Kyber, CRYSTALS-Dilithium)
- **`lib-identity/`** - Identity management for humans, devices, and organizations
- **`lib-economy/`** - Economic models, rewards, and token mechanics
- **`lib-network/`** - P2P networking with DHT integration and LoRaWAN support
- **`lib-proofs/`** - Zero-knowledge proof systems and verification
- **`lib-protocols/`** - Communication protocols and message handling
- **`lib-storage/`** - Distributed storage with mesh networking capabilities

For a full list of features that need implementing/fixing, as well as things that we already have,
go to BLOCKCHAIN_FEATURE_MATRIX.md in /zhtp

## Quick Start

### Prerequisites
- Rust (latest stable)
- Node.js (for web interface)
- Git
- openssl/tls

#### Option 1 Manual Node Type Selection
```bash
# Navigate to the ZHTP directory
cd zhtp

# Build the project
cargo build 

# Start test node****

./target/debug/zhtp.exe node start #windows
# or
./target/debug/zhtp node start #macos/linux
^^^^^^^^^^^^^^^^^^^^^^^
#"./target/debug/zhtp.exe" this is how you use the cli for now you can use --help to see the current commands.


#### *****API*****
go to /zhtp/native_zhtp_api_complete.md those are the 30 apis that should work right now.



### Running Individual Components

Each library can be tested independently:

```powershell
# Test blockchain functionality
cd lib-blockchain
cargo test

# Test consensus mechanisms
cd lib-consensus  
cargo test

# Test cryptographic functions
cd lib-crypto
cargo test

# Run specific examples
cd lib-blockchain
cargo run --example full_consensus_integration
```
