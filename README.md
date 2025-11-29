# Sovereign Network - Mono Repository

A complete, self-contained repository containing all the Rust code needed to build and run ZHTP (Zero-Trust Hybrid Protocol) orchestrator nodes for the Sovereign Network.

## 🏗️ Architecture

This mono-repo contains:

### Core Libraries (`lib-*`)
- **lib-blockchain** - Blockchain data structures and consensus
- **lib-consensus** - Consensus mechanisms and validation
- **lib-crypto** - Cryptographic primitives with post-quantum support
- **lib-dht** - Distributed Hash Table for peer discovery
- **lib-dns** - DNS resolution and management
- **lib-economy** - Economic models and token management
- **lib-identity** - Identity and authentication
- **lib-network** - Network layer and mesh networking
- **lib-proofs** - Zero-knowledge proofs and verification
- **lib-protocols** - Protocol definitions and handlers
- **lib-storage** - Distributed storage layer

### Main Application
- **zhtp** - ZHTP Orchestrator node (main binary)

## 🚀 Quick Start

### Prerequisites
- **Rust** 1.70+ (install from [rustup.rs](https://rustup.rs/))
- **Git** (for cloning the repo)

### Build & Run

**Linux/macOS/WSL:**
```bash
# Build all crates
./build.sh

# Run a node with default config
./run-node.sh

# Run with custom config
./run-node.sh zhtp/configs/test-node2.toml
```

**Windows (PowerShell):**
```powershell
# Build all crates
.\build.ps1

# Run a node with default config
.\run-node.ps1

# Run with custom config
.\run-node.ps1 -ConfigFile crates\zhtp\configs\test-node2.toml
```

### Manual Build
```bash
# Build entire workspace in release mode
cargo build --release --workspace

# Run the orchestrator
./target/release/zhtp-orchestrator --config zhtp/configs/test-node1.toml
```

## 📋 Configuration

Node configuration files are in `zhtp/configs/`:
- `test-node1.toml` - Default node configuration
- `test-node2.toml` - Secondary node for testing multi-node networks

### Key Configuration Sections
- **Node Settings**: ID, type (full/light), security level
- **Network Settings**: Ports, multicast addresses, bootstrap peers
- **Mesh Networking**: Hybrid mesh + TCP/IP mode
- **Crypto Settings**: Post-quantum cryptography options
- **DHT Settings**: Peer discovery configuration

## 🌐 Running a Network

To test a multi-node network:

**Terminal 1:**
```bash
./run-node.sh zhtp/configs/test-node1.toml
```

**Terminal 2:**
```bash
./run-node.sh zhtp/configs/test-node2.toml
```

Nodes will automatically discover each other via:
- UDP multicast (224.0.1.75:37775)
- DHT peer discovery
- Bootstrap peer connections

## 🔧 Development

### Project Structure
```
sovereign-mono-repo/
├── Cargo.toml              # Workspace configuration
├── build.sh / build.ps1    # Build scripts
├── run-node.sh / run-node.ps1  # Node launcher scripts
├── lib-blockchain/         # Blockchain library
├── lib-consensus/          # Consensus library
├── lib-crypto/             # Crypto library
├── lib-dht/                # DHT library
├── lib-dns/                # DNS library
├── lib-economy/            # Economy library
├── lib-identity/           # Identity library
├── lib-network/            # Network library
├── lib-proofs/             # Proofs library
├── lib-protocols/          # Protocols library
├── lib-storage/            # Storage library
├── zhtp/                   # Main orchestrator
│   ├── src/                # Source code
│   ├── configs/            # Configuration files
│   └── Cargo.toml          # Package manifest
└── target/                 # Build artifacts (gitignored)
```

### Building Individual Crates
```bash
# Build specific library
cargo build -p lib-crypto

# Run tests for specific crate
cargo test -p lib-network

# Build all with verbose output
cargo build --workspace --verbose
```

### Running Tests
```bash
# Run all tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture
```

## 📊 Node Status Indicators

When a node starts successfully, you'll see:
- ✅ **Node ID** - Unique identifier for this node
- ✅ **Local IP** - Network interface address
- ✅ **Mesh Port** - P2P communication port
- ✅ **Multicast Discovery** - Active peer discovery
- ✅ **Active Components** - Crypto, Network, DHT loaded
- ✅ **Broadcasting** - Announcing presence every 30 seconds

## 🔐 Security Features

- **Post-quantum cryptography** support
- **Zero-trust security model**
- **Encrypted mesh networking**
- **DHT-based peer discovery** (no central authority)
- **Configurable security levels** (Low/Medium/High)

## 🛠️ Troubleshooting

### Build Errors
- Ensure Rust 1.70+ is installed: `rustc --version`
- Update Rust: `rustup update`
- Clean build: `cargo clean && cargo build --release`

### Network Issues
- Check firewall allows UDP port 37775 (multicast)
- Check firewall allows TCP port 33444 (mesh)
- Verify network interface supports multicast

### Bootstrap Peer Timeout
- Expected if you're the first node on the network
- Once other nodes start, they'll discover via multicast

## 📝 License

MIT OR Apache-2.0

## 👥 Authors

**Sovereign Network Team**

| Contributor | Role |
|-------------|------|
| Seth Ramsay | Founder |
| Peter Rutherford | Lead Developer |
| Brad Eagle | Developer |
| David Edwards | Developer |
| David Scott | Developer |
| Hugo Perez | Developer |
| Stephen Casino | Developer |

---

**Need Help?** Check the individual crate README files in each `lib-*/` folder for library-specific documentation.
