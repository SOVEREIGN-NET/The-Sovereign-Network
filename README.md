# Sovereign Network - Mono Repository

A complete, self-contained repository containing all the Rust code needed to build and run ZHTP (Zero-Knowledge Hypertext Transfer Protocol) orchestrator nodes for the Sovereign Network.

## 📌 Repository Structure

**Default Branch:** `development`

This is a **monorepo** — all libraries are in this repository as regular directories (not git submodules).

**Git Strategy:**
- `development` — main development branch (default)
- `main` — stable release branch
- Feature branches created from `development`

## 🏗️ Architecture

### Identity Architecture (Seed-Anchored)

**Seed is the root of trust** — all identity components derive from a single seed:

- **DID**: `did:zhtp:{Blake3(seed || "ZHTP_DID_V1")}`
- **NodeId**: `Blake3("ZHTP_NODE_V2:" + DID + ":" + device)` → 32 bytes
- **Secrets**: Derived deterministically from seed
- **PQC Keypairs**: Dilithium5 (signing) + Kyber1024 (key exchange) — can be rotated

**Constructors:**
```rust
ZhtpIdentity::new_unified(identity_type, age, jurisdiction, primary_device, seed?)
```
- `seed=None` → random seed (exportable for multi-device)
- `seed=Some(...)` → deterministic identity (same seed → same DID/NodeIds)

### Proof Architecture (Versioned)

**V0 (Current):** `ProofEnvelope { version="v0", proof: ZkProof }` wraps legacy proofs  
**V1 (Planned):** Typed/governed proofs with full validation

All proof serialization includes version markers for forward compatibility.

### Core Libraries (`lib-*`)
- **lib-blockchain** — Blockchain data structures, BFT consensus, sled-backed storage
- **lib-consensus** — Tendermint-style BFT consensus engine
- **lib-crypto** — Cryptographic primitives with post-quantum support (Dilithium5, Kyber1024, BLAKE3)
- **lib-dht** — Distributed Hash Table for peer discovery
- **lib-dns** — DNS resolution and management
- **lib-economy** — Economic models and SOV token management
- **lib-identity** — Seed-anchored identity and authentication (ADR-0001)
- **lib-network** — QUIC mesh networking and UHP v2 handshake
- **lib-proofs** — Versioned zero-knowledge proofs (ADR-0003)
- **lib-protocols** — Protocol definitions and handlers
- **lib-storage** — Distributed storage layer

### Main Application
- **zhtp** — ZHTP Orchestrator node (main binary)
- **zhtp-cli** — Command-line interface for interacting with nodes

## 🚀 Quick Start

### Prerequisites
- **Rust** 1.70+ (install from [rustup.rs](https://rustup.rs/))
- **Git**

### Build & Run

```bash
# Build all crates in release mode
cargo build --release --workspace

# Run the orchestrator node binary directly
./target/release/zhtp --config zhtp/configs/test-node1.toml

# Or start from the CLI command surface
./target/release/zhtp-cli node start --config zhtp/configs/test-node1.toml
```

### Multi-node Testing

```bash
# Terminal 1
./target/release/zhtp --config zhtp/configs/test-node1.toml

# Terminal 2
./target/release/zhtp --config zhtp/configs/test-node2.toml
```

Nodes discover each other via DHT and QUIC peer connections.

## 📋 Configuration

Node configuration files are in `zhtp/configs/`:
- `test-node1.toml` — Default node configuration
- `test-node2.toml` — Secondary node for testing multi-node networks

### Key Configuration Sections
- **Node Settings**: ID, type (full/light), security level
- **Network Settings**: Ports, bootstrap peers (default port: 9334)
- **Crypto Settings**: Post-quantum cryptography options
- **DHT Settings**: Peer discovery configuration

## 🔧 Development

### First-time clone setup

After cloning, activate the pre-commit hook that blocks accidental commits of sensitive files:

```bash
git config core.hooksPath .githooks
```

The hook prevents staging of:
- Symlinks
- Files inside `tmp/` or `.zhtp/`
- Files matching `*.b64`, `*.key`, `*.pem`, `keystore*`, `.env`

> **Never commit private keys, keystore files, base64-encoded archives, or local environment configs.** Use environment variables or a secrets manager for sensitive material.

### Project Structure
```
sovereign-mono-repo/
├── Cargo.toml              # Workspace configuration
├── scripts/                # Build and validation scripts
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
├── tools/                  # Operator tooling (sled-recovery, etc.)
├── zhtp/                   # Main orchestrator
│   ├── src/                # Source code
│   ├── configs/            # Configuration files
│   └── Cargo.toml          # Package manifest
├── zhtp-cli/               # CLI tool
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
- ✅ **Node ID** — Unique identifier for this node
- ✅ **Local IP** — Network interface address
- ✅ **QUIC Port** — P2P communication port (default 9334)
- ✅ **DHT Discovery** — Active peer discovery
- ✅ **Active Components** — Crypto, Network, DHT, Consensus loaded
- ✅ **BFT Consensus** — 4-validator BFT active when quorum is met

## 🔐 Security Features

- **Post-quantum cryptography** — Dilithium5 signatures, Kyber1024 key exchange
- **Zero-trust security model** — On-chain identity verification at QUIC handshake
- **Encrypted mesh networking** — QUIC + UHP v2 + Kyber KEM defense-in-depth
- **DHT-based peer discovery** — No central authority
- **BFT consensus** — Tendermint-style finality with 2f+1 quorum

## 🛠️ Troubleshooting

### Build Errors
- Ensure Rust 1.70+ is installed: `rustc --version`
- Update Rust: `rustup update`
- Clean build: `cargo clean && cargo build --release`

### Network Issues
- Check firewall allows UDP/TCP port 9334 (QUIC mesh)
- Verify nodes can reach each other over the network

### Chain Divergence / Node Halt
- Check logs: `journalctl -u zhtp -n 50`
- If sled is corrupted: stop node, wipe `data/sled/`, restart
- Copy sled from an authoritative peer if needed

## 📝 License

MIT OR Apache-2.0

## 👥 Team

**Sovereign Network**

| Contributor | Role |
|-------------|------|
| Seth Ramsay | Founder |
| Hugo Perez | CTO |
| Peter Rutherford | Lead Developer |
| Brad Eagle | Developer |
| David Edwards | Developer |
| David Scott | Developer |
| Stephen Casino | Developer |

---

**Need Help?** Check the individual crate README files in each `lib-*/` folder for library-specific documentation.
