# Copilot Instructions for The Sovereign Network

## Project Overview

The Sovereign Network is a **Rust monorepo** implementing ZHTP (Zero-Knowledge Hypertext Transfer Protocol) orchestrator nodes. This is a complete, self-contained repository with all libraries and binaries in one place.

**Key Components:**
- Main binary: `zhtp` - ZHTP Orchestrator node
- CLI binary: `zhtp-cli` - Command-line interface
- Multiple `lib-*` crates providing modular functionality
- All libraries are regular directories (not git submodules)

## Repository Structure

```
/
├── lib-blockchain/      # Blockchain data structures and consensus
├── lib-consensus/       # Consensus mechanisms and validation
├── lib-crypto/          # Cryptographic primitives with post-quantum support
├── lib-dht/            # Distributed Hash Table for peer discovery
├── lib-dns/            # DNS resolution and management
├── lib-economy/        # Economic models and token management
├── lib-identity/       # Seed-anchored identity and authentication
├── lib-network/        # Network layer and mesh networking
├── lib-proofs/         # Versioned zero-knowledge proofs
├── lib-protocols/      # Protocol definitions and handlers
├── lib-storage/        # Distributed storage layer
├── lib-types/          # Common types and utilities
├── zhtp/               # Main orchestrator node binary
├── zhtp-cli/           # CLI binary
├── tests/              # Integration tests
└── docs/               # Documentation
```

## Build and Test Commands

### Building

```bash
# Build entire workspace
cargo build --workspace --locked

# Build specific package
cargo build -p lib-crypto
cargo build -p zhtp-cli

# Build release binary
cargo build --release -p zhtp-cli --locked
```

### Testing

```bash
# Run all tests
cargo test --workspace --locked

# Run tests for specific package
cargo test -p lib-network --locked

# Run specific test suite
cargo test -p zhtp-cli --test integration_tests --locked -- --nocapture

# Run with verbose output
cargo test --workspace -- --nocapture
```

### Running the Application

```bash
# Using convenience scripts
./build.sh              # Linux/macOS/WSL
./run-node.sh          # Run with default config
./run-node.sh zhtp/configs/test-node2.toml  # Custom config

# Using PowerShell (Windows)
.\build.ps1
.\run-node.ps1
.\run-node.ps1 -ConfigFile zhtp\configs\test-node2.toml

# Direct cargo run
cargo run --release -p zhtp -- --config zhtp/configs/test-node1.toml

# With environment variables
RUST_LOG=debug ./target/release/zhtp --testnet
DISABLE_BLUETOOTH=1 ./target/release/zhtp node start --network testnet
```

## Git Workflow

- **Default branch:** `development` (not `main`)
- Feature branches are created from `development`
- All PRs should target `development`
- Only use `main` for production releases

## Coding Conventions

### Rust Best Practices

1. **Edition:** Use Rust 2021 edition (specified in workspace Cargo.toml)
2. **Error Handling:** Use `anyhow::Result` for application code
3. **Async Runtime:** Use `tokio` for async operations
4. **Naming:**
   - Use snake_case for functions, variables, modules
   - Use CamelCase for types, structs, enums
   - Use SCREAMING_SNAKE_CASE for constants

### Architecture Principles

1. **Seed-Anchored Identity:**
   - All identity components derive from a single seed
   - DID format: `did:zhtp:{Blake3(seed || "ZHTP_DID_V1")}`
   - NodeId: `Blake3("ZHTP_NODE_V2:" + DID + ":" + device)`
   - See lib-identity for implementation details

2. **Versioned Proofs:**
   - All proofs use `ProofEnvelope` with version markers
   - Current: V0 (legacy wrapper)
   - Planned: V1 (typed/governed proofs)
   - See lib-proofs for implementation

3. **Post-Quantum Cryptography:**
   - Support for Dilithium2 and Kyber512
   - Defense-in-depth encryption (TLS 1.3 + ChaCha20+Kyber)
   - See docs/encryption/ for detailed architecture

### Code Organization

- Each `lib-*` crate should be self-contained with minimal dependencies
- Use workspace dependencies in root Cargo.toml for version consistency
- Keep example code in `examples/` directory within each crate
- Integration tests go in workspace-level `tests/` directory
- Unit tests should be in the same file as the code being tested

### Documentation

- Use rustdoc comments (`///`) for public APIs
- Include examples in documentation when appropriate
- Update relevant docs in `docs/` when making architectural changes
- Reference Architecture Decision Records (ADRs) when available

### Platform-Specific Considerations

**macOS:**
- Bluetooth requires special permissions
- Use `DISABLE_BLUETOOTH=1` to skip Bluetooth scanning
- Core Bluetooth framework linked via build.rs

**Linux:**
- Bluetooth requires `CAP_NET_ADMIN` capability
- Use `sudo setcap` or run with `DISABLE_BLUETOOTH=1`

**Network Ports:**
- 9334/UDP: QUIC Mesh Protocol (all node communication)
- 37775/UDP: Multicast Peer Discovery (local network only)

## Dependencies

### System Requirements

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y libudev-dev libdbus-1-dev pkg-config \
    build-essential clang libclang-dev libssl-dev
```

**macOS:**
```bash
brew install cmake snappy lz4 zstd rocksdb openssl
```

### Key Rust Dependencies

- `tokio` - Async runtime
- `anyhow` - Error handling
- `serde` - Serialization
- `blake3` - Cryptographic hashing
- `quinn` - QUIC protocol implementation

## Security Considerations

1. **Never commit secrets or private keys** to the repository
2. **Post-quantum crypto** is enabled by default; don't disable without good reason
3. **Validate NodeId against identity** in handshake operations
4. **Use constant-time comparisons** for cryptographic operations
5. **Follow zero-trust security model** in network operations

## Testing Requirements

- All new features must include unit tests
- Network features should include integration tests
- Use `#[tokio::test]` for async tests
- Mock external dependencies where appropriate
- Use `tempfile::TempDir` for filesystem tests

## CI/CD

- **GitHub Actions** workflows in `.github/workflows/`
- CI runs on both Ubuntu and macOS
- Build must pass `cargo build --workspace --locked`
- All tests must pass before merge
- Release builds are cached for deployment

## Common Tasks

### Adding a New Library Crate

1. Create new directory `lib-<name>/`
2. Add `lib-<name>/Cargo.toml` with workspace inheritance
3. Add to workspace members in root `Cargo.toml`
4. Follow existing lib-* structure (src/, examples/, tests/)

### Updating Dependencies

```bash
# Update Cargo.lock
cargo update

# Check for outdated dependencies
cargo outdated

# Update specific dependency
cargo update -p <package-name>
```

### Running Specific Tests

```bash
# Integration tests
cargo test -p zhtp-cli --test integration_tests

# Feature tests
cargo test -p zhtp-cli --test feature_tests

# Handler tests
cargo test -p zhtp-cli --test handler_tests

# Network tests with BLE mock
cargo test -p lib-network --features ble-mock
```

## Resources

- **Main README:** `/README.md`
- **Building Guide:** `/BUILDING.md`
- **CLI User Guide:** `/CLI_USER_GUIDE.md`
- **Encryption Docs:** `/docs/encryption/`
- **Node Connection Guide:** `/docs/NODE_CONNECTION_GUIDE.md`
- **Network Rules:** `/docs/NETWORK_RULES.md`

## Getting Help

When in doubt:
1. Check existing code in similar lib-* crates for patterns
2. Review docs/ for architectural guidance
3. Run `cargo test` early and often
4. Use `RUST_LOG=debug` for detailed logging during development
