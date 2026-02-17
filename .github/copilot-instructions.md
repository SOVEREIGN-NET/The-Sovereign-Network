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
cargo build -p lib-crypto --locked
cargo build -p zhtp-cli --locked

# Build release binary
cargo build --release -p zhtp-cli --locked
```

**IMPORTANT:** Always use the `--locked` flag to ensure Cargo.lock is respected and builds are reproducible.

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
   - All proofs use the `ZkProof` structure (see `lib-proofs/src/types/zk_proof.rs`) with version markers
   - Current: V0 (legacy wrapper)
   - Planned: V1 (typed/governed proofs)
   - See lib-proofs for implementation

3. **Post-Quantum Cryptography:**
   - Support for Dilithium2 and Kyber512
   - Defense-in-depth encryption (TLS 1.3 + ChaCha20Poly1305+Kyber512)
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

### Test Suites Overview

**Integration Tests** (`zhtp-cli/tests/integration_tests.rs`):
- End-to-end CLI command testing
- Run with: `cargo test -p zhtp-cli --test integration_tests --locked -- --nocapture`

**Feature Tests** (`zhtp-cli/tests/feature_tests.rs`):
- Individual feature validation
- Run with: `cargo test -p zhtp-cli --test feature_tests --locked`

**Handler Tests** (`zhtp-cli/tests/handler_tests.rs`):
- Command handler unit tests
- Run with: `cargo test -p zhtp-cli --test handler_tests --locked`

**Network Tests** (lib-network):
- BLE/GATT functionality on macOS with mock
- Run with: `cargo test -p lib-network --locked --features ble-mock -- --nocapture`

### Running Tests

```bash
# Quick test (single package)
cargo test -p lib-crypto --locked

# Full test suite (what CI runs)
cargo test -p zhtp-cli --test integration_tests --locked -- --nocapture
cargo test -p zhtp-cli --test feature_tests --locked
cargo test -p zhtp-cli --test handler_tests --locked

# All tests (workspace-wide - slower)
cargo test --workspace --locked

# With verbose output
cargo test --workspace -- --nocapture

# Specific test by name
cargo test -p zhtp-cli --test integration_tests test_wallet_create --locked -- --nocapture
```

## CI/CD

- **GitHub Actions** workflows in `.github/workflows/`
- CI runs on both Ubuntu and macOS
- Build must pass `cargo build --workspace --locked`
- All tests must pass before merge
- Release builds are cached for deployment

### CI Build Process

**Ubuntu (Primary CI):**
```bash
# Install system dependencies first
sudo apt-get update
sudo apt-get install -y libudev-dev libdbus-1-dev pkg-config

# Build workspace (always use --locked)
cargo build --workspace --locked

# Build release binary for orchestrator node (on main/development pushes)
cargo build --release -p zhtp --locked

# Run all test suites
cargo test -p zhtp-cli --test integration_tests --locked -- --nocapture
cargo test -p zhtp-cli --test feature_tests --locked
cargo test -p zhtp-cli --test handler_tests --locked
```

**macOS (BLE/GATT Coverage):**
```bash
# Build workspace
cargo build --workspace --locked

# Test lib-network with BLE mock feature
cargo test -p lib-network --locked --features ble-mock -- --nocapture

# Build CLI and run all tests
cargo build --release -p zhtp-cli --locked
cargo test -p zhtp-cli --test integration_tests --locked -- --nocapture
cargo test -p zhtp-cli --test feature_tests --locked
cargo test -p zhtp-cli --test handler_tests --locked
```

### CI Environment Settings

```bash
CARGO_TERM_COLOR=always
CARGO_INCREMENTAL=0    # Disable incremental compilation in CI
CARGO_BUILD_JOBS=1     # Single-threaded builds for memory constraints
```

### Disk Space Management (Important!)

CI runners have limited disk space. If builds fail with disk space errors:

```bash
# Free up space before build
sudo rm -rf /usr/share/dotnet
sudo rm -rf /usr/local/lib/android
sudo rm -rf /opt/ghc
sudo rm -rf /opt/hostedtoolcache/CodeQL
sudo docker image prune --all --force
sudo docker system prune --all --force --volumes
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*

# Clean after build
cargo clean
rm -rf target/debug
sudo docker system prune --all --force --volumes
```

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

- **Main README:** `README.md`
- **CLI User Guide:** `CLI_USER_GUIDE.md`
- **Encryption Docs:** `docs/encryption/`
- **Node Connection Guide:** `docs/NODE_CONNECTION_GUIDE.md`
- **Network Rules:** `docs/NETWORK_RULES.md`

### Important Configuration Files

- **Workspace Config:** `Cargo.toml` - Defines all workspace members and shared dependencies
- **Node Configs:** `zhtp/configs/*.toml` - Test node configurations
- **Build Scripts:** `build.sh`, `build.ps1`, `run-node.sh`, `run-node.ps1`
- **CI Workflows:** `.github/workflows/ci.yml` - Main build and test pipeline
- **Git Config:** `.gitmessage` - Commit message template

### Key Source Files

- **Identity System:** `lib-identity/src/` - Seed-anchored identity implementation
- **Proof System:** `lib-proofs/src/types/zk_proof.rs` - Versioned proof structure
- **Network Layer:** `lib-network/src/` - QUIC mesh protocol and BLE
- **Main Binary:** `zhtp/src/main.rs` - Orchestrator node entry point
- **CLI Binary:** `zhtp-cli/src/main.rs` - Command-line interface entry point

### Test Files

- **Integration Tests:** `zhtp-cli/tests/integration_tests.rs`
- **Feature Tests:** `zhtp-cli/tests/feature_tests.rs`
- **Handler Tests:** `zhtp-cli/tests/handler_tests.rs`
- **E2E Tests:** `tests/e2e/runner.sh`
- **Web4 Tests:** `zhtp-cli/tests/WEB4_FUNCTIONAL_TESTING.md`

## Getting Help

When in doubt:
1. Check existing code in similar lib-* crates for patterns
2. Review docs/ for architectural guidance
3. Run `cargo test` early and often
4. Use `RUST_LOG=debug` for detailed logging during development

## Troubleshooting Common Issues

### Build Failures

**Problem: "Out of disk space" during build**
- Solution: Run the disk cleanup commands from CI (see CI/CD section)
- In CI: Builds use `CARGO_BUILD_JOBS=1` to reduce memory usage

**Problem: "Cargo.lock is out of date"**
- Solution: Always use `--locked` flag with cargo commands
- If intentionally updating dependencies: `cargo update` then commit Cargo.lock

**Problem: Build fails on macOS with Bluetooth errors**
- Solution: Use `DISABLE_BLUETOOTH=1` environment variable
- macOS requires special permissions for Bluetooth
- See Platform-Specific Considerations section

**Problem: Linker errors or missing system libraries**
- Ubuntu/Debian: Install `libudev-dev libdbus-1-dev pkg-config build-essential clang libclang-dev libssl-dev`
- macOS: Install `cmake snappy lz4 zstd rocksdb openssl` via Homebrew

### Test Failures

**Problem: Integration tests timeout**
- Integration tests can take 60+ seconds
- Use longer timeout or run with `-- --nocapture` to see progress

**Problem: Network tests fail with "Permission denied"**
- Linux: Bluetooth requires `CAP_NET_ADMIN` capability
- Solution: Use `DISABLE_BLUETOOTH=1` or run with proper capabilities

**Problem: File system tests fail with "Directory not empty"**
- Use `tempfile::TempDir` which cleans up automatically
- Ensure tests don't leak temporary directories

### Runtime Issues

**Problem: Node won't start - "Address already in use"**
- Default ports: 9334/UDP (QUIC), 37775/UDP (Multicast)
- Check for other running nodes: `ps aux | grep zhtp`
- Kill existing: `pkill zhtp` or use different config

**Problem: "Nonce cache corruption" errors**
- Clear nonce caches (as done in deployment):
  ```bash
  rm -rf /opt/zhtp/data/tls/quic_nonce_cache/*
  rm -rf /opt/zhtp/nonce_cache_wifi/*
  rm -rf ~/.zhtp/client_nonce_cache/*
  ```

### Deployment Issues

**Problem: Service fails to start after deployment**
- Check systemd status: `systemctl status zhtp`
- View logs: `journalctl -u zhtp -f`
- Ensure binary has execute permissions: `chmod +x zhtp`
- Verify nonce caches were cleared (see Runtime Issues)

## Validation Steps

Before finalizing changes:
1. **Build**: `cargo build --workspace --locked`
2. **Test**: Run the three core test suites (integration, feature, handler)
3. **Lint**: `cargo fmt && cargo clippy`
4. **Run**: Test the binary works: `cargo run -p zhtp-cli -- --help`
5. **Verify**: Check git status and ensure no unintended changes

---

## Important Reminders

**Trust these instructions first:**
- The commands and steps documented here have been validated and tested
- Only search for additional information if these instructions are incomplete or incorrect
- This reduces time spent exploring and minimizes build/test failures

**Always use `--locked`:**
- All cargo commands should include the `--locked` flag
- This ensures Cargo.lock is respected for reproducible builds
- Exception: Only omit when intentionally updating dependencies

**Memory and disk constraints:**
- CI has limited resources - see disk cleanup commands if builds fail
- Use `CARGO_BUILD_JOBS=1` in constrained environments
- Clean build artifacts after testing: `cargo clean`
