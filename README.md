# The Sovereign Network

**A decentralized internet infrastructure built on zero-knowledge privacy
and post-quantum cryptography.**

The Sovereign Network replaces centralized internet services with a
community-owned mesh network where participants earn SOV tokens for routing
data, storing content, and running nodes. Governance is handled through DAOs,
and Universal Basic Income is distributed to all verified citizens.

## Repository layout

This is a **Rust workspace** containing all core protocol libraries, node
software, CLI tools, and supporting services.

### Node & tools

| Crate | Description |
|-------|-------------|
| [`zhtp`](zhtp/) | Main ZHTP node — orchestrates networking, blockchain, identity, and Web4 |
| [`zhtp-daemon`](zhtp-daemon/) | Local browser companion — resolves `.zhtp` domains over QUIC via localhost |
| [`zhtp-cli`](zhtp-cli/) | Command-line interface for node management, wallets, DAO, and identity |
| [`explorer`](explorer/) | Leptos/WASM block explorer |
| [`browser-extension`](browser-extension/) | Browser extension for Web4 access |

### Protocol libraries

| Crate | Description |
|-------|-------------|
| `lib-crypto` | Post-quantum cryptography (CRYSTALS-Dilithium/Kyber), BLAKE3, Ed25519 |
| `lib-proofs` | Zero-knowledge proofs (Plonky2) |
| `lib-identity` / `lib-identity-core` | Privacy-preserving DID identity management |
| `lib-network` | Mesh networking, QUIC, peer discovery, Web4 content delivery |
| `lib-dht` | Distributed hash table |
| `lib-dns` | ZDNS — decentralized domain name resolution |
| `lib-protocols` | ZHTP request/response types, protocol definitions |
| `lib-blockchain` | Chain model, WASM contracts, UBI, Web4 domain registry |
| `lib-consensus` / `lib-consensus-*` | BFT/hybrid consensus (rewrite v2 in progress) |
| `lib-economy` | Token economics, rewards, fee distribution, UBI, staking |
| `lib-tokens` / `lib-fees` | Token types and fee calculation |
| `lib-governance` | DAO governance mechanics |
| `lib-utxo` / `lib-mempool` | UTXO model and transaction mempool |
| `lib-storage` | Distributed encrypted storage |
| `lib-access-control` | Permission and capability management |
| `lib-client` | Cross-platform client SDK (UniFFI, WASM, React Native) |
| `lib-types` | Shared type definitions |

### Operations

| Path | Description |
|------|-------------|
| `deploy/` | systemd units, Ansible playbooks for multi-distro deployment |
| `tools/` | Dilithium signer, DAO registration, sled utilities |
| `tests/` | Integration and e2e test suites |
| `docs/` | Architecture notes, epics, forensic analyses |
| `.github/workflows/` | CI, release pipelines, secret scanning, SonarCloud |

## Getting started

### Prerequisites

- **Rust 1.70+** — install from [rustup.rs](https://rustup.rs/)
- 4 GB RAM, 10 GB storage minimum

### Build

```bash
git clone https://github.com/SOVEREIGN-NET/The-Sovereign-Network.git
cd The-Sovereign-Network

# Development build
cargo build

# Release build
cargo build --release

# Raspberry Pi / edge targets
cargo build --profile rpi
cargo build --profile edge
```

### Run a node

```bash
# Start in development mode
cargo run -p zhtp -- node start --dev

# Start with custom config
cargo run -p zhtp -- node start --config config.toml --port 9334
```

### CLI usage

```bash
# Node management
zhtp-cli node start --dev
zhtp-cli node status

# Wallet operations
zhtp-cli wallet create --name "MyWallet" --type citizen
zhtp-cli wallet balance <address>

# Identity
zhtp-cli identity create-did Alice --type human

# DAO governance
zhtp-cli dao info
zhtp-cli dao claim-ubi
```

See [`zhtp/README.md`](zhtp/README.md) for the full command reference.

### Run tests

```bash
cargo test --workspace
```

## Architecture

```
┌──────────────────────────────────────────────────┐
│               ZHTP Node (Orchestrator)           │
└──────────────────┬───────────────────────────────┘
                   │
     ┌─────────────┼─────────────┐
     │             │             │
┌────▼────┐  ┌─────▼─────┐  ┌────▼────┐
│Protocols│  │  Network   │  │Blockchain│
│  (ZHTP) │  │(Mesh/QUIC) │  │ (Chain)  │
└─────────┘  └───────────┘  └──────────┘
     │             │             │
┌────▼────┐  ┌─────▼─────┐  ┌────▼────┐
│ Storage │  │  Economy   │  │Consensus│
│  (DHT)  │  │(SOV/UBI)   │  │  (BFT)  │
└─────────┘  └───────────┘  └──────────┘
     │             │             │
┌────▼────┐  ┌─────▼─────┐  ┌────▼────┐
│Identity │  │  Proofs    │  │ Crypto  │
│  (DID)  │  │  (Plonky2) │  │  (PQC)  │
└─────────┘  └───────────┘  └──────────┘
```

## Deployment

The project deploys via **systemd** on Linux. See [`deploy/`](deploy/) for:

- systemd service units
- Ansible playbooks (Ubuntu, RHEL, Arch, Alpine)
- `zhtp-daemon` install scripts

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Run tests: `cargo test && cargo fmt --check && cargo clippy`
4. Submit a pull request

See [`zhtp/README.md`](zhtp/README.md) for detailed development setup.

## License

MIT OR Apache-2.0

---

[Website](https://thesovereignnetwork.org) ·
[Discord](https://discord.gg/sovereignnetwork) ·
[Documentation](https://thesovereignnetwork.org/documentation/)
