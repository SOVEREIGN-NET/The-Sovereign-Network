# macOS Node Quickstart (Validated)

This quickstart is the supported baseline for bringing up a node on macOS with stable transport defaults.

## Prerequisites

- Xcode Command Line Tools (`xcode-select --install`)
- Rust nightly toolchain (repo uses `rust-toolchain.toml`)
- Git

## 1) Install/activate nightly

```bash
rustup toolchain install nightly
rustup default nightly
```

## 2) Build binaries

```bash
cargo build --release --workspace
```

## 3) Validate mac baseline config

```bash
bash zhtp/configs/validate-config.sh zhtp/configs/mac-bootstrap.toml
```

Expected validation includes:

- `Transport contract: QUIC-only mesh transport validated`

## 4) Start the node

```bash
./target/release/zhtp --config zhtp/configs/mac-bootstrap.toml
```

## Experimental transport opt-in (macOS)

`quic` is the stable default transport profile on macOS.
To opt in to experimental transports (`bluetooth`, `bluetooth_le`, `wifi_direct`, `lorawan`):

```bash
export ZHTP_ENABLE_EXPERIMENTAL_MAC_TRANSPORTS=1
./target/release/zhtp --config zhtp/configs/full-node.toml
```
