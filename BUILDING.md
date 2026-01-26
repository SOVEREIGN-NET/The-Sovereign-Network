# Building The Sovereign Network

## Prerequisites

### Ubuntu / Debian

```bash
sudo apt update && sudo apt install -y \
    build-essential \
    clang \
    libclang-dev \
    libsnappy-dev \
    liblz4-dev \
    libzstd-dev \
    zlib1g-dev \
    libbz2-dev \
    cmake \
    pkg-config \
    libssl-dev
```

If RocksDB compilation still fails, install the system package:

```bash
sudo apt install -y librocksdb-dev
export ROCKSDB_LIB_DIR=/usr/lib
```

### Fedora / RHEL

```bash
sudo dnf install -y \
    gcc-c++ \
    clang \
    clang-devel \
    snappy-devel \
    lz4-devel \
    libzstd-devel \
    zlib-devel \
    bzip2-devel \
    cmake \
    openssl-devel
```

### macOS

```bash
brew install cmake snappy lz4 zstd rocksdb openssl
```

## Building

```bash
cargo build --release
```

## Running

**Use `--testnet` for local development and testing.** Production mode requires a configured validator identity and network connectivity that will likely fail on first run.

```bash
# Recommended for development/testing
./target/release/zhtp --testnet

# With verbose logging
RUST_LOG=debug ./target/release/zhtp --testnet
```

## Platform Notes

### macOS: Bluetooth & Network Setup

Bluetooth mesh discovery requires special permissions on macOS. If you encounter permission errors or want to disable Bluetooth scanning:

**Option 1: Skip Bluetooth (No Permissions Required)**
```bash
# Run without Bluetooth - avoids permission prompts entirely
DISABLE_BLUETOOTH=1 ./target/release/zhtp node start --network testnet

# Combined with other environment variables
ZHTP_ALLOW_BOOTSTRAP=1 DISABLE_BLUETOOTH=1 ./target/release/zhtp node start --network testnet
```

**Option 2: Grant Bluetooth Permissions**

Alternatively, grant Bluetooth permissions to Terminal/iTerm in:
**System Preferences → Privacy & Security → Bluetooth**

Then run normally:
```bash
./target/release/zhtp node start --network testnet
```

### Linux: Bluetooth & CAP_NET_ADMIN

Bluetooth requires `CAP_NET_ADMIN` capability or running with elevated privileges:

```bash
# Option 1: Run with sudo (not recommended for production)
sudo ./target/release/zhtp node start --network testnet

# Option 2: Grant capability (recommended)
sudo setcap 'cap_net_admin,cap_net_raw+eip' ./target/release/zhtp
./target/release/zhtp node start --network testnet

# Option 3: Skip Bluetooth entirely
DISABLE_BLUETOOTH=1 ./target/release/zhtp node start --network testnet
```

## Network Configuration

### Firewall Rules

The ZHTP node requires the following ports to be open for peer-to-peer communication:

| Port | Protocol | Purpose |
|------|----------|---------|
| **9334** | UDP | QUIC Mesh Protocol (all node communication) |
| **37775** | UDP Multicast | Peer Discovery (local network only) |

**Important:** Older documentation may reference ports 9333 (TCP) and 33444 (TCP+UDP), which have been replaced by QUIC on port 9334.

**Ubuntu/Debian UFW:**
```bash
sudo ufw allow 9334/udp comment 'ZHTP QUIC Mesh'
sudo ufw allow in from 224.0.1.75 to 224.0.1.75 udp -m udp --dport 37775 comment 'ZHTP Multicast Discovery'
```

**macOS (pf firewall):**
```bash
# Add to /etc/pf.conf
pass in on any proto udp from any to any port 9334
pass in on any proto udp from 224.0.1.0/24 to any port 37775
```

**Windows Firewall (PowerShell as Admin):**
```powershell
New-NetFirewallRule -DisplayName "ZHTP QUIC Mesh" -Direction Inbound -Protocol UDP -LocalPort 9334 -Action Allow
New-NetFirewallRule -DisplayName "ZHTP Multicast Discovery" -Direction Inbound -Protocol UDP -LocalPort 37775 -Action Allow
```

**Verify ports are listening:**
```bash
# Linux/macOS
netstat -tulpn | grep 9334

# macOS (alternative)
lsof -i UDP:9334

# Windows (PowerShell)
Get-NetUDPEndpoint | Where-Object {$_.LocalPort -eq 9334}
```

## Troubleshooting

### RocksDB compilation fails on Ubuntu

Install all dependencies listed above. If errors persist:

```bash
# Use system RocksDB
sudo apt install -y librocksdb-dev
export ROCKSDB_LIB_DIR=/usr/lib
cargo clean
cargo build --release
```

### Missing `libclang`

```bash
# Ubuntu/Debian
sudo apt install libclang-dev

# Fedora
sudo dnf install clang-devel

# macOS
brew install llvm
```

### OpenSSL not found

```bash
# Ubuntu/Debian
sudo apt install libssl-dev pkg-config

# Fedora
sudo dnf install openssl-devel

# macOS
brew install openssl
export OPENSSL_DIR=$(brew --prefix openssl)
```
