# ZHTP Multi-User Network Setup Guide

## 🎉 Network Status: OPERATIONAL

**Date:** November 24, 2025  
**Status:** Two-node testnet successfully deployed with automated user onboarding

---

## 🚀 Quick Start - Running Multiple Nodes

### Prerequisites
- Rust toolchain installed (cargo 1.87.0+)
- Windows PowerShell or Linux/macOS terminal
- Network access for peer discovery

### Starting Nodes with Auto-Wallet Generation

**Node 1 (Bootstrap Validator):**
```powershell
$env:ZHTP_AUTO_WALLET="1"
cd sovereign-mono-repo
.\target\release\zhtp.exe node start --config crates\zhtp\configs\test-node1.toml
```

**Node 2 (Secondary Validator):**
```powershell
$env:ZHTP_AUTO_WALLET="1"
cd sovereign-mono-repo
.\target\release\zhtp.exe node start --config crates\zhtp\configs\test-node2.toml
```

---

## 🎯 Key Features Implemented

### ✅ Automated User Onboarding
Each user/node automatically receives:
- **Primary Wallet**: For general transactions
- **Savings Wallet**: For long-term storage
- **Staking Wallet**: For validator rewards
- **5000 ZHTP**: Welcome bonus
- **20-word seed phrase**: Wallet recovery

### ✅ Network Discovery
- **UDP Multicast**: Automatic peer discovery on 224.0.1.75:37775
- **Bootstrap Peers**: Configured for localhost testing
- **DHT Integration**: Distributed hash table for peer routing
- **Port Scanning**: Fallback discovery method

### ✅ Blockchain Features
- **Genesis Block**: Automatically created with funding pools
- **Identity System**: ZK-proof based with Dilithium3 signatures
- **Validator Registry**: Identity-based consensus
- **Multi-Wallet UTXO**: Full transaction support

### ✅ Security
- **Post-Quantum Cryptography**: Dilithium3, Kyber-768
- **Hybrid Mode**: Classical + quantum-resistant
- **ZK Proofs**: Privacy-preserving identity verification
- **Secure Key Storage**: Private keys never leave memory

---

## 📋 Network Configuration

### Node 1 (test-node1.toml)
```toml
mesh_port = 9001
dht_port = 9001
api_port = 9333
bootstrap_peers = ["127.0.0.1:9002", "localhost:9002"]
```

### Node 2 (test-node2.toml)
```toml
mesh_port = 9002
dht_port = 9002
api_port = 8081
bootstrap_peers = ["127.0.0.1:9001", "localhost:9001"]
```

---

## 🔧 Building from Source

```bash
# Build release version
cd sovereign-mono-repo
cargo build --release -p zhtp

# Executables created:
# - target/release/zhtp.exe (main orchestrator)
# - target/release/zhtp-test.exe (testing)
```

**Build Time:** ~13 minutes (593 crates)

---

## 🌐 Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ZHTP Network Layer                        │
├─────────────────────────────────────────────────────────────┤
│  UDP Multicast Discovery (224.0.1.75:37775)                 │
│  ├─ Node 1: 7ee27b5e-2cb9-4af8-b75c-d457dd6a3e12           │
│  └─ Node 2: 2b7dd412-cf7a-4461-a55c-2a8a993c4040           │
├─────────────────────────────────────────────────────────────┤
│  Mesh Ports: 9001, 9002 (configured, using 33444)          │
│  API Ports: 9333, 8081                                       │
├─────────────────────────────────────────────────────────────┤
│  Identity Layer (lib-identity)                               │
│  ├─ User Identity: 032e531cdcf49cb2 (Human)                │
│  ├─ Node Device: da24d4903d3e0c55 (Device)                 │
│  └─ Wallets: bf34a9c9 (Primary), 20517b84 (Savings),       │
│              7167ceae (Staking)                             │
├─────────────────────────────────────────────────────────────┤
│  Blockchain Layer (lib-blockchain)                           │
│  ├─ Genesis Block: 5 UTXOs, 1 Validator                    │
│  ├─ UBI Pool: 500,000 ZHTP                                  │
│  ├─ Mining Pool: 300,000 ZHTP                               │
│  └─ Dev Pool: 200,000 ZHTP                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 👥 Multi-User Deployment

### For New Users (Interactive Mode)
```powershell
zhtp.exe node start --config my-node.toml
# Follow prompts:
# 1) Create new wallet (generates 20-word seed)
# 2) Import existing wallet from seed phrase
# 3) Import from mesh network
# 4) Quick start (auto-generate for testing)
```

### For Automated Deployment (Servers/CI)
```powershell
$env:ZHTP_AUTO_WALLET="1"
zhtp.exe node start --config server-node.toml
# Automatically creates wallet without prompts
```

---

## 🧪 Testing Verification

### Verified Features:
✅ Cargo build completes successfully (593 crates)  
✅ UDP multicast peer discovery working  
✅ Two nodes discover each other automatically  
✅ Auto-wallet generation via environment variable  
✅ Genesis block creation with validator funding  
✅ Identity registration on blockchain  
✅ Multi-wallet system (3 wallets per user)  
✅ Post-quantum cryptography operational  
✅ Validator registration with 1000 ZHTP stake  

### Network Logs (Node 1 Startup):
```
✓ Multicast broadcasting started (224.0.1.75:37775)
🔍 Attempting to discover existing ZHTP network...
🤖 Auto-wallet mode enabled - generating wallet automatically
✅ Identity and wallet setup complete
   User Identity: 032e531cdcf49cb2
   Node Identity: da24d4903d3e0c55
   Primary Wallet: bf34a9c91c1c0fd9
 Genesis funding created: 5 UTXOs with validator stakes
 Validator registered: 1000 ZHTP stake
```

---

## 🔑 Wallet Management

### Seed Phrase Example (Auto-Generated):
```
mule february pause virtual whale broccoli emotion topic 
denial grocery ginger card stone chair mad weather twice
toast forest honey brief balance legal disagree
```

**⚠️ CRITICAL SECURITY:**
- Write down seed phrase immediately
- Store in multiple secure, offline locations
- Never share, email, or store digitally
- Loss = permanent loss of wallet access

### Wallet Operations:
```bash
# Check wallet balance
zhtp.exe wallet balance --wallet-id <wallet-id>

# Send transaction
zhtp.exe wallet send --to <address> --amount <ZHTP>

# Validator stake
zhtp.exe consensus stake --amount 1000
```

---

## 🐛 Troubleshooting

### Issue: Nodes not discovering each other
**Solution:** Check firewall allows UDP multicast on 224.0.1.75:37775

### Issue: Bootstrap peer timeout
**Normal behavior** - Nodes use multicast discovery as primary method

### Issue: Port already in use
**Solution:** Change `mesh_port` and `api_port` in config file

### Issue: Permission denied on git push
**Solution:** Contact repository owner for write access or fork repository

---

## 📊 Genesis Funding Breakdown

| Pool Type | Amount | Purpose |
|-----------|--------|---------|
| User Welcome Bonus | 5,000 ZHTP | New user incentive |
| Validator Stake | 1,000 ZHTP | Consensus participation |
| UBI Pool | 500,000 ZHTP | Universal Basic Income distribution |
| Mining Pool | 300,000 ZHTP | Block rewards |
| Development Pool | 200,000 ZHTP | Protocol development |

**Total Genesis Supply:** 1,006,000 ZHTP

---

## 🔮 Future Enhancements

### Planned Features:
- [ ] Web dashboard for node monitoring
- [ ] Mobile wallet application
- [ ] Cross-platform peer discovery (Bluetooth, WiFi Direct)
- [ ] Automated node health checks
- [ ] Grafana/Prometheus metrics
- [ ] Smart contract deployment tools
- [ ] DAO governance interface
- [ ] UBI distribution automation

---

## 📞 Support & Contributing

### Repository Structure:
```
sovereign-mono-repo/
├── crates/
│   ├── zhtp/              # Main orchestrator
│   ├── lib-blockchain/     # Blockchain implementation
│   ├── lib-identity/       # Identity & wallet system
│   ├── lib-network/        # Mesh networking
│   ├── lib-consensus/      # Validator consensus
│   ├── lib-crypto/         # Post-quantum crypto
│   └── lib-proofs/         # Zero-knowledge proofs
├── configs/
│   ├── test-node1.toml
│   └── test-node2.toml
└── target/release/
    └── zhtp.exe
```

### Getting Help:
- GitHub Issues: Report bugs and feature requests
- Documentation: `crates/zhtp/docs/`
- API Reference: `crates/zhtp/docs/api-reference.md`

---

## 📜 License

ZHTP Network - Zero-trust Hierarchical Transport Protocol  
Quantum-resistant, privacy-preserving, decentralized internet infrastructure

---

**Status:** ✅ Network operational with 2 active validators  
**Last Updated:** November 24, 2025  
**Network ID:** zhtp-local-test  
**Chain ID:** 99 (testnet)
