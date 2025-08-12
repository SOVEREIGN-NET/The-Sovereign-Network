# Getting Started with ZHTP

## 🚀 Quick Setup

### Prerequisites
- Rust (latest stable version)
- Git
- Windows/Linux/macOS

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SOVEREIGN-NETWORK/ZHTP.git
   cd ZHTP
   ```

2. **Build the project:**
   ```bash
   cargo build --release
   ```

3. **Run the ZHTP service:**
   ```bash
   # Windows
   run-zhtp.bat
   
   # Linux/macOS
   cargo run --bin zhtp --release
   ```

4. **Access the browser:**
   - Open your web browser
   - Navigate to `http://localhost:3000`
   - Complete the onboarding process

## 🌐 Live Demo

Once the service is running:

1. **Welcome Page** - `http://localhost:3000/`
   - Choose your sign-in method
   - Create or import a wallet
   - Set up ZK identity (optional)

2. **Main Browser** - `http://localhost:3000/browser`
   - Network monitoring dashboard
   - DApp explorer and deployment
   - Wallet management
   - DNS registry
   - DAO governance
   - Developer tools

3. **Whisper Chat** - `http://localhost:3000/whisper.html`
   - Quantum-resistant messaging
   - End-to-end encrypted communications

## 🔧 Configuration

### Network Selection
- **Testnet** (default) - For development and testing
- **Mainnet** - Production network (when available)
- **Local** - Local development network

### Wallet Setup
1. **Create New Wallet** - Generate a new quantum-resistant wallet
2. **Import Wallet** - Import existing wallet with mnemonic phrase
3. **ZK Identity** - Optional privacy-preserving identity verification

## 📊 Network Status

Monitor your ZHTP network status:
- Connected nodes
- Consensus rounds
- ZK transactions
- Active DApps

## ⚡ Quick Actions

### Test the Network
```bash
# Request test tokens
curl -X POST http://localhost:3000/api/wallet/faucet \
  -H "Content-Type: application/json" \
  -d '{"wallet_address": "your_wallet_address"}'

# Check network status
curl http://localhost:3000/api/status
```

### Deploy a DApp
1. Navigate to DApp Explorer tab
2. Fill in DApp details
3. Upload your code (WASM/JS/HTML)
4. Click "Deploy DApp"

### Register a Domain
1. Go to DNS Registry tab
2. Enter your desired `.zhtp` domain
3. Click "Register ZHTP Domain"

## 🛠️ Troubleshooting

### Common Issues

**Service won't start:**
- Check if port 3000 is available
- Ensure Rust is properly installed
- Try running with `cargo run --release -- --port 3001`

**Browser shows "Please complete onboarding first":**
- Clear browser localStorage
- Visit `http://localhost:3000/` to start onboarding

**Network connection issues:**
- Check firewall settings
- Ensure internet connectivity
- Try switching networks in the browser

## 🔄 Updates

To update ZHTP:
```bash
git pull origin main
cargo build --release
```

## 📞 Support

- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/SOVEREIGN-NETWORK/ZHTP/issues)
- 💡 **Feature Requests:** [GitHub Discussions](https://github.com/SOVEREIGN-NETWORK/ZHTP/discussions)
- 📖 **Documentation:** [docs/](../docs/)

---

Next: [Browser Interface Guide](browser.md)
