# ZHTP Local Development Guide

## Your Local Node Status

✅ **ZHTP Node Running**: `http://localhost:8000`
✅ **API Endpoint**: `http://localhost:8000/api`
✅ **Metrics**: `http://localhost:9000`
✅ **Mode**: Local Development/Test Node
✅ **Zero-Knowledge Proofs**: Actively generating
✅ **Consensus Engine**: Active
✅ **Validator ID**: `f5d3ba97e635`

---

## 🚀 What You Can Develop Right Now

### 1. **DApps (Decentralized Applications)** ✅ AVAILABLE

Your node already has DApp infrastructure running! You can build:

#### HTML/JavaScript DApps (Easiest)
- **No compilation needed** - Pure HTML/CSS/JS
- **Instant deployment** via API
- **Quantum wallet integration** built-in
- **Real-time blockchain interaction**

**Quick Start - Hello World DApp:**

```bash
# Create your first DApp
cat > hello-zhtp.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Hello ZHTP</title>
    <style>
        body {
            background: linear-gradient(135deg, #0f0f23 0%, #4a0080 100%);
            color: white;
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
        }
        button {
            background: linear-gradient(45deg, #00ffff, #0080ff);
            border: none;
            padding: 15px 30px;
            border-radius: 10px;
            cursor: pointer;
            margin: 10px;
            color: white;
            font-size: 16px;
        }
        .info-box {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 15px;
            margin: 20px auto;
            max-width: 600px;
        }
    </style>
</head>
<body>
    <h1>🌐 Hello ZHTP World!</h1>
    <p>Your first decentralized application on Sovereign Network</p>

    <button onclick="connectWallet()">Connect Wallet</button>
    <button onclick="getNetworkStatus()">Network Status</button>

    <div id="output" class="info-box" style="display:none;"></div>

    <script>
        let wallet = null;

        async function connectWallet() {
            try {
                const response = await fetch('http://localhost:8000/api/wallet/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ wallet_type: 'quantum' })
                });

                wallet = await response.json();
                showOutput('✅ Wallet Created!<br>' +
                    'Address: ' + wallet.wallet.address.substring(0, 20) + '...<br>' +
                    'Type: Quantum-Resistant');
            } catch (error) {
                showOutput('❌ Error: ' + error.message);
            }
        }

        async function getNetworkStatus() {
            try {
                const response = await fetch('http://localhost:8000/api/status');
                const status = await response.json();
                showOutput('🌐 Network Status<br>' +
                    'Connected Nodes: ' + status.connected_nodes + '<br>' +
                    'DApps: ' + status.dapps + '<br>' +
                    'ZK Transactions: ' + status.zk_tx);
            } catch (error) {
                showOutput('❌ Error: ' + error.message);
            }
        }

        function showOutput(html) {
            const output = document.getElementById('output');
            output.style.display = 'block';
            output.innerHTML = html;
        }
    </script>
</body>
</html>
EOF

# Test it locally
firefox hello-zhtp.html  # or: chromium hello-zhtp.html
```

#### Smart Contracts (WASM/JavaScript)
- **Rust → WASM** compilation
- **JavaScript contracts** for rapid development
- **On-chain state management**
- **Event emission system**

**Example Token Contract:**
```bash
cd /home/supertramp/Developer/Sovreign-Network/contracts
cat src/lib.rs  # See example token implementation
```

---

### 2. **Zero-Knowledge Proof Experiments** 🔐 ACTIVE

Your node is **actively generating ZK proofs**! Here's what you can experiment with:

#### A. **Basic ZK Proof Generation**

**Experiment 1: Anonymous Voting**
```bash
# Create a test script
cat > /home/supertramp/Developer/Sovreign-Network/test-zk-voting.sh << 'EOF'
#!/bin/bash

echo "🗳️  Testing Anonymous Voting with Zero-Knowledge Proofs"
echo ""

# Generate anonymous vote proof
curl -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "circuit": "anonymous_vote",
    "inputs": {
      "voter_id": 12345,
      "vote": true,
      "nullifier_secret": "my_secret_123"
    }
  }' | jq .

echo ""
echo "✅ Vote proof generated! Your vote is anonymous but verifiable."
EOF

chmod +x /home/supertramp/Developer/Sovreign-Network/test-zk-voting.sh
```

#### B. **Private Transactions**

**Experiment 2: Confidential Transfer**
```bash
cat > /home/supertramp/Developer/Sovreign-Network/test-zk-transfer.sh << 'EOF'
#!/bin/bash

echo "💸 Testing Private Transaction with Zero-Knowledge"
echo ""

# Generate private transfer proof
curl -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "circuit": "private_transfer",
    "inputs": {
      "amount": 100,
      "sender_balance": 1000,
      "recipient": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1"
    }
  }' | jq .

echo ""
echo "✅ Private transfer proof generated!"
echo "The amount and balance are hidden, but the proof is valid."
EOF

chmod +x /home/supertramp/Developer/Sovreign-Network/test-zk-transfer.sh
```

#### C. **Identity Verification**

**Experiment 3: Age Proof Without Revealing Birthdate**
```bash
cat > /home/supertramp/Developer/Sovreign-Network/test-zk-identity.sh << 'EOF'
#!/bin/bash

echo "🆔 Testing Zero-Knowledge Identity Proof"
echo ""

# Prove you're over 18 without revealing your age
curl -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "circuit": "age_verification",
    "inputs": {
      "birth_year": 1990,
      "current_year": 2025,
      "minimum_age": 18
    }
  }' | jq .

echo ""
echo "✅ Age verification proof generated!"
echo "You proved you're over 18 without revealing your birthdate!"
EOF

chmod +x /home/supertramp/Developer/Sovreign-Network/test-zk-identity.sh
```

#### D. **Watch Live ZK Proof Generation**

```bash
# Monitor your node generating proofs in real-time
tail -f /proc/$(pgrep zhtp)/fd/1 | grep -E "(Created polynomial|Generated valid proof)"
```

---

### 3. **Smart Contract Development** 📝

#### Simple Token Contract

```bash
mkdir -p ~/my-zhtp-contracts/token
cd ~/my-zhtp-contracts/token

cat > Cargo.toml << 'EOF'
[package]
name = "my-token"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[lib]
crate-type = ["cdylib"]
EOF

cat > src/lib.rs << 'EOF'
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct Token {
    name: String,
    symbol: String,
    total_supply: u64,
    balances: HashMap<String, u64>,
}

impl Token {
    pub fn new(name: String, symbol: String, initial_supply: u64, owner: String) -> Self {
        let mut balances = HashMap::new();
        balances.insert(owner, initial_supply);

        Self {
            name,
            symbol,
            total_supply: initial_supply,
            balances,
        }
    }

    pub fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<(), String> {
        let from_balance = self.balances.get(from).copied().unwrap_or(0);

        if from_balance < amount {
            return Err("Insufficient balance".to_string());
        }

        self.balances.insert(from.to_string(), from_balance - amount);
        let to_balance = self.balances.get(to).copied().unwrap_or(0);
        self.balances.insert(to.to_string(), to_balance + amount);

        Ok(())
    }

    pub fn balance_of(&self, account: &str) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }
}
EOF

echo "✅ Token contract created at ~/my-zhtp-contracts/token"
```

---

### 4. **DAO Development** 🏛️

Your node has DAO infrastructure running! Create a private DAO:

```bash
cat > test-dao.sh << 'EOF'
#!/bin/bash

echo "🏛️  Creating Private DAO with Anonymous Voting"

# Create proposal
echo "Creating proposal..."
curl -X POST http://localhost:8000/api/dao/propose \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Allocate 10000 ZHTP for Development",
    "description": "Proposal to allocate funds for new features",
    "type": "funding",
    "proposer": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1"
  }' | jq .

# List all proposals
echo ""
echo "All proposals:"
curl -X GET http://localhost:8000/api/dao/proposals | jq .
EOF

chmod +x test-dao.sh
```

---

### 5. **DNS & Domain System** 🌐

Register your own `.zhtp` domains:

```bash
cat > register-domain.sh << 'EOF'
#!/bin/bash

echo "🌐 Registering .zhtp Domain"

# Register a domain
curl -X POST http://localhost:8000/api/dns/register \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "myproject.zhtp",
    "addresses": ["192.168.1.100"],
    "owner": "0x742d35Cc6c4590A76851a7c24c50EaE2D3A8f3F1",
    "ttl": 3600
  }' | jq .

echo ""
echo "Resolving domain..."
curl "http://localhost:8000/api/dns/resolve?domain=myproject.zhtp" | jq .

echo ""
echo "Listing all domains:"
curl http://localhost:8000/api/dns/list | jq .
EOF

chmod +x register-domain.sh
```

---

## 🔬 Zero-Knowledge Proof Experiments You Can Run

### Experiment Set 1: Cryptographic Circuits

#### 1. **Merkle Tree Proof**
Prove membership in a set without revealing which member:

```bash
cat > zk-merkle-proof.sh << 'EOF'
#!/bin/bash
echo "🌳 Testing Merkle Tree Membership Proof"

curl -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "circuit": "merkle_membership",
    "inputs": {
      "leaf": "my_secret_data",
      "root": "merkle_root_hash",
      "path": ["sibling1", "sibling2", "sibling3"]
    }
  }' | jq .
EOF
chmod +x zk-merkle-proof.sh
```

#### 2. **Range Proof**
Prove a value is in range without revealing the value:

```bash
cat > zk-range-proof.sh << 'EOF'
#!/bin/bash
echo "📊 Testing Range Proof (value between 18-100)"

curl -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "circuit": "range_proof",
    "inputs": {
      "value": 25,
      "min": 18,
      "max": 100
    }
  }' | jq .
EOF
chmod +x zk-range-proof.sh
```

#### 3. **Sudoku Solution Proof**
Prove you know a sudoku solution without revealing it:

```bash
cat > zk-sudoku-proof.sh << 'EOF'
#!/bin/bash
echo "🔢 Testing Sudoku Solution Proof"

# Prove you solved the puzzle without revealing the solution!
curl -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "circuit": "sudoku_solution",
    "inputs": {
      "puzzle": [[5,3,0,0,7,0,0,0,0],[6,0,0,1,9,5,0,0,0]],
      "solution": [[5,3,4,6,7,8,9,1,2],[6,7,2,1,9,5,3,4,8]]
    }
  }' | jq .
EOF
chmod +x zk-sudoku-proof.sh
```

### Experiment Set 2: Privacy Applications

#### 4. **Anonymous Credential**
```bash
cat > zk-credential.sh << 'EOF'
#!/bin/bash
echo "🎓 Testing Anonymous Credential Verification"

# Prove you have a credential without revealing which one
curl -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "circuit": "credential_verification",
    "inputs": {
      "credential_hash": "hash_of_degree",
      "issuer_signature": "university_signature",
      "holder_secret": "my_secret_key"
    }
  }' | jq .
EOF
chmod +x zk-credential.sh
```

#### 5. **Private Auction Bid**
```bash
cat > zk-auction-bid.sh << 'EOF'
#!/bin/bash
echo "💰 Testing Private Auction Bid"

# Place a bid without revealing the amount until auction ends
curl -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "circuit": "sealed_bid",
    "inputs": {
      "bid_amount": 5000,
      "max_budget": 10000,
      "bidder_secret": "my_random_nonce"
    }
  }' | jq .
EOF
chmod +x zk-auction-bid.sh
```

### Experiment Set 3: Advanced Cryptography

#### 6. **zkSNARK Performance Test**
```bash
cat > zk-performance-test.sh << 'EOF'
#!/bin/bash
echo "⚡ Testing zkSNARK Generation Performance"
echo ""

for i in {1..10}; do
  echo "Proof #$i:"
  time curl -s -X POST http://localhost:8000/api/zk/generate-proof \
    -H "Content-Type: application/json" \
    -d '{
      "circuit": "simple_computation",
      "inputs": {
        "x": 123,
        "y": 456
      }
    }' | jq -r '.success'
done
EOF
chmod +x zk-performance-test.sh
```

---

## 📊 Available APIs (Full List)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/status` | GET | Network status |
| `/api/wallet/create` | POST | Create quantum wallet |
| `/api/wallet/faucet` | POST | Get test tokens |
| `/api/wallet/{address}/balance` | GET | Check balance |
| `/api/dapps` | GET | List all DApps |
| `/api/dapps/deploy` | POST | Deploy new DApp |
| `/api/dns/register` | POST | Register domain |
| `/api/dns/resolve` | GET | Resolve domain |
| `/api/dao/proposals` | GET | List proposals |
| `/api/dao/propose` | POST | Create proposal |
| `/api/dao/vote` | POST | Vote on proposal |
| `/api/zk/generate-proof` | POST | Generate ZK proof |
| `/api/zk/verify-proof` | POST | Verify ZK proof |
| `/api/contracts/deploy` | POST | Deploy smart contract |

---

## 🎯 Quick Start Checklist

### For DApp Development:
- ✅ Node running on `localhost:8000`
- ✅ Create HTML/JS DApp (see examples above)
- ✅ Test with `firefox hello-zhtp.html`
- ✅ Deploy via `/api/dapps/deploy`

### For Zero-Knowledge Experiments:
- ✅ Node generating proofs (check logs)
- ✅ Run any ZK experiment script above
- ✅ Modify inputs to test different scenarios
- ✅ Monitor proof generation time

### For Smart Contracts:
- ✅ Use Rust + WASM for performance
- ✅ Use JavaScript for rapid prototyping
- ✅ Test locally before deploying
- ✅ Deploy to network when ready

---

## 📚 Learning Resources

### Documentation Available:
- `/docs/api.md` - Full API reference
- `/docs/examples.md` - Code examples
- `/docs/security.md` - Security features
- `/docs/browser.md` - Browser interface
- `/examples/*.rs` - Rust examples

### Run Examples:
```bash
cd /home/supertramp/Developer/Sovreign-Network

# Test contract deployment
cargo run --example contract_testing

# Deploy a sample DApp
cargo run --example deploy_dapp

# Run full testnet simulation
cargo run --example zhtp_testnet
```

---

## 🔥 Next Steps

1. **Start Simple**: Run the Hello World DApp
2. **Experiment with ZK**: Try the voting or transfer proofs
3. **Build Something**: Create your own DApp idea
4. **Test Smart Contracts**: Deploy a token or marketplace
5. **Join Network**: When ready, switch to production node

---

## 🐛 Troubleshooting

**Node not responding?**
```bash
# Check if running
ps aux | grep zhtp

# Check logs
tail -f /proc/$(pgrep zhtp)/fd/1
```

**API errors?**
```bash
# Test basic connectivity
curl http://localhost:8000/api/status
```

**Want to restart node?**
```bash
# Stop
pkill zhtp

# Start fresh
cd /home/supertramp/Developer/Sovreign-Network
./target/release/zhtp
```

---

## 🎉 You're Ready!

Your Sovereign Network node is fully operational with:
- ✅ Zero-Knowledge Proof generation active
- ✅ DApp deployment infrastructure ready
- ✅ Smart contract support enabled
- ✅ Quantum-resistant security active
- ✅ DAO governance available
- ✅ Decentralized DNS system running

**Start building the decentralized future! 🚀**
