# Dev Node vs Prod Node - Current Reality

## TL;DR: NO FUNCTIONAL DIFFERENCE

At this moment, there is **ZERO functional difference** between your "dev" and "prod" nodes.

They are **identical** except for port numbers.

---

## What's Actually Different

### Port Numbers Only

**Dev Node:**
```bash
API Port:     8001
P2P Port:     19848
Bind Port:    7001
Metrics Port: 9001
Node Name:    "dev-node"
```

**Prod Node:**
```bash
API Port:     8000
P2P Port:     19847
Bind Port:    7000
Metrics Port: 9000
Node Name:    "prod-node"
```

### Separate Log Files

```
logs/dev-console.log   → Dev node output
logs/prod-console.log  → Prod node output
```

### Empty Data Directories

```bash
data-dev/   → Created but empty (not used)
data-prod/  → Created but empty (not used)
```

---

## What's The SAME (Everything Else)

### 1. Same Binary
```bash
Both running: ./target/release/zhtp
Same compilation
Same code
Same features
```

### 2. Same Network Type
```
Both: Local testnet only
Both: Simulated peers (not real external nodes)
Both: Bootstrap nodes point to localhost
Both: NOT connected to mainnet (doesn't exist)
```

### 3. Same Blockchain State
```json
Dev Node:  {"connected_nodes":5,"dapps":1,"status":"ok","zk_tx":2322}
Prod Node: {"connected_nodes":5,"dapps":1,"status":"ok","zk_tx":2322}
```
**IDENTICAL** - They're likely sharing the same underlying data!

### 4. Same ZK Proof Activity
```
Dev log:  "Generated valid proof with 10 total commitments"
Prod log: "Generated valid proof with 10 total commitments"
```
Same proof generation happening on both.

### 5. Same API Endpoints
```
Both have only 4 working endpoints:
✅ GET  /api/status
✅ GET  /api/resolve
✅ GET  /api/peer-availability
✅ POST /api/message
```

### 6. Same Capabilities
```
Both support:
- ZK proofs
- Smart contracts
- DAO voting
- Token creation
- DNS resolution
- All core features
```

---

## Why This Setup Exists

**It's NOT dev vs prod functionality.**

**It's for testing different scenarios on the same machine:**

### Use Case 1: Port Conflict Testing
Test if your app works when node is on non-default ports.

### Use Case 2: Multi-Node Development
Simulate peer-to-peer connections between local nodes (though currently they're not actually talking to each other as separate peers).

### Use Case 3: API Version Testing
Test different API configurations without stopping your main node.

### Use Case 4: Organizational Convenience
- Dev node (8001): For experimental DApp testing
- Prod node (8000): For stable DApp testing

---

## What It's NOT

❌ **NOT separate networks** (mainnet vs testnet)
❌ **NOT different feature sets**
❌ **NOT different data/blockchain state**
❌ **NOT different security levels**
❌ **NOT different peer sets**
❌ **NOT production-ready vs development-only**

---

## Current Status Verification

```bash
# Check processes
ps aux | grep zhtp

Output:
supertramp  140684  ./target/release/zhtp  # Dev node
supertramp  140709  ./target/release/zhtp  # Prod node
```

**Same binary, different processes, different ports.**

```bash
# Check ports
ss -tlnp | grep zhtp

Output:
0.0.0.0:8001  # Dev node API
0.0.0.0:8000  # Prod node API
```

**Only API ports listening** (P2P ports may not be accepting external connections).

```bash
# Check status
curl http://localhost:8001/api/status
{"connected_nodes":5,"dapps":1,"status":"ok","zk_tx":2322}

curl http://localhost:8000/api/status
{"connected_nodes":5,"dapps":1,"status":"ok","zk_tx":2322}
```

**Identical responses.**

---

## What SHOULD Be Different (For Real Dev vs Prod)

If this were a **real** dev vs prod setup, you'd expect:

### Real Production Node Would Have:

1. **Different Network**
   ```
   Prod: Connected to real mainnet
   Dev:  Local testnet
   ```

2. **Different Peers**
   ```
   Prod: External seeder nodes
   Dev:  Localhost only
   ```

3. **Different Data Isolation**
   ```
   Prod: /var/lib/zhtp/prod-data
   Dev:  /home/user/zhtp-dev-data
   ```

4. **Different Configuration**
   ```
   Prod: Production bootstrap nodes
   Dev:  Local test bootstrap nodes
   ```

5. **Different Security**
   ```
   Prod: Firewall rules, rate limiting, monitoring
   Dev:  Open access for testing
   ```

6. **Different Purpose**
   ```
   Prod: Real transactions, real value
   Dev:  Testing, experimentation
   ```

### But Currently:

**NONE of the above differences exist.**

Both are just local test nodes on different ports.

---

## Practical Usage Right Now

Since they're functionally identical, here's how to use them:

### Strategy 1: Feature Segregation

```bash
# Dev Node (8001): Experimental features
curl http://localhost:8001/api/...
# Test new DApp features here
# Break things safely

# Prod Node (8000): Stable testing
curl http://localhost:8000/api/...
# Test stable DApp versions
# Reference implementation
```

### Strategy 2: Multi-Client Testing

```bash
# Test if two DApps can coexist
# DApp A → talks to localhost:8001
# DApp B → talks to localhost:8000
```

### Strategy 3: Load Testing

```bash
# Simulate multiple nodes
# Send requests to both
# Monitor resource usage
```

### Strategy 4: Just Use One

```bash
# Honestly, you could just use one node
# No functional benefit to running both right now
# Save resources, stop one:
pkill -f "zhtp" -n  # Stop newest (prod or dev)
```

---

## When They WILL Be Different

**After mainnet launches:**

### Then you could run:

**Prod Node:**
```bash
# Connected to real Sovereign Network mainnet
export ZHTP_NETWORK=mainnet
export ZHTP_BOOTSTRAP_NODES="seeder1.sovereign.network:19847,seeder2.sovereign.network:19847"
export ZHTP_DATA_DIR="/var/lib/zhtp/mainnet"
./target/release/zhtp
```

**Dev Node:**
```bash
# Connected to local testnet or official testnet
export ZHTP_NETWORK=testnet
export ZHTP_BOOTSTRAP_NODES="127.0.0.1:8002"
export ZHTP_DATA_DIR="/home/user/zhtp-testnet"
./target/release/zhtp
```

**Then they'd be truly different:**
- Different networks
- Different peers
- Different blockchain state
- Different purpose
- Different data

---

## Should You Keep Running Both?

### Keep Both If:
- ✅ Testing port compatibility
- ✅ Want separation for organization
- ✅ Testing multi-client scenarios
- ✅ Developing tools that talk to multiple nodes
- ✅ Have resources to spare (they're lightweight)

### Just Use One If:
- ✅ Simple DApp development
- ✅ Want to save resources
- ✅ Don't need multiple nodes
- ✅ Confused by having two identical nodes

### Recommendation:

**Just use the prod node (port 8000) for now.**

Stop the dev node to free up resources:
```bash
# Find dev node PID
ps aux | grep zhtp | grep 8001

# Or just use the stop script and restart only prod
./stop-nodes.sh

# Start only prod node
ZHTP_NODE_NAME="prod-node" \
ZHTP_API_PORT=8000 \
ZHTP_P2P_PORT=19847 \
ZHTP_BIND_PORT=7000 \
ZHTP_METRICS_PORT=9000 \
./target/release/zhtp > logs/prod-console.log 2>&1 &
```

**When you need dev node again, start it.**

No point running both if they're identical.

---

## Future: Real Dev vs Prod Setup

**When mainnet exists, do this:**

### 1. Prod Node → Mainnet
```bash
cat > start-prod-mainnet.sh << 'EOF'
#!/bin/bash
export ZHTP_NETWORK=mainnet
export ZHTP_NODE_NAME="prod-mainnet"
export ZHTP_API_PORT=8000
export ZHTP_P2P_PORT=19847
export ZHTP_DATA_DIR="/var/lib/zhtp/mainnet"
export ZHTP_BOOTSTRAP_NODES="seeder1.sovereign.network:19847,seeder2.sovereign.network:19847"
./target/release/zhtp
EOF
```

### 2. Dev Node → Local Testnet
```bash
cat > start-dev-local.sh << 'EOF'
#!/bin/bash
export ZHTP_NETWORK=local
export ZHTP_NODE_NAME="dev-local"
export ZHTP_API_PORT=8001
export ZHTP_P2P_PORT=19848
export ZHTP_DATA_DIR="$HOME/zhtp-dev"
export ZHTP_BOOTSTRAP_NODES="127.0.0.1:8002"
./target/release/zhtp
EOF
```

**THEN it makes sense to run both:**
- Real transactions on mainnet (prod)
- Safe testing on testnet (dev)

---

## Summary Table

| Aspect | Dev Node | Prod Node | Difference? |
|--------|----------|-----------|-------------|
| Binary | `./target/release/zhtp` | `./target/release/zhtp` | ❌ Same |
| API Port | 8001 | 8000 | ✅ Different |
| P2P Port | 19848 | 19847 | ✅ Different |
| Node Name | "dev-node" | "prod-node" | ✅ Different |
| Network | Local testnet | Local testnet | ❌ Same |
| Blockchain State | Shared | Shared | ❌ Same |
| Features | All | All | ❌ Same |
| ZK Proofs | Yes | Yes | ❌ Same |
| Smart Contracts | Yes | Yes | ❌ Same |
| DAO | Yes | Yes | ❌ Same |
| External Peers | No | No | ❌ Same |
| Data Directory | Empty | Empty | ❌ Same |
| HTTP Endpoints | 4 | 4 | ❌ Same |
| **TOTAL FUNCTIONAL DIFFERENCE** | | | **NONE** |

---

## Bottom Line

**Right now: They're the same node on different ports.**

**Future: They COULD be different when mainnet exists.**

**Recommendation: Just use one (port 8000) unless you specifically need two for testing.**

---

*Reality check: 2025-10-22*
*Both nodes verified identical except for port configuration*
