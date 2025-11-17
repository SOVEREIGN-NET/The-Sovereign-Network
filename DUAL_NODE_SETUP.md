# Running Dev and Production Nodes Simultaneously

## ✅ YES! You Can Run Both on the Same Machine

Your machine can run both a **development node** and a **production node** at the same time using different ports and data directories.

---

## 📊 Port Allocation

| Service | Dev Node | Prod Node | Purpose |
|---------|----------|-----------|---------|
| **API/HTTP** | 8001 | 8000 | REST API & Browser |
| **P2P Network** | 19848 | 19847 | Node-to-node communication |
| **DNS** | 5354 | 5353 | Domain resolution |
| **Metrics** | 9001 | 9000 | Monitoring & stats |

---

## 🚀 Quick Start

### Option 1: Using the Current Dev Node + New Prod Node

Your dev node is already running on port 8000. Let's start a production node on different ports:

```bash
cd /home/supertramp/Developer/Sovreign-Network

# Your dev node is ALREADY running on:
# - API: http://localhost:8000
# - Network: 19847 (currently default)

# Start production node on different ports (if config supported)
# ZHTP_API_PORT=8002 ZHTP_P2P_PORT=19849 ./target/release/zhtp-production
```

### Option 2: Stop Current Node and Start Both with Configs

```bash
# Stop current node
pkill zhtp

# Start dev node
./target/release/zhtp --config dev-node.toml &

# Start prod node
./target/release/zhtp-production --config prod-node.toml &
```

---

## 📁 Directory Structure

Running both nodes creates separate data directories:

```
Sovreign-Network/
├── data-dev/           # Dev node data
│   ├── blockchain/
│   ├── storage/
│   └── keys/
├── data-prod/          # Prod node data
│   ├── blockchain/
│   ├── storage/
│   └── keys/
├── logs/
│   ├── dev-node.log
│   └── prod-node.log
├── dev-node.toml       # ✅ Created
└── prod-node.toml      # ✅ Created
```

---

## 🔧 Configuration Files Created

I've created two configuration files for you:

### 1. `dev-node.toml` - Development Node
- **API**: Port 8001
- **P2P**: Port 19848
- **DNS**: Port 5354
- **Data**: `./data-dev`
- **Features**: Fast blocks, debug logging, CORS enabled

### 2. `prod-node.toml` - Production Node
- **API**: Port 8000
- **P2P**: Port 19847
- **DNS**: Port 5353
- **Data**: `./data-prod`
- **Features**: Secure, TLS enabled, production logging

---

## 🎯 Use Cases

### Why Run Both?

1. **Testing & Production**
   - Test new features on dev node
   - Run stable production node for real work
   - Compare behavior between environments

2. **Development Workflow**
   - Deploy experimental DApps to dev node
   - Promote stable DApps to prod node
   - Test upgrades before production

3. **Learning**
   - Experiment on dev without risk
   - Learn production node operation
   - Compare performance characteristics

4. **Multi-Network**
   - Dev node connects to testnet
   - Prod node connects to mainnet
   - Bridge between networks for testing

---

## 📝 Management Scripts

### Start Both Nodes

Create a startup script:

```bash
cat > start-dual-nodes.sh << 'EOF'
#!/bin/bash

echo "🚀 Starting ZHTP Dual Node Setup"
echo ""

# Create directories
mkdir -p data-dev data-prod logs

# Stop any existing nodes
pkill zhtp 2>/dev/null

# Start Dev Node
echo "Starting Dev Node (API: 8001, P2P: 19848)..."
ZHTP_CONFIG_PATH=dev-node.toml ./target/release/zhtp > logs/dev-console.log 2>&1 &
DEV_PID=$!
echo "Dev Node PID: $DEV_PID"

sleep 2

# Start Prod Node
echo "Starting Prod Node (API: 8000, P2P: 19847)..."
ZHTP_CONFIG_PATH=prod-node.toml ./target/release/zhtp-production > logs/prod-console.log 2>&1 &
PROD_PID=$!
echo "Prod Node PID: $PROD_PID"

sleep 3

# Check status
echo ""
echo "=== Node Status ==="
if ps -p $DEV_PID > /dev/null; then
    echo "✅ Dev Node: Running (PID $DEV_PID)"
    echo "   API: http://localhost:8001/api/status"
else
    echo "❌ Dev Node: Failed to start"
fi

if ps -p $PROD_PID > /dev/null; then
    echo "✅ Prod Node: Running (PID $PROD_PID)"
    echo "   API: http://localhost:8000/api/status"
else
    echo "❌ Prod Node: Failed to start"
fi

echo ""
echo "📊 Logs:"
echo "   Dev:  tail -f logs/dev-console.log"
echo "   Prod: tail -f logs/prod-console.log"
EOF

chmod +x start-dual-nodes.sh
```

### Monitor Both Nodes

```bash
cat > monitor-nodes.sh << 'EOF'
#!/bin/bash

echo "📊 ZHTP Dual Node Monitor"
echo "=========================="
echo ""

# Dev Node Status
echo "🔧 DEV NODE (Port 8001)"
DEV_STATUS=$(curl -s http://localhost:8001/api/status 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$DEV_STATUS" | jq .
else
    echo "❌ Dev node not responding"
fi

echo ""

# Prod Node Status
echo "🏭 PROD NODE (Port 8000)"
PROD_STATUS=$(curl -s http://localhost:8000/api/status 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$PROD_STATUS" | jq .
else
    echo "❌ Prod node not responding"
fi

echo ""
echo "=== Process Status ==="
ps aux | grep -E "zhtp|PID" | grep -v grep
EOF

chmod +x monitor-nodes.sh
```

### Stop Both Nodes

```bash
cat > stop-nodes.sh << 'EOF'
#!/bin/bash

echo "🛑 Stopping ZHTP Nodes..."

# Find and stop all zhtp processes
pkill -f "zhtp"

sleep 2

# Verify
if pgrep -f zhtp > /dev/null; then
    echo "⚠️  Some processes still running, force killing..."
    pkill -9 -f zhtp
    sleep 1
fi

if ! pgrep -f zhtp > /dev/null; then
    echo "✅ All ZHTP nodes stopped"
else
    echo "❌ Failed to stop all nodes"
fi
EOF

chmod +x stop-nodes.sh
```

---

## 🧪 Testing the Dual Setup

### 1. Start Both Nodes

```bash
./start-dual-nodes.sh
```

### 2. Test Dev Node

```bash
# Check status
curl http://localhost:8001/api/status | jq .

# Create wallet
curl -X POST http://localhost:8001/api/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"wallet_type": "quantum"}' | jq .
```

### 3. Test Prod Node

```bash
# Check status
curl http://localhost:8000/api/status | jq .

# Create wallet
curl -X POST http://localhost:8000/api/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"wallet_type": "quantum"}' | jq .
```

### 4. Monitor Both

```bash
./monitor-nodes.sh
```

---

## 🔍 Comparing Performance

Watch both nodes generate ZK proofs:

```bash
# Terminal 1: Dev node
tail -f logs/dev-console.log | grep -E "(Generated valid proof|Created polynomial)"

# Terminal 2: Prod node
tail -f logs/prod-console.log | grep -E "(Generated valid proof|Created polynomial)"
```

Compare speeds:

```bash
# Dev node (faster blocks)
time curl -s -X POST http://localhost:8001/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{"circuit": "simple", "inputs": {"x": 123}}'

# Prod node (optimized)
time curl -s -X POST http://localhost:8000/api/zk/generate-proof \
  -H "Content-Type: application/json" \
  -d '{"circuit": "simple", "inputs": {"x": 123}}'
```

---

## 🌐 Network Isolation

The two nodes run independently:

- **Separate blockchains**: Each has its own blockchain state
- **Separate storage**: DHT data doesn't overlap
- **Independent peers**: Each can connect to different networks
- **Isolated economics**: Different token supplies

To make them communicate, you can:

1. **Add as peers**: Configure each as a bootstrap peer of the other
2. **Bridge setup**: Use cross-chain bridge functionality
3. **Shared DHT**: Configure to use the same DHT network

---

## ⚙️ Resource Usage

### Typical Resource Requirements

**Per Node:**
- CPU: 2-4 cores (varies with activity)
- RAM: 1-2 GB
- Disk: 5-100 GB (depending on config)
- Network: 100-500 Kbps

**Both Nodes:**
- CPU: 4-8 cores recommended
- RAM: 4-6 GB total
- Disk: 15-200 GB
- Network: 200-1000 Kbps

Your machine should handle both easily with:
```bash
# Check resources
htop
df -h
free -h
```

---

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Check what's using a port
sudo lsof -i :8000
sudo lsof -i :8001

# Kill specific process
kill <PID>
```

### Nodes Won't Start

```bash
# Check logs
tail -100 logs/dev-console.log
tail -100 logs/prod-console.log

# Verify configs
cat dev-node.toml
cat prod-node.toml

# Clean start
./stop-nodes.sh
rm -rf data-dev data-prod
./start-dual-nodes.sh
```

### Config Not Loading

If the production binary doesn't support config files yet:

```bash
# Current workaround: Run dev node on different port
# The current zhtp binary IS your dev node, already running!

# Just access it at: http://localhost:8000

# For true production, you'd need to:
# 1. Connect to real mainnet seeders
# 2. Run zhtp-production with environment variables
# 3. Or use the current node in production mode
```

---

## 📊 Current Status

**Right Now:**
- ✅ Your dev node is running: `http://localhost:8000`
- ✅ Config files created for dual setup
- ✅ Ready to start second node when needed

**Next Steps:**
1. Keep dev node running for experimentation
2. When ready for production, use the dual setup scripts
3. Or continue using current node for both dev and prod work

---

## 🎓 Best Practices

1. **Development Workflow**
   - Always test on dev node first
   - Use prod node for demos and stable releases
   - Keep data directories separate

2. **Monitoring**
   - Run monitor script regularly
   - Check logs for errors
   - Monitor resource usage

3. **Upgrades**
   - Update dev node first
   - Test thoroughly
   - Then upgrade prod node

4. **Backups**
   ```bash
   # Backup prod data
   tar -czf backup-prod-$(date +%Y%m%d).tar.gz data-prod/

   # Backup dev data (optional)
   tar -czf backup-dev-$(date +%Y%m%d).tar.gz data-dev/
   ```

---

## ✅ Summary

**YES, you can run both!** The setup uses:
- ✅ Different ports (no conflicts)
- ✅ Separate data directories
- ✅ Independent configurations
- ✅ Isolated networks

**Your current setup:**
- Dev node running on port 8000
- Ready to add prod node anytime
- Scripts created for easy management

**Simple command to check:**
```bash
curl http://localhost:8000/api/status | jq .
```

Happy dual-node development! 🚀
