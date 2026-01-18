# Plan: Production Node Upgrade with Safe Testing

## Overview
Safely upgrade zhtp-prod to latest binary and convert zhtp-dev into zhtp-prod-1 (peer node), creating a 2-node production network.

**Critical Goal:** Preserve all user wallets and identities during upgrade.

## Architecture After Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRODUCTION NETWORK (testnet)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   zhtp-prod (77.42.37.161)          zhtp-prod-1 (77.42.74.80)   │
│   ┌─────────────────────┐           ┌─────────────────────┐     │
│   │  GENESIS NODE       │◄─────────►│  PEER NODE          │     │
│   │  - Original chain   │   QUIC    │  - Syncs from prod  │     │
│   │  - All wallets      │   9334    │  - Fresh identity   │     │
│   │  - bootstrap: []    │           │  - bootstrap: prod  │     │
│   └─────────────────────┘           └─────────────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Current State

### zhtp-prod (77.42.37.161) - Genesis Node
- Binary: `/opt/zhtp/zhtp` (old - Dec 17)
- Data: `/opt/zhtp/data/testnet/blockchain.dat` (445KB with user data)
- Keystore: `/root/.zhtp/keystore/` (5 files - **MUST PRESERVE**)
- No config.toml (uses defaults)

### zhtp-dev (77.42.74.80) - To Become zhtp-prod-1
- Binary: `/opt/zhtp/zhtp` (current dev binary)
- Data: `/opt/zhtp/data/dev/` (dev data - can be wiped)
- Keystore: `/root/.zhtp/keystore/` (dev identity - will be replaced)

---

# PHASE 0: SAFE UPGRADE TEST (ON PROD MACHINE)

**Purpose:** Verify that upgrading the binary preserves wallets/identities before touching the real prod node.

## Step 0.1: Create Test Environment on Prod Machine
```bash
# SSH to zhtp-prod
ssh zhtp-prod

# Create isolated test directory
mkdir -p /opt/zhtp-test
mkdir -p /root/.zhtp-test

# Copy current binary
cp /opt/zhtp/zhtp /opt/zhtp-test/zhtp

# Copy ALL data (blockchain, keystore, everything)
cp -r /opt/zhtp/data /opt/zhtp-test/
cp -r /root/.zhtp/keystore /root/.zhtp-test/
cp -r /root/.zhtp/storage /root/.zhtp-test/ 2>/dev/null || true

# Verify copy
ls -la /opt/zhtp-test/
ls -la /root/.zhtp-test/keystore/
```

**GUARDRAIL:** Do NOT proceed if copy fails or keystore is empty.

## Step 0.2: Run Test Node (Different Port)
```bash
# Create test config with different ports to avoid conflict
cat > /opt/zhtp-test/config.toml << 'EOF'
[network]
network_id = "testnet"
mesh_port = 9433
bootstrap_peers = []
max_peers = 10

[protocol_settings]
enable_quic = true
enable_bluetooth = false
enable_mdns = false
quic_port = 9434
EOF

# Run test node in foreground (not systemd)
cd /opt/zhtp-test
ZHTP_KEYSTORE_PATH=/root/.zhtp-test/keystore \
ZHTP_DATA_PATH=/opt/zhtp-test/data \
./zhtp node start --network testnet --config /opt/zhtp-test/config.toml &

# Wait for startup
sleep 10

# Verify it started (check for process)
pgrep -f "zhtp-test" || pgrep -f "9434"
```

**GUARDRAIL:** Do NOT proceed if test node fails to start.

## Step 0.3: Verify Test Node Has Data
```bash
# Check logs for wallet/identity loading
# Should see existing identities loaded

# Test locally (on prod machine)
curl -s http://localhost:9433/api/v1/health || echo "Health check"
```

## Step 0.4: Stop Test Node, Replace Binary
```bash
# Stop the test node
pkill -f "zhtp-test" || pkill -f "9434"
sleep 3

# Verify stopped
pgrep -f "zhtp-test" && echo "ERROR: Still running!" || echo "Stopped OK"
```

## Step 0.5: Copy New Binary to Test Location
```bash
# From LOCAL machine - copy new binary to test location
rsync -avz ./target/release/zhtp zhtp-prod:/opt/zhtp-test/zhtp-new

# On zhtp-prod - swap binary
ssh zhtp-prod "mv /opt/zhtp-test/zhtp /opt/zhtp-test/zhtp-old && mv /opt/zhtp-test/zhtp-new /opt/zhtp-test/zhtp && chmod +x /opt/zhtp-test/zhtp"
```

## Step 0.6: Run Upgraded Test Node
```bash
# SSH to zhtp-prod
ssh zhtp-prod

cd /opt/zhtp-test
ZHTP_KEYSTORE_PATH=/root/.zhtp-test/keystore \
ZHTP_DATA_PATH=/opt/zhtp-test/data \
./zhtp node start --network testnet --config /opt/zhtp-test/config.toml &

sleep 15
```

## Step 0.7: CRITICAL VERIFICATION - Wallets Preserved
```bash
# Check logs for:
# 1. "Loaded existing identity" - identity preserved
# 2. Blockchain height matches original
# 3. No panics or errors

journalctl --no-pager | grep -i "identity\|wallet\|keystore" | tail -20

# From LOCAL machine - try CLI against test node
ZHTP_SERVER='77.42.37.161:9434' ./target/release/zhtp-cli wallet balance --keystore ~/.zhtp/keystore --trust-node
```

**GUARDRAIL:**
- If wallets/identities NOT preserved → ABORT, investigate
- If panics → ABORT, investigate
- If works → Proceed to Phase 1

## Step 0.8: Cleanup Test Environment
```bash
# Stop test node
ssh zhtp-prod "pkill -f 'zhtp-test' || pkill -f '9434'"

# Remove test directories (only after successful verification)
ssh zhtp-prod "rm -rf /opt/zhtp-test /root/.zhtp-test"
```

---

# PHASE 1: BACKUP PRODUCTION DATA

## Step 1.1: Create Timestamped Backup
```bash
# On zhtp-prod
BACKUP_DIR="/root/zhtp-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p $BACKUP_DIR

# Backup everything critical
cp -r /root/.zhtp/keystore $BACKUP_DIR/
cp -r /opt/zhtp/data $BACKUP_DIR/
cp /opt/zhtp/zhtp $BACKUP_DIR/zhtp-old

# Verify backup
ls -la $BACKUP_DIR/
ls -la $BACKUP_DIR/keystore/

# Record backup location
echo "Backup at: $BACKUP_DIR"
```

**GUARDRAIL:** Do NOT proceed if backup fails or keystore copy is incomplete.

---

# PHASE 2: UPGRADE ZHTP-PROD (GENESIS NODE)

## Step 2.1: Stop Production Node
```bash
ssh zhtp-prod "systemctl stop zhtp && sleep 3 && systemctl status zhtp"
```

## Step 2.2: Deploy New Binary
```bash
# From LOCAL machine
rsync -avz ./target/release/zhtp zhtp-prod:/opt/zhtp/zhtp-new

# On zhtp-prod - swap binary
ssh zhtp-prod "mv /opt/zhtp/zhtp /opt/zhtp/zhtp-old && mv /opt/zhtp/zhtp-new /opt/zhtp/zhtp && chmod +x /opt/zhtp/zhtp"
```

## Step 2.3: Create Production Config
```bash
ssh zhtp-prod "cat > /opt/zhtp/config.toml << 'EOF'
[network]
network_id = \"testnet\"
mesh_port = 9333
bootstrap_peers = []
max_peers = 50

[protocol_settings]
enable_quic = true
enable_bluetooth = false
enable_mdns = true
quic_port = 9334
EOF"
```

## Step 2.4: Update Systemd Service
```bash
ssh zhtp-prod "cat > /etc/systemd/system/zhtp.service << 'EOF'
[Unit]
Description=ZHTP Node (Genesis)
After=network.target

[Service]
Type=simple
ExecStart=/opt/zhtp/zhtp node start --network testnet --config /opt/zhtp/config.toml
WorkingDirectory=/opt/zhtp
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF"
```

## Step 2.5: Start and Verify
```bash
ssh zhtp-prod "systemctl daemon-reload && systemctl start zhtp && sleep 10 && systemctl status zhtp"

# Check logs for successful startup
ssh zhtp-prod "journalctl -u zhtp --since '30 seconds ago' --no-pager | grep -iE 'identity|wallet|quic|genesis'"
```

## Step 2.6: Verify CLI Connectivity (CRITICAL)
```bash
# From LOCAL machine
ZHTP_SERVER='77.42.37.161:9334' ./target/release/zhtp-cli wallet balance --keystore ~/.zhtp/keystore --trust-node
```

**GUARDRAIL:**
- If node fails to start → ROLLBACK (see Rollback Plan)
- If wallets not accessible → ROLLBACK
- If CLI can't connect → Investigate before proceeding

---

# PHASE 3: CONVERT ZHTP-DEV TO ZHTP-PROD-1

## Step 3.1: Stop Dev Node
```bash
ssh zhtp-dev "systemctl stop zhtp"
```

## Step 3.2: Clean Dev Data (Keep Binary)
```bash
ssh zhtp-dev "rm -rf /opt/zhtp/data/dev /opt/zhtp/data/dev-mesh"
ssh zhtp-dev "rm -rf /root/.zhtp/keystore/*"
ssh zhtp-dev "rm -rf /root/.zhtp/storage/*"
ssh zhtp-dev "rm -rf /root/.zhtp/client_nonce_cache/*"
```

## Step 3.3: Deploy Same Binary as Prod
```bash
# From LOCAL machine
rsync -avz ./target/release/zhtp zhtp-dev:/opt/zhtp/zhtp
```

## Step 3.4: Configure as Peer Node
```bash
ssh zhtp-dev "cat > /opt/zhtp/config.toml << 'EOF'
[network]
network_id = \"testnet\"
mesh_port = 9333
bootstrap_peers = [\"77.42.37.161:9334\"]
max_peers = 50

[protocol_settings]
enable_quic = true
enable_bluetooth = false
enable_mdns = true
quic_port = 9334
EOF"
```

## Step 3.5: Update Systemd Service
```bash
ssh zhtp-dev "cat > /etc/systemd/system/zhtp.service << 'EOF'
[Unit]
Description=ZHTP Node (Prod-1 Peer)
After=network.target

[Service]
Type=simple
ExecStart=/opt/zhtp/zhtp node start --network testnet --config /opt/zhtp/config.toml
WorkingDirectory=/opt/zhtp
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF"
```

## Step 3.6: Start Peer Node
```bash
ssh zhtp-dev "systemctl daemon-reload && systemctl start zhtp && sleep 15 && systemctl status zhtp"

# Check for peer connection
ssh zhtp-dev "journalctl -u zhtp --since '30 seconds ago' --no-pager | grep -iE 'bootstrap|connect|peer|quic|handshake'"
```

---

# PHASE 4: VERIFY PRODUCTION NETWORK

## Step 4.1: Verify Both Nodes Running
```bash
ssh zhtp-prod "systemctl status zhtp --no-pager | head -10"
ssh zhtp-dev "systemctl status zhtp --no-pager | head -10"
```

## Step 4.2: Verify QUIC Mesh Connection
```bash
# Check prod received connection from peer
ssh zhtp-prod "journalctl -u zhtp --since '2 minutes ago' --no-pager | grep -iE 'quic.*connection|handshake|peer.*authenticated'"

# Check peer connected to prod
ssh zhtp-dev "journalctl -u zhtp --since '2 minutes ago' --no-pager | grep -iE 'bootstrap|connected'"
```

## Step 4.3: Test CLI Against Both Nodes
```bash
# Query prod (genesis)
ZHTP_SERVER='77.42.37.161:9334' ./target/release/zhtp-cli wallet balance --keystore ~/.zhtp/keystore --trust-node

# Query peer (should sync from genesis)
ZHTP_SERVER='77.42.74.80:9334' ./target/release/zhtp-cli wallet balance --keystore ~/.zhtp/keystore --trust-node
```

## Step 4.4: Test Domain Operations
```bash
# Register domain on genesis node
ZHTP_SERVER='77.42.37.161:9334' ./target/release/zhtp-cli domain register --domain centralhub.sov --keystore ~/.zhtp/keystore --trust-node

# Verify domain visible from peer node
ZHTP_SERVER='77.42.74.80:9334' ./target/release/zhtp-cli domain info --domain centralhub.sov --keystore ~/.zhtp/keystore --trust-node
```

---

# ROLLBACK PLAN

## If Phase 2 Fails (Prod Upgrade)
```bash
# On zhtp-prod
systemctl stop zhtp
cp /root/zhtp-backup-*/zhtp-old /opt/zhtp/zhtp
chmod +x /opt/zhtp/zhtp
rm -f /opt/zhtp/config.toml

# Restore original service file
cat > /etc/systemd/system/zhtp.service << 'EOF'
[Unit]
Description=ZHTP Node
After=network.target

[Service]
Type=simple
ExecStart=/opt/zhtp/zhtp node start --network testnet
WorkingDirectory=/opt/zhtp
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start zhtp
```

## If Phase 3 Fails (Peer Conversion)
```bash
# Peer failure doesn't affect genesis node
# Simply stop peer and investigate
ssh zhtp-dev "systemctl stop zhtp"
```

---

# VERIFICATION CHECKLIST

## Phase 0 (Test)
- [ ] Test environment created on prod machine
- [ ] Test node runs with OLD binary
- [ ] Test node runs with NEW binary
- [ ] Wallets/identities preserved after binary swap
- [ ] Test environment cleaned up

## Phase 1 (Backup)
- [ ] Backup created with timestamp
- [ ] Keystore backed up (5 files)
- [ ] Blockchain data backed up
- [ ] Old binary backed up

## Phase 2 (Prod Upgrade)
- [ ] Prod stopped cleanly
- [ ] New binary deployed
- [ ] Config created
- [ ] Service updated
- [ ] Prod starts successfully
- [ ] CLI connects remotely
- [ ] Wallets accessible

## Phase 3 (Peer Conversion)
- [ ] Dev node stopped
- [ ] Dev data cleaned
- [ ] New binary deployed
- [ ] Config points to prod as bootstrap
- [ ] Service updated
- [ ] Peer starts successfully
- [ ] Peer connects to prod via QUIC

## Phase 4 (Network Verification)
- [ ] Both nodes running stable
- [ ] QUIC mesh connection established
- [ ] CLI works against both nodes
- [ ] Domain operations work
- [ ] Data syncs between nodes

---

# CRITICAL REMINDERS

1. **NEVER skip Phase 0** - Test upgrade preserves data
2. **ALWAYS verify backups** before proceeding
3. **KEEP backup for 7 days** minimum after successful deployment
4. **Monitor logs** for first 24 hours after deployment
5. **Have SSH access ready** for emergency rollback
