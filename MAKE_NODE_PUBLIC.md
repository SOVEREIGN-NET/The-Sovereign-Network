# Making Your Sovereign Network Node Publicly Reachable

## Current Status: LOCAL TESTNET ONLY ❌

Your nodes are currently running in **local test mode** and are **NOT reachable** from external peers.

---

## 📊 Why It's Not Public Yet

### 1. Bootstrap Nodes Point to Localhost
- Current: `127.0.0.1:8001`, `127.0.0.1:8002`, etc.
- Problem: Only connects to local test nodes
- Needed: Real mainnet/testnet seeder addresses

### 2. P2P Ports Not Externally Accessible
- API ports (8000/8001) are listening ✅
- P2P ports (19847/19848) need external access ❌
- Behind NAT router (192.168.1.31 → 84.77.194.89)

### 3. No Port Forwarding
- Router needs to forward incoming connections
- Firewall may be blocking

### 4. Network Type
- Current: Simulated local network
- Connected "peers": Internal test nodes
- True peer count: 0 external

---

## 🚀 Steps to Make Node Publicly Reachable

### Step 1: Check If Real Network Exists

First, check if there's a live Sovereign Network mainnet or testnet:

```bash
# Look for official seeders
# Check project documentation
# Visit GitHub issues/discussions
```

**Current Status:** The Sovereign Network appears to be in development/local testing phase. There may not be a public mainnet yet.

---

### Step 2: Configure Router Port Forwarding

**If you have router access:**

1. Access router admin panel (usually http://192.168.1.1)
2. Find "Port Forwarding" or "Virtual Server"
3. Add rule:
   ```
   Service Name: ZHTP-P2P
   External Port: 19847
   Internal IP: 192.168.1.31
   Internal Port: 19847
   Protocol: TCP + UDP
   ```

4. Add rule for API (optional, for remote access):
   ```
   Service Name: ZHTP-API
   External Port: 8000
   Internal IP: 192.168.1.31
   Internal Port: 8000
   Protocol: TCP
   ```

---

### Step 3: Configure Firewall

**Allow incoming connections:**

```bash
# Using UFW (Ubuntu/Debian)
sudo ufw allow 19847/tcp comment 'ZHTP P2P'
sudo ufw allow 19847/udp comment 'ZHTP P2P'

# Optional: API access (be careful - authentication needed!)
sudo ufw allow 8000/tcp comment 'ZHTP API'

# Check status
sudo ufw status
```

**Using firewalld (CentOS/RHEL):**
```bash
sudo firewall-cmd --permanent --add-port=19847/tcp
sudo firewall-cmd --permanent --add-port=19847/udp
sudo firewall-cmd --reload
```

---

### Step 4: Update Node Configuration

**Create a production config with real seeders:**

```bash
# When real seeders are available, update bootstrap nodes
cat > prod-mainnet-config.sh << 'EOF'
#!/bin/bash

# Real mainnet configuration (EXAMPLE - replace with actual seeders)
export ZHTP_NODE_NAME="my-prod-node"
export ZHTP_API_PORT=8000
export ZHTP_P2P_PORT=19847
export ZHTP_BIND_PORT=7000
export ZHTP_METRICS_PORT=9000

# Your public IP and port
export ZHTP_PUBLIC_ADDRESS="84.77.194.89:19847"

# Real bootstrap nodes (REPLACE WITH ACTUAL MAINNET SEEDERS)
export ZHTP_BOOTSTRAP_NODES="
  seeder1.sovereign.network:19847
  seeder2.sovereign.network:19847
  seeder3.sovereign.network:19847
"

# Start node
./target/release/zhtp
EOF

chmod +x prod-mainnet-config.sh
```

---

### Step 5: Test External Reachability

**From another machine/network:**

```bash
# Test if P2P port is reachable
nc -zv 84.77.194.89 19847

# Or use online port checker
# Visit: https://www.yougetsignal.com/tools/open-ports/
# Enter IP: 84.77.194.89
# Enter Port: 19847
```

**Expected result when properly configured:**
```
Connection to 84.77.194.89 19847 port [tcp/*] succeeded!
```

---

### Step 6: Verify External Connections

**Once configured, monitor for real external peers:**

```bash
# Check connected nodes
curl http://localhost:8000/api/status | jq .

# Watch for new peer connections
tail -f logs/prod-console.log | grep -E "peer|connection|external"

# Check if connected IPs are external
# (not 127.0.0.1 or 192.168.x.x)
```

---

## 🌐 Alternative: Run as Public Seeder

**If the network is just starting, you could become a seeder:**

### Requirements:
1. ✅ Static public IP or DDNS
2. ✅ Reliable uptime (24/7)
3. ✅ Sufficient bandwidth (100+ Mbps)
4. ✅ Port forwarding configured
5. ✅ Firewall rules set

### Configuration:
```bash
cat > run-as-seeder.sh << 'EOF'
#!/bin/bash

export ZHTP_NODE_NAME="public-seeder-1"
export ZHTP_API_PORT=8000
export ZHTP_P2P_PORT=19847
export ZHTP_PUBLIC_ADDRESS="84.77.194.89:19847"

# Enable seeder mode (if supported)
export ZHTP_SEEDER_MODE=true
export ZHTP_MAX_PEERS=100

./target/release/zhtp-seeder  # If available
EOF
```

---

## 🔒 Security Considerations

### Before Making Node Public:

1. **Authentication**
   - ✅ Enable API authentication
   - ✅ Use strong passwords/keys
   - ❌ Never expose admin APIs publicly

2. **Rate Limiting**
   - ✅ Implement DDoS protection
   - ✅ Limit connections per IP
   - ✅ Monitor for abuse

3. **Updates**
   - ✅ Keep node software updated
   - ✅ Monitor security advisories
   - ✅ Have backup/recovery plan

4. **Monitoring**
   - ✅ Set up uptime monitoring
   - ✅ Alert on anomalies
   - ✅ Log all connections

---

## 🧪 Current Test Setup

**Your current setup is perfect for:**
- ✅ Local development
- ✅ Testing DApps
- ✅ Learning ZK proofs
- ✅ Experimenting with smart contracts
- ✅ Performance testing

**Not suitable for:**
- ❌ Production transactions with real value
- ❌ Public network participation
- ❌ External peer connections
- ❌ Mainnet validation

---

## 📋 Checklist: Making Node Public

### Prerequisites:
- [ ] Real mainnet/testnet exists
- [ ] Official seeder addresses available
- [ ] Network documentation reviewed
- [ ] Security implications understood

### Network Configuration:
- [ ] Router port forwarding configured (19847)
- [ ] Firewall rules added
- [ ] Public IP confirmed (84.77.194.89)
- [ ] DDNS setup (if IP changes)

### Node Configuration:
- [ ] Bootstrap nodes updated (real seeders)
- [ ] Public address set
- [ ] P2P port configured
- [ ] API authentication enabled

### Testing:
- [ ] Port 19847 externally reachable
- [ ] Node accepting external connections
- [ ] Connected to real external peers
- [ ] Sync with network progressing

### Monitoring:
- [ ] Uptime monitoring active
- [ ] Log monitoring configured
- [ ] Alert system setup
- [ ] Backup strategy implemented

---

## 🔍 Current Network Info

**Your Setup:**
- **Local IP:** 192.168.1.31
- **Public IP:** 84.77.194.89
- **Network:** Behind NAT router
- **Firewall:** Unknown status
- **Mode:** Local testnet only

**To Check if Mainnet Exists:**
```bash
# Check project repository
cd /home/supertramp/Developer/Sovreign-Network
cat README.md | grep -i "mainnet\|testnet\|seeder"

# Check for seeder configuration
grep -r "seeder\|bootstrap" docs/
```

---

## ⚡ Quick Commands

### Test Current Setup
```bash
# Internal connectivity
curl http://localhost:8000/api/status

# External API test (if port forwarded)
curl http://84.77.194.89:8000/api/status

# Check listening ports
ss -tlnp | grep zhtp
```

### Prepare for Public Network
```bash
# Enable port forwarding on router
# (Manual step - access router admin)

# Open firewall
sudo ufw allow 19847

# Update node with public address
# (Requires code changes or config file support)
```

---

## 📚 Resources

- **Router Port Forwarding Guide:** https://portforward.com/
- **UFW Firewall Guide:** https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands
- **Test Port Accessibility:** https://www.yougetsignal.com/tools/open-ports/
- **DDNS Services:** https://www.noip.com/ or https://www.duckdns.org/

---

## ✅ Summary

**Current State:**
- ✅ Dev and Prod nodes running locally
- ✅ Perfect for development and testing
- ❌ NOT reachable from external networks
- ❌ NOT connected to real mainnet (may not exist yet)

**To Make Public:**
1. Wait for/find real Sovereign Network mainnet
2. Configure router port forwarding
3. Open firewall ports
4. Update bootstrap nodes
5. Set public address
6. Test external reachability

**Recommendation:**
Keep using current local setup for development until:
- Official mainnet launches
- Real seeder nodes are published
- Network is production-ready

---

*Your local dual-node setup is excellent for development! 🚀*
