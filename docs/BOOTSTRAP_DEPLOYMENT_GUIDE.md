# Bootstrap Node Deployment Guide

This guide covers deploying bootstrap infrastructure for the Sovereign Network alpha.

## Overview

Bootstrap nodes are the entry points to the network. New nodes connect to bootstrap peers first, then discover additional peers through DHT and peer exchange.

```
                    Internet
                       │
         ┌─────────────┼─────────────┐
         │             │             │
         ▼             ▼             ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │Bootstrap │  │Bootstrap │  │Bootstrap │
   │  Node 1  │  │  Node 2  │  │  Node 3  │
   └────┬─────┘  └────┬─────┘  └────┬─────┘
        │             │             │
        └─────────────┼─────────────┘
                      │
              ┌───────┴───────┐
              │   DHT Mesh    │
              │  (all nodes)  │
              └───────────────┘
```

## Architecture

### Node Types

| Type | Purpose | Storage | Connections |
|------|---------|---------|-------------|
| **Bootstrap** | Entry point, full DHT | 2TB+ | 50,000+ |
| **Validator** | Block production | 500GB | 1,000+ |
| **Full Node** | Complete blockchain | 500GB | 500+ |
| **Edge Node** | Headers only, routing | 10GB | 100+ |

### Discovery Priority

1. **Bootstrap Peers** - Hardcoded, always tried first
2. **UDP Multicast** - Local network (224.0.0.251:5353)
3. **mDNS** - Cross-subnet local discovery
4. **Bluetooth/WiFi Direct** - Proximity (mobile)
5. **DHT Kademlia** - Global peer discovery
6. **Peer Exchange** - Learn peers from connected nodes

---

## Part 1: Bootstrap Node Setup

### Requirements

- **OS**: Ubuntu 22.04 LTS (recommended) or any Linux
- **CPU**: 4+ cores
- **RAM**: 16GB minimum, 32GB recommended
- **Storage**: 2TB SSD (for full DHT)
- **Network**: Public IP, ports 9333, 9090-9093 open
- **Bandwidth**: 1Gbps+ recommended

### Step 1: Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Rust (if building from source)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install build dependencies
sudo apt install -y build-essential pkg-config libssl-dev
```

### Step 2: Build ZHTP Node

```bash
# Clone repository
git clone https://github.com/SOVEREIGN-NET/The-Sovereign-Network.git
cd The-Sovereign-Network

# Build release binary
cargo build --release -p zhtp

# Binary location
ls -la target/release/zhtp
```

### Step 3: Configure Bootstrap Node

Create `/etc/zhtp/bootstrap.toml`:

```toml
[node]
node_type = "bootstrap"
node_name = "Bootstrap-Alpha-1"

[network]
# Listen on all interfaces
listen_address = "0.0.0.0"
api_port = 9333
mesh_port = 9090
bootstrap_port = 9091
quic_port = 9092

# IMPORTANT: Set your public IP or domain
public_address = "bootstrap1.your-domain.com"

# Bootstrap nodes can connect to other bootstraps
bootstrap_peers = [
    "bootstrap2.your-domain.com:9333",
    "bootstrap3.your-domain.com:9333"
]

# High connection limit for bootstrap
max_connections = 50000
allow_external_connections = true

[storage]
storage_path = "/var/lib/zhtp/bootstrap"
storage_capacity_gb = 2000
cache_size_mb = 16384
enable_pruning = false

[dht]
enabled = true
max_entries = 10000000
replication_factor = 3
maintenance_interval = 300

[blockchain]
sync_mode = "full"
enable_fast_sync = true
serve_headers = true
serve_blocks = true
serve_proofs = true

[security]
enable_rate_limiting = true
max_requests_per_second = 10000
max_connections_per_ip = 100
connection_timeout_seconds = 30

[logging]
level = "info"
log_to_file = true
log_file = "/var/log/zhtp/bootstrap.log"
```

### Step 4: Create Systemd Service

Create `/etc/systemd/system/zhtp-bootstrap.service`:

```ini
[Unit]
Description=ZHTP Bootstrap Node
After=network.target

[Service]
Type=simple
User=zhtp
Group=zhtp
ExecStart=/usr/local/bin/zhtp --config /etc/zhtp/bootstrap.toml
Restart=always
RestartSec=10
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/zhtp /var/log/zhtp

[Install]
WantedBy=multi-user.target
```

### Step 5: Setup Directories and User

```bash
# Create zhtp user
sudo useradd -r -s /bin/false zhtp

# Create directories
sudo mkdir -p /var/lib/zhtp/bootstrap
sudo mkdir -p /var/log/zhtp
sudo mkdir -p /etc/zhtp

# Set permissions
sudo chown -R zhtp:zhtp /var/lib/zhtp
sudo chown -R zhtp:zhtp /var/log/zhtp

# Copy binary
sudo cp target/release/zhtp /usr/local/bin/
sudo chmod +x /usr/local/bin/zhtp

# Copy config
sudo cp bootstrap.toml /etc/zhtp/
```

### Step 6: Configure Firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 9333/tcp   # API
sudo ufw allow 9090/tcp   # Mesh
sudo ufw allow 9091/tcp   # Bootstrap
sudo ufw allow 9092/udp   # QUIC
sudo ufw allow 9093/tcp   # Metrics (optional)
sudo ufw enable

# Or iptables
sudo iptables -A INPUT -p tcp --dport 9333 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9091 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 9092 -j ACCEPT
```

### Step 7: Start Bootstrap Node

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable zhtp-bootstrap
sudo systemctl start zhtp-bootstrap

# Check status
sudo systemctl status zhtp-bootstrap

# View logs
sudo journalctl -u zhtp-bootstrap -f
```

---

## Part 2: DNS Configuration

### Option A: Single Bootstrap (Minimum)

```
bootstrap.your-domain.com  A  YOUR_SERVER_IP
```

### Option B: Multiple Bootstraps (Recommended)

```
; Round-robin DNS for load balancing
bootstrap.your-domain.com  A  IP_OF_BOOTSTRAP_1
bootstrap.your-domain.com  A  IP_OF_BOOTSTRAP_2
bootstrap.your-domain.com  A  IP_OF_BOOTSTRAP_3

; Individual records for direct access
bootstrap1.your-domain.com  A  IP_OF_BOOTSTRAP_1
bootstrap2.your-domain.com  A  IP_OF_BOOTSTRAP_2
bootstrap3.your-domain.com  A  IP_OF_BOOTSTRAP_3
```

### Option C: GeoDNS (Production)

For production, use GeoDNS to route users to nearest bootstrap:

```
; Cloudflare, Route53, or similar
bootstrap.your-domain.com  -> US-East: IP_US_EAST
bootstrap.your-domain.com  -> EU-West: IP_EU_WEST
bootstrap.your-domain.com  -> Asia: IP_ASIA
```

---

## Part 3: Client Node Configuration

### Minimal Client Config

Create `~/.zhtp/config.toml`:

```toml
[node]
node_type = "full"
node_name = "My-Node"

[network]
mesh_port = 9090
api_port = 9333

# Connect to bootstrap nodes
bootstrap_peers = [
    "bootstrap.your-domain.com:9333",
    "bootstrap1.your-domain.com:9333",
    "bootstrap2.your-domain.com:9333"
]

[storage]
storage_path = "~/.zhtp/data"
storage_capacity_gb = 100

[dht]
enabled = true
```

### Edge Node Config (Lightweight)

```toml
[node]
node_type = "edge"
node_name = "Edge-Node"

[network]
bootstrap_peers = [
    "bootstrap.your-domain.com:9333"
]

[blockchain]
sync_mode = "headers"  # Headers only, not full blocks
edge_mode = true
edge_max_headers = 10000

[storage]
storage_capacity_gb = 10  # Minimal storage
```

---

## Part 4: Verification

### Check Bootstrap Node Health

```bash
# Check if node is running
curl http://localhost:9333/health

# Expected response:
{
  "status": "healthy",
  "node_type": "bootstrap",
  "peers": 150,
  "dht_entries": 50000,
  "uptime_seconds": 86400
}
```

### Check Peer Discovery

```bash
# From client node, check connected peers
curl http://localhost:9333/api/v1/peers

# Expected response:
{
  "connected_peers": 25,
  "known_peers": 150,
  "bootstrap_connected": true
}
```

### Test DHT

```bash
# Store a test value
curl -X POST http://localhost:9333/api/v1/dht/store \
  -H "Content-Type: application/json" \
  -d '{"key": "test-key", "value": "hello-world"}'

# Retrieve from another node
curl http://OTHER_NODE:9333/api/v1/dht/get/test-key
```

---

## Part 5: Monitoring

### Prometheus Metrics

Bootstrap nodes expose metrics on port 9093:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'zhtp-bootstrap'
    static_configs:
      - targets:
        - 'bootstrap1:9093'
        - 'bootstrap2:9093'
        - 'bootstrap3:9093'
```

### Key Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `zhtp_peers_connected` | Active peer connections | < 10 |
| `zhtp_dht_entries` | DHT table size | < 1000 |
| `zhtp_bytes_routed` | Traffic forwarded | depends on network |
| `zhtp_blockchain_height` | Current block height | falling behind |
| `zhtp_memory_usage_bytes` | RAM usage | > 90% of limit |

### Grafana Dashboard

Import the dashboard from `zhtp/configs/grafana-dashboard.json` (if available) or create panels for:

- Peer connections over time
- DHT operations/second
- Bandwidth in/out
- Block sync status
- Error rates

---

## Part 6: Troubleshooting

### Node Won't Start

```bash
# Check logs
sudo journalctl -u zhtp-bootstrap -n 100

# Common issues:
# 1. Port already in use
sudo lsof -i :9333

# 2. Permission denied
sudo chown -R zhtp:zhtp /var/lib/zhtp

# 3. Config syntax error
/usr/local/bin/zhtp --config /etc/zhtp/bootstrap.toml --validate
```

### No Peers Connecting

```bash
# 1. Check firewall
sudo ufw status

# 2. Check port is listening
sudo netstat -tlnp | grep zhtp

# 3. Test from outside
nc -zv YOUR_PUBLIC_IP 9333

# 4. Check DNS resolution
dig bootstrap.your-domain.com
```

### DHT Not Syncing

```bash
# Check DHT status
curl http://localhost:9333/api/v1/dht/status

# Force DHT refresh
curl -X POST http://localhost:9333/api/v1/dht/refresh
```

### High Memory Usage

```bash
# Check current usage
ps aux | grep zhtp

# Reduce cache size in config
cache_size_mb = 8192  # Reduce from 16384

# Restart
sudo systemctl restart zhtp-bootstrap
```

---

## Part 7: Security Hardening

### 1. Rate Limiting (Already in Config)

```toml
[security]
enable_rate_limiting = true
max_requests_per_second = 10000
max_connections_per_ip = 100
```

### 2. Fail2Ban Integration

Create `/etc/fail2ban/jail.d/zhtp.conf`:

```ini
[zhtp]
enabled = true
port = 9333,9090,9091
filter = zhtp
logpath = /var/log/zhtp/bootstrap.log
maxretry = 100
findtime = 60
bantime = 3600
```

Create `/etc/fail2ban/filter.d/zhtp.conf`:

```ini
[Definition]
failregex = Rate limit exceeded from <HOST>
            Connection rejected from <HOST>
            Authentication failed from <HOST>
```

### 3. TLS for API (Optional)

```toml
[api]
enable_tls = true
cert_path = "/etc/zhtp/certs/server.crt"
key_path = "/etc/zhtp/certs/server.key"
```

Generate certs:
```bash
# Self-signed for testing
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# Or use Let's Encrypt
sudo certbot certonly --standalone -d bootstrap.your-domain.com
```

---

## Part 8: Multi-Region Deployment

### Recommended Setup for Production

```
Region          Bootstrap Nodes    Purpose
─────────────────────────────────────────────
US-East         2                  Americas
EU-West         2                  Europe/Africa
Asia-Pacific    2                  Asia/Oceania
─────────────────────────────────────────────
Total           6                  Global coverage
```

### Cross-Region Bootstrap Peers

Each bootstrap should know about others:

```toml
# US-East-1 config
bootstrap_peers = [
    "us-east-2.bootstrap.sovereign.network:9333",
    "eu-west-1.bootstrap.sovereign.network:9333",
    "eu-west-2.bootstrap.sovereign.network:9333",
    "asia-1.bootstrap.sovereign.network:9333",
    "asia-2.bootstrap.sovereign.network:9333"
]
```

---

## Quick Start Checklist

- [ ] Server provisioned with public IP
- [ ] Ports 9333, 9090-9093 open
- [ ] ZHTP binary built and installed
- [ ] Config file created with correct `public_address`
- [ ] Systemd service configured
- [ ] DNS record pointing to server
- [ ] Service started and healthy
- [ ] At least one peer connecting
- [ ] Monitoring configured

---

## Support

- **GitHub Issues**: https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues
- **Documentation**: https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/main/docs

## Related Files

- `zhtp/configs/bootstrap-node.toml` - Example bootstrap config
- `zhtp/configs/full-node.toml` - Example full node config
- `zhtp/configs/edge-node.toml` - Example edge node config
- `zhtp/src/discovery_coordinator.rs` - Discovery implementation
- `lib-network/src/dht/bootstrap.rs` - DHT bootstrap logic
