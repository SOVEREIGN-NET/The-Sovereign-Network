# ZHTP Network Configuration Guide

## Overview

ZHTP uses QUIC (UDP-based) as the sole transport layer for all peer-to-peer communication. This document provides network configuration guidance for deploying ZHTP nodes.

## Required Ports

### Essential Ports

| Port | Protocol | Purpose | Direction | Required |
|------|----------|---------|-----------|----------|
| **9334** | UDP | QUIC Mesh Protocol | Inbound/Outbound | ✅ YES |
| **37775** | UDP Multicast | Peer Discovery | Inbound (local network) | ✅ YES |

**That's it!** ZHTP requires only these two ports for full functionality.

### Legacy Ports (No Longer Used)

The following ports were used in earlier versions but have been **replaced by QUIC on port 9334**:

| Port | Protocol | Status | Reason |
|------|----------|--------|--------|
| 9333 | TCP | ❌ DEPRECATED | Removed in favor of QUIC |
| 33444 | TCP+UDP | ❌ DEPRECATED | Removed in favor of QUIC |

**Do not open these ports** unless you specifically need to support legacy clients.

## Port Details

### 9334/UDP - QUIC Mesh Protocol

- **Purpose:** All node-to-node communication, client connections, and API requests
- **Direction:** Inbound and Outbound
- **Why QUIC?**
  - Quantum-resistant encryption (post-quantum cryptography)
  - Multiplexing support (multiple streams over single connection)
  - Better performance than traditional TCP
  - Connection migration support
  - Built-in reliability (no need for separate TCP)

### 37775/UDP - Multicast Peer Discovery

- **Purpose:** Automatic peer discovery on local network
- **Multicast Address:** 224.0.1.75
- **Direction:** Inbound (broadcast/multicast traffic)
- **Scope:** Local network segment only (not routed to internet)
- **Notes:**
  - Not required for nodes on different networks
  - Optional if using bootstrap peers or DNS for peer discovery
  - Improves discovery speed on LAN

## Firewall Configuration

### Ubuntu/Debian (UFW)

```bash
# Enable UFW if not already enabled
sudo ufw --force enable

# Allow SSH (if using remote access)
sudo ufw allow 22/tcp

# Allow ZHTP QUIC mesh communication
sudo ufw allow 9334/udp comment 'ZHTP QUIC Mesh Protocol'

# Allow multicast peer discovery (optional, local network only)
sudo ufw allow in from 224.0.1.75 to 224.0.1.75 udp -m udp --dport 37775 comment 'ZHTP Multicast Discovery'

# Check rules
sudo ufw status numbered
```

### Fedora/RHEL (firewalld)

```bash
# Enable firewalld
sudo systemctl enable firewalld
sudo systemctl start firewalld

# Allow ZHTP QUIC
sudo firewall-cmd --permanent --add-port=9334/udp
sudo firewall-cmd --permanent --add-service=ssh

# Multicast discovery (optional)
sudo firewall-cmd --permanent --add-port=37775/udp

# Reload rules
sudo firewall-cmd --reload

# Check rules
sudo firewall-cmd --list-all
```

### macOS (pf firewall)

Add to `/etc/pf.conf`:

```
# ZHTP Network Rules
pass in on any proto udp from any to any port 9334 comment "ZHTP QUIC Mesh"
pass in on any proto udp from 224.0.1.0/24 to any port 37775 comment "ZHTP Multicast Discovery"
```

Then reload pf:

```bash
sudo pfctl -f /etc/pf.conf
sudo pfctl -e  # Enable if not already enabled
```

### Windows Firewall (PowerShell as Admin)

```powershell
# ZHTP QUIC Mesh
New-NetFirewallRule -DisplayName "ZHTP QUIC Mesh" `
  -Direction Inbound `
  -Protocol UDP `
  -LocalPort 9334 `
  -Action Allow

# Multicast Discovery (optional)
New-NetFirewallRule -DisplayName "ZHTP Multicast Discovery" `
  -Direction Inbound `
  -Protocol UDP `
  -LocalPort 37775 `
  -Action Allow

# Verify rules
Get-NetFirewallRule -DisplayName "ZHTP*" | Get-NetFirewallPortFilter
```

### Docker Container

```dockerfile
# Dockerfile
FROM rust:latest

# ... other setup ...

# Expose QUIC mesh port
EXPOSE 9334/udp

# Optional: Expose multicast port
EXPOSE 37775/udp

# Run ZHTP node
CMD ["./target/release/zhtp", "node", "start", "--network", "testnet"]
```

Run with port mapping:

```bash
docker run -d \
  --name zhtp-node \
  -p 9334:9334/udp \
  -p 37775:37775/udp \
  zhtp-image
```

### Kubernetes

```yaml
apiVersion: v1
kind: Service
metadata:
  name: zhtp-node
spec:
  type: LoadBalancer
  ports:
    - name: quic-mesh
      protocol: UDP
      port: 9334
      targetPort: 9334
    - name: multicast-discovery
      protocol: UDP
      port: 37775
      targetPort: 37775
  selector:
    app: zhtp-node
```

## Verification

### Check if ports are listening

**Linux/macOS:**
```bash
# Check both ports
netstat -tulpn | grep -E '9334|37775'

# Or using lsof
lsof -i UDP:9334
lsof -i UDP:37775
```

**macOS (alternative):**
```bash
ss -tulpn | grep -E '9334|37775'
```

**Windows (PowerShell):**
```powershell
Get-NetUDPEndpoint | Where-Object {$_.LocalPort -in 9334, 37775}
```

### Test external connectivity

From a remote machine:

```bash
# Test UDP connectivity to 9334
nc -u -zv <node-ip> 9334

# Or using timeout for faster failure
timeout 2 bash -c 'echo "" > /dev/udp/<node-ip>/9334' && echo "Connected" || echo "Connection failed"
```

**Note:** UDP doesn't provide connection confirmation like TCP, so these tests may not be reliable. The best verification is checking node logs for peer connections.

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ZHTP Network Stack                       │
├─────────────────────────────────────────────────────────────┤
│  Application Layer (ZHTP Protocol)                           │
│  • Blockchain sync                                           │
│  • DHT operations                                            │
│  • API requests                                              │
├─────────────────────────────────────────────────────────────┤
│  Transport Layer (QUIC)                                      │
│  • UDP Port 9334                                             │
│  • Quantum-resistant encryption                              │
│  • Multiplexing & flow control                               │
├─────────────────────────────────────────────────────────────┤
│  Discovery Layer                                             │
│  • UDP Multicast Port 37775 (224.0.1.75)                     │
│  • Bootstrap peers (DNS)                                     │
│  • Bluetooth LE (optional)                                   │
└─────────────────────────────────────────────────────────────┘
```

## NAT & Port Forwarding

If your ZHTP node is behind a NAT:

1. **UPnP:** QUIC supports UPnP for automatic port mapping
2. **Manual Port Forwarding:** Forward external UDP 9334 to node's UDP 9334
3. **Public Address Configuration:** Ensure bootstrap peers know your public IP:9334

Example configuration:

```toml
[network]
bind_address = "0.0.0.0"
mesh_port = 9334  # Local port to bind to
advertised_addresses = ["your.public.ip:9334"]  # What other nodes see
```

## Security Considerations

### 🔒 TLS/Encryption

- **QUIC:** All communication is encrypted with post-quantum cryptography (Kyber-768 + AES-256)
- **No additional TLS needed:** QUIC provides end-to-end encryption

### 🛡️ Rate Limiting

- Implement rate limiting on 9334 to prevent DDoS
- ZHTP includes built-in rate limiting, but firewall limits are recommended

```bash
# UFW rate limiting example
sudo ufw limit 9334/udp comment 'ZHTP Rate Limited'
```

### 🚫 Multicast Security

- Multicast discovery (37775) is local-network only (TTL=1)
- Does not require special protection
- Optional to disable if running in untrusted network

## Environment Variables

Configure Bluetooth behavior:

```bash
# Skip Bluetooth initialization (macOS/Linux)
DISABLE_BLUETOOTH=1 ./target/release/zhtp node start --network testnet
```

## Troubleshooting

### "Connection refused" or "No route to host"

- Verify firewall allows UDP 9334
- Check `ufw status` or firewall rules
- Verify port is actually listening: `netstat -tulpn | grep 9334`

### Slow peer discovery

- Ensure UDP 37775 is not blocked
- Multicast may not work across VLANs/subnets
- Use bootstrap peers as fallback: `bootstrap_peers = ["ip:9334"]`

### High packet loss or disconnections

- Check network stability with: `ping -c 100 peer-ip`
- Verify no intermediate firewalls blocking UDP
- Check node logs for specific QUIC errors

### Cannot connect from specific network

- Verify firewall rules on both sides
- Check for corporate proxies/DPI blocking UDP
- Try specifying explicit bootstrap peers

## References

- [QUIC Specification (RFC 9000)](https://tools.ietf.org/html/rfc9000)
- [ZHTP Protocol Documentation](./zhtp/docs/)
- [Firewall Rules Best Practices](./internal-docs/deployment/DEPLOYMENT_INSTRUCTIONS.md)

