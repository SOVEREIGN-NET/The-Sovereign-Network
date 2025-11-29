                                                                                                                                                                                                      # ZHTP Node Connection & Blockchain Sync Guide

## Overview

When you connect to a ZHTP node, the following happens automatically:
1. **Peer Discovery** - Find other nodes on the network
2. **Handshake** - Exchange identities and capabilities
3. **Blockchain Sync** - Download and verify the chain
4. **Continuous Sync** - Stay updated with new blocks

---

## What Data Do You Need To Connect?

### Minimum Required
| Data | Example | Description |
|------|---------|-------------|
| **IP Address** | `192.168.1.164` | Node's network address |
| **Mesh Port** | `9001` | UDP/TCP port for mesh protocol |

That's it! With `IP:PORT` you can connect.

### Automatically Exchanged During Connection
| Data | When Received | Purpose |
|------|---------------|---------|
| Node ID (UUID) | Peer announcement | Unique identifier |
| Public Key | Handshake | Cryptographic identity |
| Supported Protocols | Handshake | `["tcp", "bluetooth", "wifi_direct"]` |
| Blockchain Height | Sync request | Determine who has newer chain |
| Chain State Proof | Sync response | Verify chain is valid |

---

## Connection Methods

### Method 1: Auto-Discovery (Same Network)
Nodes on the same local network discover each other automatically via UDP multicast.

```powershell
# Just start a node - it will find others automatically
zhtp.exe node start --port 9001 --dev
```

**How it works:**
- Broadcasts on multicast address `224.0.1.75:37775`
- Other nodes hear the broadcast and respond
- No configuration needed!

### Method 2: Bootstrap Peers (Remote/Internet)
For connecting to known nodes across the internet.

**Create a config file** (`my-node.toml`):
```toml
[network]
mesh_port = 9001

# Bootstrap peers to connect to
bootstrap_peers = [
    "203.0.113.50:9001",      # Example public node
    "198.51.100.25:9001",     # Another public node
]

[network.discovery]
enable_multicast = true
multicast_address = "224.0.1.75:37775"
```

**Start with config:**
```powershell
zhtp.exe node start --config my-node.toml
```

---

## Blockchain Sync Process

### Step 1: Initial Connection
```
Node A                          Node B
  |                               |
  |------ PeerAnnouncement ------>|  (UDP multicast or direct)
  |<----- PeerAnnouncement -------|
  |                               |
  |------ Mesh Handshake -------->|  (Exchange public keys)
  |<----- Mesh Handshake ---------|
  |                               |
```

### Step 2: Chain Height Discovery
```
Node A (height: 100)            Node B (height: 500)
  |                               |
  |--- "What's your height?" ---->|
  |<-- "I'm at block 500" --------|
  |                               |
  | (A realizes it needs sync)    |
```

### Step 3: Sync Request (Full Node vs Edge Node)

#### Full Node Sync
Downloads complete blocks with all transactions:
```
Node A                          Node B
  |                               |
  |-- BlockchainRequest --------->|  (request_type: BlocksAfter(100))
  |                               |
  |<-- BlockchainData chunk 1 ----|  (blocks 101-150)
  |<-- BlockchainData chunk 2 ----|  (blocks 151-200)
  |<-- BlockchainData chunk n ----|  (blocks 451-500)
  |                               |
  | (Verify all chunks, hash)     |
```

#### Edge Node Sync (Lightweight)
Downloads only headers + ZK proof for mobile/constrained devices:
```
Edge Node                       Full Node
  |                               |
  |-- BootstrapProofRequest ----->|  (current_height: 0)
  |                               |
  |<-- BootstrapProofResponse ----|
  |    • ZK proof of chain validity
  |    • Recent 500 headers only
  |                               |
  | (Verify ZK proof - O(1) time) |
```

### Step 4: Verification

**Full Nodes verify:**
- Each block's hash matches previous block
- All transactions have valid signatures
- Merkle roots are correct
- Consensus rules are followed

**Edge Nodes verify:**
- ZK proof is valid (proves entire chain without downloading it)
- Headers chain together correctly
- Much faster, minimal storage

---

## Message Types for Sync

### BlockchainRequest
```rust
BlockchainRequest {
    requester: PublicKey,      // Who's asking
    request_id: u64,           // Unique ID for this request
    request_type: enum {
        FullChain,             // Give me everything
        BlocksAfter(height),   // Give me blocks after height X
        Block(height),         // Give me specific block
        Transaction(hash),     // Give me specific transaction
        Mempool,               // Give me pending transactions
    }
}
```

### BlockchainData (Response)
```rust
BlockchainData {
    sender: PublicKey,
    request_id: u64,
    chunk_index: u32,          // Which chunk (0, 1, 2...)
    total_chunks: u32,         // Total chunks in response
    data: Vec<u8>,             // Serialized blockchain data
    complete_data_hash: [u8; 32], // Hash for verification
}
```

### Edge Node Messages
```rust
// Request lightweight proof
BootstrapProofRequest {
    requester: PublicKey,
    request_id: u64,
    current_height: u64,       // What I already have
}

// Response with ZK proof
BootstrapProofResponse {
    request_id: u64,
    proof_data: Vec<u8>,       // Compressed ZK proof
    proof_height: u64,         // Height the proof covers
    headers: Vec<Vec<u8>>,     // Recent headers only
}
```

---

## Chunk Sizes by Protocol

Different protocols have different MTU (max transmission unit):

| Protocol | Chunk Size | Use Case |
|----------|------------|----------|
| Bluetooth LE | 200 bytes | Phone connectivity |
| Bluetooth Classic | 1000 bytes | Desktop/laptop |
| WiFi Direct | 1400 bytes | High bandwidth |
| TCP/UDP | 1400 bytes | Internet |

---

## Real-Time Sync (After Initial Sync)

Once synced, nodes stay updated with new blocks:

```rust
// Broadcast when new block is mined/received
NewBlock {
    block: Vec<u8>,            // Serialized block
    sender: PublicKey,         // Who sent it
    height: u64,               // Block height
    timestamp: u64,            // When created
}

// Broadcast new transactions
NewTransaction {
    transaction: Vec<u8>,      // Serialized transaction
    sender: PublicKey,
    tx_hash: [u8; 32],         // For duplicate detection
    fee: u64,                  // Priority sorting
}
```

---

## Example: Connect and Sync

### Scenario: Join an Existing Network

1. **Get bootstrap peer info** from network operator:
   ```
   IP: 203.0.113.50
   Port: 9001
   ```

2. **Create config file** (`join-network.toml`):
   ```toml
   [network]
   mesh_port = 9002
   bootstrap_peers = ["203.0.113.50:9001"]
   
   [blockchain]
   data_dir = "./blockchain-data"
   ```

3. **Start your node:**
   ```powershell
   zhtp.exe node start --config join-network.toml
   ```

4. **What happens automatically:**
   - Connects to 203.0.113.50:9001
   - Exchanges handshake
   - Requests blockchain from height 0
   - Downloads all blocks in chunks
   - Verifies each block
   - Stores locally
   - Starts mining/validating
   - Broadcasts your presence to other peers

---

## Security & Verification

### How Chain Validity is Verified

1. **Hash Chain Integrity**
   ```
   Block N-1 Hash → Block N (contains hash of N-1) → Block N+1
   ```
   Any tampering breaks the chain.

2. **Transaction Signatures**
   - Every transaction signed with sender's private key
   - Verified with sender's public key
   - Invalid signatures rejected

3. **Merkle Root Verification**
   - Transactions hashed into Merkle tree
   - Root stored in block header
   - Can verify any transaction belongs to block

4. **Consensus Rules**
   - Block timestamps must be valid
   - Difficulty targets must be correct
   - Rewards must match expected amounts

### Edge Node ZK Proofs

Edge nodes don't download full blocks but still verify the chain:

```
ZK Proof says: "There exists a valid chain from genesis to block 500,000
               where all blocks follow consensus rules, all transactions
               are valid, and the final state root is X"

Verification: O(1) time, ~1KB proof size
```

---

## Troubleshooting

### "No peers discovered"
- Check firewall allows UDP port 37775 (multicast)
- Check firewall allows your mesh port (9001, etc.)
- Verify bootstrap peers are online

### "Sync failed - hash mismatch"
- Data corrupted in transit
- Will auto-retry with different peer
- Check network stability

### "Connection refused"
- Peer may be offline
- Port may be blocked
- Try different bootstrap peer

---

## Quick Reference

| Action | Command |
|--------|---------|
| Start node (auto-discovery) | `zhtp.exe node start --port 9001 --dev` |
| Start with config | `zhtp.exe node start --config mynode.toml` |
| Start as edge node | `zhtp.exe node start --port 9001 --dev --edge-mode` |
| Check peer count | `zhtp.exe network peers` |
| Test connectivity | `zhtp.exe network test` |
| **Ping a specific node** | `zhtp.exe network ping 192.168.1.164:9002` |

---

## Ping Command

Test connectivity to a specific ZHTP node using the mesh ping protocol.

### Usage

```powershell
zhtp.exe network ping <TARGET> [OPTIONS]
```

### Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `TARGET` | IP:PORT of the node to ping | `192.168.1.164:9002` |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --count` | Number of pings to send | 3 |

### Example Output

```
🏓 ZHTP Mesh Ping to 192.168.1.164:9002
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📡 Sending from 0.0.0.0:54321

✅ Reply from 192.168.1.164:9002: seq=1 time=1.25ms request_id=1732693845123
✅ Reply from 192.168.1.164:9002: seq=2 time=0.98ms request_id=1732693846124
✅ Reply from 192.168.1.164:9002: seq=3 time=1.12ms request_id=1732693847125

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Ping statistics for 192.168.1.164:9002:
   3 packets transmitted, 3 received, 0.0% packet loss
   Round-trip min/avg/max = 0.98/1.12/1.25 ms
```

### What the Ping Tests

1. **UDP Connectivity** - Can we reach the node?
2. **Mesh Protocol** - Is the node running ZHTP mesh?
3. **Response Time** - Network latency measurement
4. **Packet Loss** - Connection reliability

### Ping More Times

```powershell
# Send 10 pings
zhtp.exe network ping 192.168.1.164:9002 -c 10

# Continuous ping (100 pings)
zhtp.exe network ping 192.168.1.164:9002 -c 100
```

---

## Summary

**To connect to the ZHTP network:**
1. You only need `IP:PORT` of one existing node
2. Everything else (identity, chain, peers) is automatic
3. Full nodes download complete blockchain and verify everything
4. Edge nodes use ZK proofs for lightweight verification
5. Real-time sync keeps you updated with new blocks

The network is designed to be **zero-configuration** for local discovery and **minimal-configuration** for internet connections.
