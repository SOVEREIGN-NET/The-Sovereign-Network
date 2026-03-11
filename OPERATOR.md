# Operator Reference

## Nodes

| Alias     | IP              | Port |
|-----------|-----------------|------|
| zhtp-g1   | 77.42.37.161    | 9334 |
| zhtp-g2   | 77.42.74.80     | 9334 |
| zhtp-g3   | 91.98.113.188   | 9334 |
| zhtp-g4   | 77.42.77.183    | 9334 |

SSH uses `~/.ssh/config` aliases with `IdentityFile ~/.ssh/kode_ocr.pem`.

## Remote Paths

| File         | Path                              |
|--------------|-----------------------------------|
| Binary       | `/opt/zhtp/zhtp`                  |
| CLI          | `/opt/zhtp/zhtp-cli`              |
| Service      | `zhtp.service`                    |
| Data root    | `/opt/zhtp/data/`                 |
| Sled DB      | `/opt/zhtp/data/testnet/sled/`    |
| blockchain   | `/opt/zhtp/data/testnet/blockchain.dat` |

> **Note**: `blockchain.dat` is a periodic snapshot and may be stale. The live state is in Sled. The node loads from Sled on startup if Sled is non-empty.

## Build

```bash
# Full node binary
cargo build --release -p zhtp

# CLI only
cargo build --release -p zhtp-cli

# Both
cargo build --release -p zhtp -p zhtp-cli
```

## Deploy

### Single node
```bash
rsync -az target/release/zhtp zhtp-g3:/opt/zhtp/zhtp
ssh zhtp-g3 "chmod +x /opt/zhtp/zhtp && systemctl restart zhtp && systemctl status zhtp | head -5"
```

### All nodes (parallel)
```bash
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4; do
  rsync -az target/release/zhtp $node:/opt/zhtp/zhtp
  ssh $node "chmod +x /opt/zhtp/zhtp && systemctl restart zhtp"
  echo "$node done"
done
```

### Deploy CLI
```bash
scp target/release/zhtp-cli zhtp-g3:/opt/zhtp/zhtp-cli
```

## Restart Order

When recovering from a fork or wiping chain state, start nodes in this order:

1. **g2** first (longest chain, primary data source)
2. **g3** and **g4** (sync from g2)
3. **g1** last (bootstrap leader — if started first with local data it may create a new genesis)

```bash
ssh zhtp-g2 "systemctl start zhtp" && sleep 5
ssh zhtp-g3 "systemctl start zhtp"
ssh zhtp-g4 "systemctl start zhtp"
sleep 10
ssh zhtp-g1 "systemctl start zhtp"
```

## Service Commands

```bash
# Status
ssh zhtp-g3 "systemctl status zhtp"

# Stop all
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4; do ssh $node "systemctl stop zhtp"; done

# Start all
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4; do ssh $node "systemctl start zhtp"; done

# Restart all
for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4; do ssh $node "systemctl restart zhtp"; done
```

## Logs

```bash
# Last 50 lines
ssh zhtp-g3 "journalctl -u zhtp -n 50 --no-pager"

# Follow live
ssh zhtp-g3 "journalctl -u zhtp -f"

# Filter for errors
ssh zhtp-g3 "journalctl -u zhtp -n 200 --no-pager | grep -i 'error\|panic\|WARN'"

# Oracle activity
ssh zhtp-g3 "journalctl -u zhtp --since '1 hour ago' --no-pager | grep -i oracle"

# Consensus height
ssh zhtp-g3 "journalctl -u zhtp -n 5 --no-pager | grep 'height='"
```

## Sled Recovery

If Sled corrupts (node crashes on startup, deserialization errors):

```bash
ssh zhtp-g3 "systemctl stop zhtp && rm -rf /opt/zhtp/data/testnet/sled && systemctl start zhtp"
```

Node will re-sync from peers. `blockchain.dat` is the fallback — but see note above about staleness.

## Nonce Cache

Bootstrap nonce cache lives at `/tmp/zhtp_bootstrap_nonce` on each node. If you see epoch mismatch errors:

```bash
ssh zhtp-g3 "rm -rf /tmp/zhtp_bootstrap_nonce"
```

## Chain State Patch (Sled)

To remove a specific key from a sled tree (e.g. remove a bad token contract):

```bash
# Build the patch tool
cargo build --release -p tools --bin remove_token

# Copy and run on target node (nodes must be STOPPED first)
scp target/release/remove_token zhtp-g3:/tmp/remove_token
ssh zhtp-g3 "systemctl stop zhtp && chmod +x /tmp/remove_token && /tmp/remove_token /opt/zhtp/data/testnet/sled <token_id_hex>"
ssh zhtp-g3 "systemctl start zhtp"
```

Run on all nodes if state must be consistent.

## Test Identity Registration

```bash
DN="mig_$(date +%s)"
./target/release/zhtp-cli -v -s 91.98.113.188:9334 identity register \
  --display-name "$DN" --device-id "dev_test" --trust-node
```

## Check Chain Tip

```bash
./target/release/zhtp-cli -s 91.98.113.188:9334 blockchain tip
```

## Token Operations

```bash
# Query token info by ID
./target/release/zhtp-cli -s 91.98.113.188:9334 token info --token-id <hex>

# Create token (fee=0, system tx)
./target/release/zhtp-cli -s 91.98.113.188:9334 token create \
  --name "MyToken" --symbol "MTK" --initial-supply 1000000000
```
