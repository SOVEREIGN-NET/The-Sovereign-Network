# Golden Rules - Critical Configuration Reference

> **Purpose**: This file documents critical configuration and debugging information that MUST be referenced to prevent regression. Updated: 2026-01-18

---

## Server IPs (DO NOT CONFUSE)

| Server       | IP Address       | Purpose              |
|--------------|------------------|----------------------|
| zhtp-dev-2   | 91.98.113.188    | Development/Testing  |
| zhtp-prod-1  | 167.71.167.138   | Production (DO-NYC)  |

**SSH Access**: `ssh zhtp-dev-2` (configured in ~/.ssh/config)

---

## Port Configuration

| Port | Protocol | Purpose                                    |
|------|----------|--------------------------------------------|
| 9333 | HTTP     | HTTP server, mesh protocol, API endpoints  |
| 9334 | QUIC     | QUIC/TLS for CLI authenticated operations  |

**CLI uses port 9334** (QUIC) for authenticated control-plane operations.

---

## Environment Variables

| Variable      | Correct Value               | Purpose                    |
|---------------|-----------------------------|----------------------------|
| ZHTP_SERVER   | `91.98.113.188:9334`        | CLI target (QUIC port!)    |

**WRONG**: `ZHTP_API_SERVER` - This variable does not exist!

---

## UHP v2 Session Authentication - Working State

When handshake is working correctly, client and server MUST produce matching values:

```
Client:                              Server:
pqc_shared_prefix    = XXXXXXXX      pqc_shared_prefix    = XXXXXXXX (MUST MATCH)
classical_key_prefix = XXXXXXXX      classical_key_prefix = XXXXXXXX (MUST MATCH)
hybrid_key_prefix    = XXXXXXXX      hybrid_key_prefix    = XXXXXXXX (MUST MATCH)
session_id           = XXXXXXXX      session_id           = XXXXXXXX (MUST MATCH)
```

### Key Derivation Chain (UHP v2)
1. `classical_key` = HKDF-SHA3-256(client_nonce, server_nonce, SessionContext)
2. `pqc_shared_secret` = Kyber1024 key exchange
3. `hybrid_key` = derive_hybrid_session_key(pqc_shared_secret, classical_key)
4. `session_key` = hybrid_key
5. `mac_key` = HKDF-SHA3-256(session_key, handshake_hash, "v2_mac_key")
6. `session_id` = SHA3-256(session_key || client_nonce || server_nonce)[0..32]

### MAC Computation (V2)
- Algorithm: **HMAC-SHA3-256** (NOT BLAKE3!)
- Input format: `canonical_request || counter(u64 BE) || session_id(32 bytes)`
- Canonical request: `method(1 byte) || path_len(u16 BE) || path || body_len(u32 BE) || body`
- Counter: Starts at **1** (NOT 0!) - server's last_counter starts at 0

---

## Common Issues & Fixes

### 1. "MAC verification failed" (401)
**Symptoms**: Client connects but requests fail with 401
**Causes**:
- Mismatched binaries (client vs server have different code)
- Stale nonce cache (sled DB corruption)
- Wrong MAC algorithm (must be HMAC-SHA3-256)
- Counter starting at 0 instead of 1

**Fix**:
```bash
# On server:
ssh zhtp-dev-2 'rm -rf /opt/zhtp/data/tls/quic_nonce_cache /root/.zhtp/storage/dht_db'
ssh zhtp-dev-2 'systemctl restart zhtp'

# On client:
rm -rf ~/.zhtp/client_nonce_cache
```

### 2. "QUIC connection failed"
**Symptoms**: Cannot establish connection
**Causes**:
- Wrong IP address
- Wrong port (using 9333 instead of 9334)
- Server not running

**Verify**:
```bash
ssh -G zhtp-dev-2 | grep hostname  # Get correct IP
ssh zhtp-dev-2 'systemctl status zhtp'
```

### 3. Node crashes on startup (sled panic)
**Symptoms**: Service fails immediately after restart
**Cause**: Corrupted sled database (nonce cache)

**Fix**:
```bash
ssh zhtp-dev-2 'rm -rf /opt/zhtp/data/tls/quic_nonce_cache && systemctl restart zhtp'
```

---

## Deployment Checklist

Before deploying to zhtp-dev-2:

1. [ ] Build release: `cargo build --release -p zhtp -p zhtp-cli`
2. [ ] Stop service: `ssh zhtp-dev-2 'systemctl stop zhtp'`
3. [ ] Deploy binary: `scp target/release/zhtp zhtp-dev-2:/opt/zhtp/zhtp`
4. [ ] Set permissions: `ssh zhtp-dev-2 'chmod +x /opt/zhtp/zhtp'`
5. [ ] Clear stale caches if needed (see fix above)
6. [ ] Start service: `ssh zhtp-dev-2 'systemctl start zhtp'`
7. [ ] Verify: `ssh zhtp-dev-2 'systemctl status zhtp'`

---

## Test Command

```bash
ZHTP_SERVER=91.98.113.188:9334 ~/Developer/The-Sovereign-Network/target/release/zhtp-cli domain check --domain test.sov --keystore ~/.zhtp/keystore --trust-node
```

Expected output:
```
Domain 'test.sov' is available
```

---

## Debug Logging Locations

If keys mismatch, add debug logging to:
- **Client**: `lib-network/src/client/zhtp_client.rs` (after `derive_v2_session_keys`)
- **Server/Handshake**: `lib-network/src/handshake/mod.rs` (in `new_v2_with_pqc` around line 1869)

Example debug:
```rust
eprintln!("[DEBUG] pqc_shared_prefix={}", hex::encode(&pqc_secret[..8]));
eprintln!("[DEBUG] classical_key_prefix={}", hex::encode(&classical_key[..8]));
eprintln!("[DEBUG] hybrid_key_prefix={}", hex::encode(&hybrid_key[..8]));
```

---

## SDK-TS Alignment

The TypeScript SDK must match the Rust implementation:
- PR #818: feat(sdk-ts): Align MAC computation with Rust UHP v2 implementation
- Key files: `sdk-ts/src/quic/wire.ts`, `sdk-ts/src/quic/client.ts`
- Counter starts at 1 (not 0)
- Uses HMAC-SHA3-256 (not BLAKE3)
