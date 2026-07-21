# GENESIS-3 — Developer node connect guide

**Audience:** External / team developers connecting a **client or full node** to the live GENESIS-3 testnet.  
**Network role model:** **Three validators only** (g1, g2, g3). There is **no gateway layer**. Clients talk to validators on port **9334**.

**Status (as of 2026-07-21):** Chain is **active and producing blocks**. If you hit a stuck or unreachable network earlier today, retry now — consensus recovered and is advancing.

---

## 1. Can you connect now?

**Yes**, for normal client / non-validator use:

| Check | Expected |
|-------|----------|
| Chain status | `"status": "active"` |
| Height | advancing (seconds between blocks) |
| Consensus epoch | `6` on all three validators |
| Your role | **not** a BFT validator unless operators add you to the set |

You do **not** need a gateway. Point tools and node config at any of the three validators below.

---

## 2. Public endpoints (validators only)

| Name | Host / IP | QUIC / API port |
|------|-----------|-----------------|
| g1 | `g1.thesovereignnetwork.org` → `77.42.37.161` | **9334** |
| g2 | `g2.thesovereignnetwork.org` → `77.42.74.80` | **9334** |
| g3 | `g3.thesovereignnetwork.org` → `178.105.9.247` | **9334** |

Bootstrap list (same as `tools/node-configs/shared.toml`):

```text
77.42.37.161:9334
77.42.74.80:9334
178.105.9.247:9334
```

**Firewall on your machine / VPS:** allow **outbound UDP/TCP 9334** to those three IPs (QUIC control plane). If you run a reachable full node, open **inbound 9334** (and mesh **9333** if you use mesh) for peer traffic.

---

## 3. Prove the network is up (do this first)

Build CLI from a recent tree (or use a release binary that matches testnet):

```bash
cargo build --profile dev-release -p zhtp-cli
```

### 3.1 Consensus epoch (must be 6)

```bash
./target/dev-release/zhtp-cli -s g1.thesovereignnetwork.org:9334 version --remote --build-id-only
./target/dev-release/zhtp-cli -s g2.thesovereignnetwork.org:9334 version --remote --build-id-only
./target/dev-release/zhtp-cli -s g3.thesovereignnetwork.org:9334 version --remote --build-id-only
```

All three should print:

```text
6
```

If a node is unreachable or reports a different epoch, use another of the three. Do not mix epoch-mismatched binaries if you run a consensus-aware full node.

### 3.2 Chain tip / status

```bash
./target/dev-release/zhtp-cli -s g1.thesovereignnetwork.org:9334 blockchain status
```

Expect something like:

- `status` → `"active"`
- `height` → a number that **increases** if you run the command twice ~15–30s apart

Example (height will be higher by the time you read this):

```text
height               3334
status               "active"
```

---

## 4. What kind of node are you running?

### A) Client / CLI only (recommended first step)

Use `zhtp-cli` against a validator. No local chain required.

```bash
# always pass -s <validator>:9334
./target/dev-release/zhtp-cli -s g1.thesovereignnetwork.org:9334 blockchain status
./target/dev-release/zhtp-cli -s g1.thesovereignnetwork.org:9334 identity register --display-name YourName
```

Identity registration:

- Success often returns **`queued`** (tx in mempool), not “already final”.
- Final when the DID is queryable after a block includes the registration txs.
- Optional: poll identity get, or use API `wait_for_inclusion` if your client supports it.

### B) Local full node (sync / mesh), **not** a validator

1. Build:

   ```bash
   cargo build --release -p zhtp
   ```

2. Config: start from `tools/node-configs/shared.toml` and set:

   - `network_id = "testnet"`
   - `bootstrap_peers` = the three IPs above on **9334**
   - **`validator_enabled = false`** (unless operators have explicitly onboarded you as a validator)
   - Fresh data dir (do not reuse an old mainnet or pre–GENESIS-3 sled)

3. Start with testnet flags matching operators (typical pattern):

   ```bash
   ./target/release/zhtp --testnet --config /path/to/your.toml --data-dir /path/to/data
   ```

4. Confirm you sync: local height should catch up toward validator height from `blockchain status`.

### C) Joining as a BFT validator

**Not self-service.** Validators are the fixed set g1–g3 for GENESIS-3. Contact operators; do not enable validator mode hoping to join quorum.

---

## 5. Config snippet (non-validator)

Minimal network section:

```toml
[network]
network_id = "testnet"
mesh_port = 9333
bootstrap_peers = [
  "77.42.37.161:9334",
  "77.42.74.80:9334",
  "178.105.9.247:9334",
]
max_peers = 50

[protocol_settings]
enable_quic = true
quic_port = 9334

[consensus_config]
# Client / follower: do not propose
validator_enabled = false
```

Copy full bootstrap validator identity rows from `tools/node-configs/shared.toml` if your binary requires them for peer trust.

---

## 6. Common failures and fixes

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Connection timeout to `:9334` | Firewall / wrong host | Use IPs in §2; open outbound 9334; try all three validators |
| Looking for a “gateway” host | Gateways are **retired** | Connect **only** to g1/g2/g3 |
| `status` not active / height stuck | Your process only, or old binary | Re-check §3 against g1; rebuild from current `development` |
| Identity returns `queued` forever | Tx not included or rejected | Check node logs / mempool; re-query tip height; ensure registration path is current |
| Reward claim errors (`token_contract_not_found` etc.) | Claim token has rewards module but no token contract on chain | Do **not** spam claim against incomplete asset setup; ask operators for supported reward token |
| Mixed consensus epoch vs peers | Binary too old/new | Align build; epoch must be **6** on GENESIS-3 right now |

---

## 7. What operators fixed recently (why it may have failed earlier)

Earlier today GENESIS-3 briefly **stopped producing blocks** after a bad reward-claim path. That was recovered without wiping the chain, and validators were upgraded so invalid reward claims are **rejected at admission** instead of halting apply.

For you as a connecting developer:

- **Retry connect and status checks now.**
- Prefer **current** `zhtp` / `zhtp-cli` from the repo.
- Still **no gateways** — same three validators as always for GENESIS-3.

---

## 8. Success checklist (send this back to operators)

When it works, you should be able to report:

1. `version --remote --build-id-only` → **6** on at least one of g1/g2/g3  
2. `blockchain status` → **`active`**, height **N** (and N increases on a second poll)  
3. (If registering) identity **`queued`** or **`confirmed`**, then DID visible via identity get  
4. (If full node) local height within a few blocks of N  

---

## 9. Contact / scope

- **Testnet:** GENESIS-3 only (g1–g3).  
- **Docs nearby:** `docs/protocol/genesis-3-testnet-reset.md` (topology), `tools/node-configs/shared.toml` (canonical peer list).  
- **Not covered here:** becoming a council/validator member, mainnet, or gateway-style reverse proxies (not part of this network).
