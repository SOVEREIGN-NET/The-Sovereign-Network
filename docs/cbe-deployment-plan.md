# CBE Token Deployment Plan

## Overview

CBE (CarbonBlue Engine) token deployment has two independent tracks:

1. **Token Creation** — can be done immediately
2. **Oracle operational** — required before bonding curve graduation
3. **Treasury distribution** — requires DAO governance (dao-2 fix + dao-4/dao-6 for automation)

---

## Track 1: Token Creation (Ready Now)

### Parameters
```
symbol:                   CBE
total_supply:             100_000_000_000_000_000  (1e17 atomic units, 9 decimals)
decimals:                 9 (or 8 — confirm before deploy)
treasury_allocation_bps:  2000  (20% → treasury)
treasury_recipient:       6adb0279d2af625f4d292bafe0fcfe3e2020436478b0f90d98adaf820cac1547
```

### Treasury Address
Deterministic — derived from `blake3(b"SOV_DAO_TREASURY_V1")`:
```
6adb0279d2af625f4d292bafe0fcfe3e2020436478b0f90d98adaf820cac1547
```
Same address on every node. No setup required — already initialized on all validators.

### Allocation Split
| Recipient | Bps | Share | Notes |
|---|---|---|---|
| Creator wallet | 8000 | 80% | Circulates immediately |
| DAO Treasury | 2000 | 20% | Sits until governance distributes |

### Treasury Pool Distribution (future governance)
The 20% will be split into 5 pools via DAO proposals once pool DAOs are deployed:
- Pool 1: TBD %
- Pool 2: TBD %
- Pool 3: TBD %
- Pool 4: TBD %
- Pool 5: TBD %

*(Fill in pool addresses and percentages once DAOs are live)*

### Deployment Command
```bash
./target/release/zhtp-cli -s 91.98.113.188:9334 token create \
  --symbol CBE \
  --total-supply 100000000000000000 \
  --decimals 9 \
  --treasury-allocation-bps 2000 \
  --treasury-recipient 6adb0279d2af625f4d292bafe0fcfe3e2020436478b0f90d98adaf820cac1547
```

### Status: BLOCKED ON
- [ ] CLI `token create` command exists and accepts these flags (verify)
- [ ] Signing wallet ready (creator holds 80%)

---

## Track 2: Oracle Operational (Required for CBE Graduation)

### What's Needed
CBE graduation (`BondingCurveGraduate` tx) is gated by:
1. Finalized oracle price for SOV/USD
2. Price not stale (`<= max_price_staleness_epochs`)
3. Token reserve balance `>= $269,000 * 1_000_000` micro-USD

### Oracle Implementation Gaps

| Gap | Description |
|---|---|
| Gossip wiring | `message_handler.rs` drops received `OracleAttestation` messages (explicit TODO stub) |
| Producer loop | `OracleProducerService` is built but never instantiated at startup |
| Price feed fetcher | No exchange API calls exist — prices must be supplied externally |
| API endpoints | No HTTP endpoints for submitting/querying oracle attestations |
| Committee config | All validators have `oracle_key_id: None` — empty committee |

### Work Required (in order)

#### Step 1 — Configure oracle committee members
- Assign `oracle_key_id` to each of the 4 validator nodes
- Derive deterministically: `blake3(identity_id_bytes || b"oracle_v1")` or use dedicated keypair
- Populate `oracle_state.committee.members` at startup from validator registry
- Config in `[consensus_config]` section of each node's TOML

#### Step 2 — Wire gossip → blockchain state
- `lib-network/src/messaging/message_handler.rs` line 365
- Add channel/callback: received `OracleAttestation` payload → deserialize → `blockchain.oracle_state.process_attestation()`
- Forward via existing channel pattern (same as block/vote forwarding)

#### Step 3 — Spawn async oracle producer loop
- Create tokio task in `zhtp/src/runtime/components/` (new `oracle.rs` component)
- Loop: fetch prices → `OracleProducerService::build_attestation()` → gossip to peers
- Epoch-aligned: produce attestation once per epoch (default epoch = 100 blocks = ~16 minutes)

#### Step 4 — Price feed fetcher
- HTTP fetch from 1+ exchange APIs (CoinGecko, Binance, etc.)
- Median aggregation across sources
- Supply as `Vec<OracleFetchedPrice>` to `build_attestation()`

#### Step 5 — Oracle API endpoints
```
GET  /api/v1/oracle/price           → latest finalized SOV/USD price
GET  /api/v1/oracle/status          → committee state, epoch, last finalized height
POST /api/v1/oracle/attest          → submit attestation (validator nodes only)
```

### Oracle Status: NOT RUNNING
- No prices ever finalized on live nodes
- CBE graduation permanently blocked until oracle is live

---

## Track 3: Treasury Distribution (DAO Governance)

### Prerequisites
- [ ] **dao-2 fix merged**: `execute_dao_proposal()` must use balance model (currently broken UTXO path)
- [ ] **dao-1 merged**: Bootstrap council exists for Phase 0 governance
- [ ] Pool DAO addresses established (each pool needs a wallet/identity)

### Distribution Flow
1. Pool DAOs deployed (each has a wallet registered on-chain)
2. Proposer submits `DaoProposal` with:
   - `execution_type: "treasury_transfer"`
   - `recipient_wallet_id: <pool_dao_wallet_id>`
   - `amount: <allocation_amount>`
3. Council votes (Phase 0) or DAO votes (Phase 1+)
4. `execute_dao_proposal()` transfers from treasury → pool DAO wallet
5. Repeat for each pool

### Status: BLOCKED ON
- [ ] dao-1 (Bootstrap Council) — not yet implemented
- [ ] dao-2 (Fix treasury execution) — not yet implemented
- [ ] Pool DAO addresses — TBD

---

## Deployment Sequence

```
NOW:
  ├── Deploy CBE token (TokenCreation tx)
  │   → 80% to creator, 20% to treasury
  │   → Treasury holds CBE allocation

PARALLEL TRACKS:
  ├── Oracle track (1-2 weeks)
  │   ├── Step 1: oracle committee config
  │   ├── Step 2: gossip wiring
  │   ├── Step 3: producer loop
  │   ├── Step 4: price feed fetcher
  │   └── Step 5: API endpoints
  │   → CBE graduation unblocked
  │
  └── DAO track (follows DAO epic #1464)
      ├── dao-1: Bootstrap Council
      ├── dao-2: Fix treasury execution
      ├── dao-5: Voting power
      ├── dao-3: Phase transitions
      ├── dao-4: Hybrid governance
      └── dao-6: Full DAO
      → Treasury distribution to pool DAOs unblocked

AFTER BOTH TRACKS COMPLETE:
  └── CBE bonding curve graduation (when reserve >= $269k)
```

---

## Open Questions
- [ ] Exact decimal count for CBE (8 or 9)?
- [ ] 5 pool DAO names and target allocation percentages?
- [ ] Oracle epoch length — keep default 100 blocks (~16 min) or change?
- [ ] Price feed sources — which exchanges? (CoinGecko, Binance, Kraken?)
- [ ] Oracle committee threshold — 3-of-4 validators or all 4?
