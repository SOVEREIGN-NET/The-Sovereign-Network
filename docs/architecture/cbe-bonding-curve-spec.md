# CBE Bonding Curve Mechanics — Canonical Specification

*The Sovereign Network · CBE DAO · April 2026*

## CANONICAL PRINCIPLES

- CBE is the first for-profit DAO on the Sovereign Network. Its bonding curve bootstraps SOV into existence.
- The reserve asset is SOV. SOV is the network's internal settlement currency. It cannot be bought or sold on external markets.
- SOV genesis price: $0.01 (financial projections, Year 1). CBE genesis price: $0.10. CBE/SOV ratio at genesis: 10 CBE = 1 SOV.
- No external oracle required. CBE prices in SOV. SOV prices via NAV from on-chain treasury state.
- Every CBE that exists was either minted by the curve against real value, or carries a PRE_BACKED flag and a satisfaction obligation.
- No pool is pre-minted. All pools mint on event. Ceilings are maximums, not balances.

## 1. Bonding Curve Mechanics

### 1.1 The price function

CBE price is a piecewise linear function of circulating CBE supply S_c. S_c starts at zero. Genesis tokens allocated to the SOV treasury are off-curve — they do not increment S_c and do not affect the curve price. External buyers always enter at Band 0 pricing.

```
P(S_c) = (slope_num × S_c / slope_den) + intercept_band

S_c:  curve-sold supply only — starts at 0
      genesis allocation (20B to SOV treasury) excluded
      S_c increments only when value enters through the curve

Five bands — slope and intercept defined at genesis as protocol constants
Price is monotonically increasing — every curve buy raises the price
Price is denominated in SOV
  CBE initial price: 10 SOV per CBE (CBE=$0.10, SOV=$0.01 at genesis)
```

### 1.2 The on-ramp split

Every value input through the curve executes a deterministic two-stage split. All four lines execute atomically or none do.

```
Input: fiat or SOV value V enters through curve

Stage 1 — first split:
  20% of V  →  SOV treasury
              held as CBE tokens — not swapped to SOV
              SOV treasury NAV grows
  80% of V  →  CBE backing economy

Stage 2 — second split of the 80%:
  40% of 80% = 32% of V  →  CBE locked reserve
                             LOCKED — never discretionary
                             backs floor price
                             floor = locked_reserve / circulating_CBE
  60% of 80% = 48% of V  →  CBE liquidity pool
                             accumulates pre-graduation
                             SOVRN mints against this at current CBE price
                             becomes AMM seed CBE side at graduation

From 100 SOV input:
  SOV treasury:    20 SOV worth of CBE
  Locked reserve:  32 SOV worth of CBE  ← floor backing
  Liquidity pool:  48 SOV worth of CBE  ← AMM seed + SOVRN
```

### FLOOR PRICE INVARIANT

```
floor_price = locked_reserve / circulating_CBE
```

The locked reserve grows with every curve buy. It can only decrease when holders sell CBE back through the curve. No discretionary action can touch the locked reserve. It is a protocol invariant enforced by the contract.

## 2. Operations That Pass Through the Curve

| Operation | Passes through curve | What happens |
|-----------|---------------------|--------------|
| Fiat on-ramp buy | YES — primary curve event | Fiat in → CBE minted. 20/32/48 split fires. SOVRN mints. |
| CBE/SOV swap (buy CBE with SOV) | YES — curve event | SOV priced at NAV ($0.01 genesis). SOV in → curve prices it → CBE mints. Split fires. |
| CBE/SOV swap (sell CBE for SOV) | YES — curve event | CBE burns → reserve pays SOV equivalent at current NAV price. Draws from locked reserve. |
| Payroll mint | YES — synthetic curve event | 1.25× minted. 20% routes to SOV treasury. 80% split 40/60. Full curve logic applies. PRE_BACKED flag set. |
| Transfer to collaborator wallet | NO — transfer only | CBE moves from backing pool to collaborator wallet. No curve logic. |
| CBE transfer between wallets | NO | Standard token transfer. No curve involvement. |
| SOV staking into welfare DAO | NO | Internal SOV mechanism. Not a CBE curve event. |
| DAO tax (20% CBE to SOV treasury) | NO — routing event | CBE tokens move to SOV treasury. Not a new curve mint. |
| Graduation — AMM seed | ONE-TIME — final curve event | Curve freezes. Locked reserve + liquidity pool seeds AMM. SOVRN burns. LP tokens locked forever. |

### THE CRITICAL DISTINCTION

The curve fires when value enters or exits the CBE economy. Transfers do not fire the curve. The payroll mint fires the curve. The subsequent transfer to the collaborator wallet does not.

## 3. Graduation Threshold

### 3.1 The trigger

```
Graduation fires when:
  SOVRN_total_supply >= GRADUATION_THRESHOLD

SOVRN mints on every on-ramp deposit:
  SOVRN_minted = CBE_deposited_to_liquidity_pool × CBE_price_current
               = 48% of input × P(S_c) in SOV terms

GRADUATION_THRESHOLD is a protocol constant set at genesis
No oracle required — SOVRN supply is on-chain state
No team decision required — contract executes automatically
```

### 3.2 The 20B genesis token problem and AMM price

The 20B CBE allocated to SOV treasury at genesis are off-curve. They do not count toward S_c. However they will eventually circulate and the AMM must price against total circulating supply including these tokens.

```
AMM implied price at graduation:
  P_amm = locked_reserve / (S_c + 20B_genesis + D_payroll_debt)

For AMM price to match curve price within 20% discount:
  locked_reserve / ((S_c + 20B + D) × 0.8) = P(S_c)

Requirement: SOV treasury's 20B CBE must be locked
  through graduation and minimum 12 months post-graduation
  OR until S_c exceeds 5B CBE — whichever is later
  Locked tokens excluded from AMM circulating supply
  Unlocking requires governance supermajority

With 20B locked at graduation:
  AMM prices against S_c + D only
  Genesis payroll ceiling D ≤ 71M CBE
  keeps AMM opening within 20% of last curve price
```

### 3.3 Graduation sequence

1. SOVRN_total_supply reaches GRADUATION_THRESHOLD
2. Bonding curve contract freezes — buy() and sell() disabled
3. P(S_c_graduation) recorded — immutable final curve price
4. SOVRN burns completely
5. AMM seeded: CBE side = liquidity_pool_CBE_balance, SOV side = liquidity_pool_CBE × P(S_c_graduation), AMM genesis price = P(S_c_graduation) — exact, no gap
6. LP tokens permanently locked — protocol-owned liquidity
7. CBE trades freely on AMM from P(S_c_graduation) forward
8. SOVRN does not exist post-graduation

## 4. Debt Policy — Genesis Payroll

### 4.1 The genesis problem

At genesis no buyers have arrived. The curve has no inflow. Compensation pool is empty. Collaborators must be paid in CBE to build the thing that attracts buyers. CBE minted before the first buyer is necessarily unbacked at the moment of minting. This is the genesis debt.

**GENESIS DEBT IS NOT FREE MONEY**
- Every genesis payroll mint represents real verified work delivered to the protocol.
- The CBE is a work-for-CBE swap. Work existed before the fiat. The fiat backs it retroactively.
- PRE_BACKED flag makes unbacked status visible to every holder and future buyer.
- The first on-ramp fiat satisfies PRE_BACKED obligations in FIFO order before filling any other pool.

### 4.2 Debt ceiling

Maximum genesis payroll debt: **71,000,000 CBE**

Derived from AMM crash analysis: At $269K graduation threshold with 20B SOV treasury tokens locked, D ≤ 71M CBE keeps AMM opening within 20% of last curve price.

71M CBE = 17.75% of COMPENSATION_POOL ceiling (400M). Protocol invariant — cannot be raised by governance.

### 4.3 Debt triggers and safety valves

| State | Outstanding debt | Triggered actions |
|-------|-----------------|-------------------|
| GREEN | 0 – 17.75M CBE (0–25%) | Normal operations. Simple governance majority. Public debt dashboard. |
| YELLOW | 17.75M – 35.5M CBE (25–50%) | Supermajority (67%) for new approvals. On-ramp routing +5%. Public alert. |
| ORANGE | 35.5M – 53.25M CBE (50–75%) | New payroll minting halts. Emergency routing rate. No new work commissioned. |
| RED | 53.25M – 71M CBE (75–100%) | Protocol emergency. Graduation threshold -20%. SOV treasury lock extended. All non-essential spending halted. |

### 4.4 PRE_BACKED satisfaction

- Every PRE_BACKED token has a FIFO position in the satisfaction queue
- Queue ordered by block height of mint — oldest satisfied first
- On every real on-ramp inflow: compensation_pool routing share clears PRE_BACKED first
- When cleared: PRE_BACKED flag removed — token is fully backed

## 5. Compensation Pool and All Pools

### 5.1 The pool model — no pre-minting

The 1,000,000,000 CBE total supply is a ceiling. No pool has tokens at genesis.

| Pool | Ceiling | % | Minting trigger |
|------|---------|---|-----------------|
| COMPENSATION_POOL | 400M | 40% | Mints on verified work event. PRE_BACKED at genesis. |
| TREASURY_POOL | 200M | 20% | Mints from on-ramp routing. Protocol operational reserve. |
| LIQUIDITY_POOL | 200M | 20% | Mints from on-ramp routing. AMM seed at graduation. |
| INCENTIVE_POOL | 100M | 10% | Mints on protocol incentive events. |
| STRATEGIC_RESERVE | 100M | 10% | Mints on governance approval only. Supermajority required. |

### 5.2 How the 40/60 split maps to pools

```
32% of V  →  locked_reserve (40% of 80%)
             Backs: COMPENSATION_POOL, STRATEGIC_RESERVE, floor price
             Cannot be accessed until holder sells through curve

48% of V  →  liquidity_pool (60% of 80%)
             Backs: LIQUIDITY_POOL (AMM seed), INCENTIVE_POOL, TREASURY_POOL
             SOVRN mints against every deposit here
```

## 6. Payroll Mint + Transfer

### 6.1 The two-step payroll

**Step 1 — Payroll mint (curve event)**

Collaborator earns X CBE for verified, governance-approved work.

```
Protocol mints: X × (100/80) = 1.25X CBE total
  The extra 0.25X covers the 20% SOV treasury tax on the gross

Curve split executes on 1.25X:
  0.25X CBE  →  SOV treasury (held as CBE)
  X CBE      →  CBE backing (the 80%)
    0.40X CBE  →  locked reserve (floor pre-funded)
    0.60X CBE  →  liquidity pool (SOVRN mints, graduation advances)

All minted CBE carries PRE_BACKED = true at genesis
Governance-approved deliverable recorded on-chain before mint
No deliverable = no mint — protocol invariant
```

**Step 2 — Transfer to collaborator wallet (no curve)**

X CBE transfers from backing pool to collaborator wallet. Standard token transfer. No curve logic. No split.

### 6.2 Payroll debt check

```
Before any payroll mint:
  assert!(outstanding_PRE_BACKED_total + 1.25X ≤ DEBT_CEILING)
  assert!(deliverable_hash is recorded on-chain)
  assert!(governance_multisig has approved)
```
