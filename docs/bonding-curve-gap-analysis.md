# CBE/SOV Bonding Curve — Gap Analysis & Incremental Build Plan

**Date:** 2026-04-11  
**Spec version:** Canonical v1.0 (April 2026)  
**Analysis method:** Claude subagent (full file access, `lib-blockchain/src/contracts/bonding_curve/`, `execution/executor.rs`, `lib-types/`) + Codex (sandbox filesystem restriction blocked execution — no output produced)

---

## 1. What Is Already Correct

These components match the canonical spec exactly. Do not touch them.

### 1.1 Price Function — Five Bands
**Status: IMPLEMENTED**  
`lib-blockchain/src/contracts/bonding_curve/canonical.rs:37–105`

- All five band constants present: `slope_num`, `slope_den`, `p_start` per band
- Initial price `P_START_0 = 313_345_700_000_000` raw SOV/CBE matches spec `INTERCEPT_0`
- Price continuity invariant verified in tests (`canonical.rs:435–444`)
- Monotonically increasing with supply: ✓

### 1.2 Cost Integral — Factored Form with U256
**Status: IMPLEMENTED**  
`lib-blockchain/src/contracts/bonding_curve/canonical.rs:233–271`

The mandatory factored form is implemented exactly:
```
term1 = slope_num × (Sb+Sa) × (Sb−Sa) / (2 × slope_den × SCALE)  [U256]
term2 = p_start × delta_s / SCALE
cost  = term1 + term2  → downcast u128
```
U256 widening used for intermediate. Correct downcast to u128. No overflow risk.

### 1.3 Inverse Quote — isqrt Rounds Down
**Status: IMPLEMENTED**  
`lib-blockchain/src/contracts/bonding_curve/canonical.rs:273–306`

- Flat band (`slope_num = 0`) handled explicitly at line 278: `return mul_div_floor_u128(reserve_credit, SCALE, band.p_start)`
- Quadratic `isqrt` rounds down (confirmed in test at line 472–478)
- Formula matches spec exactly

### 1.4 Multi-Band Crossing
**Status: IMPLEMENTED**  
`lib-blockchain/src/contracts/bonding_curve/canonical.rs:330–391`

Binary search for partial band fill. Full band consumption loop. MAX_SUPPLY check enforces Band 4 as terminal.

### 1.5 Graduation Threshold Value
**Status: IMPLEMENTED**  
`canonical.rs:24`: `GRAD_THRESHOLD = 2_745_966 * SCALE`

Correct value. Used in graduation check.

### 1.6 Graduation Event & AMM Seeding
**Status: IMPLEMENTED**  
`lib-blockchain/src/contracts/bonding_curve/amm_pool.rs:138–220`

Protocol-owned liquidity (PolPool) creation at graduation. Reserve migrated to AMM. LP tokens locked.

---

## 2. Critical Divergences — Must Fix

### 2.1 THE SPLIT — Core Economic Model Is Inverted

**Status: CRITICAL DIVERGENCE**  
`lib-blockchain/src/execution/executor.rs:1791–1844`

| | Canonical Spec | Current Code |
|---|---|---|
| SOV flow | 100% gross_sov enters curve | 20% → reserve, 80% → treasury (SOV diverted before curve) |
| What curve sees | Full gross_sov | 20% of gross_sov only |
| Token distribution | 80% delta_s → buyer, 20% → treasury | 100% delta_s → buyer |
| Reserve split | 40% locked / 60% liquid | Single `reserve_balance` field |

**The code implements the OLD economic model** (20/80 SOV split described in v0 spec). The canonical spec inverts this: all SOV enters the reserve, and the treasury's share is a **token allocation** (20% of newly minted CBE), not a SOV diversion.

**Why this matters:**
- Under the old model, the treasury holds SOV tokens that are backed by only 20% of their implied value
- Under the canonical model, the treasury's CBE is fully backed (minted from 100% reserve)
- Floor price formula `locked_reserve / circulating_CBE` is only valid under the canonical model

### 2.2 GRAD Transformer — Missing Async Accumulator

**Status: NOT IMPLEMENTED**  
`executor.rs:1837–1839`

Current code: synchronous check `if econ.reserve_balance >= GRAD_THRESHOLD`  
Spec requires: async post-finality accumulator `GRAD_total_supply += gross_sov * 60 / 100` per `BuyReceipt`

The distinction matters for correctness and auditability:
- Synchronous: graduation fires mid-block, state root at graduation height is ambiguous
- Async post-finality: GRAD_total_supply is a separate monotonic counter, auditable per block, never rolls back

### 2.3 Locked / Liquid Reserve — Not Tracked Separately

**Status: NOT IMPLEMENTED**  
`lib-blockchain/src/contracts/executor/storage/state_root.rs:56–57`: placeholders present but "zero-filled until Sprint 4"

Single `reserve_balance` field tracks combined reserve. Spec requires:
- `locked_reserve` (40% of gross_sov per buy, never decreases, solvency invariant)
- `liquid_reserve` (60% of gross_sov per buy, seeds AMM at graduation)

Without this split, the `floor_price = locked_reserve / circulating_CBE` invariant cannot be computed or verified.

---

## 3. Next Logical Build Steps — Incremental Order

Each step is independently shippable and builds on the previous.

### Step 1 — Add Token Mint Split (80/20 Buyer/Treasury)

**What:** Change the buy executor to split `delta_s` at mint time. 80% to buyer, 20% to the canonical SOV treasury wallet key_id.

**Scope:** `executor.rs` buy path + treasury wallet address constant  
**Risk:** Low — pure additive. Existing mint math unchanged. Only the destination of 20% of tokens changes.  
**Test:** existing buy tests need to check `treasury_balance += delta_s * 20 / 100`

```rust
let buyer_receives   = delta_s * 80 / 100;
let treasury_receives = delta_s - buyer_receives;
// credit buyer_receives to buyer
// credit treasury_receives to SOV_TREASURY_KEY_ID
```

### Step 2 — Add Reserve Curve Input Correction (gross_sov → 100%)

**What:** Change the buy executor to pass `gross_sov` (not `gross_sov * 20 / 100`) to `mint_with_reserve()`.

**Scope:** `executor.rs` ~2 lines  
**Risk:** Medium — this changes the economics of every buy. Requires verifying all band constants still produce correct prices at full gross_sov scale. Run integration tests.  
**Dependency:** Step 1 must ship first (treasury wallet must exist to receive 20% token allocation before more CBE is minted)

### Step 3 — Split reserve_balance Into locked_reserve + liquid_reserve

**What:** Replace single `reserve_balance: u128` with two fields:
- `locked_reserve: u128` — accumulated at `gross_sov * 40 / 100` per buy
- `liquid_reserve: u128` — accumulated at `gross_sov * 60 / 100` per buy

**Scope:** `lib-types/src/bonding_curve.rs` state struct + all read/write sites + state root  
**Risk:** Medium — state schema change, requires migration or genesis reset on testnet  
**Benefit:** Enables floor price computation `locked_reserve / circulating_CBE` as a real protocol metric

```rust
let locked_credit = gross_sov * 40 / 100;
let liquid_credit = gross_sov - locked_credit;  // exact remainder goes to locked
state.locked_reserve = state.locked_reserve.checked_add(locked_credit)?;
state.liquid_reserve  = state.liquid_reserve.checked_add(liquid_credit)?;
```

### Step 4 — Implement GRAD_total_supply Accumulator

**What:** Add a post-finality async task that reads finalized `BuyReceipt`s and increments `GRAD_total_supply += gross_sov * 60 / 100` per receipt. Replace synchronous `reserve_balance >= GRAD_THRESHOLD` check with `GRAD_total_supply >= GRADUATION_THRESHOLD`.

**Scope:** New async task in `zhtp/src/runtime/` + `GRAD_total_supply` field in bonding curve state  
**Risk:** Low — off critical path, post-finality. Cannot delay block production.  
**Benefit:** Makes graduation proximity auditable per block, non-repudiable in tension chain

```rust
// Runs post-finality after every BFT-committed block
for receipt in finalized_block.buy_receipts {
    let liquid_credit = receipt.gross_sov * 60 / 100;
    state.GRAD_total_supply = state.GRAD_total_supply
        .checked_add(liquid_credit)
        .expect("GRAD overflow");
}
if state.GRAD_total_supply >= GRADUATION_THRESHOLD {
    trigger_graduation();
}
```

### Step 5 — Wire Floor Price as a Live Protocol Metric

**What:** Expose `floor_price = locked_reserve / circulating_CBE` as a queryable API field and include it in the state root hash commitment.

**Scope:** `zhtp/src/api/handlers/bonding_curve/api_v1.rs` + state root  
**Dependency:** Step 3 (locked_reserve must exist)  
**Benefit:** External clients can verify solvency invariant at any block height. Tension chain makes it non-repudiable.

---

## 4. What Codex Said

Codex CLI (`gpt-5.4`, v0.118.0) was invoked with the same prompt and spec. It hit a sandbox restriction (`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`) that blocked all filesystem access before any file was read. It produced no analysis output.

**Implication for tooling:** `codex exec` in non-interactive mode runs inside a `bwrap` namespace that requires network loopback for some internal setup. This fails in certain host kernel configurations. For codebase-exploration tasks, the Claude subagent (which uses direct file tools, no shell sandbox) is the reliable path.

---

## 5. One-Sentence Build Priority

**Fix the split first** (Steps 1→2), then **split the reserve** (Step 3), then **make GRAD async** (Step 4) — the price math is already correct and should not be touched until the economic model feeding it is canonical.
