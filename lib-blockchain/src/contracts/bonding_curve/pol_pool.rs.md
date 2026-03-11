# Issue #1849: Protocol-Owned Liquidity (POL) Pool - Security Specification

## Overview

Issue #1849 implements a hardened **Protocol-Owned Liquidity (POL) AMM Pool** for CBE token graduation. Unlike traditional AMMs where liquidity providers can withdraw, POL pools have **permanently locked liquidity** that can never leave.

## Security Architecture

### Disabled Operations (Physically Impossible)

| Operation | Status | Reason |
|-----------|--------|--------|
| `add_liquidity()` | **NOT IMPLEMENTED** | Function does not exist in `PolPool` |
| `remove_liquidity()` | **NOT IMPLEMENTED** | Function does not exist in `PolPool` |
| `mint_lp()` | **NOT IMPLEMENTED** | LP tokens don't exist |
| `burn_lp()` | **NOT IMPLEMENTED** | LP tokens don't exist |
| `skim()` | **PANICS** | Explicitly disabled, panics if called |
| `sync()` | **PANICS** | Explicitly disabled, panics if called |

### Allowed Operations

| Operation | Description |
|-----------|-------------|
| `initialize()` | One-time setup at graduation |
| `swap_sov_to_token()` | Buy CBE with SOV |
| `swap_token_to_sov()` | Sell CBE for SOV |
| `get_token_price()` | Read current price |
| `get_reserves()` | Read current reserves |
| `calculate_token_out()` | Preview swap output |
| `calculate_sov_out()` | Preview swap output |

## Critical Design Decisions

### 1. No LP Token Interface

Traditional AMMs fail at POL because:
```solidity
// THIS IS BROKEN - Can still add liquidity
function burnLpTokens() {
    lpToken.burn(address(this), lpToken.balanceOf(address(this)));
}

// Attacker can still:
addLiquidity() -> receive LP tokens -> removeLiquidity()
```

Our solution: **LP tokens don't exist**. The pool has no liquidity interface.

### 2. Fees Accumulate Forever

```rust
// Every swap increases k:
// - SOV→token: Fee stays in SOV reserve
// - token→SOV: Fee stays in SOV reserve
// Result: k(new) > k(old) always
```

### 3. Permanent Liquidity

Once initialized:
- `sov_reserve` can only increase (via SOV→token swaps)
- `token_reserve` can only change via swaps
- Neither reserve can ever exit the pool

## Economic Properties

### Price Formula
```
price = (sov_reserve * PRICE_SCALE) / token_reserve
```

### Constant Product with Fees
```
Initial: k = sov_reserve * token_reserve

After SOV→token swap:
  fee = sov_in * 0.003
  effective_input = sov_in - fee
  new_token = k / (sov_reserve + effective_input)
  sov_reserve = sov_reserve + sov_in  // Full amount stays!
  token_reserve = new_token
  k_new = sov_reserve * token_reserve >= k

After token→SOV swap:
  new_sov = k / (token_reserve + token_in)
  sov_out_before_fee = sov_reserve - new_sov
  fee = sov_out_before_fee * 0.003
  sov_out = sov_out_before_fee - fee
  sov_reserve = new_sov + fee  // Fee stays!
  token_reserve = token_reserve + token_in
  k_new = sov_reserve * token_reserve >= k
```

### Key Property: k Is Non-Decreasing

With every trade, fees remain in the pool, so `k` is non-decreasing and
increases whenever fee rounding is non-zero. This means:
- Pool becomes **deeper over time**
- Price impact **decreases over time**
- **Liquidity death spiral is impossible**

## Comparison: Traditional AMM vs POL

| Property | Traditional AMM | POL Pool |
|----------|----------------|----------|
| Liquidity withdrawal | Yes (LPs can exit) | **No (physically impossible)** |
| LP tokens | Yes | **No (don't exist)** |
| Fee destination | To LPs | **Stays in pool** |
| k over time | Decreases on LP exit | **Always increases** |
| Liquidity death spiral | Possible | **Impossible** |
| Skim/sync attacks | Possible | **Panics** |

## Testing

### Test Coverage

```rust
test_pol_pool_initialization           // One-time init
test_pol_pool_double_initialization_fails  // Cannot re-init
test_pol_pool_swap_sov_to_token        // Buy works
test_pol_pool_swap_token_to_sov        // Sell works
test_pol_pool_fee_accumulation         // k is non-decreasing
test_pol_pool_skim_disabled            // Panics as expected
test_pol_pool_sync_disabled            // Panics as expected
test_pol_pool_slippage_protection      // MEV protection
test_pol_pool_price_evolution          // Price changes correctly
test_pol_pool_no_liquidity_interface   // No add/remove liquidity
```

### Security Test Results

All 21 POL pool tests pass, including:
- ✅ `skim()` panics with "OPERATION DISABLED"
- ✅ `sync()` panics with "OPERATION DISABLED"
- ✅ k is non-decreasing after swaps
- ✅ No liquidity functions exist

## Integration

### Creating a POL Pool at Graduation

```rust
use lib_blockchain::contracts::bonding_curve::{
    create_pol_pool_for_graduated_token,
    PolPool,
};

// After token graduates...
let (pool, result, event) = create_pol_pool_for_graduated_token(
    &mut token,
    governance,
    treasury,
    block_height,
    timestamp,
)?;

// Pool is now permanent - liquidity can never leave
```

### Swap Example

```rust
// Buy CBE with SOV
let cbe_received = pool.swap_sov_to_token(
    sov_amount,      // SOV to spend
    min_cbe_out,     // Slippage protection
)?;

// Sell CBE for SOV
let sov_received = pool.swap_token_to_sov(
    cbe_amount,      // CBE to sell
    min_sov_out,     // Slippage protection
)?;
```

## References

- Issue #1849: Protocol-Owned Liquidity (POL)
- Issue #1848: AMM Pool Creation (predecessor)
- Issue #1847: Oracle Observer Mode
- Issue #1846: Graduation Threshold
- Issue #1845: Pre-Graduation Sell

## Security Audit Checklist

- [x] No `add_liquidity()` function exists
- [x] No `remove_liquidity()` function exists
- [x] No LP token minting exists
- [x] `skim()` panics
- [x] `sync()` panics
- [x] k is non-decreasing with every trade
- [x] Fee stays in pool permanently
- [x] Reserves can only change via swaps
- [x] One-time initialization
- [x] Slippage protection on all swaps
- [x] Overflow protection on all math
- [x] Division by zero protection

## Deployment Notes

When deploying the CBE token:

1. Token graduates from curve at $269K USD threshold
2. `create_pol_pool_for_graduated_token()` is called
3. All reserve SOV + calculated CBE goes to POL pool
4. Pool becomes permanent AMM infrastructure
5. **No upgrade path exists** - this is intentional

The POL pool is designed to be **immutable and eternal**.
