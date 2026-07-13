# Economic Rules Activation at Block 80,000

**Status:** Scheduled — rules ship in production binary (deployed 2026-07-13) but **enforce at height ≥ 80,000**  
**Authority:** [`dao-launch-decision-register.md`](../arch/dao-launch-decision-register.md) (locked Q1–Q10)  
**Code gate:** `economic_rules_active()` and `GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT` in `lib-blockchain/src/contracts/sovereign_asset/state.rs`

---

## Summary

DAO Launch v1 economic rules are implemented in consensus but **height-gated** so chain replay below block 80,000 stays deterministic. At and above **80,000**, the executor enforces class-based minting, treasury authorization, transfer burn, reward-liquidity semantics, and related timelock activations.

| | Below 80,000 | At / above 80,000 |
|---|--------------|-------------------|
| Replay / history | Pre-rules behavior preserved | Full Q1–Q8 enforcement |
| New sovereign assets | `AssetLaunch` stores `dao_class` / `burn_bps`; initial split via `mint_and_allocate()` | Same at launch |
| Post-launch mints (elastic) | Legacy path (ungated mint to recipient) | **Rejected** for fixed supply; elastic requires governance + class split |
| Treasury spends | No governance signer check | **Requires** governance verifier signer |
| Sovereign transfers | Standard token transfer | Optional **burn** + treasury spend auth (Q2/Q8) |
| Reward claims | Standard insufficient-balance error | **`InsufficientRewardLiquidity`** when delegate underfunded (Q3) |
| Pending timelocks | Authority / burn-bps activation **no-op** | Queued updates **activate** after timelock |

**Current chain height (post-deploy):** ~40,250 — roughly **39,750 blocks** until activation.

---

## Activation constant

```rust
// lib-blockchain/src/contracts/sovereign_asset/state.rs (non-test builds)
pub const GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT: u64 = 80_000;

pub fn economic_rules_active(block_height: u64) -> bool {
    block_height >= GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT
}
```

Functions that share this height gate:

- `economic_rules_active()` — mint, treasury, burn, reward liquidity
- `activate_pending_authority_transfers()` — creator → governance handoffs (P6)
- `activate_pending_burn_bps()` — burn rate changes (Q8)

---

## Rules that activate at 80,000

### Q1 — Post-launch mint & class-based split

**Fixed supply (`SupplyMode::Fixed`)**

- All post-launch `TokenMint` against a sovereign asset are **rejected**.
- Governance cannot bypass fixed supply via ordinary mint.

**Elastic supply (`SupplyMode::Elastic`)**

- Every net-new mint must go through **`mint_and_allocate()`** (single shared path).
- Split is determined by on-chain **`dao_class`** (Q7).

| Class | Recipient share | Treasury share |
|-------|-----------------|----------------|
| **FP** (for-profit) | 80% | 20% |
| **NP** (non-profit) | 0% | 100% |

- Elastic mints require a **governance verifier signer** (not creator-only).

**Already active before 80k:** initial `AssetLaunch` allocation uses the same split at launch time (not gated).

---

### Q2 — Treasury spend authorization

- Transfers **from** the asset treasury wallet require a valid **governance verifier signer**.
- Consensus does **not** categorize spend purpose (grants, rewards, etc.) — only whether the DAO authorized the move.
- Creator private key cannot unilaterally drain treasury once rules are active.

---

### Q3 — Rewards delegate liquidity

- `RewardClaim` debits the **spend delegate** balance (existing Q4 path).
- At 80k+, insufficient delegate balance returns **`InsufficientRewardLiquidity`** instead of a generic insufficient-balance error.
- Launch with rewards configured but unfunded delegate remains **valid**; claims fail deterministically until treasury funds the delegate.

**Related (already shipped, not gated by 80k):** Q4 spend-delegate settlement, Q5 decrease timelock (7,200 blocks), Q6 on-chain rewards state.

---

### Q7 — `dao_class` (NP / FP)

Stored on-chain at launch in:

- `AssetLaunchPayloadV1` (wire V2)
- Canonical `SovereignAsset` state
- Registry projections (derived from chain — not independent defaults)

| Constant | Value |
|----------|-------|
| `FP_TREASURY_BPS` | 2,000 (20%) |
| `NP_TREASURY_BPS` | 10,000 (100%) |

**Legacy sled records** (pre-Q7 layout) deserialize with migration defaults: `dao_class = Fp`, `burn_bps = 0`.

---

### Q8 — Per-transfer burn

Applies to **sovereign asset transfers only** when `economic_rules_active`:

| Rule | Detail |
|------|--------|
| Scope | Transfers — **not** mints |
| Formula | `burn = floor(amount × burn_bps / 10_000)` |
| Supply | Burned atoms reduce `total_supply` (not treasury) |
| Recipient gets | `amount - burn - protocol_fee` |
| Default `burn_bps` | `0` |
| Protocol max | **1,000 bps (10%)** (`MAX_TRANSFER_BURN_BPS`) |
| Governance change | Queued in `pending_burn_bps`; timelock **7,200 blocks**; activates only ≥ 80k |

---

### Q10 — Domain binding & claim fee

**Transaction model (not gated by 80k — enforce when domain tx submitted):**

- Domain registration is a **separate** `DomainRegistration` transaction (not embedded in `AssetLaunch`).
- Optional `asset_id` field binds domain to a sovereign DAO (V3 memo).
- Standard claim fee: **100 whole SOV** → protocol treasury (`DEFAULT_DOMAIN_REGISTRATION_FEE_ATOMS`).
- Failed domain tx does **not** invalidate a successful `AssetLaunch`.

---

### Q9 — Curve, APY, welfare sector

**Registry / display rules** — do not alter monetary consensus at activation:

- Initial price only when curve module enabled (derived from curve state).
- Staking APY is display-only until on-chain staking integrated.
- Welfare sector is registry classification; optional at launch.

---

## Timelocks (blocks)

| Parameter | Blocks | ~time @ 12s/block |
|-----------|--------|-------------------|
| `AUTHORITY_TRANSFER_TIMELOCK_BLOCKS` | 7,200 | ~24 h |
| `REWARDS_POLICY_DECREASE_TIMELOCK_BLOCKS` | 7,200 | ~24 h |
| Burn bps update | 7,200 | ~24 h |

---

## What does *not* wait for 80k

These are live now on the deployed binary:

| Feature | PR / note |
|---------|-----------|
| Build epoch peer rejection (`CONSENSUS_BUILD_ID = "1"`) | #2861 |
| RewardClaim unregistered-`owner_did` gate | #2859 |
| `AssetLaunch` with `dao_class` / `burn_bps` on wire | #2858 |
| Initial launch split via `mint_and_allocate()` | #2858 |
| Sled migration for legacy `SovereignAsset` rows | #2858 |

---

## Pre-activation checklist (before block 80,000)

1. **Sled audit on g1** — confirm all `SovereignAsset` records deserialize via `deserialize_sovereign_asset()`; legacy rows should default to `Fp` / `burn_bps = 0`.
2. **DAO launch smoke test** — FP and NP launches on staging; verify treasury_bps matches class; verify fixed-supply mint rejected after 80k (can test with `GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT = 0` in local/test builds only).
3. **Governance module** — ensure no unexpected `pending_transfer` or `pending_burn_bps` queued with `effective_height < 80_000`.
4. **Rewards path** — fund spend delegate from treasury before expecting claims post-80k; verify API surfaces `InsufficientRewardLiquidity`.
5. **Domain workflow** — separate `AssetLaunch` + `DomainRegistration` with `asset_id`; 100 SOV fee path.
6. **Monitor height** — alert when chain crosses 79,000 / 79,500 / 80,000.

No validator redeploy is required at activation — rules flip by block height in the binary already running.

---

## Operator reference

| Check | Command |
|-------|---------|
| Chain height | `ssh zhtp-g1 journalctl -u zhtp -n 20 \| grep -oE 'height=[0-9]+' \| tail -1` |
| Build epoch | `zhtp-cli -s <ip>:9334 version --remote --build-id-only` |
| Future deploys | `scripts/deploy-validators.sh target/dev-release/zhtp` (halt via CLI first) |

---

## Change log

| Date | Change |
|------|--------|
| 2026-07-13 | Initial ops doc after #2858/#2861 deploy |