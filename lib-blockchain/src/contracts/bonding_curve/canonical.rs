pub use lib_types::{
    BondingCurveBand as Band, BondingCurveBuyReceipt, BondingCurveBuyTx, BondingCurveSellReceipt,
    BondingCurveSellTx, TOKEN_SCALE_18,
};
use primitive_types::U256;

use crate::contracts::utils::{integer_sqrt_u256, mul_div_floor_u128, u256_to_u128, MathError};

// ── CBE economic identity constants ─────────────────────────────────────────
//
// These constants define the CBE token's identity and economic parameters.
// They were originally in `contracts/tokens/cbe_token.rs` and were moved here
// (EPIC-001 Phase 1F) because the bonding curve is the canonical home for CBE
// economics after the CbeToken struct was removed from the protocol layer.

/// Token symbol used by the bonding curve registry and oracle checks.
pub const CBE_SYMBOL: &str = "CBE";

/// Token name used to derive the canonical CBE token ID.
pub const CBE_NAME: &str = "CBE Equity";

/// Number of decimal places for CBE display (1 CBE = 10^8 atoms in the legacy
/// runtime; the bonding curve itself uses 18 decimals internally).
pub const CBE_DECIMALS: u8 = 8;

/// Whole-token CBE total supply (100 billion).
pub const CBE_TOTAL_SUPPLY_TOKENS: u64 = 100_000_000_000;

/// Total supply in legacy 8-decimal atoms (100B * 10^8).
pub const CBE_TOTAL_SUPPLY: u64 = CBE_TOTAL_SUPPLY_TOKENS * 100_000_000;

// ── Immutable curve logic ────────────────────────────────────────────────────
//
// The following constants encode the CBE bonding curve execution rules as
// defined in "CBE Bonding Curve — Rust Implementation Specification" sections
// 2, 3, and 5.  They are IMMUTABLE after genesis: changing any of these values
// constitutes a hard fork and requires an explicit protocol upgrade transaction.
//
// Do NOT modify these constants in a regular code change.  Any PR that touches
// them must carry a protocol-upgrade migration path and be reviewed accordingly.

pub const SCALE: u128 = TOKEN_SCALE_18;
pub const SLOPE_DEN: u128 = 100_000_000_000_000;

/// Graduation threshold (atomic SOV units).  Locked by team decision.
/// Changing this value is a hard fork.
pub const GRAD_THRESHOLD: u128 = 2_745_966 * SCALE;

pub const BAND_COUNT: usize = 5;

/// Per-transaction gross-SOV cap.  Changing this value is a hard fork.
pub const MAX_GROSS_SOV_PER_TX: u128 = 1_000_000_000_000_000_000_000_000;

/// Per-transaction minted-supply cap.  Changing this value is a hard fork.
pub const MAX_DELTA_S_PER_TX: u128 = 100_000_000_000 * SCALE;

/// CBE max supply in 18-decimal bonding curve atoms (100B tokens × 10^18).
/// This is the bonding curve's internal accounting unit, independent of CBE's
/// 8-decimal display convention. Immutable — changing is a hard fork.
pub const MAX_SUPPLY: u128 = 100_000_000_000 * SCALE;

/// Band price anchors — part of the immutable curve shape.
pub const P_START_0: u128 = 313_345_700_000_000;
pub const P_START_1: u128 = 413_345_700_000_000;
pub const P_START_2: u128 = 813_345_700_000_000;
pub const P_START_3: u128 = 1_713_345_700_000_000;
pub const P_START_4: u128 = 2_713_345_700_000_000;

// ── Upgrade-gated curve parameters ──────────────────────────────────────────
//
// The following parameters CAN change via a protocol upgrade transaction but
// must NEVER be mutated ad-hoc at runtime or by background services.
//
// sell_enabled: bool   — stored in BondingCurveEconomicState; starts false at
//                        genesis; may be set to true by a future upgrade tx.
//                        The executor gate is in apply_canonical_bonding_curve_tx
//                        (step 5).  No runtime service may set this flag.
//
// ALPHA / RHO split (20 / 80): encoded directly in apply_buy_cbe as
//   reserve_credit = amount_in * 20 / 100
//   treasury_credit = amount_in - reserve_credit
// Changing the split ratio requires a protocol upgrade.
//
/// Canonical band table for the bonding curve.
///
/// Although defined here, BANDS (and BAND_COUNT, MAX_SUPPLY, SLOPE_DEN, and
/// the P_START_* anchors) are part of the immutable curve shape defined
/// above.  Changing any of these values is a hard fork and requires an
/// explicit protocol upgrade transaction.
pub const BANDS: [Band; BAND_COUNT] = [
    Band {
        index: 0,
        start_supply: 0,
        end_supply: 10_000_000_000u128 * SCALE,
        slope_num: 1,
        slope_den: SLOPE_DEN,
        p_start: P_START_0,
    },
    Band {
        index: 1,
        start_supply: 10_000_000_000u128 * SCALE,
        end_supply: 30_000_000_000u128 * SCALE,
        slope_num: 2,
        slope_den: SLOPE_DEN,
        p_start: P_START_1,
    },
    Band {
        index: 2,
        start_supply: 30_000_000_000u128 * SCALE,
        end_supply: 60_000_000_000u128 * SCALE,
        slope_num: 3,
        slope_den: SLOPE_DEN,
        p_start: P_START_2,
    },
    Band {
        index: 3,
        start_supply: 60_000_000_000u128 * SCALE,
        end_supply: 85_000_000_000u128 * SCALE,
        slope_num: 4,
        slope_den: SLOPE_DEN,
        p_start: P_START_3,
    },
    Band {
        index: 4,
        start_supply: 85_000_000_000u128 * SCALE,
        end_supply: MAX_SUPPLY,
        slope_num: 5,
        slope_den: SLOPE_DEN,
        p_start: P_START_4,
    },
];

/// Derive the full 5-band table from a single `p_start_0` value.
///
/// All subsequent `p_start` values follow the price-continuity invariant:
/// `p_start_{N+1} = p_start_N + slope_num_N * band_size_N / SLOPE_DEN`
/// where `band_size_N = end_supply_N - start_supply_N` (in 18-decimal atomic units).
///
/// This function is the canonical source of truth for band derivation.
/// The `BANDS` constant hard-codes the values derived from `P_START_0`;
/// `derive_cbe_bands(P_START_0)` must return an identical table.
pub fn derive_cbe_bands(p_start_0: u128) -> [Band; BAND_COUNT] {
    const S1: u128 = 10_000_000_000u128 * SCALE; //  10 B CBE boundary
    const S2: u128 = 30_000_000_000u128 * SCALE; //  30 B CBE boundary
    const S3: u128 = 60_000_000_000u128 * SCALE; //  60 B CBE boundary
    const S4: u128 = 85_000_000_000u128 * SCALE; //  85 B CBE boundary

    // Integer division is exact: each band_size is an exact multiple of SLOPE_DEN.
    let p1 = p_start_0 + 1 * (S1) / SLOPE_DEN;
    let p2 = p1 + 2 * (S2 - S1) / SLOPE_DEN;
    let p3 = p2 + 3 * (S3 - S2) / SLOPE_DEN;
    let p4 = p3 + 4 * (S4 - S3) / SLOPE_DEN;

    [
        Band {
            index: 0,
            start_supply: 0,
            end_supply: S1,
            slope_num: 1,
            slope_den: SLOPE_DEN,
            p_start: p_start_0,
        },
        Band {
            index: 1,
            start_supply: S1,
            end_supply: S2,
            slope_num: 2,
            slope_den: SLOPE_DEN,
            p_start: p1,
        },
        Band {
            index: 2,
            start_supply: S2,
            end_supply: S3,
            slope_num: 3,
            slope_den: SLOPE_DEN,
            p_start: p2,
        },
        Band {
            index: 3,
            start_supply: S3,
            end_supply: S4,
            slope_num: 4,
            slope_den: SLOPE_DEN,
            p_start: p3,
        },
        Band {
            index: 4,
            start_supply: S4,
            end_supply: MAX_SUPPLY,
            slope_num: 5,
            slope_den: SLOPE_DEN,
            p_start: p4,
        },
    ]
}

fn price_at_supply_in_band(supply: u128, band: &Band) -> Result<u128, MathError> {
    if supply < band.start_supply || supply > band.end_supply {
        return Err(MathError::Overflow);
    }

    let band_local_supply = band_local_supply(supply, band)?;
    let slope_component = mul_div_floor_u128(band.slope_num, band_local_supply, band.slope_den)?;
    band.p_start
        .checked_add(slope_component)
        .ok_or(MathError::Overflow)
}

pub fn band_for_supply(supply: u128) -> Result<Band, MathError> {
    if supply > MAX_SUPPLY {
        return Err(MathError::Overflow);
    }

    for band in BANDS {
        let in_band = if band.index as usize == BAND_COUNT - 1 {
            supply >= band.start_supply && supply <= band.end_supply
        } else {
            supply >= band.start_supply && supply < band.end_supply
        };
        if in_band {
            return Ok(band);
        }
    }

    Err(MathError::Overflow)
}

pub fn band_for_redemption_supply(supply: u128) -> Band {
    for band in BANDS {
        let in_band = if band.index == 0 {
            supply >= band.start_supply && supply <= band.end_supply
        } else {
            supply > band.start_supply && supply <= band.end_supply
        };
        if in_band {
            return band;
        }
    }
    BANDS[0]
}

pub fn band_local_supply(supply: u128, band: &Band) -> Result<u128, MathError> {
    supply
        .checked_sub(band.start_supply)
        .ok_or(MathError::Overflow)
}

pub fn price_at_supply(supply: u128) -> u128 {
    let band = band_for_supply(supply).expect("canonical price supply out of range");
    price_at_supply_in_band(supply, &band).expect("canonical price evaluation failed")
}

pub fn integer_sqrt(n: u128) -> u128 {
    u256_to_u128(integer_sqrt_u256(U256::from(n)))
        .expect("canonical integer_sqrt downcast overflow")
}

pub fn cost_single_band(s_from: u128, s_to: u128, band: &Band) -> Result<u128, MathError> {
    if s_from > s_to || s_from < band.start_supply || s_to > band.end_supply {
        return Err(MathError::Overflow);
    }

    let from_local = band_local_supply(s_from, band)?;
    let to_local = band_local_supply(s_to, band)?;
    let delta_s = s_to.checked_sub(s_from).ok_or(MathError::Overflow)?;
    let sum_local = U256::from(to_local)
        .checked_add(U256::from(from_local))
        .ok_or(MathError::Overflow)?;

    let numerator = U256::from(band.slope_num)
        .checked_mul(sum_local)
        .ok_or(MathError::Overflow)?
        .checked_mul(U256::from(delta_s))
        .ok_or(MathError::Overflow)?;
    let denominator = U256::from(2u8)
        .checked_mul(U256::from(band.slope_den))
        .ok_or(MathError::Overflow)?
        .checked_mul(U256::from(SCALE))
        .ok_or(MathError::Overflow)?;
    let term1 = if numerator.is_zero() {
        U256::zero()
    } else {
        if denominator.is_zero() {
            return Err(MathError::DivisionByZero);
        }
        numerator / denominator
    };

    let term2 = U256::from(band.p_start)
        .checked_mul(U256::from(delta_s))
        .ok_or(MathError::Overflow)?
        / U256::from(SCALE);
    let cost = term1.checked_add(term2).ok_or(MathError::Overflow)?;

    u256_to_u128(cost)
}

pub fn inverse_mint(reserve_credit: u128, s_c: u128, band: &Band) -> Result<u128, MathError> {
    if s_c < band.start_supply || s_c > band.end_supply {
        return Err(MathError::Overflow);
    }

    if band.slope_num == 0 {
        return mul_div_floor_u128(reserve_credit, SCALE, band.p_start);
    }

    let p_local = price_at_supply_in_band(s_c, band)?;
    let p_local_u256 = U256::from(p_local);
    let p_local_sq = p_local_u256
        .checked_mul(p_local_u256)
        .ok_or(MathError::Overflow)?;
    let two_m_r = U256::from(2u8)
        .checked_mul(U256::from(band.slope_num))
        .ok_or(MathError::Overflow)?
        .checked_mul(U256::from(reserve_credit))
        .ok_or(MathError::Overflow)?
        .checked_mul(U256::from(SCALE))
        .ok_or(MathError::Overflow)?
        / U256::from(band.slope_den);
    let discriminant = p_local_sq.checked_add(two_m_r).ok_or(MathError::Overflow)?;
    let sqrt_disc = integer_sqrt_u256(discriminant);
    let numerator = sqrt_disc
        .checked_sub(p_local_u256)
        .ok_or(MathError::Overflow)?;
    let delta_s = numerator
        .checked_mul(U256::from(band.slope_den))
        .ok_or(MathError::Overflow)?
        / U256::from(band.slope_num);

    u256_to_u128(delta_s)
}

pub fn cost_to_mint(delta_s: u128, s_c: u128) -> Result<u128, MathError> {
    let target_supply = s_c.checked_add(delta_s).ok_or(MathError::Overflow)?;
    if target_supply > MAX_SUPPLY {
        return Err(MathError::Overflow);
    }

    let mut total_cost = 0u128;
    let mut current_supply = s_c;

    while current_supply < target_supply {
        let band = band_for_supply(current_supply)?;
        let band_end = band.end_supply.min(target_supply);
        let band_cost = cost_single_band(current_supply, band_end, &band)?;
        total_cost = total_cost
            .checked_add(band_cost)
            .ok_or(MathError::Overflow)?;
        current_supply = band_end;
    }

    Ok(total_cost)
}

pub fn mint_with_reserve(reserve_credit: u128, s_c: u128) -> Result<u128, MathError> {
    if s_c > MAX_SUPPLY {
        return Err(MathError::Overflow);
    }

    let mut remaining_reserve = reserve_credit;
    let mut minted = 0u128;
    let mut current_supply = s_c;

    while remaining_reserve > 0 && current_supply < MAX_SUPPLY {
        let band = band_for_supply(current_supply)?;
        let band_capacity = band
            .end_supply
            .checked_sub(current_supply)
            .ok_or(MathError::Overflow)?;
        if band_capacity == 0 {
            break;
        }

        let full_band_cost = cost_single_band(current_supply, band.end_supply, &band)?;
        if full_band_cost <= remaining_reserve {
            minted = minted
                .checked_add(band_capacity)
                .ok_or(MathError::Overflow)?;
            remaining_reserve = remaining_reserve
                .checked_sub(full_band_cost)
                .ok_or(MathError::Overflow)?;
            current_supply = band.end_supply;
            continue;
        }

        let estimate = inverse_mint(remaining_reserve, current_supply, &band)?.min(band_capacity);
        let mut low = 0u128;
        let mut high = estimate;

        if cost_single_band(current_supply, current_supply + high, &band)? <= remaining_reserve {
            high = band_capacity;
        }

        while low < high {
            let mid = low
                .checked_add(high)
                .ok_or(MathError::Overflow)?
                .checked_add(1)
                .ok_or(MathError::Overflow)?
                / 2;
            let mid_cost = cost_single_band(current_supply, current_supply + mid, &band)?;
            if mid_cost <= remaining_reserve {
                low = mid;
            } else {
                high = mid - 1;
            }
        }

        let delta_s = low;

        minted = minted.checked_add(delta_s).ok_or(MathError::Overflow)?;
        break;
    }

    Ok(minted)
}

pub fn payout_for_burn(amount_cbe: u128, s_c: u128) -> Result<u128, MathError> {
    if amount_cbe > s_c {
        return Err(MathError::Overflow);
    }

    let mut remaining_burn = amount_cbe;
    let mut current_supply = s_c;
    let mut total_payout = 0u128;

    while remaining_burn > 0 {
        let band = band_for_redemption_supply(current_supply);
        let band_floor = current_supply
            .checked_sub(remaining_burn)
            .ok_or(MathError::Overflow)?
            .max(band.start_supply);
        let band_payout = cost_single_band(band_floor, current_supply, &band)?;
        total_payout = total_payout
            .checked_add(band_payout)
            .ok_or(MathError::Overflow)?;

        let burned_here = current_supply
            .checked_sub(band_floor)
            .ok_or(MathError::Overflow)?;
        remaining_burn = remaining_burn
            .checked_sub(burned_here)
            .ok_or(MathError::Overflow)?;
        current_supply = band_floor;
    }

    Ok(total_payout)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_cbe_bands_matches_hardcoded_table() {
        let derived = derive_cbe_bands(P_START_0);
        assert_eq!(derived, BANDS);
    }

    #[test]
    fn derive_cbe_bands_continuity_invariant() {
        let derived = derive_cbe_bands(P_START_0);
        for pair in derived.windows(2) {
            let price_at_left_end = price_at_supply_in_band(pair[0].end_supply, &pair[0]).unwrap();
            assert_eq!(
                price_at_left_end, pair[1].p_start,
                "Price continuity broken at band {} → {} boundary",
                pair[0].index, pair[1].index
            );
        }
    }

    #[test]
    fn band_table_is_contiguous_and_hits_max_supply() {
        assert_eq!(BANDS[0].start_supply, 0);
        assert_eq!(BANDS[BAND_COUNT - 1].end_supply, MAX_SUPPLY);

        for pair in BANDS.windows(2) {
            assert_eq!(pair[0].end_supply, pair[1].start_supply);
        }
    }

    #[test]
    fn price_is_continuous_at_boundaries() {
        for pair in BANDS.windows(2) {
            let left = price_at_supply_in_band(pair[0].end_supply, &pair[0]).unwrap();
            let right = price_at_supply_in_band(pair[1].start_supply, &pair[1]).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    fn price_matches_known_initial_value() {
        assert_eq!(price_at_supply(0), P_START_0);
    }

    #[test]
    fn integer_sqrt_rounds_down() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(15), 3);
        assert_eq!(integer_sqrt(16), 4);
        assert_eq!(integer_sqrt(17), 4);
    }

    #[test]
    fn boundary_prices_increase_across_bands() {
        let p0 = price_at_supply(BANDS[0].start_supply);
        let p1 = price_at_supply(BANDS[1].start_supply);
        let p2 = price_at_supply(BANDS[2].start_supply);
        let p3 = price_at_supply(BANDS[3].start_supply);
        let p4 = price_at_supply(BANDS[4].start_supply);

        assert!(p1 > p0);
        assert!(p2 > p1);
        assert!(p3 > p2);
        assert!(p4 > p3);
    }

    #[test]
    fn band_for_supply_rejects_out_of_range_supply() {
        assert_eq!(band_for_supply(MAX_SUPPLY + 1), Err(MathError::Overflow));
    }

    #[test]
    fn cost_single_band_zero_width_is_zero() {
        let band = BANDS[0];
        assert_eq!(
            cost_single_band(band.start_supply, band.start_supply, &band).unwrap(),
            0
        );
    }

    #[test]
    fn cost_single_band_is_monotonic_with_range() {
        let band = BANDS[0];
        let one_token = SCALE;
        let cost_small =
            cost_single_band(band.start_supply, band.start_supply + one_token, &band).unwrap();
        let cost_large =
            cost_single_band(band.start_supply, band.start_supply + 10 * one_token, &band).unwrap();
        assert!(cost_large > cost_small);
    }

    #[test]
    fn inverse_mint_flat_band_special_case_uses_division() {
        let band = Band {
            index: 99,
            start_supply: 0,
            end_supply: 100 * SCALE,
            slope_num: 0,
            slope_den: 1,
            p_start: P_START_0,
        };
        let reserve_credit = 10 * SCALE;
        let minted = inverse_mint(reserve_credit, 0, &band).unwrap();
        assert_eq!(
            minted,
            mul_div_floor_u128(reserve_credit, SCALE, band.p_start).unwrap()
        );
    }

    #[test]
    fn inverse_mint_returns_positive_amount_for_positive_credit() {
        let band = BANDS[0];
        let minted = inverse_mint(4 * SCALE, band.start_supply, &band).unwrap();
        assert!(minted > 0);
    }

    #[test]
    fn cost_to_mint_matches_single_band_cost_when_no_boundary_is_crossed() {
        let band = BANDS[0];
        let delta = 50 * SCALE;
        assert_eq!(
            cost_to_mint(delta, band.start_supply).unwrap(),
            cost_single_band(band.start_supply, band.start_supply + delta, &band).unwrap()
        );
    }

    #[test]
    fn mint_with_reserve_consumes_full_band_when_reserve_matches_boundary_cost() {
        let band = BANDS[0];
        let reserve_credit = cost_single_band(band.start_supply, band.end_supply, &band).unwrap();
        assert_eq!(
            mint_with_reserve(reserve_credit, band.start_supply).unwrap(),
            band.end_supply - band.start_supply
        );
    }

    #[test]
    fn payout_for_burn_matches_single_band_cost_when_no_boundary_is_crossed() {
        let band = BANDS[0];
        let amount = 75 * SCALE;
        let current_supply = band.start_supply + amount;
        assert_eq!(
            payout_for_burn(amount, current_supply).unwrap(),
            cost_single_band(band.start_supply, current_supply, &band).unwrap()
        );
    }

    #[test]
    fn payout_for_burn_crosses_boundary_right_to_left() {
        let current_supply = BANDS[1].start_supply + 10 * SCALE;
        let amount = 20 * SCALE;
        let expected = cost_single_band(
            BANDS[0].end_supply - 10 * SCALE,
            BANDS[0].end_supply,
            &BANDS[0],
        )
        .unwrap()
            + cost_single_band(BANDS[1].start_supply, current_supply, &BANDS[1]).unwrap();
        assert_eq!(payout_for_burn(amount, current_supply).unwrap(), expected);
    }
}
