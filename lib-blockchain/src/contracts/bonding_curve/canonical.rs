pub use lib_types::{
    BondingCurveBand as Band, BondingCurveBuyReceipt, BondingCurveBuyTx, BondingCurveSellReceipt,
    BondingCurveSellTx, CBE_MAX_SUPPLY, TOKEN_SCALE_18,
};
use primitive_types::U256;

use crate::contracts::utils::{
    integer_sqrt_u256, mul_div_floor_u128, u256_to_u128, MathError,
};

pub const SCALE: u128 = TOKEN_SCALE_18;
pub const SLOPE_DEN: u128 = 100_000_000_000_000;

/// Graduation threshold: reserve_balance must reach this value (in atomic units).
/// Team decision: GRAD_THRESHOLD = 2_745_966 * SCALE
/// Used by the economic computation in #1930/#1931; allow until those land.
#[allow(dead_code)]
pub const GRAD_THRESHOLD: u128 = 2_745_966 * SCALE;
pub const BAND_COUNT: usize = 5;
pub const MAX_GROSS_SOV_PER_TX: u128 = 1_000_000_000_000_000_000_000_000;
pub const MAX_DELTA_S_PER_TX: u128 = 100_000_000_000 * SCALE;
pub const MAX_SUPPLY: u128 = CBE_MAX_SUPPLY;

pub const P_START_0: u128 = 313_345_700_000_000;
pub const P_START_1: u128 = 413_345_700_000_000;
pub const P_START_2: u128 = 813_345_700_000_000;
pub const P_START_3: u128 = 1_713_345_700_000_000;
pub const P_START_4: u128 = 2_713_345_700_000_000;

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
    u256_to_u128(integer_sqrt_u256(U256::from(n))).expect("canonical integer_sqrt downcast overflow")
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
            cost_single_band(band.start_supply, band.start_supply + 10 * one_token, &band)
                .unwrap();
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
        let expected = cost_single_band(BANDS[0].end_supply - 10 * SCALE, BANDS[0].end_supply, &BANDS[0]).unwrap()
            + cost_single_band(BANDS[1].start_supply, current_supply, &BANDS[1]).unwrap();
        assert_eq!(payout_for_burn(amount, current_supply).unwrap(), expected);
    }
}
