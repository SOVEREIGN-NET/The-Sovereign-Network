pub use lib_types::{
    BondingCurveBand as Band, BondingCurveBuyReceipt, BondingCurveBuyTx, BondingCurveSellReceipt,
    BondingCurveSellTx, CBE_MAX_SUPPLY, TOKEN_SCALE_18,
};

pub const SCALE: u128 = TOKEN_SCALE_18;
pub const SLOPE_DEN: u128 = 100_000_000_000_000;
pub const BAND_COUNT: usize = 5;
pub const MAX_GROSS_SOV_PER_TX: u128 = 1_000_000_000_000_000_000_000_000;
pub const MAX_DELTA_S_PER_TX: u128 = 100_000_000_000 * SCALE;
pub const MAX_SUPPLY: u128 = CBE_MAX_SUPPLY;

pub const INTERCEPT_0: i128 = 313_345_700_000_000;
pub const INTERCEPT_1: i128 = 213_345_700_000_000;
pub const INTERCEPT_2: i128 = -86_654_300_000_000;
pub const INTERCEPT_3: i128 = -686_654_300_000_000;
pub const INTERCEPT_4: i128 = -1_536_654_300_000_000;

pub const BANDS: [Band; BAND_COUNT] = [
    Band {
        index: 0,
        start_supply: 0,
        end_supply: 10_000_000_000u128 * SCALE,
        slope_num: 1,
        slope_den: SLOPE_DEN,
        intercept: INTERCEPT_0,
    },
    Band {
        index: 1,
        start_supply: 10_000_000_000u128 * SCALE,
        end_supply: 30_000_000_000u128 * SCALE,
        slope_num: 2,
        slope_den: SLOPE_DEN,
        intercept: INTERCEPT_1,
    },
    Band {
        index: 2,
        start_supply: 30_000_000_000u128 * SCALE,
        end_supply: 60_000_000_000u128 * SCALE,
        slope_num: 3,
        slope_den: SLOPE_DEN,
        intercept: INTERCEPT_2,
    },
    Band {
        index: 3,
        start_supply: 60_000_000_000u128 * SCALE,
        end_supply: 85_000_000_000u128 * SCALE,
        slope_num: 4,
        slope_den: SLOPE_DEN,
        intercept: INTERCEPT_3,
    },
    Band {
        index: 4,
        start_supply: 85_000_000_000u128 * SCALE,
        end_supply: MAX_SUPPLY,
        slope_num: 5,
        slope_den: SLOPE_DEN,
        intercept: INTERCEPT_4,
    },
];

pub fn band_for_supply(supply: u128) -> Band {
    for band in BANDS {
        let in_band = if band.index as usize == BAND_COUNT - 1 {
            supply >= band.start_supply && supply <= band.end_supply
        } else {
            supply >= band.start_supply && supply < band.end_supply
        };
        if in_band {
            return band;
        }
    }
    BANDS[BAND_COUNT - 1]
}

pub fn price_at_supply(supply: u128) -> u128 {
    let band = band_for_supply(supply);
    let slope_component = band
        .slope_num
        .checked_mul(supply)
        .and_then(|v| v.checked_div(band.slope_den))
        .expect("canonical price slope component overflow");
    let price = band.intercept + slope_component as i128;
    price.max(0) as u128
}

pub fn integer_sqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }

    let mut x0 = n;
    let mut x1 = (x0 + n / x0) / 2;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + n / x0) / 2;
    }
    x0
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
            let left = price_at_supply(pair[0].end_supply);
            let right = price_at_supply(pair[1].start_supply);
            assert_eq!(left, right);
        }
    }

    #[test]
    fn price_matches_known_initial_value() {
        assert_eq!(price_at_supply(0), INTERCEPT_0 as u128);
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
}
