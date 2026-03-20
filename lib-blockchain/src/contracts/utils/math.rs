use primitive_types::U256;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MathError {
    #[error("arithmetic overflow")]
    Overflow,
    #[error("division by zero")]
    DivisionByZero,
    #[error("u256 to u128 downcast overflow")]
    DowncastOverflow,
}

/// Integer square root using canonical binary search for smaller utility callers.
pub fn integer_sqrt(n: u64) -> u64 {
    if n < 2 {
        return n;
    }

    let mut lo = 0u64;
    let mut hi = n.min(u32::MAX as u64 + 1);

    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if mid <= n / mid {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    lo
}

pub fn u256_to_u128(value: U256) -> Result<u128, MathError> {
    if value > U256::from(u128::MAX) {
        return Err(MathError::DowncastOverflow);
    }
    Ok(value.as_u128())
}

pub fn mul_div_floor_u256(a: U256, b: U256, den: U256) -> Result<U256, MathError> {
    if den.is_zero() {
        return Err(MathError::DivisionByZero);
    }
    Ok(a.checked_mul(b).ok_or(MathError::Overflow)? / den)
}

pub fn mul_div_floor_u128(a: u128, b: u128, den: u128) -> Result<u128, MathError> {
    let result = mul_div_floor_u256(U256::from(a), U256::from(b), U256::from(den))?;
    u256_to_u128(result)
}

pub fn scaled_mul_u128(a: u128, b: u128, scale: u128) -> Result<u128, MathError> {
    mul_div_floor_u128(a, b, scale)
}

pub fn integer_sqrt_u256(n: U256) -> U256 {
    if n <= U256::from(1u8) {
        return n;
    }

    let mut lo = U256::zero();
    let mut hi = U256::from(u128::MAX) + U256::from(1u8);

    while lo + U256::from(1u8) < hi {
        let mid = lo + ((hi - lo) >> 1);
        if mid <= n / mid {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_sqrt_perfect_squares() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(16), 4);
        assert_eq!(integer_sqrt(25), 5);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(10000), 100);
    }

    #[test]
    fn test_integer_sqrt_non_perfect_squares() {
        // Floor of sqrt
        assert_eq!(integer_sqrt(2), 1);
        assert_eq!(integer_sqrt(3), 1);
        assert_eq!(integer_sqrt(5), 2);
        assert_eq!(integer_sqrt(8), 2);
        assert_eq!(integer_sqrt(99), 9);
        assert_eq!(integer_sqrt(101), 10);
    }

    #[test]
    fn test_integer_sqrt_large_numbers() {
        // Test with larger values
        assert_eq!(integer_sqrt(1_000_000), 1000);
        assert_eq!(integer_sqrt(u64::MAX / 2), 3_037_000_499);
    }

    #[test]
    fn test_integer_sqrt_edge_cases() {
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(2), 1);
        assert_eq!(integer_sqrt(3), 1);
        assert_eq!(integer_sqrt(4), 2);
    }

    #[test]
    fn test_mul_div_floor_u128() {
        assert_eq!(mul_div_floor_u128(10, 3, 4).unwrap(), 7);
        assert_eq!(scaled_mul_u128(5_000_000_000_000_000_000, 2, 1).unwrap(), 10_000_000_000_000_000_000);
    }

    #[test]
    fn test_mul_div_floor_rejects_zero_divisor() {
        assert_eq!(mul_div_floor_u128(1, 2, 0), Err(MathError::DivisionByZero));
    }

    #[test]
    fn test_integer_sqrt_u256_rounds_down() {
        assert_eq!(integer_sqrt_u256(U256::from(0u8)), U256::zero());
        assert_eq!(integer_sqrt_u256(U256::from(1u8)), U256::from(1u8));
        assert_eq!(integer_sqrt_u256(U256::from(15u8)), U256::from(3u8));
        assert_eq!(integer_sqrt_u256(U256::from(16u8)), U256::from(4u8));
        assert_eq!(integer_sqrt_u256(U256::from(17u8)), U256::from(4u8));
    }

    #[test]
    fn test_integer_sqrt_u256_large_value_properties() {
        let n = U256::MAX;
        let r = integer_sqrt_u256(n);
        assert!(r <= n / r);
        let next = r + U256::from(1u8);
        assert!(next > n / next);
    }
}
