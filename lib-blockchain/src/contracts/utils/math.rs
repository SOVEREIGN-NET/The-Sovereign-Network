/// Integer square root using Newton's method
///
/// Returns floor(sqrt(n)) for all u64 inputs using Newton's method for fast convergence.
/// Uses saturating arithmetic to prevent overflow on large numbers.
pub fn integer_sqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    if n < 4 {
        return 1;
    }

    // For very large numbers, use bit-length based initial guess
    // sqrt(n) ≈ 2^(floor(log2(n)/2))
    let bit_length = (n.ilog2() + 1) as u64;
    let initial = 1u64 << (bit_length / 2);

    let mut x = initial;
    loop {
        // Use saturating operations to prevent overflow
        let next_x = x.saturating_add(n.saturating_div(x.max(1))) / 2;
        if next_x >= x {
            break;
        }
        x = next_x;
    }
    x
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
}
