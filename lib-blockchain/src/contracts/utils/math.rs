/// Integer square root using Newton's method
///
/// Returns floor(sqrt(n)) for all u64 inputs using Newton's method for fast convergence.
///
/// # Error bounds
///
/// Newton's method converges quadratically for this function. For most inputs, the result
/// is exact when `n` is a perfect square (e.g., sqrt(100) = 10, sqrt(10000) = 100).
/// For non-perfect squares, returns the floor of the true mathematical square root,
/// with 0 error in integer terms (e.g., sqrt(99) = 9, sqrt(101) = 10).
pub fn integer_sqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }

    // Use bit-length based initial guess (overestimate to ensure convergence from above)
    // sqrt(n) < 2^((log2(n) + 1) / 2)
    let shift = (63 - n.leading_zeros()) / 2 + 1;
    let mut x = 1u64 << shift;

    // Newton's method: x_{n+1} = (x_n + n/x_n) / 2
    // Converges when x doesn't change (or oscillates between floor and ceiling)
    loop {
        let next_x = (x + n / x) / 2;
        if next_x >= x {
            return x;
        }
        x = next_x;
    }
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
