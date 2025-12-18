//! Rate limiting for chunk reception per peer
//!
//! Prevents DoS attacks by limiting the number of chunks a peer can send per second.

use std::time::{Duration, Instant};

/// Rate limiter for chunk reception per peer
#[derive(Debug)]
pub struct ChunkRateLimiter {
    chunks_received: u32,
    window_start: Instant,
}

impl ChunkRateLimiter {
    pub fn new() -> Self {
        Self {
            chunks_received: 0,
            window_start: Instant::now(),
        }
    }

    /// Check if chunk is allowed and increment counter
    /// Returns false if rate limit exceeded
    pub fn check_and_increment(&mut self, max_per_second: u32) -> bool {
        let elapsed = self.window_start.elapsed();

        // Reset window every second
        if elapsed >= Duration::from_secs(1) {
            self.chunks_received = 0;
            self.window_start = Instant::now();
        }

        if self.chunks_received >= max_per_second {
            return false;
        }

        self.chunks_received += 1;
        true
    }
}

impl Default for ChunkRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = ChunkRateLimiter::new();

        for _ in 0..10 {
            assert!(limiter.check_and_increment(10));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = ChunkRateLimiter::new();

        for _ in 0..10 {
            assert!(limiter.check_and_increment(10));
        }

        assert!(!limiter.check_and_increment(10));
    }

    #[test]
    fn test_rate_limiter_resets_after_window() {
        let mut limiter = ChunkRateLimiter::new();

        for _ in 0..5 {
            assert!(limiter.check_and_increment(5));
        }

        assert!(!limiter.check_and_increment(5));

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(1100));

        assert!(limiter.check_and_increment(5));
    }
}
