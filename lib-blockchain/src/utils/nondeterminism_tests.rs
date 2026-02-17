//! Tests for blockchain nondeterminism detection
//!
//! These tests verify that time and randomness utilities correctly detect
//! and prevent nondeterministic operations during consensus validation.

#[cfg(test)]
mod tests {
    use crate::utils::time;
    use crate::utils::hash;

    #[test]
    fn test_time_guard_inactive_by_default() {
        assert!(!time::is_consensus_validation_active());
    }

    #[test]
    fn test_time_guard_activation() {
        time::enter_consensus_validation();
        assert!(time::is_consensus_validation_active());
        time::exit_consensus_validation();
        assert!(!time::is_consensus_validation_active());
    }

    #[test]
    fn test_current_timestamp_works_when_inactive() {
        // Should work fine when not in consensus validation
        let timestamp = time::current_timestamp();
        assert!(timestamp > 0);
    }

    #[test]
    #[should_panic(expected = "FATAL: current_timestamp() called during consensus validation")]
    fn test_current_timestamp_panics_during_consensus() {
        time::enter_consensus_validation();
        let _timestamp = time::current_timestamp();
        time::exit_consensus_validation();
    }

    #[test]
    fn test_random_hash_works_when_inactive() {
        // Should work fine when not in consensus validation
        let hash1 = hash::random_hash();
        let hash2 = hash::random_hash();
        // Hashes should be different (extremely high probability)
        assert_ne!(hash1, hash2);
    }

    #[test]
    #[should_panic(expected = "FATAL: random_hash() called during consensus validation")]
    fn test_random_hash_panics_during_consensus() {
        time::enter_consensus_validation();
        let _hash = hash::random_hash();
        time::exit_consensus_validation();
    }

    #[test]
    fn test_scoped_validation_guard() {
        {
            time::enter_consensus_validation();
            assert!(time::is_consensus_validation_active());
        }
        // Manual cleanup for test
        time::exit_consensus_validation();
        assert!(!time::is_consensus_validation_active());
    }
}
