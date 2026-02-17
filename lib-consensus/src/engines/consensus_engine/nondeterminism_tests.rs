//! Tests for nondeterminism detection
//!
//! These tests verify that the fail-fast nondeterminism detection system
//! correctly identifies and prevents nondeterministic operations during
//! consensus-critical sections.

#[cfg(test)]
mod tests {
    use super::super::validation::determinism_guard;

    #[test]
    fn test_determinism_guard_inactive_by_default() {
        assert!(!determinism_guard::is_consensus_active());
    }

    #[test]
    fn test_determinism_guard_activation() {
        determinism_guard::enter_consensus_scope();
        assert!(determinism_guard::is_consensus_active());
        determinism_guard::exit_consensus_scope();
        assert!(!determinism_guard::is_consensus_active());
    }

    #[test]
    #[should_panic(expected = "CONSENSUS NONDETERMINISM DETECTED")]
    fn test_determinism_guard_detects_violation() {
        determinism_guard::enter_consensus_scope();
        determinism_guard::assert_no_nondeterminism("test_operation");
        determinism_guard::exit_consensus_scope();
    }

    #[test]
    fn test_determinism_guard_allows_when_inactive() {
        // Should not panic when consensus is not active
        determinism_guard::assert_no_nondeterminism("test_operation");
    }

    #[test]
    fn test_scoped_guard_cleanup() {
        {
            determinism_guard::enter_consensus_scope();
            let _guard = scopeguard::guard((), |_| {
                determinism_guard::exit_consensus_scope();
            });
            assert!(determinism_guard::is_consensus_active());
        }
        // Guard should have cleaned up
        assert!(!determinism_guard::is_consensus_active());
    }
}
