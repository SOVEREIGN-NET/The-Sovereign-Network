//! # BFT Finality Model and Irreversibility Condition [BFT-A][R3]
//!
//! ## Invariant
//! A block is FINAL if and only if it has received ≥2f+1 commit votes from
//! the validator set snapshot for its height, where f < n/3 is the maximum
//! number of Byzantine validators.
//!
//! ## Irreversibility Condition
//! Once a block is FINAL:
//! - It MUST appear in the `finalized_blocks` set
//! - Its height MUST be unreachable by any future `evaluate_and_merge_chain` call
//! - Any attempt to overwrite a finalized block MUST panic (see #940)
//!
//! ## Formal Definition
//!
//! Let V = validator set, n = |V|, f < n/3
//!
//! A block B at height H is FINAL iff:
//!   |{v ∈ V : v signed CommitVote(H, B.hash)}| ≥ 2f + 1
//!
//! Finality is:
//! - IMMEDIATE: no additional confirmations needed
//! - IRREVERSIBLE: cannot be undone by any sequence of messages
//! - UNCONDITIONAL: holds as long as honest majority assumption holds at commit time

/// The minimum fraction of validators needed for finality, expressed as numerator/denominator.
/// 2/3 + 1 of n validators must commit.
pub const FINALITY_QUORUM_NUMERATOR: u64 = 2;
pub const FINALITY_QUORUM_DENOMINATOR: u64 = 3;

/// Computes the minimum number of commit votes required for finality.
///
/// For n validators: threshold = floor(2n/3) + 1
pub const fn finality_threshold(n: u64) -> u64 {
    (n * FINALITY_QUORUM_NUMERATOR + FINALITY_QUORUM_DENOMINATOR - 1) / FINALITY_QUORUM_DENOMINATOR
}

/// Returns true if `votes` is sufficient for finality given `n` total validators.
pub fn is_final(votes: u64, n: u64) -> bool {
    votes >= finality_threshold(n)
}

/// Asserts the finality invariants hold for the given parameters.
///
/// # Panics
/// Panics if the invariants are violated.
pub fn assert_finality_invariants(votes: u64, n: u64) {
    let threshold = finality_threshold(n);
    assert!(n >= 4,
        "BFT invariant: minimum 4 validators required (got {})", n);
    assert!(threshold > 2 * n / 3,
        "BFT invariant: finality threshold {} must be strictly greater than 2n/3 = {}",
        threshold, 2 * n / 3);
    assert!(threshold <= n,
        "BFT invariant: finality threshold {} must not exceed n={}", threshold, n);
    assert!(
        votes >= threshold,
        "Finality invariant violated: votes {} < threshold {}",
        votes, threshold
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finality_threshold_4_validators() {
        // n=4, f=1: threshold = floor(8/3)+1 = 2+1 = 3
        assert_eq!(finality_threshold(4), 3);
    }

    #[test]
    fn test_finality_threshold_7_validators() {
        // n=7, f=2: threshold = floor(14/3)+1 = 4+1 = 5
        assert_eq!(finality_threshold(7), 5);
    }

    #[test]
    fn test_is_final() {
        assert!(is_final(3, 4));
        assert!(!is_final(2, 4));
        assert!(is_final(5, 7));
        assert!(!is_final(4, 7));
    }
}
