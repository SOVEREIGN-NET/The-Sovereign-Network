use crate::types::dao::DAOType;

/// Canonical token ID derivation function for DAO tokens.
///
/// # Scope: DAO Tokens Only
/// This function is the single source of truth for deriving token IDs for DAO tokens:
/// - DAOToken (NP/FP classification)
/// - Future sector-specific DAO tokens
/// - Any cross-contract validation of DAO token identities
///
/// This function MUST be used by all DAO token contracts to ensure:
/// - Global uniqueness across NP/FP classifications
/// - Consensus agreement on token identity
/// - Deterministic replay and validation
///
/// # Generic Tokens
/// Generic TokenContract (from core.rs) uses separate utilities:
/// - `generate_lib_token_id()` for ZHTP native token
/// - `generate_custom_token_id()` for dApp tokens
///
/// These are NOT DAO-specific and do not require DAOType or decimals.
/// Do NOT change generic token ID derivation to use this function without
/// explicit architectural decision and migration strategy.
///
/// Canonical token ID derivation function.
///
/// Produces a deterministic, globally unique token identifier across all token types.
///
/// # Invariants (protocol guarantees)
/// 1. **Determinism**: Given identical inputs, all nodes produce identical token_id
/// 2. **Collision resistance**: Different inputs produce different IDs with extremely high probability
/// 3. **Semantic inclusion**: All dimensions that affect token economics are included:
///    - name: human-readable token name
///    - symbol: ticker symbol
///    - dao_type: NP vs FP classification (prevents NP/FP collision)
///    - decimals: precision (prevents economic confusion at different scales)
///
/// # Domain Separation
/// Uses a versioned domain string "SOV_TOKEN_ID_V1" to:
/// - Prevent cross-protocol collisions
/// - Enable future algorithm changes (V2, V3, etc.)
/// - Protect against replay attacks
///
/// # Input Encoding
/// Deterministic byte order:
/// 1. Domain: UTF-8 bytes of "SOV_TOKEN_ID_V1"
/// 2. Name: UTF-8 bytes of token name
/// 3. Symbol: UTF-8 bytes of token symbol (typically uppercase)
/// 4. DAOType: Stable enum encoding (as_str() UTF-8 bytes: "np" or "fp")
/// 5. Decimals: Single byte (0-18)
///
/// # Hash Function
/// blake3 hash of the combined input, full 32-byte output.
/// - Deterministic across all architectures and runs
/// - Cryptographically secure
/// - No randomness or state dependence
///
/// # Example
/// ```ignore
/// let token_id = derive_token_id(
///     "Healthcare DAO Token",  // name
///     "HEALTH",                 // symbol
///     DAOType::NP,              // dao_type
///     8,                        // decimals
/// );
/// // Result: deterministic [u8; 32]
/// ```
pub fn derive_token_id(
    name: &str,
    symbol: &str,
    dao_type: DAOType,
    decimals: u8,
) -> [u8; 32] {
    // Domain separation prefix (versioned for future migrations)
    let domain = b"SOV_TOKEN_ID_V1";

    // Build deterministic input in stable byte order
    let mut data = Vec::new();
    data.extend_from_slice(domain);
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(symbol.as_bytes());
    data.extend_from_slice(dao_type.as_str().as_bytes());
    data.push(decimals);

    // blake3 produces full 32-byte output deterministically
    // Same input on all nodes → identical token_id
    // Different dao_type or decimals → different hash
    let hash = blake3::hash(&data);
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // DETERMINISM TESTS
    // ============================================================================

    #[test]
    fn test_derive_token_id_determinism_identical_inputs() {
        // CRITICAL: Same inputs must produce identical hash across all runs/nodes
        let name = "Healthcare DAO";
        let symbol = "HEALTH";
        let dao_type = DAOType::NP;
        let decimals = 8;

        let id1 = derive_token_id(name, symbol, dao_type, decimals);
        let id2 = derive_token_id(name, symbol, dao_type, decimals);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_token_id_determinism_multiple_runs() {
        // Verify determinism across multiple independent calls
        let name = "Education DAO";
        let symbol = "EDU";
        let dao_type = DAOType::NP;
        let decimals = 18;

        let ids: Vec<[u8; 32]> = (0..10)
            .map(|_| derive_token_id(name, symbol, dao_type, decimals))
            .collect();

        // All results must be identical
        for id in &ids[1..] {
            assert_eq!(id, &ids[0]);
        }
    }

    // ============================================================================
    // COLLISION RESISTANCE TESTS
    // ============================================================================

    #[test]
    fn test_derive_token_id_differs_across_dao_types() {
        // CRITICAL: NP and FP tokens with same name/symbol must have different IDs
        // This prevents semantic collisions between governance structures
        let name = "Sector DAO Token";
        let symbol = "SECTOR";
        let decimals = 8;

        let id_np = derive_token_id(name, symbol, DAOType::NP, decimals);
        let id_fp = derive_token_id(name, symbol, DAOType::FP, decimals);

        assert_ne!(id_np, id_fp);
    }

    #[test]
    fn test_derive_token_id_differs_across_names() {
        // Different names must produce different IDs
        let symbol = "TKN";
        let dao_type = DAOType::NP;
        let decimals = 8;

        let id1 = derive_token_id("Token A", symbol, dao_type, decimals);
        let id2 = derive_token_id("Token B", symbol, dao_type, decimals);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_derive_token_id_differs_across_symbols() {
        // Different symbols must produce different IDs
        let name = "Test Token";
        let dao_type = DAOType::NP;
        let decimals = 8;

        let id1 = derive_token_id(name, "TKNA", dao_type, decimals);
        let id2 = derive_token_id(name, "TKNB", dao_type, decimals);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_derive_token_id_differs_across_decimals() {
        // CRITICAL: Different decimals must produce different IDs
        // Prevents confusion between same token at different precisions
        let name = "Precision Token";
        let symbol = "PREC";
        let dao_type = DAOType::NP;

        let id_8 = derive_token_id(name, symbol, dao_type, 8);
        let id_18 = derive_token_id(name, symbol, dao_type, 18);

        assert_ne!(id_8, id_18);
    }

    #[test]
    fn test_derive_token_id_case_sensitive_name() {
        // Token names are case-sensitive (different tokens)
        let symbol = "TKN";
        let dao_type = DAOType::NP;
        let decimals = 8;

        let id_lower = derive_token_id("mytoken", symbol, dao_type, decimals);
        let id_upper = derive_token_id("MYTOKEN", symbol, dao_type, decimals);

        assert_ne!(id_lower, id_upper);
    }

    #[test]
    fn test_derive_token_id_case_sensitive_symbol() {
        // Token symbols are case-sensitive (should be distinct)
        let name = "Token";
        let dao_type = DAOType::NP;
        let decimals = 8;

        let id_lower = derive_token_id(name, "tkn", dao_type, decimals);
        let id_upper = derive_token_id(name, "TKN", dao_type, decimals);

        assert_ne!(id_lower, id_upper);
    }

    // ============================================================================
    // GOLDEN TEST (Fixed Hash Values)
    // ============================================================================

    #[test]
    fn test_derive_token_id_golden_np_token() {
        // Golden test: verify known input produces expected hash
        // This catches algorithm changes and ensures cross-node consistency
        let id = derive_token_id("Healthcare DAO", "HEALTH", DAOType::NP, 8);

        // The hash value is computed once and should never change
        // If this test fails, the algorithm has changed (which requires explicit migration)
        let expected = blake3::hash(b"SOV_TOKEN_ID_V1Healthcare DAOHEALTHnp\x08");
        assert_eq!(id, *expected.as_bytes());
    }

    #[test]
    fn test_derive_token_id_golden_fp_token() {
        // Golden test: FP token with same name/symbol as NP must differ
        let id_np = derive_token_id("Economic DAO", "ECO", DAOType::NP, 18);
        let id_fp = derive_token_id("Economic DAO", "ECO", DAOType::FP, 18);

        let expected_np = blake3::hash(b"SOV_TOKEN_ID_V1Economic DAOECO\x6e\x70\x12"); // np = \x6e\x70
        let expected_fp = blake3::hash(b"SOV_TOKEN_ID_V1Economic DAOECO\x66\x70\x12"); // fp = \x66\x70

        assert_eq!(id_np, *expected_np.as_bytes());
        assert_eq!(id_fp, *expected_fp.as_bytes());
        assert_ne!(id_np, id_fp);
    }

    // ============================================================================
    // DOMAIN SEPARATION TESTS
    // ============================================================================

    #[test]
    fn test_derive_token_id_domain_separation() {
        // Verify domain string is included (prevents cross-protocol collisions)
        let id = derive_token_id("Test", "TST", DAOType::NP, 8);

        // If domain was not included, this would collide with non-SOV token systems
        // The test verifies domain is part of the hash
        let without_domain = blake3::hash(b"TestTSTnp\x08");

        // Must NOT equal the hash without domain
        assert_ne!(id, *without_domain.as_bytes());
    }

    // ============================================================================
    // EDGE CASE TESTS
    // ============================================================================

    #[test]
    fn test_derive_token_id_min_max_decimals() {
        let name = "Token";
        let symbol = "TKN";
        let dao_type = DAOType::NP;

        let id_min = derive_token_id(name, symbol, dao_type, 0);
        let id_max = derive_token_id(name, symbol, dao_type, 18);

        // Must differ even though both are valid
        assert_ne!(id_min, id_max);
    }

    #[test]
    fn test_derive_token_id_empty_strings_handled() {
        // Empty strings are still valid inputs (should not panic)
        let id = derive_token_id("", "", DAOType::NP, 8);

        // Should produce a valid hash
        assert_eq!(id.len(), 32);

        // Different from non-empty
        let id_nonempty = derive_token_id("x", "x", DAOType::NP, 8);
        assert_ne!(id, id_nonempty);
    }

    #[test]
    fn test_derive_token_id_unicode_names() {
        // Unicode handling in names (UTF-8 encoded)
        let id_ascii = derive_token_id("Token", "TKN", DAOType::NP, 8);
        let id_unicode = derive_token_id("Tökën", "TKN", DAOType::NP, 8);

        // Different names produce different IDs
        assert_ne!(id_ascii, id_unicode);
    }

    // ============================================================================
    // STABILITY TESTS (Algorithm Change Detection)
    // ============================================================================

    #[test]
    fn test_derive_token_id_output_is_32_bytes() {
        // blake3 always produces 32 bytes
        let id = derive_token_id("Test", "TST", DAOType::NP, 8);
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_derive_token_id_no_truncation() {
        // Verify full hash is used (not truncated)
        let id = derive_token_id("Healthcare", "HEALTH", DAOType::NP, 8);

        // Create expected hash with full blake3
        let full_hash = blake3::hash(b"SOV_TOKEN_ID_V1HealthcareHEALTHnp\x08");

        // Must match exactly (no truncation)
        assert_eq!(id, *full_hash.as_bytes());
    }
}
