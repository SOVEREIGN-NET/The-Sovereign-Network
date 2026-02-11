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
/// - `generate_lib_token_id()` for SOV native token
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
/// 3. **Injectivity**: Distinct input tuples must map to distinct token IDs (no collisions)
/// 4. **Semantic inclusion**: All dimensions that affect token economics are included:
///    - name: human-readable token name
///    - symbol: ticker symbol
///    - dao_type: NP vs FP classification (prevents NP/FP collision)
///    - decimals: precision (prevents economic confusion at different scales)
///
/// # Domain Separation
/// Uses a versioned domain string "SOV_TOKEN_ID_V2" to:
/// - Prevent cross-protocol collisions
/// - Enable future algorithm changes (V2, V3, etc.)
/// - Protect against replay attacks
///
/// # Input Encoding (Length-Prefixed Canonical Format)
/// Deterministic, unambiguous byte order with length separators:
/// 1. Domain: UTF-8 bytes of "SOV_TOKEN_ID_V2"
/// 2. Name length: u16 big-endian (0-65535 bytes)
/// 3. Name: UTF-8 bytes of token name
/// 4. Symbol length: u16 big-endian (0-65535 bytes)
/// 5. Symbol: UTF-8 bytes of token symbol (typically uppercase)
/// 6. DAOType: Fixed 2-byte ASCII ("np" or "fp")
/// 7. Decimals: Single byte (0-18)
///
/// Length-prefixing ensures injectivity: distinct (name, symbol) pairs
/// cannot serialize to the same preimage, even if concatenation would be ambiguous.
///
/// Example:
/// - ("ab", "c") → [0x00, 0x02] + "ab" + [0x00, 0x01] + "c" = unique encoding
/// - ("a", "bc") → [0x00, 0x01] + "a" + [0x00, 0x02] + "bc" = distinct encoding
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
    // Domain separation prefix (versioned for migration from V1)
    let domain = b"SOV_TOKEN_ID_V2";

    // Build deterministic, unambiguous input with length prefixes
    let mut data = Vec::new();
    
    // Domain
    data.extend_from_slice(domain);
    
    // Name: length-prefixed (u16 big-endian) + UTF-8 bytes
    let name_bytes = name.as_bytes();
    data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(name_bytes);
    
    // Symbol: length-prefixed (u16 big-endian) + UTF-8 bytes
    let symbol_bytes = symbol.as_bytes();
    data.extend_from_slice(&(symbol_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(symbol_bytes);
    
    // DAOType: fixed 2-byte ASCII encoding ("np" or "fp")
    data.extend_from_slice(dao_type.as_str().as_bytes());
    
    // Decimals: single byte (0-18)
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
        // Golden test: verify known input produces expected hash (V2 with length-prefixes)
        // This catches algorithm changes and ensures cross-node consistency
        let id = derive_token_id("Healthcare DAO", "HEALTH", DAOType::NP, 8);

        // Reconstruct the V2 canonical encoding with length prefixes
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(b"SOV_TOKEN_ID_V2");
        expected_input.extend_from_slice(&(14u16).to_be_bytes()); // "Healthcare DAO" length
        expected_input.extend_from_slice(b"Healthcare DAO");
        expected_input.extend_from_slice(&(6u16).to_be_bytes()); // "HEALTH" length
        expected_input.extend_from_slice(b"HEALTH");
        expected_input.extend_from_slice(b"np"); // DAOType::NP as 2 bytes
        expected_input.push(8); // decimals
        
        let expected = blake3::hash(&expected_input);
        assert_eq!(id, *expected.as_bytes());
    }

    #[test]
    fn test_derive_token_id_golden_fp_token() {
        // Golden test: FP token with same name/symbol as NP must differ (V2)
        let id_np = derive_token_id("Economic DAO", "ECO", DAOType::NP, 18);
        let id_fp = derive_token_id("Economic DAO", "ECO", DAOType::FP, 18);

        // Reconstruct V2 encodings
        let mut expected_np_input = Vec::new();
        expected_np_input.extend_from_slice(b"SOV_TOKEN_ID_V2");
        expected_np_input.extend_from_slice(&(12u16).to_be_bytes()); // "Economic DAO" length
        expected_np_input.extend_from_slice(b"Economic DAO");
        expected_np_input.extend_from_slice(&(3u16).to_be_bytes()); // "ECO" length
        expected_np_input.extend_from_slice(b"ECO");
        expected_np_input.extend_from_slice(b"np");
        expected_np_input.push(18);

        let mut expected_fp_input = Vec::new();
        expected_fp_input.extend_from_slice(b"SOV_TOKEN_ID_V2");
        expected_fp_input.extend_from_slice(&(12u16).to_be_bytes());
        expected_fp_input.extend_from_slice(b"Economic DAO");
        expected_fp_input.extend_from_slice(&(3u16).to_be_bytes());
        expected_fp_input.extend_from_slice(b"ECO");
        expected_fp_input.extend_from_slice(b"fp");
        expected_fp_input.push(18);

        let expected_np = blake3::hash(&expected_np_input);
        let expected_fp = blake3::hash(&expected_fp_input);

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
        // The test verifies domain is part of the hash (using V2 format)
        let mut without_domain_input = Vec::new();
        without_domain_input.extend_from_slice(&(4u16).to_be_bytes()); // "Test" length
        without_domain_input.extend_from_slice(b"Test");
        without_domain_input.extend_from_slice(&(3u16).to_be_bytes()); // "TST" length
        without_domain_input.extend_from_slice(b"TST");
        without_domain_input.extend_from_slice(b"np");
        without_domain_input.push(8);

        let without_domain = blake3::hash(&without_domain_input);

        // Must NOT equal the hash without domain prefix
        assert_ne!(id, *without_domain.as_bytes());
    }

    // ============================================================================
    // CRITICAL INJECTIVITY TEST (Collision Prevention)
    // ============================================================================

    #[test]
    fn test_derive_token_id_injectivity_prevents_concatenation_collision() {
        // CRITICAL: Prevent collision from ambiguous concatenation.
        // Without length-prefixes, ("ab", "c") and ("a", "bc") both produce "abc".
        // With length-prefixes, they must produce different preimages and thus different hashes.
        //
        // This is a protocol-critical invariant: token identity must be injective.
        let id_ab_c = derive_token_id("ab", "c", DAOType::NP, 8);
        let id_a_bc = derive_token_id("a", "bc", DAOType::NP, 8);

        // These MUST be different (injectivity invariant)
        assert_ne!(id_ab_c, id_a_bc);

        // Verify the preimages are indeed different (length-prefixes distinguish them)
        // ("ab", "c"): len(2) + "ab" + len(1) + "c"
        let mut preimage_ab_c = Vec::new();
        preimage_ab_c.extend_from_slice(b"SOV_TOKEN_ID_V2");
        preimage_ab_c.extend_from_slice(&(2u16).to_be_bytes());
        preimage_ab_c.extend_from_slice(b"ab");
        preimage_ab_c.extend_from_slice(&(1u16).to_be_bytes());
        preimage_ab_c.extend_from_slice(b"c");
        preimage_ab_c.extend_from_slice(b"np");
        preimage_ab_c.push(8);

        // ("a", "bc"): len(1) + "a" + len(2) + "bc"
        let mut preimage_a_bc = Vec::new();
        preimage_a_bc.extend_from_slice(b"SOV_TOKEN_ID_V2");
        preimage_a_bc.extend_from_slice(&(1u16).to_be_bytes());
        preimage_a_bc.extend_from_slice(b"a");
        preimage_a_bc.extend_from_slice(&(2u16).to_be_bytes());
        preimage_a_bc.extend_from_slice(b"bc");
        preimage_a_bc.extend_from_slice(b"np");
        preimage_a_bc.push(8);

        // Preimages must be different
        assert_ne!(preimage_ab_c, preimage_a_bc);

        // And thus hashes must be different
        let hash_ab_c = blake3::hash(&preimage_ab_c);
        let hash_a_bc = blake3::hash(&preimage_a_bc);
        assert_ne!(hash_ab_c.as_bytes(), hash_a_bc.as_bytes());
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

        // Create expected hash with full blake3 (V2 length-prefixed format)
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(b"SOV_TOKEN_ID_V2");
        expected_input.extend_from_slice(&(10u16).to_be_bytes()); // "Healthcare" length
        expected_input.extend_from_slice(b"Healthcare");
        expected_input.extend_from_slice(&(6u16).to_be_bytes()); // "HEALTH" length
        expected_input.extend_from_slice(b"HEALTH");
        expected_input.extend_from_slice(b"np");
        expected_input.push(8);

        let full_hash = blake3::hash(&expected_input);

        // Must match exactly (no truncation)
        assert_eq!(id, *full_hash.as_bytes());
    }
}
