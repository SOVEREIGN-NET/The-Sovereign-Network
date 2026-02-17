//! Issue #956: PoW Fields Ignored in BFT Mode
//!
//! Verifies that `difficulty`, `nonce`, and `cumulative_difficulty` fields on
//! `BlockHeader` are transparent to BFT consensus. Because these fields are
//! annotated `#[serde(skip, default)]` they are:
//!
//!   1. Omitted from every serialized representation (wire format, DB format).
//!   2. Restored to their `Default` value on every deserialization.
//!
//! Consequently, two blocks that are identical in every non-PoW field are
//! indistinguishable after a serialization round-trip, which is the behavior
//! required for a PoW-free BFT chain.

use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::types::{Difficulty, Hash};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal but structurally valid `BlockHeader` using explicit field
/// values so the test does not rely on `BlockHeader::new` (which immediately
/// recalculates `block_hash` and therefore couples the hash to `difficulty` and
/// `nonce` via `calculate_hash`).
///
/// `block_hash` is set to `Hash::default()` on purpose: the tests focus on
/// serialization behavior of the PoW fields, not on hash correctness.
fn make_header(
    nonce: u64,
    difficulty_bits: u32,
    cumulative_difficulty_bits: u32,
) -> BlockHeader {
    BlockHeader {
        version: 1,
        previous_block_hash: Hash::new([0xAB; 32]),
        merkle_root: Hash::new([0xCD; 32]),
        timestamp: 1_700_000_000,
        difficulty: Difficulty::from_bits(difficulty_bits),
        nonce,
        height: 1,
        block_hash: Hash::default(),
        transaction_count: 0,
        block_size: 0,
        cumulative_difficulty: Difficulty::from_bits(cumulative_difficulty_bits),
        fee_model_version: 1,
    }
}

fn make_block(nonce: u64, difficulty_bits: u32, cumulative_difficulty_bits: u32) -> Block {
    Block::new(
        make_header(nonce, difficulty_bits, cumulative_difficulty_bits),
        vec![],
    )
}

// ---------------------------------------------------------------------------
// Test 1: PoW fields are absent from bincode (wire) bytes
//
// When two blocks share identical non-PoW content but differ in every PoW
// field, their serialized bytes must be identical.
// ---------------------------------------------------------------------------

#[test]
fn test_pow_fields_absent_from_serialized_bytes() {
    // Block A: arbitrary PoW values
    let block_a = make_block(/*nonce*/ 99_999, /*difficulty*/ 0x1d00ffff, /*cumulative*/ 0x1e00ffff);

    // Block B: completely different PoW values, same everything else
    let block_b = make_block(/*nonce*/ 1, /*difficulty*/ 0x207fffff, /*cumulative*/ 0x20000001);

    // Confirm the in-memory structs actually differ in PoW fields.
    assert_ne!(block_a.header.nonce, block_b.header.nonce,
        "Test precondition: nonce values must differ");
    assert_ne!(block_a.header.difficulty, block_b.header.difficulty,
        "Test precondition: difficulty values must differ");
    assert_ne!(block_a.header.cumulative_difficulty, block_b.header.cumulative_difficulty,
        "Test precondition: cumulative_difficulty values must differ");

    // Serialize both blocks.
    let bytes_a = bincode::serialize(&block_a)
        .expect("block_a serialization should not fail");
    let bytes_b = bincode::serialize(&block_b)
        .expect("block_b serialization should not fail");

    // The wire bytes must be identical because PoW fields are skipped.
    assert_eq!(
        bytes_a, bytes_b,
        "Blocks that differ only in PoW fields must produce identical wire bytes. \
         If this assertion fails it means a PoW field is being serialized, \
         which breaks BFT mode."
    );
}

// ---------------------------------------------------------------------------
// Test 2: PoW fields are reset to defaults on deserialization
//
// After a serialization/deserialization round-trip the PoW fields must equal
// their `Default` values, regardless of what they held before serialization.
// ---------------------------------------------------------------------------

#[test]
fn test_pow_fields_reset_to_defaults_after_round_trip() {
    let non_default_nonce: u64 = 42_000;
    // 0x207fffff is Difficulty::minimum() — the hardest difficulty — which is
    // NOT equal to Difficulty::default() (= Difficulty::maximum() = 0x1d00ffff).
    let non_default_difficulty = Difficulty::from_bits(0x207fffff);
    let non_default_cumulative = Difficulty::from_bits(0x1e00ffff);

    // Verify our chosen values actually differ from the defaults.
    assert_ne!(
        non_default_nonce, 0u64,
        "Test precondition: nonce must be non-zero"
    );
    assert_ne!(
        non_default_difficulty,
        Difficulty::default(),
        "Test precondition: difficulty must differ from default"
    );
    assert_ne!(
        non_default_cumulative,
        Difficulty::default(),
        "Test precondition: cumulative_difficulty must differ from default"
    );

    let original = make_block(
        non_default_nonce,
        non_default_difficulty.bits(),
        non_default_cumulative.bits(),
    );

    // Perform a bincode round-trip (the format used on the wire and in the DB).
    let bytes = bincode::serialize(&original)
        .expect("serialization should not fail");
    let restored: Block = bincode::deserialize(&bytes)
        .expect("deserialization should not fail");

    assert_eq!(
        restored.header.nonce, 0u64,
        "nonce must be 0 (default) after deserialization; \
         got {} instead. PoW field is not being skipped correctly.",
        restored.header.nonce
    );

    assert_eq!(
        restored.header.difficulty,
        Difficulty::default(),
        "difficulty must equal Difficulty::default() after deserialization; \
         got {:?} instead. PoW field is not being skipped correctly.",
        restored.header.difficulty
    );

    assert_eq!(
        restored.header.cumulative_difficulty,
        Difficulty::default(),
        "cumulative_difficulty must equal Difficulty::default() after deserialization; \
         got {:?} instead. PoW field is not being skipped correctly.",
        restored.header.cumulative_difficulty
    );
}

// ---------------------------------------------------------------------------
// Test 3: PoW fields are reset to defaults on JSON deserialization
//
// Validates the same invariant for the JSON format, which may be used for
// human-readable storage or API responses.
// ---------------------------------------------------------------------------

#[test]
fn test_pow_fields_reset_to_defaults_after_json_round_trip() {
    let original = make_block(
        /*nonce*/ 77_777,
        /*difficulty*/ 0x1d00ffff,
        /*cumulative*/ 0x1e00ffff,
    );

    let json = serde_json::to_string(&original)
        .expect("JSON serialization should not fail");

    // The JSON must not contain the field names for the skipped PoW fields.
    assert!(
        !json.contains("\"nonce\""),
        "JSON must not contain \"nonce\" field — it is a PoW field and must be skipped"
    );
    assert!(
        !json.contains("\"difficulty\""),
        "JSON must not contain \"difficulty\" field — it is a PoW field and must be skipped"
    );
    assert!(
        !json.contains("\"cumulative_difficulty\""),
        "JSON must not contain \"cumulative_difficulty\" field — it is a PoW field and must be skipped"
    );

    let restored: Block = serde_json::from_str(&json)
        .expect("JSON deserialization should not fail");

    assert_eq!(
        restored.header.nonce, 0u64,
        "nonce must be 0 (default) after JSON round-trip"
    );
    assert_eq!(
        restored.header.difficulty,
        Difficulty::default(),
        "difficulty must equal Difficulty::default() after JSON round-trip"
    );
    assert_eq!(
        restored.header.cumulative_difficulty,
        Difficulty::default(),
        "cumulative_difficulty must equal Difficulty::default() after JSON round-trip"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Non-PoW fields survive the round-trip unchanged
//
// Confirms that the serialization changes introduced to drop PoW fields do
// NOT accidentally drop any of the consensus-critical non-PoW fields.
// ---------------------------------------------------------------------------

#[test]
fn test_non_pow_fields_survive_round_trip() {
    let original = make_block(
        /*nonce*/ 1_234,
        /*difficulty*/ 0x207fffff,
        /*cumulative*/ 0x1d00ffff,
    );

    let bytes = bincode::serialize(&original)
        .expect("serialization should not fail");
    let restored: Block = bincode::deserialize(&bytes)
        .expect("deserialization should not fail");

    assert_eq!(
        restored.header.version,
        original.header.version,
        "version must survive round-trip"
    );
    assert_eq!(
        restored.header.previous_block_hash,
        original.header.previous_block_hash,
        "previous_block_hash must survive round-trip"
    );
    assert_eq!(
        restored.header.merkle_root,
        original.header.merkle_root,
        "merkle_root must survive round-trip"
    );
    assert_eq!(
        restored.header.timestamp,
        original.header.timestamp,
        "timestamp must survive round-trip"
    );
    assert_eq!(
        restored.header.height,
        original.header.height,
        "height must survive round-trip"
    );
    assert_eq!(
        restored.header.block_hash,
        original.header.block_hash,
        "block_hash must survive round-trip"
    );
    assert_eq!(
        restored.header.transaction_count,
        original.header.transaction_count,
        "transaction_count must survive round-trip"
    );
    assert_eq!(
        restored.header.block_size,
        original.header.block_size,
        "block_size must survive round-trip"
    );
    assert_eq!(
        restored.header.fee_model_version,
        original.header.fee_model_version,
        "fee_model_version must survive round-trip"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Blocks that differ in non-PoW fields produce different wire bytes
//
// This is the complementary guard: confirms that the serialization can still
// distinguish legitimately different blocks (i.e., that the skipping only
// applies to PoW fields, not to consensus-critical fields).
// ---------------------------------------------------------------------------

#[test]
fn test_different_non_pow_fields_produce_different_bytes() {
    let block_x = Block::new(
        BlockHeader {
            version: 1,
            previous_block_hash: Hash::new([0x11; 32]),
            merkle_root: Hash::new([0xAA; 32]),
            timestamp: 1_000_000,
            difficulty: Difficulty::from_bits(0x207fffff), // same PoW fields
            nonce: 100,
            height: 5,
            block_hash: Hash::default(),
            transaction_count: 0,
            block_size: 0,
            cumulative_difficulty: Difficulty::from_bits(0x207fffff),
            fee_model_version: 1,
        },
        vec![],
    );

    let block_y = Block::new(
        BlockHeader {
            version: 1,
            previous_block_hash: Hash::new([0x22; 32]), // different non-PoW field
            merkle_root: Hash::new([0xAA; 32]),
            timestamp: 1_000_000,
            difficulty: Difficulty::from_bits(0x207fffff), // same PoW fields
            nonce: 100,
            height: 5,
            block_hash: Hash::default(),
            transaction_count: 0,
            block_size: 0,
            cumulative_difficulty: Difficulty::from_bits(0x207fffff),
            fee_model_version: 1,
        },
        vec![],
    );

    let bytes_x = bincode::serialize(&block_x)
        .expect("serialization of block_x should not fail");
    let bytes_y = bincode::serialize(&block_y)
        .expect("serialization of block_y should not fail");

    assert_ne!(
        bytes_x, bytes_y,
        "Blocks that differ in non-PoW fields (previous_block_hash) \
         must produce different wire bytes."
    );
}
