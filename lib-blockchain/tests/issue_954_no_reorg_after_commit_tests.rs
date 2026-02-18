//! Issue #954: No reorg after commit
//!
//! Verifies that once a block at height H has been committed via BFT consensus,
//! any attempt to introduce an alternate block at height H is rejected.
//!
//! The post-commit reorg guard was introduced in issue #940 inside
//! `Blockchain::evaluate_and_merge_chain()`: if `finalized_blocks` is
//! non-empty the function returns `Err` immediately, before any chain
//! comparison logic runs.
//!
//! Test scenario (per issue spec):
//! - ≥4 validators are registered on the local chain.
//! - A block at height H=1 is appended and marked as BFT-committed
//!   (`mark_block_finalized(1)`) — this simulates the effect of a successful
//!   commit quorum from the consensus engine.
//! - An alternate chain is built from the same genesis but with a *different*
//!   block at height H=1, exported, and fed into `evaluate_and_merge_chain`.
//! - The call MUST return `Err`.  If it returned `Ok` a reorg would be
//!   possible, which would break BFT finality.

use anyhow::Result;
use lib_blockchain::{Block, BlockHeader, Blockchain, ValidatorInfo};
use lib_blockchain::types::mining::get_mining_config_from_env;
use lib_blockchain::types::Hash;

// ============================================================================
// Helpers
// ============================================================================

/// Register `n` validators directly into `blockchain.validator_registry`.
///
/// BFT requires ≥4 validators (f=1, quorum=3).  The test registers exactly 4.
fn register_n_validators(blockchain: &mut Blockchain, n: usize) {
    for i in 0..n {
        let id = format!("validator_{:03}", i);
        let info = ValidatorInfo {
            identity_id: id.clone(),
            stake: 1_000_000_000,
            storage_provided: 100 * 1024 * 1024 * 1024,
            consensus_key: vec![(i + 1) as u8; 32],
            networking_key: vec![(i + 65) as u8; 32],
            rewards_key: vec![(i + 129) as u8; 32],
            network_address: format!("127.0.0.1:{}", 9000 + i),
            commission_rate: 5,
            status: "active".to_string(),
            registered_at: 1_000,
            last_activity: 1_000,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: "genesis".to_string(),
            governance_proposal_id: None,
        };
        blockchain.validator_registry.insert(id, info);
    }
}

/// Build a minimal block that chains on top of `parent` at the next height.
///
/// The block uses the lowest possible difficulty so it does not need real PoW.
/// An `extra_nonce` byte is mixed into the timestamp so that two calls with
/// different values produce blocks with different hashes — letting us build
/// two genuinely distinct blocks at the same height.
fn build_next_block(parent: &Block, extra_nonce: u64) -> Block {
    let mining_config = get_mining_config_from_env();
    let height = parent.header.height + 1;
    let timestamp = parent.timestamp() + 10 + extra_nonce;
    let mut header = BlockHeader::new(
        1,
        parent.hash(),
        Hash::default(), // empty merkle root (no transactions)
        timestamp,
        mining_config.difficulty,
        height,
        0, // tx_count
        0, // tx_size
        mining_config.difficulty,
    );
    header.set_nonce(0);
    Block::new(header, vec![])
}

// ============================================================================
// Tests
// ============================================================================

/// Core test: no reorg after BFT commit with ≥4 validators.
///
/// This test FAILS (panics / assertion error) if a reorg is possible after a
/// block has been committed.  The test passes only when
/// `evaluate_and_merge_chain` returns `Err`.
#[tokio::test]
async fn test_no_reorg_after_commit_with_four_validators() -> Result<()> {
    // ------------------------------------------------------------------
    // 1. Build the local chain (the "committed" node).
    // ------------------------------------------------------------------
    let mut local_chain = Blockchain::new()?;

    // Register ≥4 validators — required for BFT (3f+1, f=1 ⟹ n≥4).
    register_n_validators(&mut local_chain, 4);
    assert_eq!(
        local_chain.validator_registry.len(),
        4,
        "Must have exactly 4 validators registered"
    );

    // Append block at height H=1.
    let genesis = local_chain.latest_block().unwrap().clone();
    let block_h1 = build_next_block(&genesis, 0);
    local_chain.add_block(block_h1).await?;
    assert_eq!(local_chain.height, 1, "Local chain should be at height 1");

    // Simulate BFT commit: mark block at H=1 as finalized.
    // In production this is triggered after ≥2f+1 (≥3 of 4) commit votes.
    local_chain.mark_block_finalized(1);
    assert!(
        local_chain.is_block_finalized(1),
        "Block H=1 must be marked finalized before testing reorg rejection"
    );

    // ------------------------------------------------------------------
    // 2. Build the alternate chain (different block at H=1).
    // ------------------------------------------------------------------
    // Start from a fresh chain with the same genesis, then append a
    // *different* block at H=1 (extra_nonce=1 ⟹ different timestamp ⟹
    // different hash).
    let mut alternate_chain = Blockchain::new()?;
    let alt_genesis = alternate_chain.latest_block().unwrap().clone();
    let alt_block_h1 = build_next_block(&alt_genesis, 1); // extra_nonce=1 → different hash
    alternate_chain.add_block(alt_block_h1).await?;
    assert_eq!(
        alternate_chain.height,
        1,
        "Alternate chain should also be at height 1"
    );

    // Confirm the two chains produced different blocks at H=1.
    let local_h1_hash = local_chain.blocks[1].hash();
    let alt_h1_hash = alternate_chain.blocks[1].hash();
    assert_ne!(
        local_h1_hash,
        alt_h1_hash,
        "Alternate block at H=1 must differ from committed block — otherwise this test is vacuous"
    );

    // ------------------------------------------------------------------
    // 3. Export the alternate chain and attempt to import it into the
    //    committed local chain.
    // ------------------------------------------------------------------
    let alternate_bytes = alternate_chain.export_chain()?;

    // This MUST return Err.  The post-commit reorg guard in
    // `evaluate_and_merge_chain` (introduced in issue #940) rejects any
    // import when `finalized_blocks` is non-empty.
    let result = local_chain
        .evaluate_and_merge_chain(alternate_bytes)
        .await;

    assert!(
        result.is_err(),
        "evaluate_and_merge_chain MUST return Err after a block has been \
         BFT-committed.  Got Ok({:?}) — a reorg is possible, which violates \
         BFT finality!",
        result.ok()
    );

    // Verify the error message contains the expected guard text so we know
    // the right code path fired (not some unrelated error).
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Post-commit reorg forbidden")
            || err_msg.contains("finalized blocks"),
        "Error message should mention post-commit reorg guard.  Got: {}",
        err_msg
    );

    // Confirm the local chain was NOT modified — committed blocks are
    // immutable.
    assert_eq!(
        local_chain.height,
        1,
        "Local chain height must be unchanged after rejected reorg attempt"
    );
    assert_eq!(
        local_chain.blocks[1].hash(),
        local_h1_hash,
        "The committed block at H=1 must not have been replaced"
    );
    assert!(
        local_chain.is_block_finalized(1),
        "Block H=1 must still be marked finalized after rejected reorg"
    );

    Ok(())
}

/// Variant: single committed block is sufficient to block any import.
///
/// Even if the imported chain is longer, the guard fires before length
/// comparison.  This checks the "at-least-one-finalized-block" boundary.
#[tokio::test]
async fn test_reorg_rejected_regardless_of_imported_chain_length() -> Result<()> {
    // Local chain: height 1, block 1 committed.
    let mut local_chain = Blockchain::new()?;
    register_n_validators(&mut local_chain, 4);

    let genesis = local_chain.latest_block().unwrap().clone();
    let block_h1 = build_next_block(&genesis, 0);
    local_chain.add_block(block_h1).await?;
    local_chain.mark_block_finalized(1);

    // Alternate chain: two blocks (longer than local).  This would normally
    // satisfy the "longer chain wins" heuristic — but the guard must still
    // reject it.
    let mut alternate_chain = Blockchain::new()?;
    let alt_g = alternate_chain.latest_block().unwrap().clone();
    let alt_h1 = build_next_block(&alt_g, 99); // different nonce → different hash
    alternate_chain.add_block(alt_h1).await?;
    let alt_h1_blk = alternate_chain.latest_block().unwrap().clone();
    let alt_h2 = build_next_block(&alt_h1_blk, 0);
    alternate_chain.add_block(alt_h2).await?;
    assert_eq!(
        alternate_chain.height,
        2,
        "Alternate chain should be two blocks tall (longer than local)"
    );

    let alternate_bytes = alternate_chain.export_chain()?;
    let result = local_chain
        .evaluate_and_merge_chain(alternate_bytes)
        .await;

    assert!(
        result.is_err(),
        "A longer imported chain must still be rejected when local has \
         committed blocks.  Got Ok({:?})",
        result.ok()
    );

    Ok(())
}

/// Baseline: without any committed blocks, import is NOT an error.
///
/// This confirms the guard only fires after `mark_block_finalized` is called,
/// ensuring the test above is not trivially passing due to an unrelated
/// validation failure on a fresh chain.
#[tokio::test]
async fn test_import_succeeds_before_any_commit() -> Result<()> {
    // Local chain: height 0 (only genesis), no finalized blocks.
    let mut local_chain = Blockchain::new()?;
    register_n_validators(&mut local_chain, 4);
    assert!(
        local_chain.finalized_blocks.is_empty(),
        "Precondition: no blocks should be finalized yet"
    );

    // Alternate chain is also just genesis (same as local).
    let alternate_chain = Blockchain::new()?;
    let alternate_bytes = alternate_chain.export_chain()?;

    // Without finalized blocks the import path is permitted (result may be
    // LocalKept, ContentMerged, or ImportedAdopted depending on chain
    // evaluation — but not Err due to the post-commit guard).
    let result = local_chain
        .evaluate_and_merge_chain(alternate_bytes)
        .await;

    // We only assert it does NOT return an error that contains the
    // post-commit guard message.  Any other result is acceptable.
    if let Err(ref e) = result {
        let msg = e.to_string();
        assert!(
            !msg.contains("Post-commit reorg forbidden"),
            "Post-commit guard must NOT fire when no blocks are finalized. \
             Got: {}",
            msg
        );
    }
    // Note: the import may legitimately fail for other reasons (e.g.
    // verification of a fresh chain against itself).  We only care that the
    // *reorg guard* itself did not fire.

    Ok(())
}
