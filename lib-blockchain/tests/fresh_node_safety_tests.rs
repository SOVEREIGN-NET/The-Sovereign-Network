//! Fresh-node safety: a bootstrapping node must not adopt an unverified chain.
//!
//! Background
//! ----------
//! `Blockchain::evaluate_and_merge_chain()` is reached on a fresh node when it
//! syncs its first chain from a network peer (QUIC bootstrap, UDP mesh transfer,
//! or the import API). The deserialized `BlockchainImport` is fully attacker-
//! controlled.
//!
//! The legacy fast path, taken when the local chain was empty, assigned the
//! import's precomputed `blocks` **and** state maps (`validator_registry`,
//! `utxo_set`, `identity_registry`, …) directly — performing no genesis check,
//! no continuity check, and no block verification. A malicious peer could hand a
//! bootstrapping node a fabricated genesis, a validator set it controls, and
//! arbitrary balances: a complete chain-substitution takeover.
//!
//! The fix pins block 0 to the node's own embedded `genesis.toml`, verifies
//! continuity, applies every block through the verified sync path, and *derives*
//! all state from the blocks — the import's state maps are never trusted.
//!
//! These tests exercise that contract directly.

use anyhow::Result;
use lib_blockchain::types::Hash;
use lib_blockchain::{Block, BlockHeader, Blockchain, BlockchainImport, ValidatorInfo};

// ============================================================================
// Helpers
// ============================================================================

/// Build a minimal empty block chaining onto `parent` at the next height.
/// `extra_nonce` perturbs the timestamp so distinct calls yield distinct hashes.
fn build_next_block(parent: &Block, extra_nonce: u64) -> Block {
    let mut header = BlockHeader {
        version: 1,
        previous_hash: parent.hash().into(),
        data_helix_root: Hash::default().into(),
        timestamp: parent.timestamp() + 10 + extra_nonce,
        height: parent.header.height + 1,
        verification_helix_root: [0u8; 32],
        state_root: Hash::default().into(),
        bft_quorum_root: [0u8; 32],
        block_hash: Hash::default(),
    };
    header.block_hash = header.calculate_hash();
    Block::new(header, vec![])
}

/// A throwaway `ValidatorInfo` an attacker might try to smuggle in via the
/// import's `validator_registry` map.
fn attacker_validator() -> ValidatorInfo {
    ValidatorInfo {
        identity_id: "attacker_validator".to_string(),
        stake: 1_000_000_000,
        storage_provided: 100 * 1024 * 1024 * 1024,
        consensus_key: [0xAA; 2592],
        networking_key: vec![0xBB; 32],
        rewards_key: vec![0xCC; 32],
        network_address: "10.0.0.1:9000".to_string(),
        commission_rate: 5,
        status: "active".to_string(),
        registered_at: 1,
        last_activity: 1,
        blocks_validated: 0,
        slash_count: 0,
        admission_source: "forged".to_string(),
        governance_proposal_id: None,
        oracle_key_id: None,
    }
}

/// Produce a legitimate exported chain of `extra_blocks` blocks above genesis.
async fn legit_export(extra_blocks: usize) -> Result<Vec<u8>> {
    let mut node = Blockchain::new()?;
    for _ in 0..extra_blocks {
        let parent = node.latest_block().expect("chain has a tip").clone();
        let block = build_next_block(&parent, 0);
        node.add_block(block).await?;
    }
    node.export_chain()
}

// ============================================================================
// Tests
// ============================================================================

/// A fresh node MUST reject an import whose block 0 is not its own canonical
/// genesis — this is the chain-substitution defense.
#[tokio::test]
async fn fresh_node_rejects_forged_genesis() -> Result<()> {
    let export = legit_export(1).await?;
    let mut import: BlockchainImport =
        bincode::deserialize(&export).expect("legit export deserializes");

    // Forge block 0: bump the timestamp and recompute its hash so it is a
    // structurally valid block that simply is not the canonical genesis.
    let mut forged_header = import.blocks[0].header.clone();
    forged_header.timestamp += 1;
    forged_header.block_hash = forged_header.calculate_hash();
    import.blocks[0] = Block::new(forged_header, vec![]);

    let forged_bytes = bincode::serialize(&import).expect("re-serialize forged import");

    let mut node = Blockchain::new()?;
    let canonical_genesis = node.blocks[0].hash();

    let result = node.evaluate_and_merge_chain(forged_bytes).await;

    assert!(
        result.is_err(),
        "fresh node MUST reject a forged genesis — got Ok({:?})",
        result.ok()
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("genesis block mismatch"),
        "rejection must fire on the genesis-pin check, got: {err}"
    );

    // The rejected import must not have corrupted the node.
    assert_eq!(node.height, 0, "node height must be untouched after rejection");
    assert_eq!(node.blocks.len(), 1, "node must still hold only its genesis");
    assert_eq!(
        node.blocks[0].hash(),
        canonical_genesis,
        "node's genesis block must be untouched after rejection"
    );
    Ok(())
}

/// A fresh node MUST reject an import whose blocks do not form an unbroken
/// hash chain from the pinned genesis.
#[tokio::test]
async fn fresh_node_rejects_broken_continuity() -> Result<()> {
    let export = legit_export(2).await?;
    let mut import: BlockchainImport =
        bincode::deserialize(&export).expect("legit export deserializes");

    // Sever the link between block 0 and block 1.
    import.blocks[1].header.previous_hash = [0xFF; 32];

    let tampered = bincode::serialize(&import).expect("re-serialize tampered import");

    let mut node = Blockchain::new()?;
    let result = node.evaluate_and_merge_chain(tampered).await;

    assert!(
        result.is_err(),
        "fresh node MUST reject a chain with broken continuity — got Ok({:?})",
        result.ok()
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("breaks continuity"),
        "rejection must fire on the continuity check, got: {err}"
    );
    assert_eq!(node.height, 0, "node must be untouched after rejection");
    Ok(())
}

/// A fresh node MUST derive its state from the verified blocks and ignore the
/// import's precomputed state maps — an attacker cannot smuggle in a validator
/// set or balances by populating those maps.
#[tokio::test]
async fn fresh_node_ignores_forged_state_maps() -> Result<()> {
    let export = legit_export(1).await?;
    let mut import: BlockchainImport =
        bincode::deserialize(&export).expect("legit export deserializes");

    // The blocks stay legitimate; only the trusted-on-faith maps are forged.
    import
        .validator_registry
        .insert("attacker_validator".to_string(), attacker_validator());
    let forged_validator_count = import.validator_registry.len();
    assert!(forged_validator_count > 0, "test must actually inject a validator");

    let bytes = bincode::serialize(&import).expect("re-serialize import");

    let mut node = Blockchain::new()?;
    let result = node.evaluate_and_merge_chain(bytes).await;

    // The blocks are valid, so the import itself succeeds.
    assert!(
        result.is_ok(),
        "an import with legitimate blocks must still be adopted, got: {:?}",
        result.err()
    );
    assert_eq!(node.height, 1, "the one legitimate block must be applied");

    // …but the attacker's forged validator must NOT have leaked into state.
    assert!(
        !node.validator_exists("attacker_validator"),
        "forged validator from the import map must be ignored — state is \
         derived from blocks, not copied from the import"
    );
    Ok(())
}

/// Sanity baseline: a wholly legitimate export is still adopted by a fresh
/// node, confirming the verification path does not reject honest chains.
#[tokio::test]
async fn fresh_node_adopts_legitimate_chain() -> Result<()> {
    let export = legit_export(3).await?;

    let mut node = Blockchain::new()?;
    let result = node.evaluate_and_merge_chain(export).await?;

    assert!(
        matches!(result, lib_blockchain::ChainMergeResult::ImportedAdopted),
        "a legitimate 3-block chain must be adopted, got {result:?}"
    );
    assert_eq!(node.height, 3, "all three blocks must be applied");
    assert_eq!(node.blocks.len(), 4, "genesis + 3 blocks");
    Ok(())
}
