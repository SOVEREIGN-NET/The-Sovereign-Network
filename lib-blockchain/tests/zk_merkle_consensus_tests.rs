//! Dual-node Merkle-root consensus test for ZK-enabled transactions.
//!
//! Verifies that two independent nodes compute the exact same UTXO Merkle
//! root after applying a block containing real ZK transaction proofs and
//! merkle_leaf outputs.

use anyhow::Result;

mod common;

use lib_blockchain::{
    integration::crypto_integration::SignatureAlgorithm,
    storage::{BlockchainStore, OutPoint, SledStore},
    transaction::{Transaction, TransactionInput, TransactionOutput},
    Block, BlockHeader, Blockchain, Hash, TransactionType,
};
use lib_proofs::transaction::ZkTransactionProof;
use std::sync::Arc;

fn test_public_key(seed: u8) -> lib_crypto::PublicKey { common::crypto_fixtures::seeded_public_key(seed) }
fn test_signature(seed: u8) -> lib_crypto::Signature { common::crypto_fixtures::seeded_signature(seed) }
fn build_block_with_transactions(parent: &Block, txs: Vec<Transaction>) -> Block { common::block_builders::child_block(parent, txs) }

fn create_output_with_leaf(seed: u8, merkle_leaf: [u8; 32]) -> TransactionOutput {
    TransactionOutput {
        commitment: Hash::from([seed; 32]),
        note: Hash::default(),
        recipient: test_public_key(seed),
        merkle_leaf: Hash::from(merkle_leaf),
    }
}

fn create_output_no_leaf(seed: u8) -> TransactionOutput {
    TransactionOutput {
        commitment: Hash::from([seed; 32]),
        note: Hash::default(),
        recipient: test_public_key(seed),
        merkle_leaf: Hash::default(),
    }
}

/// Mine a block with easy difficulty for tests.
fn mine_block(block: Block) -> Block {
    use lib_blockchain::block::creation::mine_block;
    let _difficulty = lib_blockchain::Difficulty::from_bits(0x1fffffff);
    mine_block(block, 1_000_000).expect("mining should succeed with easy difficulty")
}

fn create_blockchain_with_temp_store() -> Result<(Blockchain, tempfile::TempDir)> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);
    let bc = Blockchain::new_with_store(store.clone())?;

    // Seed the store with the genesis block so the executor expects height 1 next.
    let genesis = bc.blocks[0].clone();
    store.begin_block(0)?;
    store.append_block(&genesis)?;
    store.commit_block()?;

    Ok((bc, tmp))
}

#[tokio::test]
async fn test_dual_node_merkle_root_consensus_with_real_zk_proofs() -> Result<()> {
    // Create two independent nodes with isolated storage.
    // Blockchain::new() is deterministic (embedded genesis.toml), so both nodes
    // start from an identical genesis block and state.
    let (mut node_a, _tmp_a) = create_blockchain_with_temp_store()?;
    let (mut node_b, _tmp_b) = create_blockchain_with_temp_store()?;

    // Build a coinbase funding transaction that creates spendable UTXOs
    // with merkle_leaf commitments. Coinbase is the only tx type allowed
    // to have empty inputs.
    let funding_tx = Transaction {
        version: 8,
        chain_id: 0x03,
        transaction_type: TransactionType::Coinbase,
        inputs: vec![],
        outputs: vec![
            create_output_with_leaf(1, [1u8; 32]),
            create_output_with_leaf(2, [2u8; 32]),
        ],
        fee: 0,
        signature: test_signature(1),
        memo: b"fund".to_vec(),
        payload: lib_blockchain::transaction::TransactionPayload::None,
    };

    let genesis = node_a.latest_block().expect("genesis exists").clone();
    let block1 = mine_block(build_block_with_transactions(&genesis, vec![funding_tx.clone()]));
    node_a.add_block(block1.clone()).await?;
    node_b.add_block(block1).await?;

    // Now spend one of the funded UTXOs with a REAL ZK transaction proof.
    let tx_hash = funding_tx.hash();

    let zk_proof = ZkTransactionProof::prove_transaction(
        1000,                 // sender_balance
        0,                    // receiver_balance (unused in unified proof)
        100,                  // amount
        10,                   // fee
        [42u8; 32],           // sender_blinding
        [0u8; 32],            // receiver_blinding
        tx_hash.as_array(),   // nullifier
    )?;

    assert!(
        !zk_proof.has_empty_proofs(),
        "Expected a non-empty real ZK proof"
    );

    let spend_input = TransactionInput {
        previous_output: tx_hash,
        output_index: 0,
        nullifier: Hash::from(tx_hash.as_array()),
        zk_proof,
    };

    let spend_tx = Transaction {
        version: 8,
        chain_id: 0x03,
        transaction_type: TransactionType::Transfer,
        inputs: vec![spend_input],
        outputs: vec![
            create_output_with_leaf(3, [3u8; 32]),
            create_output_no_leaf(4),
        ],
        fee: 10_000,
        signature: test_signature(2),
        memo: b"spend".to_vec(),
        payload: lib_blockchain::transaction::TransactionPayload::None,
    };

    let parent = node_a.latest_block().expect("block1 exists").clone();
    let block2 = mine_block(build_block_with_transactions(&parent, vec![spend_tx.clone()]));

    // Apply the same block to both nodes.
    node_a.add_block(block2.clone()).await?;
    node_b.add_block(block2).await?;

    // Verify both nodes reached the same height and tip hash.
    assert_eq!(node_a.height, node_b.height);
    assert_eq!(
        node_a.latest_block().unwrap().hash(),
        node_b.latest_block().unwrap().hash()
    );

    // Verify both nodes computed the exact same UTXO Merkle root.
    let store_a = node_a.store.as_ref().expect("node_a has store");
    let store_b = node_b.store.as_ref().expect("node_b has store");

    let root_a = store_a.get_utxo_merkle_root()?;
    let root_b = store_b.get_utxo_merkle_root()?;
    assert_eq!(
        root_a, root_b,
        "UTXO Merkle roots diverged across nodes after applying identical block with real ZK proofs"
    );

    // Verify both nodes have the same set of tracked UTXO Merkle leaves.
    let outpoint = OutPoint::new(lib_blockchain::storage::TxHash::new(tx_hash.as_array()), 0);
    let leaf_idx_a = store_a.get_utxo_merkle_leaf_index(&outpoint)?;
    let leaf_idx_b = store_b.get_utxo_merkle_leaf_index(&outpoint)?;
    assert_eq!(leaf_idx_a, leaf_idx_b);

    Ok(())
}
