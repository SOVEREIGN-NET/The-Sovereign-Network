//! Shared block-construction helpers for lib-blockchain integration tests.
//!
//! Provides deterministic genesis and height-N block factories so test files
//! do not each need their own copy of the same BlockHeader boilerplate.

use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::integration::zk_integration::ZkTransactionProof;
use lib_blockchain::transaction::{Transaction, TransactionInput, TransactionOutput, TransactionPayload};
use lib_blockchain::types::{transaction_type::TransactionType, Hash};
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

/// A canonical genesis block (height 0) with a recognisable first byte (0x01).
pub fn genesis_block() -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = 0x01;
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_hash: Hash::default().into(),
        data_helix_root: Hash::default().into(),
        state_root: Hash::default().into(),
        timestamp: 1_000,
        height: 0,
        verification_helix_root: [0u8; 32],
        bft_quorum_root: [0u8; 32],
        block_hash,
    };
    Block::new(header, vec![])
}

/// A block at the given height with `prev_hash` as parent and no transactions.
pub fn block_at_height(height: u64, prev_hash: Hash) -> Block {
    block_at_height_with_txs(height, prev_hash, vec![])
}

/// A block at the given height with `prev_hash` and an explicit transaction set.
/// The block hash encodes height in bytes 0–7 and tx count in byte 8.
pub fn block_at_height_with_txs(height: u64, prev_hash: Hash, txs: Vec<Transaction>) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
    hash_bytes[8] = txs.len() as u8;
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_hash: prev_hash.into(),
        data_helix_root: Hash::default().into(),
        state_root: Hash::default().into(),
        timestamp: 1_000 + height * 600,
        height,
        verification_helix_root: [0u8; 32],
        bft_quorum_root: [0u8; 32],
        block_hash,
    };
    Block::new(header, txs)
}

/// Build a child block from a parent reference, computing a Merkle root for txs.
/// Used by dual-node Merkle-root consensus tests.
pub fn child_block(parent: &Block, txs: Vec<Transaction>) -> Block {
    let merkle_root =
        lib_blockchain::transaction::hashing::calculate_transaction_merkle_root(&txs);
    let header = BlockHeader {
        version: 1,
        previous_hash: parent.hash().into(),
        data_helix_root: merkle_root.as_array(),
        state_root: Hash::default().into(),
        timestamp: parent.timestamp() + 10,
        height: parent.height() + 1,
        verification_helix_root: [0u8; 32],
        bft_quorum_root: [0u8; 32],
        block_hash: Hash::default(),
    };
    Block::new(header, txs)
}

/// A minimal `TransactionInput` with all-default fields.
pub fn test_input() -> TransactionInput {
    TransactionInput::new(
        Hash::default(),
        0,
        Hash::default(),
        ZkTransactionProof::default(),
    )
}

/// A minimal `TransactionOutput` with a seeded recipient key.
pub fn test_output() -> TransactionOutput {
    TransactionOutput::new(
        Hash::default(),
        Hash::default(),
        super::crypto_fixtures::seeded_public_key(1),
    )
}

/// A `Transaction` of the given type and fee, seeded by `index`.
pub fn test_transaction_at(tx_type: TransactionType, fee: u64, index: u32) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 1,
        transaction_type: tx_type,
        inputs: vec![],
        outputs: vec![TransactionOutput {
            commitment: Hash::default(),
            note: Hash::default(),
            recipient: super::crypto_fixtures::seeded_public_key(index as u8),
            merkle_leaf: Hash::default(),
        }],
        fee,
        signature: Signature {
            signature: format!("sig_{}", index).as_bytes().to_vec(),
            public_key: super::crypto_fixtures::seeded_public_key(index as u8),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        },
        memo: format!("test_tx_{}", index).as_bytes().to_vec(),
        payload: TransactionPayload::None,
    }
}
