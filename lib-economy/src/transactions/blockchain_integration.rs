//! Blockchain Integration Traits for Economy Transactions
//!
//! This module provides trait-based conversion utilities for transforming
//! lib-economy transactions into blockchain-compatible format.
//!
//! Architecture Note: lib-economy is Layer 2, lib-blockchain is Layer 3.
//! Direct dependency would violate architecture, so we use traits that
//! lib-blockchain implements via the integration layer in zhtp.
//!
//! Signing uses the same canonical `hash_for_signature` field ordering as
//! `lib_blockchain::transaction::hashing::hash_for_signature`. Keep in sync
//! with that function when changing transaction wire format.

use crate::transactions::Transaction as EconomyTransaction;
use crate::types::TransactionType as EconomyTxType;
use crate::types::TransactionTypeExt;
use anyhow::Result;
use blake3::Hasher as Blake3Hasher;
use lib_crypto::types::keys::PublicKey as CryptoPublicKey;
use serde::Serialize;

/// Mirror of lib-blockchain `TX_VERSION_V8`.
const BLOCKCHAIN_TX_VERSION_V8: u32 = 8;

/// Economy transaction data needed for blockchain conversion
/// This struct provides the necessary data without importing blockchain types
#[derive(Debug, Clone)]
pub struct BlockchainTransactionData {
    pub version: u32,
    pub chain_id: u32,
    pub tx_type_name: String,
    pub inputs: Vec<u8>, // Serialized inputs (empty for system transactions)
    pub outputs: Vec<BlockchainOutput>,
    pub fee: u64,
    pub signature_data: Vec<u8>,
    pub public_key: Vec<u8>,
    pub timestamp: u64,
    pub memo: Vec<u8>,
}

/// Output data for blockchain transactions
#[derive(Debug, Clone)]
pub struct BlockchainOutput {
    pub commitment: [u8; 32],
    pub note: [u8; 32],
    pub recipient: Vec<u8>,
}

/// Mirror of lib-blockchain `TransactionType` for canonical signing-hash serialization.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[repr(u8)]
enum BlockchainMirrorTxType {
    Transfer = 0,
}

/// Mirror of lib-blockchain `TransactionPayload::None` variant.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
enum BlockchainMirrorPayload {
    None,
}

/// Mirror of lib-blockchain `Hash` tuple struct for bincode compatibility.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct BlockchainMirrorHash([u8; 32]);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct BlockchainMirrorOutput {
    commitment: BlockchainMirrorHash,
    note: BlockchainMirrorHash,
    recipient: CryptoPublicKey,
    merkle_leaf: BlockchainMirrorHash,
}

/// Compute the canonical blockchain signing hash for a system transfer skeleton.
///
/// MUST match `lib_blockchain::transaction::hashing::hash_for_signature`.
fn hash_for_signature_mirror(
    version: u32,
    chain_id: u8,
    transaction_type: BlockchainMirrorTxType,
    outputs: &[BlockchainMirrorOutput],
    fee: u64,
    memo: &[u8],
) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();

    hasher.update(&version.to_le_bytes());
    hasher.update(&[chain_id]);

    let type_bytes =
        bincode::serialize(&transaction_type).expect("TransactionType serialization should never fail");
    hasher.update(&type_bytes);

    hasher.update(&(0u64).to_le_bytes()); // empty inputs

    let mut sorted_outputs = outputs.to_vec();
    sorted_outputs.sort_by_key(|output| output.commitment.0);
    hasher.update(&(sorted_outputs.len() as u64).to_le_bytes());
    for output in &sorted_outputs {
        let output_bytes =
            bincode::serialize(output).expect("TransactionOutput serialization should never fail");
        hasher.update(&output_bytes);
    }

    hasher.update(&fee.to_le_bytes());
    hasher.update(&(memo.len() as u64).to_le_bytes());
    hasher.update(memo);

    let payload = BlockchainMirrorPayload::None;
    let payload_bytes =
        bincode::serialize(&payload).expect("TransactionPayload serialization should never fail");
    hasher.update(&(payload_bytes.len() as u64).to_le_bytes());
    hasher.update(&payload_bytes);

    *hasher.finalize().as_bytes()
}

/// Convert economics transaction to blockchain-compatible data
///
/// This creates a data structure that lib-blockchain can convert into its Transaction type.
/// System transactions (UBI, rewards) don't spend UTXOs - they create new money from protocol rules.
///
/// # Arguments
/// * `economics_tx` - The economy transaction to convert
/// * `chain_id` - The blockchain chain ID
/// * `system_keypair` - Keypair for signing system transactions
pub fn to_blockchain_data(
    economics_tx: &EconomyTransaction,
    chain_id: u32,
    system_keypair: &lib_crypto::KeyPair,
) -> Result<BlockchainTransactionData> {
    use lib_crypto::{hashing::hash_blake3, sign_message};

    let inputs = Vec::new();

    let commitment = hash_blake3(format!("commitment_{}", economics_tx.amount).as_bytes());
    let note = hash_blake3(format!("note_{}", hex::encode(economics_tx.tx_id)).as_bytes());
    let recipient_pk = CryptoPublicKey::new([0u8; 2592]);

    let outputs = vec![BlockchainOutput {
        commitment,
        note,
        recipient: recipient_pk.dilithium_pk.to_vec(),
    }];

    let mirror_outputs = vec![BlockchainMirrorOutput {
        commitment: BlockchainMirrorHash(commitment),
        note: BlockchainMirrorHash(note),
        recipient: recipient_pk.clone(),
        merkle_leaf: BlockchainMirrorHash([0u8; 32]),
    }];

    let tx_type_name = match economics_tx.tx_type {
        EconomyTxType::UbiDistribution => "Transfer",
        EconomyTxType::Reward => "Transfer",
        EconomyTxType::Payment => "Transfer",
        _ => "Transfer",
    }
    .to_string();

    let memo = format!(
        "System TX: {} {} SOV to {:?}",
        economics_tx.tx_type.description(),
        economics_tx.amount,
        economics_tx.to
    )
    .into_bytes();

    let chain_id_u8: u8 = chain_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("chain_id {} exceeds u8 wire format", chain_id))?;
    let signing_hash = hash_for_signature_mirror(
        BLOCKCHAIN_TX_VERSION_V8,
        chain_id_u8,
        BlockchainMirrorTxType::Transfer,
        &mirror_outputs,
        0,
        &memo,
    );

    let signature = sign_message(system_keypair, &signing_hash)?;

    Ok(BlockchainTransactionData {
        version: BLOCKCHAIN_TX_VERSION_V8,
        chain_id,
        tx_type_name,
        inputs,
        outputs,
        fee: 0,
        signature_data: signature.signature,
        public_key: system_keypair.public_key.dilithium_pk.to_vec(),
        timestamp: economics_tx.timestamp,
        memo,
    })
}

/// Create UBI distribution as blockchain-compatible data
///
/// # Arguments
/// * `citizen_id` - Identity of the citizen receiving UBI
/// * `amount` - Amount of SOV tokens to distribute
/// * `chain_id` - The blockchain chain ID
/// * `system_keypair` - Keypair for signing system transactions
pub fn create_ubi_blockchain_data(
    citizen_id: crate::wasm::IdentityId,
    amount: u128,
    chain_id: u32,
    system_keypair: &lib_crypto::KeyPair,
) -> Result<BlockchainTransactionData> {
    use crate::transactions::creation::create_ubi_distributions;

    let ubi_distributions = create_ubi_distributions(&[(citizen_id, amount)])?;

    if ubi_distributions.is_empty() {
        return Err(anyhow::anyhow!("No UBI distributions created"));
    }

    let economics_tx = &ubi_distributions[0];
    to_blockchain_data(economics_tx, chain_id, system_keypair)
}

/// Create reward as blockchain-compatible data
///
/// # Arguments
/// * `node_id` - The 32-byte unique identifier of the node receiving the reward
/// * `reward_amount` - The amount of SOV tokens to award
/// * `chain_id` - The blockchain chain ID
/// * `system_keypair` - Keypair for signing system transactions
pub fn create_reward_blockchain_data(
    node_id: [u8; 32],
    reward_amount: u128,
    chain_id: u32,
    system_keypair: &lib_crypto::KeyPair,
) -> Result<BlockchainTransactionData> {
    use crate::transactions::creation::create_reward_transaction;

    let reward_tx = create_reward_transaction(node_id, reward_amount)?;

    to_blockchain_data(&reward_tx, chain_id, system_keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubi_blockchain_data_creation() {
        let keypair = lib_crypto::generate_keypair().unwrap();
        let citizen_id = crate::wasm::IdentityId([1u8; 32]);

        let result = create_ubi_blockchain_data(
            citizen_id, 1000, 1, // chain_id
            &keypair,
        );

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.chain_id, 1);
        assert_eq!(data.fee, 0);
        assert!(data.inputs.is_empty());
        assert_eq!(data.outputs.len(), 1);
        assert_eq!(data.tx_type_name, "Transfer");
    }

    #[test]
    fn test_reward_blockchain_data_creation() {
        let keypair = lib_crypto::generate_keypair().unwrap();
        let node_id = [2u8; 32];

        let result = create_reward_blockchain_data(
            node_id, 500, 1, // chain_id
            &keypair,
        );

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.chain_id, 1);
        assert_eq!(data.fee, 0);
        assert!(data.inputs.is_empty());
        assert_eq!(data.outputs.len(), 1);
    }

    #[test]
    fn hash_for_signature_mirror_is_deterministic_with_sorted_outputs() {
        let pk = CryptoPublicKey::new([7u8; 2592]);
        let outputs = vec![
            BlockchainMirrorOutput {
                commitment: BlockchainMirrorHash([2u8; 32]),
                note: BlockchainMirrorHash([1u8; 32]),
                recipient: pk.clone(),
                merkle_leaf: BlockchainMirrorHash([0u8; 32]),
            },
            BlockchainMirrorOutput {
                commitment: BlockchainMirrorHash([1u8; 32]),
                note: BlockchainMirrorHash([2u8; 32]),
                recipient: pk,
                merkle_leaf: BlockchainMirrorHash([0u8; 32]),
            },
        ];
        let memo = b"determinism-test";
        let h1 = hash_for_signature_mirror(8, 0x03, BlockchainMirrorTxType::Transfer, &outputs, 0, memo);
        let h2 = hash_for_signature_mirror(8, 0x03, BlockchainMirrorTxType::Transfer, &outputs, 0, memo);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_blockchain_data_signatures() {
        let keypair = lib_crypto::generate_keypair().unwrap();
        let node_id = [3u8; 32];

        let data = create_reward_blockchain_data(node_id, 250, 1, &keypair).unwrap();

        assert!(!data.signature_data.is_empty());
        assert!(!data.public_key.is_empty());
        assert!(data.timestamp > 0);
        assert_eq!(data.public_key, keypair.public_key.dilithium_pk);
    }
}