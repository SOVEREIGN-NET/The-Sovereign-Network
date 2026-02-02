//! Issue #1016: Fee Auto-Deduction Tests
//!
//! Verifies that transaction fees are actually deducted from sender balances
//! during block processing, not just declared in the transaction.

use lib_blockchain::Blockchain;
use lib_blockchain::contracts::TokenContract;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::transaction::{Transaction, TransactionInput, TransactionOutput};
use lib_blockchain::types::TransactionType;
use lib_blockchain::types::{Hash, Difficulty};
use lib_blockchain::block::{Block, BlockHeader};
use lib_crypto::types::keys::PublicKey;
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

/// Create a test public key with a specific ID byte
/// Uses PublicKey::new() to ensure consistent key_id computation
fn create_test_pubkey(id: u8) -> PublicKey {
    let dilithium_pk = vec![id; 32];
    PublicKey::new(dilithium_pk)
}

/// Create a test signature with the given public key
fn create_test_signature(pubkey: &PublicKey) -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: pubkey.clone(),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

/// Create a minimal transfer transaction with specified fee
fn create_transfer_tx(sender: &PublicKey, fee: u64, nullifier_id: u8) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 0x03, // development
        transaction_type: TransactionType::Transfer,
        inputs: vec![TransactionInput {
            previous_output: Hash::new([1u8; 32]),
            output_index: 0,
            nullifier: Hash::new([nullifier_id; 32]),
            zk_proof: lib_blockchain::integration::zk_integration::ZkTransactionProof::default(),
        }],
        outputs: vec![TransactionOutput {
            commitment: Hash::new([3u8; 32]),
            note: Hash::new([4u8; 32]),
            recipient: create_test_pubkey(2),
        }],
        fee,
        signature: create_test_signature(sender),
        memo: b"test transfer".to_vec(),
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        governance_config_data: None,
    }
}

/// Create a test block with the given transactions
fn create_test_block(height: u64, transactions: Vec<Transaction>) -> Block {
    let header = BlockHeader {
        version: 1,
        height,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        previous_block_hash: Hash::zero(),
        merkle_root: Hash::zero(),
        block_hash: Hash::zero(),
        nonce: 0,
        difficulty: Difficulty::from_bits(0),
        cumulative_difficulty: Difficulty::from_bits(0),
        transaction_count: transactions.len() as u32,
        block_size: 0,
        fee_model_version: 2, // Phase 2+ uses v2
    };
    Block::new(header, transactions)
}

#[test]
fn test_fee_deduction_reduces_sender_balance() {
    // Setup: Create blockchain with SOV token
    let mut blockchain = Blockchain::default();

    // Create SOV token with kernel authority
    let kernel_pubkey = create_test_pubkey(99);
    let sov_token = TokenContract::new_sov_with_kernel_authority(kernel_pubkey);
    let sov_token_id = generate_lib_token_id();

    // Register the SOV token
    blockchain.token_contracts.insert(sov_token_id, sov_token);

    // Setup sender with initial balance
    let sender = create_test_pubkey(1);
    let initial_balance: u64 = 10_000;
    let fee: u64 = 100;

    // Credit initial balance to sender
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.balances.insert(sender.clone(), initial_balance);
    }

    // Verify initial balance
    let balance_before = blockchain.token_contracts
        .get(&sov_token_id)
        .map(|t| t.balance_of(&sender))
        .unwrap_or(0);
    assert_eq!(balance_before, initial_balance);

    // Create a transfer transaction with fee
    let tx = create_transfer_tx(&sender, fee, 10);

    // Create a minimal block with the transaction
    let block = create_test_block(1, vec![tx]);

    // Call fee deduction directly (normally called by process_and_commit_block)
    let fees_collected = blockchain.deduct_transaction_fees(&block).unwrap();

    // Verify: fee was collected
    assert_eq!(fees_collected, fee, "Expected {} fee collected, got {}", fee, fees_collected);

    // Verify: sender balance was reduced
    let balance_after = blockchain.token_contracts
        .get(&sov_token_id)
        .map(|t| t.balance_of(&sender))
        .unwrap_or(0);

    assert_eq!(
        balance_after,
        initial_balance - fee,
        "Expected balance {} after fee deduction, got {}",
        initial_balance - fee,
        balance_after
    );
}

#[test]
fn test_fee_deduction_skips_system_transactions() {
    // Setup: Create blockchain with SOV token
    let mut blockchain = Blockchain::default();

    // Create SOV token with kernel authority
    let kernel_pubkey = create_test_pubkey(99);
    let sov_token = TokenContract::new_sov_with_kernel_authority(kernel_pubkey);
    let sov_token_id = generate_lib_token_id();

    // Register the SOV token
    blockchain.token_contracts.insert(sov_token_id, sov_token);

    // Create a system transaction (empty inputs = UBI distribution)
    let sender = create_test_pubkey(1);
    let mut system_tx = create_transfer_tx(&sender, 0, 20);
    system_tx.inputs.clear(); // Empty inputs = system transaction

    // Create a minimal block with the system transaction
    let block = create_test_block(1, vec![system_tx]);

    // Call fee deduction
    let fees_collected = blockchain.deduct_transaction_fees(&block).unwrap();

    // Verify: no fees collected from system transaction
    assert_eq!(fees_collected, 0, "System transactions should not have fees deducted");
}

#[test]
fn test_fee_deduction_handles_insufficient_balance() {
    // Setup: Create blockchain with SOV token
    let mut blockchain = Blockchain::default();

    // Create SOV token with kernel authority
    let kernel_pubkey = create_test_pubkey(99);
    let sov_token = TokenContract::new_sov_with_kernel_authority(kernel_pubkey);
    let sov_token_id = generate_lib_token_id();

    // Register the SOV token
    blockchain.token_contracts.insert(sov_token_id, sov_token);

    // Setup sender with low balance (less than fee)
    let sender = create_test_pubkey(1);
    let initial_balance: u64 = 50;
    let fee: u64 = 100; // More than balance

    // Credit low balance to sender
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.balances.insert(sender.clone(), initial_balance);
    }

    // Create a transfer transaction with fee higher than balance
    let tx = create_transfer_tx(&sender, fee, 30);

    // Create a minimal block with the transaction
    let block = create_test_block(1, vec![tx]);

    // Call fee deduction - should not panic, just skip the tx
    let fees_collected = blockchain.deduct_transaction_fees(&block).unwrap();

    // Verify: no fees collected (insufficient balance)
    assert_eq!(fees_collected, 0, "Should not collect fees when sender has insufficient balance");

    // Verify: sender balance unchanged
    let balance_after = blockchain.token_contracts
        .get(&sov_token_id)
        .map(|t| t.balance_of(&sender))
        .unwrap_or(0);

    assert_eq!(
        balance_after,
        initial_balance,
        "Balance should be unchanged when fee deduction fails"
    );
}

#[test]
fn test_fee_deduction_accumulates_multiple_transactions() {
    // Setup: Create blockchain with SOV token
    let mut blockchain = Blockchain::default();

    // Create SOV token with kernel authority
    let kernel_pubkey = create_test_pubkey(99);
    let sov_token = TokenContract::new_sov_with_kernel_authority(kernel_pubkey);
    let sov_token_id = generate_lib_token_id();

    // Register the SOV token
    blockchain.token_contracts.insert(sov_token_id, sov_token);

    // Setup multiple senders with balances
    let sender1 = create_test_pubkey(1);
    let sender2 = create_test_pubkey(2);
    let sender3 = create_test_pubkey(3);
    let initial_balance: u64 = 10_000;

    // Credit initial balances
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.balances.insert(sender1.clone(), initial_balance);
        token.balances.insert(sender2.clone(), initial_balance);
        token.balances.insert(sender3.clone(), initial_balance);
    }

    // Create transactions with different fees and unique nullifiers
    let fee1: u64 = 100;
    let fee2: u64 = 200;
    let fee3: u64 = 300;

    let tx1 = create_transfer_tx(&sender1, fee1, 41);
    let tx2 = create_transfer_tx(&sender2, fee2, 42);
    let tx3 = create_transfer_tx(&sender3, fee3, 43);

    // Create a block with multiple transactions
    let block = create_test_block(1, vec![tx1, tx2, tx3]);

    // Call fee deduction
    let fees_collected = blockchain.deduct_transaction_fees(&block).unwrap();

    // Verify: total fees collected
    let expected_total = fee1 + fee2 + fee3;
    assert_eq!(
        fees_collected,
        expected_total,
        "Expected {} total fees, got {}",
        expected_total,
        fees_collected
    );

    // Verify: each sender's balance was reduced correctly
    let token = blockchain.token_contracts.get(&sov_token_id).unwrap();
    assert_eq!(token.balance_of(&sender1), initial_balance - fee1);
    assert_eq!(token.balance_of(&sender2), initial_balance - fee2);
    assert_eq!(token.balance_of(&sender3), initial_balance - fee3);
}
