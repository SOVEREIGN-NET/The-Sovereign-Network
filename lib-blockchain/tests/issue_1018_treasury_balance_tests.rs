//! Issue #1018: Treasury Balance Query Tests
//!
//! Verifies that treasury balance queries use TokenContract::balance_of()
//! instead of the placeholder UTXO counting approach.

use lib_blockchain::Blockchain;
use lib_blockchain::contracts::TokenContract;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::transaction::WalletTransactionData;
use lib_blockchain::types::Hash;
use lib_crypto::types::keys::PublicKey;

/// Create a test public key with a specific ID byte
/// Uses PublicKey::new() to ensure consistent key_id computation
fn create_test_pubkey(id: u8) -> PublicKey {
    // PublicKey::new() computes key_id as hash_blake3(&dilithium_pk)
    // This ensures consistency between key creation and lookup
    PublicKey::new(vec![id; 32])
}

/// Setup a blockchain with treasury wallet and SOV token
fn setup_blockchain_with_treasury() -> (Blockchain, PublicKey) {
    let mut blockchain = Blockchain::default();

    // Create treasury public key using PublicKey::new() for consistent key_id
    let treasury_pubkey = create_test_pubkey(50);

    // Setup treasury wallet with correct struct fields
    let treasury_wallet = WalletTransactionData {
        wallet_id: Hash::new([50u8; 32]),
        wallet_type: "multisig".to_string(),
        wallet_name: "dao_treasury".to_string(),
        alias: Some("DAO Treasury".to_string()),
        public_key: treasury_pubkey.dilithium_pk.clone(),
        owner_identity_id: None,
        seed_commitment: Hash::new([0u8; 32]),
        created_at: 0,
        registration_fee: 0,
        capabilities: 0,
        initial_balance: 0,
    };

    // Register the treasury wallet
    blockchain
        .wallet_registry
        .insert("dao_treasury".to_string(), treasury_wallet);
    blockchain.dao_treasury_wallet_id = Some("dao_treasury".to_string());

    // Create SOV token with kernel authority
    let kernel_pubkey = create_test_pubkey(99);
    let sov_token = TokenContract::new_sov_with_kernel_authority(kernel_pubkey);
    let sov_token_id = generate_lib_token_id();

    // Register the SOV token
    blockchain.token_contracts.insert(sov_token_id, sov_token);

    (blockchain, treasury_pubkey)
}

#[test]
fn test_treasury_balance_uses_token_contract() {
    let (mut blockchain, treasury_pubkey) = setup_blockchain_with_treasury();

    // Initially treasury should have 0 balance
    let balance_before = blockchain.get_dao_treasury_balance().unwrap();
    assert_eq!(balance_before, 0, "Initial treasury balance should be 0");

    // Credit the treasury with SOV tokens
    let sov_token_id = generate_lib_token_id();
    let treasury_amount: u64 = 1_000_000;

    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.balances.insert(treasury_pubkey.clone(), treasury_amount);
    }

    // Query treasury balance - should reflect the credited amount
    let balance_after = blockchain.get_dao_treasury_balance().unwrap();
    assert_eq!(
        balance_after, treasury_amount,
        "Treasury balance should be {} from TokenContract, got {}",
        treasury_amount, balance_after
    );
}

#[test]
fn test_treasury_balance_not_placeholder() {
    // This test verifies we're not using the old placeholder (balance += 1 per UTXO)
    let (mut blockchain, treasury_pubkey) = setup_blockchain_with_treasury();

    // Credit treasury with specific amount
    let sov_token_id = generate_lib_token_id();
    let expected_amount: u64 = 5_555_555;

    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.balances.insert(treasury_pubkey.clone(), expected_amount);
    }

    // Query balance multiple times - should always return the exact amount
    for _ in 0..5 {
        let balance = blockchain.get_dao_treasury_balance().unwrap();
        assert_eq!(
            balance, expected_amount,
            "Balance should be exact amount {}, not placeholder count",
            expected_amount
        );
    }
}

#[test]
fn test_treasury_balance_returns_zero_without_token_contract() {
    let mut blockchain = Blockchain::default();

    // Create treasury public key
    let treasury_pubkey = create_test_pubkey(50);

    // Setup treasury wallet (but no SOV token contract)
    let treasury_wallet = WalletTransactionData {
        wallet_id: Hash::new([50u8; 32]),
        wallet_type: "multisig".to_string(),
        wallet_name: "dao_treasury".to_string(),
        alias: Some("DAO Treasury".to_string()),
        public_key: treasury_pubkey.dilithium_pk.clone(),
        owner_identity_id: None,
        seed_commitment: Hash::new([0u8; 32]),
        created_at: 0,
        registration_fee: 0,
        capabilities: 0,
        initial_balance: 0,
    };

    blockchain
        .wallet_registry
        .insert("dao_treasury".to_string(), treasury_wallet);
    blockchain.dao_treasury_wallet_id = Some("dao_treasury".to_string());

    // No SOV token contract registered - should return 0 (not panic)
    let balance = blockchain.get_dao_treasury_balance().unwrap();
    assert_eq!(
        balance, 0,
        "Treasury balance should be 0 when token contract not initialized"
    );
}

#[test]
fn test_treasury_balance_updates_after_transactions() {
    let (mut blockchain, treasury_pubkey) = setup_blockchain_with_treasury();
    let sov_token_id = generate_lib_token_id();

    // Initial balance
    let balance1 = blockchain.get_dao_treasury_balance().unwrap();
    assert_eq!(balance1, 0);

    // Add some tokens
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.balances.insert(treasury_pubkey.clone(), 100_000);
    }

    let balance2 = blockchain.get_dao_treasury_balance().unwrap();
    assert_eq!(balance2, 100_000);

    // Add more tokens
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.balances.insert(treasury_pubkey.clone(), 250_000);
    }

    let balance3 = blockchain.get_dao_treasury_balance().unwrap();
    assert_eq!(balance3, 250_000);

    // Reduce tokens (simulating spending)
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.balances.insert(treasury_pubkey.clone(), 150_000);
    }

    let balance4 = blockchain.get_dao_treasury_balance().unwrap();
    assert_eq!(balance4, 150_000);
}
