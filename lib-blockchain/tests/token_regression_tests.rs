//! Token System Regression Tests (#1126)
//!
//! Exercises every token operation through the same code paths real clients use:
//! create, mint, transfer (SOV wallet-to-wallet + custom token), burn, balance queries.
//!
//! These tests call the blockchain processing functions directly to verify state changes,
//! serving as a safety net for token system refactoring.

use lib_blockchain::Blockchain;
use lib_blockchain::contracts::TokenContract;
use lib_blockchain::contracts::utils::{generate_lib_token_id, generate_custom_token_id};
use lib_blockchain::transaction::{
    Transaction, TransactionInput, TransactionOutput,
    TokenTransferData, TokenMintData, WalletTransactionData,
};
use lib_blockchain::types::{TransactionType, Hash, Difficulty};
use lib_blockchain::types::contract_call::ContractCall;
use lib_blockchain::block::{Block, BlockHeader};
use lib_crypto::types::keys::PublicKey;
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

// ============================================================================
// Test helpers
// ============================================================================

/// Create a test public key with deterministic key_id from an id byte.
fn test_pubkey(id: u8) -> PublicKey {
    PublicKey::new(vec![id; 32])
}

/// Create a test signature with the given public key.
fn test_signature(pubkey: &PublicKey) -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: pubkey.clone(),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 1_700_000_000,
    }
}

/// Create a test block at the given height with transactions.
fn test_block(height: u64, transactions: Vec<Transaction>) -> Block {
    let header = BlockHeader {
        version: 1,
        height,
        timestamp: 1_700_000_000 + height,
        previous_block_hash: Hash::zero(),
        merkle_root: Hash::zero(),
        state_root: Hash::default(),
        block_hash: Hash::zero(),
        nonce: 0,
        difficulty: Difficulty::minimum(),
        cumulative_difficulty: Difficulty::minimum(),
        transaction_count: transactions.len() as u32,
        block_size: 0,
        fee_model_version: 2,
    };
    Block::new(header, transactions)
}

/// Create a wallet registration transaction.
fn wallet_registration_tx(
    wallet_id: [u8; 32],
    owner_pubkey: &PublicKey,
    initial_balance: u64,
) -> Transaction {
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::WalletRegistration,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(owner_pubkey),
        memo: Vec::new(),
        identity_data: None,
        wallet_data: Some(WalletTransactionData {
            wallet_id: Hash::new(wallet_id),
            wallet_type: "Primary".to_string(),
            wallet_name: format!("Wallet-{}", hex::encode(&wallet_id[..4])),
            alias: None,
            public_key: owner_pubkey.dilithium_pk.clone(),
            owner_identity_id: None,
            seed_commitment: Hash::zero(),
            created_at: 1_700_000_000,
            registration_fee: 0,
            capabilities: 0,
            initial_balance,
        }),
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
    }
}

/// Create a TokenTransfer transaction (for SOV wallet-to-wallet or custom token key-to-key).
fn token_transfer_tx(
    sender: &PublicKey,
    token_id: [u8; 32],
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    nullifier_id: u8,
) -> Transaction {
    token_transfer_tx_with_nonce(sender, token_id, from, to, amount, nullifier_id, 0)
}

/// Create a TokenTransfer transaction with explicit nonce.
fn token_transfer_tx_with_nonce(
    sender: &PublicKey,
    token_id: [u8; 32],
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    nullifier_id: u8,
    nonce: u64,
) -> Transaction {
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenTransfer,
        inputs: vec![TransactionInput {
            previous_output: Hash::new([nullifier_id; 32]),
            output_index: 0,
            nullifier: Hash::new([nullifier_id; 32]),
            zk_proof: lib_blockchain::integration::zk_integration::ZkTransactionProof::default(),
        }],
        outputs: vec![TransactionOutput {
            commitment: Hash::new([3u8; 32]),
            note: Hash::new([4u8; 32]),
            recipient: test_pubkey(0),
        }],
        fee: 0,
        signature: test_signature(sender),
        memo: Vec::new(),
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: Some(TokenTransferData {
            token_id,
            from,
            to,
            amount: amount as u128,
            nonce,
        }),
        token_mint_data: None,
        governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
    }
}

/// Create a TokenMint transaction (v2).
fn token_mint_tx(
    signer: &PublicKey,
    token_id: [u8; 32],
    to: [u8; 32],
    amount: u64,
) -> Transaction {
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenMint,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(signer),
        memo: Vec::new(),
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: Some(TokenMintData {
            token_id,
            to,
            amount: amount as u128,
        }),
        governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
    }
}

/// Create a ContractExecution transaction with a token contract call.
fn contract_execution_tx(
    signer: &PublicKey,
    method: &str,
    params: Vec<u8>,
) -> Transaction {
    let call = ContractCall::token_call(method.to_string(), params);
    let sig = test_signature(signer);
    let call_data = bincode::serialize(&(&call, &sig)).expect("serialize call+sig");
    let mut memo = b"ZHTP".to_vec();
    memo.extend_from_slice(&call_data);

    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(signer),
        memo,
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
    }
}

/// Register a wallet directly in the blockchain state (bypasses block processing).
fn register_wallet(blockchain: &mut Blockchain, wallet_id: [u8; 32], owner: &PublicKey, initial_balance: u64) {
    let wallet_id_hex = hex::encode(wallet_id);
    blockchain.wallet_registry.insert(wallet_id_hex.clone(), WalletTransactionData {
        wallet_id: Hash::new(wallet_id),
        wallet_type: "Primary".to_string(),
        wallet_name: format!("Wallet-{}", hex::encode(&wallet_id[..4])),
        alias: None,
        public_key: owner.dilithium_pk.clone(),
        owner_identity_id: None,
        seed_commitment: Hash::zero(),
        created_at: 1_700_000_000,
        registration_fee: 0,
        capabilities: 0,
        initial_balance,
    });
    blockchain.wallet_blocks.insert(wallet_id_hex, 0);
}

/// Register an identity directly in the blockchain state.
fn register_identity(blockchain: &mut Blockchain, identity_id: &str, pubkey: &PublicKey) {
    use lib_blockchain::transaction::IdentityTransactionData;
    blockchain.identity_registry.insert(identity_id.to_string(), IdentityTransactionData {
        did: identity_id.to_string(),
        display_name: format!("Test-{}", &identity_id[..8.min(identity_id.len())]),
        public_key: pubkey.dilithium_pk.clone(),
        ownership_proof: vec![],
        identity_type: "human".to_string(),
        did_document_hash: Hash::zero(),
        created_at: 1_700_000_000,
        registration_fee: 0,
        dao_fee: 0,
        controlled_nodes: vec![],
        owned_wallets: vec![],
    });
    blockchain.identity_blocks.insert(identity_id.to_string(), 0);
}

/// Synthetic PublicKey keyed by wallet_id for SOV balance lookups.
fn wallet_key(wallet_id: &[u8; 32]) -> PublicKey {
    PublicKey {
        dilithium_pk: Vec::new(),
        kyber_pk: Vec::new(),
        key_id: *wallet_id,
    }
}

/// Insert the native SOV token contract into the blockchain (replaces private ensure_sov_token_contract).
fn insert_sov_token(blockchain: &mut Blockchain) {
    let sov_token_id = generate_lib_token_id();
    if !blockchain.token_contracts.contains_key(&sov_token_id) {
        let sov_token = TokenContract::new_sov_native();
        blockchain.token_contracts.insert(sov_token_id, sov_token);
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test 1: Create a custom token via ContractExecution and verify it appears in token_contracts.
#[test]
fn test_create_custom_token() {
    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);

    // Build create_custom_token params matching the struct in execute_token_contract_call
    #[derive(serde::Serialize)]
    struct CreateTokenParams {
        name: String,
        symbol: String,
        initial_supply: u64,
        decimals: u8,
    }

    let params = CreateTokenParams {
        name: "CarbonBlue".to_string(),
        symbol: "CBE".to_string(),
        initial_supply: 1_000_000,
        decimals: 8,
    };
    let params_bytes = bincode::serialize(&params).unwrap();
    let tx = contract_execution_tx(&creator, "create_custom_token", params_bytes);
    let block = test_block(1, vec![tx]);

    // Process contract transactions
    blockchain.process_contract_transactions(&block).unwrap();

    // Verify token was created
    let token_id = generate_custom_token_id("CarbonBlue", "CBE");
    let token = blockchain.token_contracts.get(&token_id)
        .expect("Token should exist after creation");

    assert_eq!(token.name, "CarbonBlue");
    assert_eq!(token.symbol, "CBE");
    assert_eq!(token.balance_of(&creator), 1_000_000, "Creator should have initial supply");
    assert_eq!(token.total_supply, 1_000_000);
}

/// Test 2: Mint custom tokens via TokenMint transaction as the token creator.
#[test]
fn test_mint_custom_token_by_creator() {
    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);
    let recipient = test_pubkey(2);

    // Register recipient identity so resolve_public_key_by_key_id can find them
    register_identity(&mut blockchain, "did:zhtp:recipient_02", &recipient);

    // Create custom token directly in state
    let token = TokenContract::new_custom(
        "CarbonBlue".to_string(),
        "CBE".to_string(),
        1_000_000,
        creator.clone(),
    );
    let token_id = token.token_id;
    blockchain.token_contracts.insert(token_id, token);

    // Build TokenMint transaction signed by creator
    let tx = token_mint_tx(&creator, token_id, recipient.key_id, 500_000);
    let block = test_block(1, vec![tx]);

    blockchain.process_token_transactions(&block).unwrap();

    let token = blockchain.token_contracts.get(&token_id).unwrap();
    assert_eq!(token.balance_of(&recipient), 500_000, "Recipient should have minted tokens");
    assert_eq!(token.total_supply, 1_500_000, "Total supply should include minted amount");
}

/// Test 3: Mint custom tokens by non-creator is rejected (issue #1129 fixed).
#[test]
fn test_mint_custom_token_unauthorized_rejected() {
    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);
    let attacker = test_pubkey(99);
    let recipient = test_pubkey(2);

    // Register recipient identity
    register_identity(&mut blockchain, "did:zhtp:recipient_02", &recipient);

    // Create token owned by creator
    let token = TokenContract::new_custom(
        "CarbonBlue".to_string(),
        "CBE".to_string(),
        1_000_000,
        creator.clone(),
    );
    let token_id = token.token_id;
    blockchain.token_contracts.insert(token_id, token);

    // Attacker signs a TokenMint — must be rejected
    let tx = token_mint_tx(&attacker, token_id, recipient.key_id, 999_999);
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_token_transactions(&block);
    assert!(result.is_err(), "Unauthorized mint must be rejected");
    assert!(result.unwrap_err().to_string().contains("unauthorized"));

    // Verify no tokens were minted
    let token = blockchain.token_contracts.get(&token_id).unwrap();
    assert_eq!(token.balance_of(&recipient), 0, "Attacker should not have minted anything");
    assert_eq!(token.total_supply, 1_000_000, "Supply should be unchanged");
}

/// Test 3b: Kernel-controlled tokens reject direct TokenMint bypass from non-kernel callers.
#[test]
fn test_kernel_controlled_tokenmint_bypass_rejected() {
    let mut blockchain = Blockchain::default();
    let kernel_authority = test_pubkey(77);
    let attacker = test_pubkey(88);
    let recipient = test_pubkey(2);

    blockchain.initialize_treasury_kernel(kernel_authority.clone());
    register_identity(&mut blockchain, "did:zhtp:recipient_02", &recipient);

    let mut token = TokenContract::new_custom(
        "KernelToken".to_string(),
        "KRN".to_string(),
        1_000_000,
        test_pubkey(1),
    );
    token.kernel_mint_authority = Some(kernel_authority.clone());
    let token_id = token.token_id;
    blockchain.token_contracts.insert(token_id, token);

    let tx = token_mint_tx(&attacker, token_id, recipient.key_id, 1_000);
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_token_transactions(&block);
    assert!(result.is_err(), "Non-kernel caller must be rejected");
    assert!(
        result.unwrap_err().to_string().contains("TokenMint failed"),
        "Rejection should come from kernel-routed mint path"
    );
}

/// Test 3c: Kernel-controlled token mint succeeds when signed by kernel authority.
#[test]
fn test_kernel_controlled_tokenmint_via_kernel_authority_succeeds() {
    let mut blockchain = Blockchain::default();
    let kernel_authority = test_pubkey(77);
    let recipient = test_pubkey(2);

    blockchain.initialize_treasury_kernel(kernel_authority.clone());
    register_identity(&mut blockchain, "did:zhtp:recipient_02", &recipient);

    let mut token = TokenContract::new_custom(
        "KernelToken".to_string(),
        "KRN".to_string(),
        1_000_000,
        test_pubkey(1),
    );
    token.kernel_mint_authority = Some(kernel_authority.clone());
    let token_id = token.token_id;
    blockchain.token_contracts.insert(token_id, token);

    let tx = token_mint_tx(&kernel_authority, token_id, recipient.key_id, 1_000);
    let block = test_block(1, vec![tx]);

    blockchain.process_token_transactions(&block).unwrap();

    let token = blockchain.token_contracts.get(&token_id).unwrap();
    assert_eq!(token.balance_of(&recipient), 1_000);
}

/// Test 4: SOV wallet-to-wallet transfer using wallet_id addressing.
#[test]
fn test_sov_wallet_transfer() {
    let mut blockchain = Blockchain::default();
    let sov_token_id = generate_lib_token_id();

    // Setup SOV token
    insert_sov_token(&mut blockchain);

    // Create sender and recipient with distinct wallet IDs
    let sender_pk = test_pubkey(1);
    let recipient_pk = test_pubkey(2);
    let sender_wallet_id = [0x11u8; 32];
    let recipient_wallet_id = [0x22u8; 32];

    // Register wallets
    register_wallet(&mut blockchain, sender_wallet_id, &sender_pk, 0);
    register_wallet(&mut blockchain, recipient_wallet_id, &recipient_pk, 0);

    // Mint SOV to sender wallet (using synthetic wallet key)
    let sender_wallet_key = wallet_key(&sender_wallet_id);
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.mint(&sender_wallet_key, 10_000).unwrap();
    }

    // Build TokenTransfer with wallet_id addressing
    let tx = token_transfer_tx(
        &sender_pk,
        sov_token_id,
        sender_wallet_id,
        recipient_wallet_id,
        3_000,
        10,
    );
    let block = test_block(1, vec![tx]);

    blockchain.process_token_transactions(&block).unwrap();

    let token = blockchain.token_contracts.get(&sov_token_id).unwrap();
    let sender_balance = token.balance_of(&wallet_key(&sender_wallet_id));
    let recipient_balance = token.balance_of(&wallet_key(&recipient_wallet_id));

    assert_eq!(sender_balance, 7_000, "Sender should have 10000 - 3000 = 7000");
    assert_eq!(recipient_balance, 3_000, "Recipient should have 3000");
}

/// Test 5: Custom token transfer using key_id addressing.
#[test]
fn test_custom_token_transfer() {
    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);
    let recipient = test_pubkey(2);

    // Register recipient in wallet registry so resolve_public_key_by_key_id can find them
    let recipient_wallet_id = [0x22u8; 32];
    register_wallet(&mut blockchain, recipient_wallet_id, &recipient, 0);

    // Create custom token with initial supply to creator
    let token = TokenContract::new_custom(
        "CarbonBlue".to_string(),
        "CBE".to_string(),
        1_000_000,
        creator.clone(),
    );
    let token_id = token.token_id;
    blockchain.token_contracts.insert(token_id, token);

    // Transfer using key_id addressing (not wallet_id — this is a custom token)
    let tx = token_transfer_tx(
        &creator,
        token_id,
        creator.key_id,
        recipient.key_id,
        250_000,
        20,
    );
    let block = test_block(1, vec![tx]);

    blockchain.process_token_transactions(&block).unwrap();

    let token = blockchain.token_contracts.get(&token_id).unwrap();
    assert_eq!(token.balance_of(&creator), 750_000, "Creator should have 1M - 250K");
    assert_eq!(token.balance_of(&recipient), 250_000, "Recipient should have 250K");
}

/// Test 6: ContractExecution token burn is rejected.
#[test]
fn test_contract_execution_burn_rejected() {
    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);

    // Create custom token
    let token = TokenContract::new_custom(
        "CarbonBlue".to_string(),
        "CBE".to_string(),
        1_000_000,
        creator.clone(),
    );
    let token_id = token.token_id;
    let initial_supply = token.total_supply;
    blockchain.token_contracts.insert(token_id, token);

    // Burn via ContractExecution
    #[derive(serde::Serialize)]
    struct BurnParams {
        token_id: [u8; 32],
        amount: u64,
    }
    let params = BurnParams {
        token_id,
        amount: 100_000,
    };
    let params_bytes = bincode::serialize(&params).unwrap();
    let tx = contract_execution_tx(&creator, "burn", params_bytes);
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_contract_transactions(&block);
    assert!(result.is_ok(), "process_contract_transactions must not abort on a rejected ContractExecution");

    let token = blockchain.token_contracts.get(&token_id).unwrap();
    assert_eq!(token.balance_of(&creator), 1_000_000, "Creator balance must be unchanged after rejected burn");
    assert_eq!(token.total_supply, initial_supply, "Total supply must be unchanged after rejected burn");
}

/// Test 6a: ContractExecution mint cannot bypass kernel authority on protected tokens.
#[test]
fn test_contract_execution_mint_rejected_for_kernel_controlled_token() {
    #[derive(serde::Serialize)]
    struct MintParams {
        token_id: [u8; 32],
        to: Vec<u8>,
        amount: u64,
    }

    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);
    let kernel_authority = test_pubkey(77);
    let recipient = test_pubkey(2);
    register_identity(&mut blockchain, "did:zhtp:recipient_02", &recipient);

    let mut token = TokenContract::new_custom(
        "KernelToken".to_string(),
        "KRN".to_string(),
        1_000_000,
        creator.clone(),
    );
    token.kernel_mint_authority = Some(kernel_authority);
    let token_id = token.token_id;
    blockchain.token_contracts.insert(token_id, token);

    let params = MintParams {
        token_id,
        to: recipient.key_id.to_vec(),
        amount: 500,
    };
    let tx = contract_execution_tx(&creator, "mint", bincode::serialize(&params).unwrap());
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_contract_transactions(&block);
    assert!(
        result.is_ok(),
        "process_contract_transactions currently swallows contract-execution errors"
    );

    let token = blockchain.token_contracts.get(&token_id).unwrap();
    assert_eq!(
        token.balance_of(&recipient),
        0,
        "Kernel-protected mint bypass must not mutate balances"
    );
}

/// Test 6aa: ContractExecution burn cannot bypass kernel authority on protected tokens.
#[test]
fn test_contract_execution_burn_rejected_for_kernel_controlled_token() {
    #[derive(serde::Serialize)]
    struct BurnParams {
        token_id: [u8; 32],
        amount: u64,
    }

    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);
    let kernel_authority = test_pubkey(77);

    let mut token = TokenContract::new_custom(
        "KernelToken".to_string(),
        "KRN".to_string(),
        1_000_000,
        creator.clone(),
    );
    token.kernel_mint_authority = Some(kernel_authority);
    let token_id = token.token_id;
    blockchain.token_contracts.insert(token_id, token);

    let params = BurnParams {
        token_id,
        amount: 500,
    };
    let tx = contract_execution_tx(&creator, "burn", bincode::serialize(&params).unwrap());
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_contract_transactions(&block);
    assert!(
        result.is_ok(),
        "process_contract_transactions currently swallows contract-execution errors"
    );

    let token = blockchain.token_contracts.get(&token_id).unwrap();
    assert_eq!(
        token.total_supply,
        1_000_000,
        "Kernel-protected burn bypass must not mutate supply"
    );
}

/// Test 6b: ContractExecution token transfer is rejected.
#[test]
fn test_contract_execution_transfer_rejected() {
    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);
    let recipient = test_pubkey(2);

    let token = TokenContract::new_custom(
        "CarbonBlue".to_string(),
        "CBE".to_string(),
        1_000_000,
        creator.clone(),
    );
    let token_id = token.token_id;
    blockchain.token_contracts.insert(token_id, token);

    #[derive(serde::Serialize)]
    struct TransferParams {
        token_id: [u8; 32],
        to: Vec<u8>,
        amount: u64,
    }
    let params = TransferParams {
        token_id,
        to: recipient.key_id.to_vec(),
        amount: 10_000,
    };
    let tx = contract_execution_tx(&creator, "transfer", bincode::serialize(&params).unwrap());
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_contract_transactions(&block);
    assert!(result.is_err(), "ContractExecution transfer must be rejected");

    let token = blockchain.token_contracts.get(&token_id).unwrap();
    assert_eq!(token.balance_of(&creator), 1_000_000);
    assert_eq!(token.balance_of(&recipient), 0);
}

/// Test 7: Balance queries return correct values after mixed operations.
#[test]
fn test_balance_queries_after_operations() {
    let mut blockchain = Blockchain::default();
    let sov_token_id = generate_lib_token_id();
    insert_sov_token(&mut blockchain);

    let user_a = test_pubkey(1);
    let user_b = test_pubkey(2);
    let wallet_a = [0xAAu8; 32];
    let wallet_b = [0xBBu8; 32];

    register_wallet(&mut blockchain, wallet_a, &user_a, 0);
    register_wallet(&mut blockchain, wallet_b, &user_b, 0);

    // Mint SOV to wallet A
    let wallet_a_key = wallet_key(&wallet_a);
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.mint(&wallet_a_key, 50_000).unwrap();
    }

    // Transfer 20K from A to B (nonce 0)
    let tx1 = token_transfer_tx(&user_a, sov_token_id, wallet_a, wallet_b, 20_000, 30);
    let block1 = test_block(1, vec![tx1]);
    blockchain.process_token_transactions(&block1).unwrap();

    // Transfer another 5K from A to B (nonce 1)
    let tx2 = token_transfer_tx_with_nonce(&user_a, sov_token_id, wallet_a, wallet_b, 5_000, 31, 1);
    let block2 = test_block(2, vec![tx2]);
    blockchain.process_token_transactions(&block2).unwrap();

    let token = blockchain.token_contracts.get(&sov_token_id).unwrap();
    assert_eq!(token.balance_of(&wallet_key(&wallet_a)), 25_000, "A: 50K - 20K - 5K = 25K");
    assert_eq!(token.balance_of(&wallet_key(&wallet_b)), 25_000, "B: 20K + 5K = 25K");
}

/// Test 8: Created tokens appear in token_contracts listing.
#[test]
fn test_token_list() {
    let mut blockchain = Blockchain::default();
    insert_sov_token(&mut blockchain);

    let creator = test_pubkey(1);

    // Create two custom tokens
    let token1 = TokenContract::new_custom("Alpha".to_string(), "ALP".to_string(), 100, creator.clone());
    let token2 = TokenContract::new_custom("Beta".to_string(), "BET".to_string(), 200, creator.clone());
    let id1 = token1.token_id;
    let id2 = token2.token_id;
    blockchain.token_contracts.insert(id1, token1);
    blockchain.token_contracts.insert(id2, token2);

    // Verify all tokens are listed
    let contracts = &blockchain.token_contracts;
    assert!(contracts.contains_key(&generate_lib_token_id()), "SOV should be in list");
    assert!(contracts.contains_key(&id1), "Alpha should be in list");
    assert!(contracts.contains_key(&id2), "Beta should be in list");
    assert!(contracts.len() >= 3, "Should have at least SOV + 2 custom tokens");

    // Verify metadata
    assert_eq!(contracts[&id1].symbol, "ALP");
    assert_eq!(contracts[&id2].symbol, "BET");
}

/// Test 9: Wallet registration via block processing mints initial SOV balance.
#[test]
fn test_wallet_registration_mints_initial_balance() {
    let mut blockchain = Blockchain::default();
    insert_sov_token(&mut blockchain);
    let sov_token_id = generate_lib_token_id();

    let owner = test_pubkey(5);
    let wallet_id = [0x55u8; 32];
    let initial_balance = 1_000;

    let tx = wallet_registration_tx(wallet_id, &owner, initial_balance);
    let block = test_block(1, vec![tx]);

    blockchain.process_wallet_transactions(&block).unwrap();

    let token = blockchain.token_contracts.get(&sov_token_id).unwrap();
    let balance = token.balance_of(&wallet_key(&wallet_id));
    assert_eq!(balance, initial_balance, "Wallet should have initial balance minted via block processing");
}

/// Test 10: Transfer fails with insufficient balance.
#[test]
fn test_transfer_insufficient_balance() {
    let mut blockchain = Blockchain::default();
    let sov_token_id = generate_lib_token_id();
    insert_sov_token(&mut blockchain);

    let sender_pk = test_pubkey(1);
    let recipient_pk = test_pubkey(2);
    let sender_wallet = [0x11u8; 32];
    let recipient_wallet = [0x22u8; 32];

    register_wallet(&mut blockchain, sender_wallet, &sender_pk, 0);
    register_wallet(&mut blockchain, recipient_wallet, &recipient_pk, 0);

    // Mint only 100 SOV to sender
    let sender_key = wallet_key(&sender_wallet);
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.mint(&sender_key, 100).unwrap();
    }

    // Try to transfer 1000 SOV (more than balance)
    let tx = token_transfer_tx(&sender_pk, sov_token_id, sender_wallet, recipient_wallet, 1_000, 40);
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_token_transactions(&block);
    assert!(result.is_err(), "Transfer should fail with insufficient balance");
}

/// Test 11: Transfer to non-existent SOV wallet fails.
#[test]
fn test_transfer_to_nonexistent_wallet_fails() {
    let mut blockchain = Blockchain::default();
    let sov_token_id = generate_lib_token_id();
    insert_sov_token(&mut blockchain);

    let sender_pk = test_pubkey(1);
    let sender_wallet = [0x11u8; 32];
    let ghost_wallet = [0xFFu8; 32]; // Not registered

    register_wallet(&mut blockchain, sender_wallet, &sender_pk, 0);

    let sender_key = wallet_key(&sender_wallet);
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.mint(&sender_key, 10_000).unwrap();
    }

    let tx = token_transfer_tx(&sender_pk, sov_token_id, sender_wallet, ghost_wallet, 100, 50);
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_token_transactions(&block);
    assert!(result.is_err(), "Transfer to unregistered wallet should fail");
}

/// Test 12: Duplicate token symbol creation is rejected.
#[test]
fn test_duplicate_symbol_rejected() {
    let mut blockchain = Blockchain::default();
    let creator = test_pubkey(1);

    // First token creation
    let token = TokenContract::new_custom("CarbonBlue".to_string(), "CBE".to_string(), 1000, creator.clone());
    blockchain.token_contracts.insert(token.token_id, token);

    // Try creating another token with same symbol via ContractExecution
    #[derive(serde::Serialize)]
    struct CreateTokenParams {
        name: String,
        symbol: String,
        initial_supply: u64,
        decimals: u8,
    }
    let params = CreateTokenParams {
        name: "CarbonBlueDuplicate".to_string(),
        symbol: "CBE".to_string(),
        initial_supply: 500,
        decimals: 8,
    };
    let params_bytes = bincode::serialize(&params).unwrap();
    let tx = contract_execution_tx(&creator, "create_custom_token", params_bytes);
    let block = test_block(1, vec![tx]);

    let result = blockchain.process_contract_transactions(&block);
    assert!(result.is_err(), "Duplicate symbol contract execution should be rejected");

    // Verify only the original token exists (no duplicate created)
    let count = blockchain.token_contracts.values()
        .filter(|t| t.symbol.to_uppercase() == "CBE")
        .count();
    assert_eq!(count, 1, "Only one CBE token should exist");
}

// ─── Replay protection tests ───────────────────────────────────────────────

/// Test 13: Replay protection - second transfer with same nonce is rejected.
#[test]
fn test_replay_protection_rejects_duplicate_nonce() {
    let mut blockchain = Blockchain::default();
    let sender_pk = test_pubkey(1);
    let recipient_pk = test_pubkey(2);
    let sender_wid = [0x51u8; 32];
    let recipient_wid = [0x52u8; 32];
    let sov_token_id = generate_lib_token_id();

    insert_sov_token(&mut blockchain);
    register_wallet(&mut blockchain, sender_wid, &sender_pk, 0);
    register_wallet(&mut blockchain, recipient_wid, &recipient_pk, 0);

    // Mint SOV to sender
    let sender_key = wallet_key(&sender_wid);
    blockchain.token_contracts.get_mut(&sov_token_id).unwrap()
        .mint(&sender_key, 1_000_000).unwrap();

    // First transfer with nonce 0 succeeds
    let tx1 = token_transfer_tx_with_nonce(
        &sender_pk, sov_token_id, sender_wid, recipient_wid, 100_000, 30, 0,
    );
    let block1 = test_block(1, vec![tx1]);
    blockchain.process_token_transactions(&block1).unwrap();

    // Verify nonce incremented
    assert_eq!(blockchain.get_token_nonce(&sov_token_id, &sender_wid), 1);

    // Replay with nonce 0 again — must be rejected
    let tx_replay = token_transfer_tx_with_nonce(
        &sender_pk, sov_token_id, sender_wid, recipient_wid, 100_000, 31, 0,
    );
    let block2 = test_block(2, vec![tx_replay]);
    let result = blockchain.process_token_transactions(&block2);
    assert!(result.is_err(), "Replayed transaction must be rejected");
    assert!(result.unwrap_err().to_string().contains("nonce mismatch"));
}

/// Test 14: Sequential nonces work correctly.
#[test]
fn test_sequential_nonces() {
    let mut blockchain = Blockchain::default();
    let sender_pk = test_pubkey(1);
    let recipient_pk = test_pubkey(2);
    let sender_wid = [0x61u8; 32];
    let recipient_wid = [0x62u8; 32];
    let sov_token_id = generate_lib_token_id();

    insert_sov_token(&mut blockchain);
    register_wallet(&mut blockchain, sender_wid, &sender_pk, 0);
    register_wallet(&mut blockchain, recipient_wid, &recipient_pk, 0);

    // Mint SOV to sender
    let sender_key = wallet_key(&sender_wid);
    blockchain.token_contracts.get_mut(&sov_token_id).unwrap()
        .mint(&sender_key, 1_000_000).unwrap();

    // Three sequential transfers with incrementing nonces
    for nonce in 0..3u64 {
        let tx = token_transfer_tx_with_nonce(
            &sender_pk, sov_token_id, sender_wid, recipient_wid, 10_000, (40 + nonce) as u8, nonce,
        );
        let block = test_block(nonce + 1, vec![tx]);
        blockchain.process_token_transactions(&block).unwrap();
        assert_eq!(blockchain.get_token_nonce(&sov_token_id, &sender_wid), nonce + 1);
    }

    // Verify final balances
    let token = blockchain.token_contracts.get(&sov_token_id).unwrap();
    assert_eq!(token.balance_of(&wallet_key(&sender_wid)), 1_000_000 - 30_000);
    assert_eq!(token.balance_of(&wallet_key(&recipient_wid)), 30_000);
}

/// Test 15: Nonces are independent per token for the same sender.
#[test]
fn test_nonces_are_per_token() {
    let mut blockchain = Blockchain::default();
    let sender_pk = test_pubkey(1);
    let recipient_pk = test_pubkey(2);
    let sender_wid = [0x71u8; 32];
    let recipient_wid = [0x72u8; 32];
    let sov_token_id = generate_lib_token_id();

    insert_sov_token(&mut blockchain);
    register_wallet(&mut blockchain, sender_wid, &sender_pk, 0);
    register_wallet(&mut blockchain, recipient_wid, &recipient_pk, 0);
    register_identity(&mut blockchain, "did:zhtp:recipient_02", &recipient_pk);

    // Create a custom token and mint to sender
    let custom_token = TokenContract::new_custom(
        "CarbonBlue".to_string(),
        "CBE".to_string(),
        1_000_000,
        sender_pk.clone(),
    );
    let custom_token_id = custom_token.token_id;
    blockchain.token_contracts.insert(custom_token_id, custom_token);
    blockchain.token_contracts.get_mut(&custom_token_id).unwrap()
        .mint(&sender_pk, 500_000).unwrap();

    // Mint SOV to sender wallet
    let sender_key = wallet_key(&sender_wid);
    blockchain.token_contracts.get_mut(&sov_token_id).unwrap()
        .mint(&sender_key, 1_000_000).unwrap();

    // SOV transfer with nonce 0
    let tx1 = token_transfer_tx_with_nonce(
        &sender_pk, sov_token_id, sender_wid, recipient_wid, 100_000, 50, 0,
    );
    let block1 = test_block(1, vec![tx1]);
    blockchain.process_token_transactions(&block1).unwrap();

    // Custom token transfer with nonce 0 should still succeed
    let tx2 = token_transfer_tx_with_nonce(
        &sender_pk, custom_token_id, sender_pk.key_id, recipient_pk.key_id, 25_000, 51, 0,
    );
    let block2 = test_block(2, vec![tx2]);
    blockchain.process_token_transactions(&block2).unwrap();

    assert_eq!(blockchain.get_token_nonce(&sov_token_id, &sender_wid), 1);
    assert_eq!(blockchain.get_token_nonce(&custom_token_id, &sender_pk.key_id), 1);
}
