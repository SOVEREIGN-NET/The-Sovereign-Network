//! Bonding Curve Transaction Integration Tests
//!
//! Tests for Issue #1820: Bonding Curve Token Deployment via Consensus
//! 
//! These tests verify that all four bonding curve transaction types
//! (BondingCurveDeploy, BondingCurveBuy, BondingCurveSell, BondingCurveGraduate)
//! are properly processed through process_token_transactions.

use lib_blockchain::{
    block::{Block, BlockHeader},
    contracts::bonding_curve::{Phase, Threshold},
    contracts::tokens::CBE_SYMBOL,
    integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm},
    transaction::{
        BondingCurveBuyData, BondingCurveDeployData, BondingCurveGraduateData,
        BondingCurveSellData, Transaction,
    },
    types::{Difficulty, Hash},
    Blockchain,
};

// ============================================================================
// Test Helpers
// ============================================================================

fn test_key(id: u8) -> PublicKey {
    PublicKey::new(vec![id; 1312])
}

fn test_signature(key: &PublicKey) -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: 1_700_000_000,
    }
}

fn make_test_block(height: u64, timestamp: u64, transactions: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            previous_block_hash: Hash::default(),
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            timestamp,
            difficulty: Difficulty::minimum(),
            nonce: 0,
            height,
            block_hash: Hash::default(),
            cumulative_difficulty: Difficulty::minimum(),
            transaction_count: transactions.len() as u32,
            block_size: 0,
            fee_model_version: 2,
        },
        transactions,
    }
}

fn create_deploy_transaction(
    creator_key: &PublicKey,
    name: &str,
    symbol: &str,
    nonce: u64,
) -> Transaction {
    let mut creator_key_id = [0u8; 32];
    creator_key_id.copy_from_slice(&creator_key.key_id[..32.min(creator_key.key_id.len())]);

    let deploy_data = BondingCurveDeployData {
        name: name.to_string(),
        symbol: symbol.to_string(),
        curve_type: 0, // Linear
        base_price: 1_000_000, // $0.01
        curve_param: 100, // slope
        midpoint_supply: None,
        threshold_type: 0, // ReserveAmount
        threshold_value: 10_000_000, // $100
        threshold_time_seconds: None,
        sell_enabled: true,
        creator: creator_key_id,
        nonce,
    };

    Transaction::new_bonding_curve_deploy_with_chain_id(
        0x03,
        deploy_data,
        test_signature(creator_key),
        b"ZHTP_BONDING_CURVE_DEPLOY".to_vec(),
    )
}

fn create_buy_transaction(
    buyer_key: &PublicKey,
    token_id: [u8; 32],
    stable_amount: u64,
    min_tokens_out: u64,
    nonce: u64,
) -> Transaction {
    let mut buyer_key_id = [0u8; 32];
    buyer_key_id.copy_from_slice(&buyer_key.key_id[..32.min(buyer_key.key_id.len())]);

    let buy_data = BondingCurveBuyData {
        token_id,
        stable_amount,
        min_tokens_out,
        buyer: buyer_key_id,
        nonce,
    };

    Transaction::new_bonding_curve_buy_with_chain_id(
        0x03,
        buy_data,
        test_signature(buyer_key),
        b"ZHTP_BONDING_CURVE_BUY".to_vec(),
    )
}

fn create_sell_transaction(
    seller_key: &PublicKey,
    token_id: [u8; 32],
    token_amount: u64,
    min_stable_out: u64,
    nonce: u64,
) -> Transaction {
    let mut seller_key_id = [0u8; 32];
    seller_key_id.copy_from_slice(&seller_key.key_id[..32.min(seller_key.key_id.len())]);

    let sell_data = BondingCurveSellData {
        token_id,
        token_amount,
        min_stable_out,
        seller: seller_key_id,
        nonce,
    };

    Transaction::new_bonding_curve_sell_with_chain_id(
        0x03,
        sell_data,
        test_signature(seller_key),
        b"ZHTP_BONDING_CURVE_SELL".to_vec(),
    )
}

fn create_graduate_transaction(
    graduator_key: &PublicKey,
    token_id: [u8; 32],
    pool_id: [u8; 32],
    nonce: u64,
) -> Transaction {
    let mut graduator_key_id = [0u8; 32];
    graduator_key_id.copy_from_slice(&graduator_key.key_id[..32.min(graduator_key.key_id.len())]);

    let graduate_data = BondingCurveGraduateData {
        token_id,
        pool_id,
        sov_seed_amount: 1_000_000,
        token_seed_amount: 1_000_000,
        graduator: graduator_key_id,
        nonce,
    };

    Transaction::new_bonding_curve_graduate_with_chain_id(
        0x03,
        graduate_data,
        test_signature(graduator_key),
        b"ZHTP_BONDING_CURVE_GRADUATE".to_vec(),
    )
}

// ============================================================================
// BondingCurveDeploy Tests
// ============================================================================

#[test]
fn test_bonding_curve_deploy_transaction_success() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);

    let deploy_tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    let block = make_test_block(1, 1_700_000_000, vec![deploy_tx]);

    // Process the transaction
    let result = blockchain.process_token_transactions(&block);
    assert!(result.is_ok(), "Deploy transaction should succeed: {:?}", result);

    // Verify token was registered
    let token_id_input = format!("Test Token:TEST:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let expected_token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());
    
    assert!(
        blockchain.bonding_curve_registry.contains(&expected_token_id),
        "Token should be registered in bonding_curve_registry"
    );

    let token = blockchain.bonding_curve_registry.get(&expected_token_id).unwrap();
    assert_eq!(token.name, "Test Token");
    assert_eq!(token.symbol, "TEST");
    assert_eq!(token.phase, Phase::Curve);
    assert!(token.sell_enabled);
}

#[test]
fn test_bonding_curve_deploy_duplicate_symbol_fails() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);

    // First deploy should succeed
    let deploy_tx1 = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx1]);
    let result = blockchain.process_token_transactions(&block1);
    assert!(result.is_ok(), "First deploy should succeed");

    // Second deploy with same symbol should fail
    let deploy_tx2 = create_deploy_transaction(&creator, "Another Token", "TEST", 0);
    let block2 = make_test_block(2, 1_700_000_100, vec![deploy_tx2]);
    let result = blockchain.process_token_transactions(&block2);
    assert!(result.is_err(), "Duplicate symbol should fail");
}

#[test]
fn test_bonding_curve_deploy_empty_name_fails() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);

    let mut deploy_tx = create_deploy_transaction(&creator, "", "TEST", 0);
    // Manually set empty name in the data
    if let Some(ref mut data) = deploy_tx.bonding_curve_deploy_data {
        data.name = "".to_string();
    }

    let block = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    let result = blockchain.process_token_transactions(&block);
    assert!(result.is_err(), "Empty name should fail");
}

// ============================================================================
// BondingCurveBuy Tests
// ============================================================================

#[test]
fn test_bonding_curve_buy_transaction_success() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    let buyer = test_key(2);

    // First deploy the token
    let deploy_tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    blockchain.process_token_transactions(&block1).expect("Deploy should succeed");

    let token_id_input = format!("Test Token:TEST:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());

    // Now buy tokens
    let buy_tx = create_buy_transaction(&buyer, token_id, 1_000_000, 0, 0);
    let block2 = make_test_block(2, 1_700_000_100, vec![buy_tx]);
    
    let result = blockchain.process_token_transactions(&block2);
    assert!(result.is_ok(), "Buy transaction should succeed: {:?}", result);

    // Verify token state updated
    // Issue #1844: 20/80 split - reserve gets 20%, treasury gets 80%
    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert_eq!(token.reserve_balance, 200_000, "Reserve should be 20% of buy amount");
    assert_eq!(token.treasury_balance, 800_000, "Treasury should be 80% of buy amount");
    assert!(token.total_supply > 0);
}

#[test]
fn test_bonding_curve_buy_slippage_protection() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    let buyer = test_key(2);

    // Deploy token
    let deploy_tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    blockchain.process_token_transactions(&block1).expect("Deploy should succeed");

    let token_id_input = format!("Test Token:TEST:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());

    // Try to buy with very high min_tokens_out (should fail due to slippage)
    let buy_tx = create_buy_transaction(&buyer, token_id, 1_000_000, 1_000_000_000, 0);
    let block2 = make_test_block(2, 1_700_000_100, vec![buy_tx]);
    
    let result = blockchain.process_token_transactions(&block2);
    assert!(result.is_err(), "Buy with excessive slippage should fail");
}

#[test]
fn test_bonding_curve_buy_nonexistent_token_fails() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let buyer = test_key(2);

    let fake_token_id = [99u8; 32];
    let buy_tx = create_buy_transaction(&buyer, fake_token_id, 1_000_000, 0, 0);
    let block = make_test_block(1, 1_700_000_000, vec![buy_tx]);
    
    let result = blockchain.process_token_transactions(&block);
    assert!(result.is_err(), "Buy of nonexistent token should fail");
}

#[test]
fn test_bonding_curve_buy_key_mismatch_fails() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    let buyer = test_key(2);
    let wrong_key = test_key(3);

    // Deploy token
    let deploy_tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    blockchain.process_token_transactions(&block1).expect("Deploy should succeed");

    let token_id_input = format!("Test Token:TEST:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());

    // Create buy transaction with wrong signer
    let mut buy_tx = create_buy_transaction(&wrong_key, token_id, 1_000_000, 0, 0);
    // Set buyer to buyer's key_id but signature from wrong_key
    if let Some(ref mut data) = buy_tx.bonding_curve_buy_data {
        data.buyer = buyer.key_id[..32.min(buyer.key_id.len())].try_into().unwrap_or([0u8; 32]);
    }

    let block2 = make_test_block(2, 1_700_000_100, vec![buy_tx]);
    let result = blockchain.process_token_transactions(&block2);
    assert!(result.is_err(), "Buy with key mismatch should fail");
}

// ============================================================================
// BondingCurveSell Tests
// ============================================================================

#[test]
fn test_bonding_curve_sell_transaction_success() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    let buyer = test_key(2);
    let seller = buyer.clone(); // Same as buyer

    // Deploy token
    let deploy_tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    blockchain.process_token_transactions(&block1).expect("Deploy should succeed");

    let token_id_input = format!("Test Token:TEST:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());

    // Buy tokens first - use larger amount so reserve has enough for sells
    // Issue #1844: 20/80 split - only 20% goes to reserve
    let buy_tx = create_buy_transaction(&buyer, token_id, 100_000_000, 0, 0);
    let block2 = make_test_block(2, 1_700_000_100, vec![buy_tx]);
    blockchain.process_token_transactions(&block2).expect("Buy should succeed");

    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    // deploy() initializes total_supply to 0; all minted tokens come from buys
    let initial_supply = token.total_supply;
    let initial_reserve = token.reserve_balance;
    let initial_treasury = token.treasury_balance;

    // Issue #1845: Due to 20/80 split, reserve only has 20% of SOV
    // Must sell small portion to stay within reserve limits
    let sell_amount = initial_supply / 20; // Sell only 5% of tokens
    let sell_tx = create_sell_transaction(&seller, token_id, sell_amount, 0, 0);
    let block3 = make_test_block(3, 1_700_000_200, vec![sell_tx]);

    let result = blockchain.process_token_transactions(&block3);
    assert!(result.is_ok(), "Sell transaction should succeed: {:?}", result);

    // Verify exact deltas: supply burns by sold amount, reserve decreases, treasury unchanged
    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert_eq!(token.total_supply, initial_supply - sell_amount, "Supply should decrease by exact sell amount (burn)");
    assert!(token.reserve_balance < initial_reserve, "Reserve should decrease after sell");
    assert_eq!(token.treasury_balance, initial_treasury, "Treasury should be unaffected by sell");
}

#[test]
fn test_bonding_curve_sell_disabled_fails() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    let buyer = test_key(2);

    // Deploy token with sell_enabled = false
    let mut deploy_tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    if let Some(ref mut data) = deploy_tx.bonding_curve_deploy_data {
        data.sell_enabled = false;
    }

    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    blockchain.process_token_transactions(&block1).expect("Deploy should succeed");

    let token_id_input = format!("Test Token:TEST:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());

    // Buy tokens first
    let buy_tx = create_buy_transaction(&buyer, token_id, 10_000_000, 0, 0);
    let block2 = make_test_block(2, 1_700_000_100, vec![buy_tx]);
    blockchain.process_token_transactions(&block2).expect("Buy should succeed");

    // Try to sell (should fail because sell is disabled)
    let sell_tx = create_sell_transaction(&buyer, token_id, 100_000, 0, 0);
    let block3 = make_test_block(3, 1_700_000_200, vec![sell_tx]);
    
    let result = blockchain.process_token_transactions(&block3);
    assert!(result.is_err(), "Sell should fail when sell_enabled is false");
}

// ============================================================================
// BondingCurveGraduate Tests
// ============================================================================

#[test]
fn test_bonding_curve_graduate_transaction_success() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    let buyer = test_key(2);
    let graduator = creator.clone(); // Creator graduates the token

    // Deploy token with low threshold for easy graduation
    let mut deploy_tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    if let Some(ref mut data) = deploy_tx.bonding_curve_deploy_data {
        // Issue #1844: With 20/80 split, reserve gets 20% of buy amount
        // To have 5 SOV in reserve, need 25 SOV buy
        data.threshold_value = 5_000_000; // $50 threshold
    }

    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    blockchain.process_token_transactions(&block1).expect("Deploy should succeed");

    let token_id_input = format!("Test Token:TEST:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());

    // Issue #1844: Buy tokens to reach graduation threshold
    // With 20/80 split, need 5x the threshold amount in buys
    // threshold = $50, so need $250 buy to get $50 in reserve
    let buy_tx = create_buy_transaction(&buyer, token_id, 50_000_000, 0, 0);
    let block2 = make_test_block(2, 1_700_000_100, vec![buy_tx]);
    blockchain.process_token_transactions(&block2).expect("Buy should succeed");

    // Verify token can graduate (reserve should be 10 SOV)
    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert_eq!(token.reserve_balance, 10_000_000, "Reserve should be 20% of 50 SOV = 10 SOV");
    assert!(token.can_graduate(1_700_000_200), "Token should be ready to graduate");

    // Graduate the token
    let pool_id = [99u8; 32];
    let graduate_tx = create_graduate_transaction(&graduator, token_id, pool_id, 0);
    let block3 = make_test_block(3, 1_700_000_200, vec![graduate_tx]);
    
    let result = blockchain.process_token_transactions(&block3);
    assert!(result.is_ok(), "Graduate transaction should succeed: {:?}", result);

    // Verify token is now graduated
    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert!(token.phase.is_graduated(), "Token should be in Graduated phase");
}

#[test]
fn test_bonding_curve_graduate_threshold_not_met_fails() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);

    // Deploy token with high threshold
    let mut deploy_tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);
    if let Some(ref mut data) = deploy_tx.bonding_curve_deploy_data {
        data.threshold_value = 1_000_000_000; // $10,000 threshold (very high)
    }

    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    blockchain.process_token_transactions(&block1).expect("Deploy should succeed");

    let token_id_input = format!("Test Token:TEST:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());

    // Try to graduate without meeting threshold
    let pool_id = [99u8; 32];
    let graduate_tx = create_graduate_transaction(&creator, token_id, pool_id, 0);
    let block2 = make_test_block(2, 1_700_000_100, vec![graduate_tx]);
    
    let result = blockchain.process_token_transactions(&block2);
    assert!(result.is_err(), "Graduate should fail when threshold not met");
}

// ============================================================================
// Full Lifecycle Test
// ============================================================================

#[test]
fn test_bonding_curve_full_lifecycle_via_transactions() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    let buyer = test_key(2);

    // Step 1: Deploy
    let deploy_tx = create_deploy_transaction(&creator, "Lifecycle Token", "LIFE", 0);
    let block1 = make_test_block(1, 1_700_000_000, vec![deploy_tx]);
    blockchain.process_token_transactions(&block1).expect("Deploy should succeed");

    let token_id_input = format!("Lifecycle Token:LIFE:{}", hex::encode(&creator.key_id[..32.min(creator.key_id.len())]));
    let token_id = lib_crypto::hash_blake3(token_id_input.as_bytes());

    // Verify deploy
    assert!(blockchain.bonding_curve_registry.contains(&token_id));
    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert_eq!(token.phase, Phase::Curve);

    // Step 2: Buy
    // Issue #1844: 20/80 split - reserve gets 20%
    let buy_tx = create_buy_transaction(&buyer, token_id, 50_000_000, 0, 0);
    let block2 = make_test_block(2, 1_700_000_100, vec![buy_tx]);
    blockchain.process_token_transactions(&block2).expect("Buy should succeed");

    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert_eq!(token.reserve_balance, 10_000_000, "Reserve should be 20% of 50 SOV");
    assert_eq!(token.treasury_balance, 40_000_000, "Treasury should be 80% of 50 SOV");
    let tokens_before_sell = token.total_supply;
    // deploy() initializes total_supply to 0; all tokens come from buys

    // Step 3: Sell a small portion
    // Issue #1845: Due to 20/80 split, can only sell ~20% of tokens before reserve depleted
    let sell_amount = tokens_before_sell / 20; // Sell 5% of tokens
    let sell_tx = create_sell_transaction(&buyer, token_id, sell_amount, 0, 0);
    let block3 = make_test_block(3, 1_700_000_200, vec![sell_tx]);
    blockchain.process_token_transactions(&block3).expect("Sell should succeed");

    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert!(token.reserve_balance < 10_000_000, "Reserve should decrease after sell");
    assert_eq!(token.total_supply, tokens_before_sell - sell_amount, "Supply should decrease by sold amount (burn)");

    // Step 4: Buy more to reach threshold
    // First get current reserve and update threshold to be achievable
    let current_reserve = {
        let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
        token.reserve_balance
    };
    {
        let token_mut = blockchain.bonding_curve_registry.get_mut(&token_id).unwrap();
        token_mut.threshold = Threshold::ReserveAmount(current_reserve + 1);
    }

    let buy_tx2 = create_buy_transaction(&buyer, token_id, 2_000_000, 0, 1);
    let block4 = make_test_block(4, 1_700_000_300, vec![buy_tx2]);
    blockchain.process_token_transactions(&block4).expect("Buy should succeed");

    // Step 5: Graduate
    let pool_id = [42u8; 32];
    let graduate_tx = create_graduate_transaction(&creator, token_id, pool_id, 0);
    let block5 = make_test_block(5, 1_700_000_400, vec![graduate_tx]);
    blockchain.process_token_transactions(&block5).expect("Graduate should succeed");

    let token = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert!(token.phase.is_graduated(), "Token should be graduated");

    println!("✅ Full lifecycle test passed!");
    println!("   - Deployed: {} ({})", token.name, token.symbol);
    println!("   - Final phase: {:?}", token.phase);
    println!("   - Final reserve: {}", token.reserve_balance);
    println!("   - Final supply: {}", token.total_supply);
}

// ============================================================================
// CBE Genesis Initialization Test
// ============================================================================

#[test]
fn test_cbe_genesis_initialization() {
    let blockchain = Blockchain::new().expect("Failed to create blockchain");

    // CBE should be automatically initialized at genesis
    let cbe_token_id = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        "CBE Equity".hash(&mut hasher);
        CBE_SYMBOL.hash(&mut hasher);
        let hash = hasher.finish();
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());
        for i in 8..32 {
            id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
        }
        id
    };

    assert!(
        blockchain.bonding_curve_registry.contains(&cbe_token_id),
        "CBE should be initialized at genesis"
    );

    let cbe = blockchain.bonding_curve_registry.get(&cbe_token_id).unwrap();
    assert_eq!(cbe.name, "CBE Equity");
    assert_eq!(cbe.symbol, CBE_SYMBOL);
    assert_eq!(cbe.phase, Phase::Curve);
    assert!(cbe.sell_enabled);

    println!("✅ CBE genesis initialization verified!");
    println!("   - Token ID: {}", hex::encode(&cbe_token_id[..8]));
    println!("   - Name: {}", cbe.name);
    println!("   - Symbol: {}", cbe.symbol);
    println!("   - Phase: {:?}", cbe.phase);
}
