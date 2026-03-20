//! Bonding Curve Transaction Integration Tests
//!
//! These tests cover the legacy no-executor path only.
//! Bonding-curve state mutations are no longer allowed there.

use lib_blockchain::{
    block::{Block, BlockHeader},
    contracts::bonding_curve::Phase,
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
    stable_amount: u128,
    min_tokens_out: u128,
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
    token_amount: u128,
    min_stable_out: u128,
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

fn assert_legacy_path_rejects(blockchain: &mut Blockchain, tx: Transaction, expected: &str) {
    let block = make_test_block(1, 1_700_000_000, vec![tx]);
    let err = blockchain
        .process_token_transactions(&block)
        .expect_err("legacy path should reject bonding-curve tx");
    assert!(
        err.to_string().contains(expected),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_legacy_path_rejects_bonding_curve_deploy() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    let tx = create_deploy_transaction(&creator, "Test Token", "TEST", 0);

    assert_legacy_path_rejects(&mut blockchain, tx, "BondingCurveDeploy requires BlockExecutor");
}

#[test]
fn test_legacy_path_rejects_bonding_curve_buy() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let buyer = test_key(2);
    let tx = create_buy_transaction(&buyer, [9u8; 32], 1_000_000, 0, 0);

    assert_legacy_path_rejects(&mut blockchain, tx, "BondingCurveBuy requires BlockExecutor");
}

#[test]
fn test_legacy_path_rejects_bonding_curve_sell() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let seller = test_key(3);
    let tx = create_sell_transaction(&seller, [7u8; 32], 1_000_000, 0, 0);

    assert_legacy_path_rejects(&mut blockchain, tx, "BondingCurveSell requires BlockExecutor");
}

#[test]
fn test_legacy_path_rejects_bonding_curve_graduate() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let graduator = test_key(4);
    let tx = create_graduate_transaction(&graduator, [5u8; 32], [6u8; 32], 0);

    assert_legacy_path_rejects(
        &mut blockchain,
        tx,
        "BondingCurveGraduate requires BlockExecutor",
    );
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
