//! Bonding Curve Transaction Integration Tests
//!
//! The legacy user-deployable bonding curve execution path has been removed (#1945).
//! The canonical CBE curve is initialized at genesis and executed via the
//! fixed-width memo payload lane (BondingCurveBuy/Sell canonical path).

use lib_blockchain::{contracts::bonding_curve::Phase, contracts::tokens::CBE_SYMBOL, Blockchain};

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

    let cbe = blockchain
        .bonding_curve_registry
        .get(&cbe_token_id)
        .unwrap();
    assert_eq!(cbe.name, "CBE Equity");
    assert_eq!(cbe.symbol, CBE_SYMBOL);
    assert_eq!(cbe.phase, Phase::Curve);
    assert!(cbe.sell_enabled);
}

// ============================================================================
// Legacy Path Rejection Regression Test (#1945)
// ============================================================================
//
// This test ensures the safety guard in blockchain.rs that rejects
// BondingCurve* transactions at the process_token_transactions layer
// remains in place. This prevents accidental re-enablement of the
// legacy non-executor mutation path.

#[test]
fn test_legacy_bonding_curve_path_rejected() {
    use lib_blockchain::block::Block;
    use lib_blockchain::transaction::{Transaction, TransactionPayload};
    use lib_blockchain::types::TransactionType;
    use lib_crypto::types::{PublicKey, Signature, SignatureAlgorithm};

    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");

    // Create a minimal PublicKey
    let fake_public_key = PublicKey {
        dilithium_pk: vec![0u8; 32],
        kyber_pk: vec![0u8; 32],
        key_id: [0u8; 32],
    };

    // Create a minimal BondingCurveDeploy transaction
    let fake_signature = Signature {
        signature: vec![0u8; 64],
        public_key: fake_public_key,
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 1000,
    };

    let bc_deploy_tx = Transaction {
        version: 1,
        chain_id: 0x03, // development
        transaction_type: TransactionType::BondingCurveDeploy,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: fake_signature,
        memo: vec![],
        payload: TransactionPayload::None,
    };

    let block = Block {
        header: lib_blockchain::block::BlockHeader {
            version: 1,
            previous_block_hash: [0u8; 32].into(),
            merkle_root: [0u8; 32].into(),
            timestamp: 1000,
            difficulty: Default::default(),
            nonce: 0,
            height: 1,
            transaction_count: 1,
            block_size: 0,
            cumulative_difficulty: Default::default(),
            fee_model_version: 1,
            block_hash: [0u8; 32].into(),
            state_root: [0u8; 32].into(),
        },
        transactions: vec![bc_deploy_tx],
    };

    // The legacy path should be rejected
    let result = blockchain.process_token_transactions(&block);
    assert!(
        result.is_err(),
        "Legacy BondingCurveDeploy path should be rejected"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("legacy bonding-curve mutation path is disabled"),
        "Error should mention legacy path disabled"
    );
}
