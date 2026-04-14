// CBE token field removed from Blockchain struct (EPIC-001 Phase 1).
// These tests verified cbe_token in-memory state and are no longer applicable.
// Retained tests that don't depend on cbe_token below.

use super::*;

#[test]
fn test_sov_wallet_registration_deficit_minting() {
    use crate::contracts::utils::generate_lib_token_id;

    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let sov_token_id = generate_lib_token_id();
    blockchain.ensure_sov_token_contract();

    let mut wallet_id_bytes = [0u8; 32];
    wallet_id_bytes[..13].copy_from_slice(b"test-wallet-1");
    let recipient_pk = Blockchain::wallet_key_for_sov(&wallet_id_bytes);

    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        token.mint(&recipient_pk, 3000).expect("Pre-mint should succeed");
    }

    let current_balance = blockchain
        .token_contracts
        .get(&sov_token_id)
        .map(|token| token.balance_of(&recipient_pk))
        .unwrap_or(0);
    assert_eq!(current_balance, 3000, "Pre-minted balance should be 3000");

    let wallet_data = crate::transaction::core::WalletTransactionData {
        wallet_id: Hash::new(wallet_id_bytes),
        wallet_type: "Primary".to_string(),
        wallet_name: "Test Wallet".to_string(),
        alias: None,
        public_key: vec![0u8; 32],
        owner_identity_id: None,
        seed_commitment: Hash::default(),
        created_at: 0,
        registration_fee: 0,
        capabilities: 0,
        initial_balance: 5000,
    };

    let tx = Transaction::new_wallet_registration(
        wallet_data,
        vec![],
        crate::integration::crypto_integration::Signature::default(),
        b"test".to_vec(),
    );

    let prev_hash = blockchain.blocks.last().unwrap().hash();
    let block = crate::block::BlockBuilder::new(prev_hash, 1, crate::types::Difficulty::default())
        .version(1)
        .timestamp(1001)
        .transactions(vec![tx])
        .build()
        .expect("block build should succeed");

    blockchain
        .process_wallet_transactions(&block)
        .expect("Should process successfully");

    let final_balance = blockchain
        .token_contracts
        .get(&sov_token_id)
        .map(|token| token.balance_of(&recipient_pk))
        .unwrap_or(0);

    assert_eq!(
        final_balance, 5000,
        "Final balance should be 5000 (3000 pre-minted + 2000 deficit)"
    );
}

#[test]
fn test_cbe_bonding_curve_starts_with_zero_supply() {
    let blockchain = Blockchain::new().expect("Failed to create blockchain");

    use crate::contracts::tokens::{CBE_NAME, CBE_SYMBOL};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let token_id = {
        let mut hasher = DefaultHasher::new();
        CBE_NAME.hash(&mut hasher);
        CBE_SYMBOL.hash(&mut hasher);
        let hash = hasher.finish();
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());
        for i in 8..32 {
            id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
        }
        id
    };

    let cbe_curve_token = blockchain
        .bonding_curve_registry
        .get(&token_id)
        .expect("CBE bonding curve token should exist");

    assert_eq!(
        cbe_curve_token.total_supply, 0,
        "CBE bonding curve should start with 0 circulating supply"
    );
}
