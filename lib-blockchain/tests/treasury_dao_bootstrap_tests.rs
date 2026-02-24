//! TREASURY-DAO: DAO Treasury Initialization Tests
//!
//! Verifies that the deterministic treasury wallet is bootstrapped correctly on
//! every node, survives persistence round-trips, and is consistent with the fee
//! crediting path.

use lib_blockchain::Blockchain;
use lib_blockchain::contracts::TokenContract;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::types::hash::blake3_hash;
use lib_crypto::types::keys::PublicKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The canonical deterministic treasury wallet ID (hex).
fn expected_treasury_id_hex() -> String {
    hex::encode(blake3_hash(b"SOV_DAO_TREASURY_V1").as_bytes())
}

/// Build a wallet-key-for-sov style PublicKey from raw 32-byte wallet ID.
/// This mirrors the private `wallet_key_for_sov` method used by fee crediting.
fn wallet_key_for_sov(wallet_id: &[u8; 32]) -> PublicKey {
    PublicKey {
        dilithium_pk: vec![],
        kyber_pk: vec![],
        key_id: *wallet_id,
    }
}

// ---------------------------------------------------------------------------
// TREASURY-DAO-2 Tests
// ---------------------------------------------------------------------------

#[test]
fn test_treasury_wallet_initialized_on_new_blockchain() {
    let blockchain = Blockchain::default();

    let wallet_id = blockchain
        .dao_treasury_wallet_id
        .as_ref()
        .expect("dao_treasury_wallet_id must be set after Blockchain::default()");

    assert_eq!(
        *wallet_id,
        expected_treasury_id_hex(),
        "Treasury wallet ID must be the deterministic blake3 hash"
    );

    // Registry entry must exist
    assert!(
        blockchain.wallet_registry.contains_key(wallet_id),
        "Treasury wallet must be present in wallet_registry"
    );

    let entry = &blockchain.wallet_registry[wallet_id];
    assert_eq!(entry.wallet_type, "treasury");
    assert_eq!(entry.wallet_name, "DAO Treasury");
    assert_eq!(entry.initial_balance, 0);
}

#[test]
fn test_treasury_wallet_deterministic_id() {
    // Two independently created blockchains must have the same treasury wallet ID.
    let bc1 = Blockchain::default();
    let bc2 = Blockchain::default();

    assert_eq!(
        bc1.dao_treasury_wallet_id,
        bc2.dao_treasury_wallet_id,
        "Treasury wallet ID must be identical across independent blockchain instances"
    );

    let expected = expected_treasury_id_hex();
    assert_eq!(
        bc1.dao_treasury_wallet_id.as_deref(),
        Some(expected.as_str()),
        "Treasury wallet ID must equal blake3(\"SOV_DAO_TREASURY_V1\")"
    );
}

#[test]
fn test_treasury_wallet_idempotent() {
    // Initial bootstrap: exactly one entry.
    let blockchain = Blockchain::default();

    let wallet_id = blockchain.dao_treasury_wallet_id.as_ref().unwrap().clone();

    let count = blockchain
        .wallet_registry
        .keys()
        .filter(|k| *k == &wallet_id)
        .count();
    assert_eq!(count, 1, "There must be exactly one treasury wallet registry entry after initial bootstrap");

    assert_eq!(
        blockchain.dao_treasury_wallet_id.as_deref(),
        Some(wallet_id.as_str())
    );

    // Persist and reload — load_from_file calls ensure_treasury_wallet() again.
    // Must not create a duplicate entry.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("blockchain_idempotent.dat");

    #[allow(deprecated)]
    blockchain.save_to_file(&path).expect("save_to_file");

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load_from_file");

    let reloaded_count = loaded
        .wallet_registry
        .keys()
        .filter(|k| *k == &wallet_id)
        .count();
    assert_eq!(
        reloaded_count, 1,
        "load_from_file must not create duplicate treasury wallet registry entries"
    );

    assert_eq!(
        loaded.dao_treasury_wallet_id.as_deref(),
        Some(wallet_id.as_str()),
        "dao_treasury_wallet_id must remain unchanged after reconstruction"
    );
}

#[test]
fn test_treasury_wallet_survives_round_trip() {
    let mut blockchain = Blockchain::default();

    // Ensure SOV token contract is present (needed for persistence tests).
    let sov_token_id = generate_lib_token_id();
    if !blockchain.token_contracts.contains_key(&sov_token_id) {
        blockchain
            .token_contracts
            .insert(sov_token_id, TokenContract::new_sov_native());
    }

    let original_id = blockchain.dao_treasury_wallet_id.clone().unwrap();

    // Persist to a temp file and reload.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("blockchain.dat");

    #[allow(deprecated)]
    blockchain.save_to_file(&path).expect("save_to_file");

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load_from_file");

    // Treasury wallet ID must survive the round-trip.
    assert_eq!(
        loaded.dao_treasury_wallet_id.as_deref(),
        Some(original_id.as_str()),
        "dao_treasury_wallet_id must survive save_to_file / load_from_file"
    );

    // Registry entry must also survive.
    assert!(
        loaded.wallet_registry.contains_key(&original_id),
        "Treasury wallet registry entry must survive persistence round-trip"
    );
}

#[test]
fn test_block_fees_credited_to_treasury() {
    // Verify that get_dao_treasury_balance() reads balances that are credited
    // using the same key pattern as the fee crediting code (wallet_key_for_sov).
    let mut blockchain = Blockchain::default();

    let treasury_id_hex = blockchain
        .dao_treasury_wallet_id
        .clone()
        .expect("treasury must be initialized");

    let treasury_id_bytes = hex::decode(&treasury_id_hex).expect("valid hex");
    let mut treasury_id = [0u8; 32];
    treasury_id.copy_from_slice(&treasury_id_bytes);

    // Ensure SOV token contract exists.
    let sov_token_id = generate_lib_token_id();
    blockchain
        .token_contracts
        .entry(sov_token_id)
        .or_insert_with(TokenContract::new_sov_native);

    // Initial balance must be zero.
    let balance_before = blockchain
        .get_dao_treasury_balance()
        .expect("get_dao_treasury_balance");
    assert_eq!(balance_before, 0, "Treasury must start with zero balance");

    // Simulate what process_token_transactions does: credit fees via wallet_key_for_sov.
    let fee_amount: u64 = 42_000_000;
    let treasury_key = wallet_key_for_sov(&treasury_id);
    if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
        let current = token.balance_of(&treasury_key);
        token
            .balances
            .insert(treasury_key, current.saturating_add(fee_amount));
    }

    // get_dao_treasury_balance must reflect the credited fees.
    let balance_after = blockchain
        .get_dao_treasury_balance()
        .expect("get_dao_treasury_balance");
    assert_eq!(
        balance_after, fee_amount,
        "Treasury balance must equal credited fee amount ({} SOV)",
        fee_amount
    );
}
