//! S2 tests (#2647): mempool admit gate, originator audit counter,
//! sled durability across restart.

use super::*;
use crate::storage::SledStore;
use crate::transaction::Transaction;
use crate::types::TransactionType;
use std::sync::Arc;

use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_mempool::{MempoolConfigExt, MempoolStateExt};

fn make_tx(tx_type: TransactionType) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: tx_type,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: Signature {
            signature: vec![0u8; 64],
            public_key: PublicKey::new([1u8; 2592]),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        },
        memo: vec![],
        payload: crate::transaction::TransactionPayload::None,
    }
}

#[test]
fn admit_gate_rejects_when_tx_count_cap_exceeded() {
    let mut bc = Blockchain::new().expect("blockchain construct");

    // Force the admit gate to reject every tx: capacity = 0.
    bc.mempool_config = lib_mempool::MempoolConfig {
        max_tx_count: 0,
        ..lib_mempool::MempoolConfig::audit_only()
    };

    let result = bc.add_pending_transaction(make_tx(TransactionType::Transfer));
    let err = result.expect_err("admit() should reject when capacity is 0");
    assert!(
        err.to_string().contains("mempool admit"),
        "expected admit rejection, got: {}",
        err
    );
    assert!(
        bc.pending_transactions.is_empty(),
        "rejected tx must not enter the pending queue"
    );
}

#[test]
fn system_tx_originator_counter_increments_per_call() {
    let mut bc = Blockchain::new().expect("blockchain construct");

    bc.add_system_transaction(make_tx(TransactionType::Coinbase), "test_originator")
        .expect("system tx accept");
    bc.add_system_transaction(make_tx(TransactionType::Coinbase), "test_originator")
        .expect("system tx accept");
    bc.add_system_transaction(make_tx(TransactionType::Coinbase), "other_originator")
        .expect("system tx accept");

    assert_eq!(
        *bc.system_tx_originators.get("test_originator").unwrap(),
        2,
        "test_originator should count both injections"
    );
    assert_eq!(
        *bc.system_tx_originators.get("other_originator").unwrap(),
        1,
    );
    assert_eq!(bc.pending_transactions.len(), 3);
}

#[test]
fn pending_tx_survives_store_reattach() {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("pending_recovery_store");
    let store = Arc::new(SledStore::open(&store_path).unwrap());

    let mut bc1 = Blockchain::new().expect("blockchain construct");
    bc1.set_store(store.clone());

    let tx = make_tx(TransactionType::Coinbase);
    let tx_hash = tx.hash();
    bc1.add_system_transaction(tx, "durability_test")
        .expect("system tx accept");
    assert_eq!(bc1.pending_transactions.len(), 1);

    // Simulate restart: drop bc1, build a fresh Blockchain, re-attach the
    // same on-disk store. The recovery hook on set_store should re-hydrate
    // pending_transactions and the admit state.
    drop(bc1);

    let mut bc2 = Blockchain::new().expect("blockchain construct");
    bc2.set_store(store);

    assert_eq!(
        bc2.pending_transactions.len(),
        1,
        "pending tx must be recovered from sled on reattach"
    );
    assert_eq!(
        bc2.pending_transactions[0].hash(),
        tx_hash,
        "recovered tx hash must match the one that was persisted"
    );
    assert_eq!(
        bc2.mempool_state.tx_count, 1,
        "mempool admission state must reflect the recovered tx"
    );
}

#[test]
fn system_injection_rejects_unsigned_token_mint_from_unknown_originator() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let mint_data = crate::transaction::TokenMintData {
        token_id: crate::contracts::utils::generate_lib_token_id(),
        to: [7u8; 32],
        amount: 100,
    };
    let tx = Transaction::new_token_mint(mint_data, Signature {
        signature: Vec::new(),
        public_key: PublicKey::new([0u8; 2592]),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    }, b"not-a-pouw-mint".to_vec());

    let err = bc
        .add_system_transaction(tx, "admin_sov_mint")
        .expect_err("unsigned mint must be rejected");
    assert!(
        err.to_string().contains("rejecting unsigned TokenMint"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn system_injection_allows_pouw_mint_with_matching_memo() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let recipient = [9u8; 32];
    let amount = 500u128;
    let mint_data = crate::transaction::TokenMintData {
        token_id: crate::contracts::utils::generate_lib_token_id(),
        to: recipient,
        amount,
    };
    let memo = format!("pouw:mint:{}:{}", hex::encode(recipient), amount).into_bytes();
    let tx = Transaction::new_token_mint(mint_data, Signature {
        signature: Vec::new(),
        public_key: PublicKey::new([0u8; 2592]),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    }, memo);

    bc.add_system_transaction(tx, "pouw_mint").expect("pouw mint allowed");
    assert_eq!(bc.pending_transactions.len(), 1);
}

#[test]
fn audit_only_config_admits_zero_fee_transactions() {
    // The S2 default (`audit_only`) must not reject the existing zero-fee
    // traffic (coinbase, system mints) at the admission gate; BlockExecutor
    // remains the fee authority during S2.
    let bc = Blockchain::new().expect("blockchain construct");
    let tx = make_tx(TransactionType::Coinbase);
    let admit_tx = tx.to_admit_tx();
    let result = lib_mempool::admit(
        &admit_tx,
        &lib_fees::FeeParams::default(),
        &bc.mempool_config,
        &bc.mempool_state,
        0,
    );
    assert!(
        matches!(result, lib_mempool::AdmitResult::Accepted),
        "audit_only config must accept zero-fee coinbase; got: {:?}",
        result
    );
}
