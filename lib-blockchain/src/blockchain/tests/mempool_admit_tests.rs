//! S2 tests (#2647): mempool admit gate, originator audit counter,
//! sled durability across restart.

use super::*;
use crate::storage::SledStore;
use crate::transaction::Transaction;
use crate::types::TransactionType;
use std::sync::Arc;

use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use crate::transaction::core::IdentityTransactionData;
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

    bc.add_system_transaction(make_tx(TransactionType::Coinbase), crate::blockchain::SystemOriginator::TestOriginator)
        .expect("system tx accept");
    bc.add_system_transaction(make_tx(TransactionType::Coinbase), crate::blockchain::SystemOriginator::TestOriginator)
        .expect("system tx accept");
    bc.add_system_transaction(
        make_tx(TransactionType::Coinbase),
        crate::blockchain::SystemOriginator::Other("other_originator"),
    )
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
    bc1.add_system_transaction(tx, crate::blockchain::SystemOriginator::DurabilityTest)
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
        .add_system_transaction(tx, crate::blockchain::SystemOriginator::Other("evil_originator"))
        .expect_err("unsigned mint must be rejected");
    assert!(
        err.to_string().contains("untrusted originator"),
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

    bc.add_system_transaction(tx, crate::blockchain::SystemOriginator::PouwMint)
        .expect("pouw mint allowed");
    assert_eq!(bc.pending_transactions.len(), 1);
}

#[test]
fn system_injection_rejects_pouw_mint_with_mismatched_recipient() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let recipient = [9u8; 32];
    let amount = 500u128;
    let mint_data = crate::transaction::TokenMintData {
        token_id: crate::contracts::utils::generate_lib_token_id(),
        to: [8u8; 32],
        amount,
    };
    let memo = format!("pouw:mint:{}:{}", hex::encode(recipient), amount).into_bytes();
    let tx = Transaction::new_token_mint(mint_data, Signature {
        signature: Vec::new(),
        public_key: PublicKey::new([0u8; 2592]),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    }, memo);

    let err = bc
        .add_system_transaction(tx, crate::blockchain::SystemOriginator::PouwMint)
        .expect_err("mismatched recipient must be rejected");
    assert!(err.to_string().contains("recipient does not match"));
}

#[test]
fn system_injection_rejects_token_mint_from_ipc_external() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let mint_data = crate::transaction::TokenMintData {
        token_id: crate::contracts::utils::generate_lib_token_id(),
        to: [7u8; 32],
        amount: 100,
    };
    let tx = Transaction::new_token_mint(mint_data, Signature {
        signature: vec![1u8; 64],
        public_key: PublicKey::new([0u8; 2592]),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    }, b"signed-but-untrusted".to_vec());

    let err = bc
        .add_system_transaction(tx, crate::blockchain::SystemOriginator::IpcExternal)
        .expect_err("ipc TokenMint must be rejected");
    assert!(err.to_string().contains("untrusted originator"));
}

#[test]
fn system_injection_rejects_wallet_registration_without_wallet_data() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let tx = make_tx(TransactionType::WalletRegistration);

    let err = bc
        .add_system_transaction(tx, crate::blockchain::SystemOriginator::AutoWalletRegistration)
        .expect_err("wallet registration without payload must be rejected");
    assert!(err.to_string().contains("missing wallet_data"));
}

#[test]
fn system_injection_rejects_funded_wallet_registration_from_non_treasury() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let wallet_data = crate::transaction::WalletTransactionData {
        wallet_id: crate::types::Hash::new([0x11; 32]),
        wallet_type: "Primary".to_string(),
        wallet_name: "test".to_string(),
        alias: None,
        public_key: vec![0x22; 32],
        owner_identity_id: None,
        seed_commitment: crate::types::Hash::new([0x33; 32]),
        created_at: 0,
        registration_fee: 0,
        capabilities: 0,
        initial_balance: 1_000,
    };
    let tx = Transaction::new_wallet_registration(
        wallet_data,
        vec![],
        Signature {
            signature: vec![0u8; 64],
            public_key: PublicKey::new([1u8; 2592]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        },
        vec![],
    );

    let err = bc
        .add_system_transaction(tx, crate::blockchain::SystemOriginator::AutoWalletRegistration)
        .expect_err("funded wallet registration must be rejected");
    assert!(err.to_string().contains("initial_balance=1000"));
}

fn make_client_identity_registration_tx(
    dilithium_pk: [u8; 2592],
    ownership_proof: Vec<u8>,
    did_override: Option<&str>,
) -> Transaction {
    let key_id = crate::types::hash::blake3_hash(&dilithium_pk);
    let did = did_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("did:zhtp:{}", hex::encode(key_id.as_bytes())));
    let identity_data = IdentityTransactionData::new(
        did,
        "test_user".to_string(),
        dilithium_pk.to_vec(),
        ownership_proof,
        "human".to_string(),
        crate::types::Hash::default(),
        0,
        0,
    );
    Transaction::new_identity_registration(
        identity_data,
        vec![],
        Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(dilithium_pk),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 1,
        },
        b"client-identity-register:test".to_vec(),
    )
}

#[test]
fn system_injection_accepts_valid_client_identity_registration() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let pk = [0xABu8; 2592];
    let tx = make_client_identity_registration_tx(pk, vec![0x01, 0x02], None);

    bc.add_system_transaction(
        tx,
        crate::blockchain::SystemOriginator::ClientIdentityRegistration,
    )
    .expect("valid client identity registration should be accepted");
    assert_eq!(bc.pending_transactions.len(), 1);
}

#[test]
fn system_injection_rejects_client_identity_registration_without_proof() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let pk = [0xCDu8; 2592];
    let tx = make_client_identity_registration_tx(pk, Vec::new(), None);

    let err = bc
        .add_system_transaction(
            tx,
            crate::blockchain::SystemOriginator::ClientIdentityRegistration,
        )
        .expect_err("missing ownership_proof must be rejected");
    assert!(err.to_string().contains("ownership_proof"));
}

#[test]
fn system_injection_rejects_client_identity_registration_did_mismatch() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let pk = [0xEFu8; 2592];
    let tx = make_client_identity_registration_tx(pk, vec![0x01], Some("did:zhtp:deadbeef"));

    let err = bc
        .add_system_transaction(
            tx,
            crate::blockchain::SystemOriginator::ClientIdentityRegistration,
        )
        .expect_err("DID/public-key mismatch must be rejected");
    assert!(err.to_string().contains("DID does not match"));
}

#[test]
fn system_injection_rejects_treasury_welcome_bonus_with_bad_memo() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let wallet_id = [0x11u8; 32];
    let mint_data = crate::transaction::TokenMintData {
        token_id: crate::contracts::utils::generate_lib_token_id(),
        to: wallet_id,
        amount: lib_types::sov::atoms(5_000),
    };
    let tx = Transaction::new_token_mint(
        mint_data,
        Signature {
            signature: Vec::new(),
            public_key: PublicKey::new([0u8; 2592]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        },
        b"WRONG_PREFIX:deadbeef".to_vec(),
    );

    let err = bc
        .add_system_transaction(tx, crate::blockchain::SystemOriginator::TreasuryWalletBootstrap)
        .expect_err("invalid welcome bonus memo must be rejected");
    assert!(err.to_string().contains("WELCOME_BONUS_V1"));
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
