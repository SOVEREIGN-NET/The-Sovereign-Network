use std::sync::Arc;

use anyhow::Result;
use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::storage::{BlockchainStore, SledStore, WalletProjectionRecord};
use lib_blockchain::transaction::{Transaction, TransactionPayload, WalletTransactionData};
use lib_blockchain::types::{Hash, TransactionType};
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

mod common;

fn test_pubkey(_id: u8) -> PublicKey { common::crypto_fixtures::dummy_public_key() }
fn test_signature(pubkey: &PublicKey) -> Signature { common::crypto_fixtures::signature_for(pubkey) }

fn wallet_data(wallet_id: [u8; 32], owner_pubkey: &PublicKey, name: &str) -> WalletTransactionData {
    WalletTransactionData {
        wallet_id: Hash::new(wallet_id),
        wallet_type: "Primary".to_string(),
        wallet_name: name.to_string(),
        alias: None,
        public_key: owner_pubkey.dilithium_pk.to_vec(),
        owner_identity_id: None,
        seed_commitment: Hash::zero(),
        created_at: 1_700_000_000,
        registration_fee: 0,
        capabilities: 0,
        initial_balance: 0,
    }
}

fn wallet_tx(
    tx_type: TransactionType,
    wallet: WalletTransactionData,
    owner_pubkey: &PublicKey,
) -> Transaction {
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: tx_type,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(owner_pubkey),
        memo: Vec::new(),
        payload: TransactionPayload::Wallet(wallet),
    }
}

fn block(height: u64, txs: Vec<Transaction>) -> Block {
    let header = BlockHeader {
        version: 1,
        previous_hash: Hash::zero().into(),
        data_helix_root: Hash::zero().into(),
        timestamp: 1_700_000_000 + height,
        height,
        verification_helix_root: [0u8; 32],
        state_root: Hash::default().into(),
        bft_quorum_root: [0u8; 32],
        block_hash: Hash::zero(),
    };
    Block::new(header, txs)
}

#[test]
fn test_wallet_projection_loaded_state_matches_replay_rebuilt_state() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let owner = test_pubkey(1);
    let wallet_id = [0x41u8; 32];
    let wallet = wallet_data(wallet_id, &owner, "Projection Wallet");
    let canonical_record = WalletProjectionRecord {
        wallet_data: wallet.clone(),
        committed_at_height: 0,
    };

    store.begin_block(0)?;
    store.put_wallet_projection(&wallet_id, &canonical_record)?;
    store.append_block(&block(
        0,
        vec![wallet_tx(
            TransactionType::WalletRegistration,
            wallet.clone(),
            &owner,
        )],
    ))?;
    store.commit_block()?;

    let projection_loaded =
        lib_blockchain::Blockchain::load_from_store(store.clone())?.expect("projection load");

    store.replace_wallet_projections(&[])?;

    let replay_rebuilt =
        lib_blockchain::Blockchain::load_from_store(store.clone())?.expect("replay rebuild");

    let wallet_id_hex = hex::encode(wallet_id);
    assert_eq!(
        projection_loaded.wallet_registry.get(&wallet_id_hex),
        replay_rebuilt.wallet_registry.get(&wallet_id_hex)
    );
    assert_eq!(
        projection_loaded.wallet_blocks.get(&wallet_id_hex),
        replay_rebuilt.wallet_blocks.get(&wallet_id_hex)
    );
    assert_eq!(replay_rebuilt.wallet_blocks.get(&wallet_id_hex), Some(&0));
    assert_eq!(store.get_wallet_projection(&wallet_id)?, Some(canonical_record));

    Ok(())
}

#[test]
fn test_uncommitted_wallet_projection_update_does_not_leak_after_restart() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let db_path = tmp.path().to_path_buf();

    let owner = test_pubkey(2);
    let wallet_id = [0x52u8; 32];
    let wallet = wallet_data(wallet_id, &owner, "Committed Wallet");
    let committed_record = WalletProjectionRecord {
        wallet_data: wallet.clone(),
        committed_at_height: 0,
    };

    let committed_store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(&db_path)?);
    committed_store.begin_block(0)?;
    committed_store.put_wallet_projection(&wallet_id, &committed_record)?;
    committed_store.append_block(&block(
        0,
        vec![wallet_tx(
            TransactionType::WalletRegistration,
            wallet.clone(),
            &owner,
        )],
    ))?;
    committed_store.commit_block()?;
    drop(committed_store);

    let mut updated_wallet = wallet.clone();
    updated_wallet.wallet_name = "Uncommitted Wallet Update".to_string();

    let crashing_store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(&db_path)?);
    crashing_store.begin_block(1)?;
    crashing_store.put_wallet_projection(
        &wallet_id,
        &WalletProjectionRecord {
            wallet_data: updated_wallet.clone(),
            committed_at_height: 1,
        },
    )?;
    crashing_store.append_block(&block(
        1,
        vec![wallet_tx(
            TransactionType::WalletUpdate,
            updated_wallet,
            &owner,
        )],
    ))?;
    // Intentionally do not commit block 1 to simulate a crash.
    drop(crashing_store);

    let recovered_store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(&db_path)?);
    let recovered =
        lib_blockchain::Blockchain::load_from_store(recovered_store.clone())?.expect("recovered");

    let wallet_id_hex = hex::encode(wallet_id);
    assert_eq!(recovered.height, 0);
    assert_eq!(recovered.wallet_registry.get(&wallet_id_hex), Some(&wallet));
    assert_eq!(recovered.wallet_blocks.get(&wallet_id_hex), Some(&0));
    assert_eq!(
        recovered_store.get_wallet_projection(&wallet_id)?,
        Some(committed_record)
    );

    Ok(())
}
