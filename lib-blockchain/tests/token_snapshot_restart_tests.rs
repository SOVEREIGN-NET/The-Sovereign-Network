use std::sync::Arc;

use anyhow::Result;
use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::contracts::TokenContract;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::storage::{BlockchainStore, SledStore, TokenStateSnapshot};
use lib_blockchain::transaction::{TokenTransferData, Transaction, TransactionInput, TransactionOutput, WalletTransactionData};
use lib_blockchain::types::{Difficulty, Hash, TransactionType};
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

fn test_pubkey(id: u8) -> PublicKey {
    PublicKey::new(vec![id; 32])
}

fn test_signature(pubkey: &PublicKey) -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: pubkey.clone(),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 1_700_000_000,
    }
}

fn wallet_registration_tx(wallet_id: [u8; 32], owner_pubkey: &PublicKey) -> Transaction {
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
            initial_balance: 0,
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
    }
}

fn token_transfer_tx(
    sender: &PublicKey,
    token_id: [u8; 32],
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    nonce: u64,
) -> Transaction {
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenTransfer,
        inputs: vec![TransactionInput {
            previous_output: Hash::new([7u8; 32]),
            output_index: 0,
            nullifier: Hash::new([7u8; 32]),
            zk_proof: lib_blockchain::integration::zk_integration::ZkTransactionProof::default(),
        }],
        outputs: vec![TransactionOutput {
            commitment: Hash::new([8u8; 32]),
            note: Hash::new([9u8; 32]),
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
    }
}

fn block(height: u64, txs: Vec<Transaction>) -> Block {
    let header = BlockHeader {
        version: 1,
        height,
        timestamp: 1_700_000_000 + height,
        previous_block_hash: Hash::zero(),
        merkle_root: Hash::zero(),
        state_root: Hash::default(),
        block_hash: Hash::zero(),
        nonce: 0,
        difficulty: Difficulty::from_bits(0),
        cumulative_difficulty: Difficulty::from_bits(0),
        transaction_count: txs.len() as u32,
        block_size: 0,
        fee_model_version: 2,
    };
    Block::new(header, txs)
}

fn wallet_key(wallet_id: &[u8; 32]) -> PublicKey {
    PublicKey {
        dilithium_pk: Vec::new(),
        kyber_pk: Vec::new(),
        key_id: *wallet_id,
    }
}

#[test]
fn test_restart_restores_token_snapshot_and_nonces() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let sender_pk = test_pubkey(1);
    let recipient_pk = test_pubkey(2);
    let sender_wallet = [0x11u8; 32];
    let recipient_wallet = [0x22u8; 32];
    let sov_token_id = generate_lib_token_id();

    let mut sov = TokenContract::new_sov_native();
    sov.mint(&wallet_key(&sender_wallet), 10_000).unwrap();
    sov.transfer(
        &lib_blockchain::contracts::executor::ExecutionContext::new(
            wallet_key(&sender_wallet),
            0,
            1_700_000_000,
            0,
            [0u8; 32],
        ),
        &wallet_key(&recipient_wallet),
        1_500,
    )
    .unwrap();

    let mut snapshot = TokenStateSnapshot::default();
    snapshot.token_contracts.insert(sov_token_id, sov);
    snapshot
        .token_nonces
        .insert((sov_token_id, sender_wallet), 1);

    store.begin_block(0)?;
    store.put_token_state_snapshot(&snapshot)?;
    store.append_block(&block(
        0,
        vec![
            wallet_registration_tx(sender_wallet, &sender_pk),
            wallet_registration_tx(recipient_wallet, &recipient_pk),
        ],
    ))?;
    store.commit_block()?;

    let reloaded = lib_blockchain::Blockchain::load_from_store(store)?
        .expect("Expected blockchain to load from snapshot");

    let token = reloaded
        .token_contracts
        .get(&sov_token_id)
        .expect("SOV token must exist");
    assert_eq!(token.balance_of(&wallet_key(&sender_wallet)), 8_500);
    assert_eq!(token.balance_of(&wallet_key(&recipient_wallet)), 1_500);
    assert_eq!(reloaded.get_token_nonce(&sov_token_id, &sender_wallet), 1);

    let replay_block = block(
        1,
        vec![token_transfer_tx(
            &sender_pk,
            sov_token_id,
            sender_wallet,
            recipient_wallet,
            100,
            0,
        )],
    );

    let mut replay_chain = reloaded;
    let replay_result = replay_chain.process_token_transactions(&replay_block);
    assert!(replay_result.is_err(), "replayed nonce should be rejected");

    Ok(())
}

#[test]
fn test_cross_node_loads_converge_to_identical_token_state() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let sender_pk = test_pubkey(1);
    let recipient_pk = test_pubkey(2);
    let sender_wallet = [0x33u8; 32];
    let recipient_wallet = [0x44u8; 32];
    let sov_token_id = generate_lib_token_id();

    let mut sov = TokenContract::new_sov_native();
    sov.mint(&wallet_key(&sender_wallet), 20_000).unwrap();
    sov.transfer(
        &lib_blockchain::contracts::executor::ExecutionContext::new(
            wallet_key(&sender_wallet),
            0,
            1_700_000_000,
            0,
            [0u8; 32],
        ),
        &wallet_key(&recipient_wallet),
        2_500,
    )
    .unwrap();

    let mut snapshot = TokenStateSnapshot::default();
    snapshot.token_contracts.insert(sov_token_id, sov);
    snapshot
        .token_nonces
        .insert((sov_token_id, sender_wallet), 1);

    store.begin_block(0)?;
    store.put_token_state_snapshot(&snapshot)?;
    store.append_block(&block(
        0,
        vec![
            wallet_registration_tx(sender_wallet, &sender_pk),
            wallet_registration_tx(recipient_wallet, &recipient_pk),
        ],
    ))?;
    store.commit_block()?;

    let node_a = lib_blockchain::Blockchain::load_from_store(store.clone())?
        .expect("node A should load");
    let node_b = lib_blockchain::Blockchain::load_from_store(store)?
        .expect("node B should load");

    let token_a = node_a
        .token_contracts
        .get(&sov_token_id)
        .expect("node A token missing");
    let token_b = node_b
        .token_contracts
        .get(&sov_token_id)
        .expect("node B token missing");

    assert_eq!(token_a.balance_of(&wallet_key(&sender_wallet)), 17_500);
    assert_eq!(token_b.balance_of(&wallet_key(&sender_wallet)), 17_500);
    assert_eq!(token_a.balance_of(&wallet_key(&recipient_wallet)), 2_500);
    assert_eq!(token_b.balance_of(&wallet_key(&recipient_wallet)), 2_500);
    assert_eq!(node_a.get_token_nonce(&sov_token_id, &sender_wallet), 1);
    assert_eq!(node_b.get_token_nonce(&sov_token_id, &sender_wallet), 1);
    assert_eq!(node_a.token_nonces, node_b.token_nonces);
    assert_eq!(node_a.token_contracts.len(), node_b.token_contracts.len());

    Ok(())
}

#[test]
fn test_uncommitted_block_does_not_leak_token_state_after_restart() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let db_path = tmp.path().to_path_buf();

    let sender_wallet = [0x55u8; 32];
    let recipient_wallet = [0x66u8; 32];
    let sov_token_id = generate_lib_token_id();

    let committed_store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(&db_path)?);
    let mut committed_token = TokenContract::new_sov_native();
    committed_token.mint(&wallet_key(&sender_wallet), 9_000).unwrap();

    let mut committed_snapshot = TokenStateSnapshot::default();
    committed_snapshot
        .token_contracts
        .insert(sov_token_id, committed_token);
    committed_snapshot
        .token_nonces
        .insert((sov_token_id, sender_wallet), 0);

    committed_store.begin_block(0)?;
    committed_store.put_token_state_snapshot(&committed_snapshot)?;
    committed_store.append_block(&block(0, vec![]))?;
    committed_store.commit_block()?;
    drop(committed_store);

    let crashing_store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(&db_path)?);
    let mut uncommitted_token = TokenContract::new_sov_native();
    uncommitted_token.mint(&wallet_key(&sender_wallet), 9_000).unwrap();
    uncommitted_token
        .transfer(
            &lib_blockchain::contracts::executor::ExecutionContext::new(
                wallet_key(&sender_wallet),
                1,
                1_700_000_001,
                0,
                [1u8; 32],
            ),
            &wallet_key(&recipient_wallet),
            1_000,
        )
        .unwrap();

    let mut uncommitted_snapshot = TokenStateSnapshot::default();
    uncommitted_snapshot
        .token_contracts
        .insert(sov_token_id, uncommitted_token);
    uncommitted_snapshot
        .token_nonces
        .insert((sov_token_id, sender_wallet), 1);

    crashing_store.begin_block(1)?;
    crashing_store.put_token_state_snapshot(&uncommitted_snapshot)?;
    crashing_store.append_block(&block(1, vec![]))?;
    // Intentionally do not commit block 1 to simulate crash.
    drop(crashing_store);

    let recovered_store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(&db_path)?);
    let recovered = lib_blockchain::Blockchain::load_from_store(recovered_store)?
        .expect("recovery load should succeed");

    let token = recovered
        .token_contracts
        .get(&sov_token_id)
        .expect("SOV token should exist after recovery");
    assert_eq!(token.balance_of(&wallet_key(&sender_wallet)), 9_000);
    assert_eq!(token.balance_of(&wallet_key(&recipient_wallet)), 0);
    assert_eq!(recovered.get_token_nonce(&sov_token_id, &sender_wallet), 0);
    assert_eq!(recovered.height, 0);

    Ok(())
}
