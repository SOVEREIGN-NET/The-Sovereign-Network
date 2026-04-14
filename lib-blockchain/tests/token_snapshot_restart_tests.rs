use std::sync::Arc;

use anyhow::Result;
use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::execution::executor::{BlockExecutor, ExecutorConfig};
use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::storage::{Address, BlockchainStore, SledStore, TokenId};
use lib_blockchain::transaction::{
    TokenMintData, TokenTransferData, Transaction, WalletTransactionData,
};
use lib_blockchain::types::Hash;
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

fn test_pubkey(id: u8) -> PublicKey {
    PublicKey::new([0u8; 2592])
}

fn test_signature(pubkey: &PublicKey) -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: pubkey.clone(),
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: 1_700_000_000,
    }
}

fn wallet_registration_tx(wallet_id: [u8; 32], owner_pubkey: &PublicKey) -> Transaction {
    Transaction::new_wallet_registration(
        WalletTransactionData {
            wallet_id: Hash::new(wallet_id),
            wallet_type: "Primary".to_string(),
            wallet_name: format!("Wallet-{}", hex::encode(&wallet_id[..4])),
            alias: None,
            public_key: owner_pubkey.dilithium_pk.to_vec(),
            owner_identity_id: None,
            seed_commitment: Hash::zero(),
            created_at: 1_700_000_000,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        },
        Vec::new(),
        test_signature(owner_pubkey),
        Vec::new(),
    )
}

fn token_transfer_tx(
    sender: &PublicKey,
    token_id: [u8; 32],
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    nonce: u64,
) -> Transaction {
    Transaction::new_token_transfer(
        TokenTransferData {
            token_id,
            from,
            to,
            amount: amount as u128,
            nonce,
        },
        test_signature(sender),
        b"restart-test-transfer".to_vec(),
    )
}

fn token_mint_tx(signer: &PublicKey, token_id: [u8; 32], to: [u8; 32], amount: u64) -> Transaction {
    Transaction::new_token_mint(
        TokenMintData {
            token_id,
            to,
            amount: amount as u128,
        },
        test_signature(signer),
        b"restart-test-mint".to_vec(),
    )
}

fn create_genesis_block() -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = 0x01;
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_hash: Hash::default().into(),
        data_helix_root: Hash::default().into(),
        timestamp: 1_700_000_000,
        height: 0,
        verification_helix_root: [0u8; 32],
        state_root: Hash::default().into(),
        bft_quorum_root: [0u8; 32],
        block_hash,
    };
    Block::new(header, vec![])
}

fn create_block_at_height(height: u64, prev_hash: Hash, txs: Vec<Transaction>) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = height as u8 + 1;
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_hash: prev_hash.into(),
        data_helix_root: Hash::default().into(),
        timestamp: 1_700_000_000 + height,
        height,
        verification_helix_root: [0u8; 32],
        state_root: Hash::default().into(),
        bft_quorum_root: [0u8; 32],
        block_hash,
    };
    Block::new(header, txs)
}

fn wallet_key(wallet_id: &[u8; 32]) -> PublicKey {
    // Match the executor's wallet_key_for_sov format:
    // dilithium_pk = [0u8; 2592], kyber_pk = [0u8; 1568], key_id = wallet_id
    PublicKey {
        dilithium_pk: [0u8; 2592],
        kyber_pk: [0u8; 1568],
        key_id: *wallet_id,
    }
}

fn funded_recipient_count(token: &lib_blockchain::contracts::TokenContract) -> usize {
    token.holder_count()
}

#[test]
fn test_restart_replays_committed_token_state_and_nonces() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let sender_pk = test_pubkey(1);
    let recipient_pk = test_pubkey(2);
    let sender_wallet = [0x11u8; 32];
    let recipient_wallet = [0x22u8; 32];
    let sov_token_id = generate_lib_token_id();

    // Create and apply genesis first
    let genesis = create_genesis_block();
    let executor = BlockExecutor::from_config(Arc::clone(&store), ExecutorConfig::default());
    executor.apply_block(&genesis)?;
    
    // Create and apply block 1 with wallet registrations and mint
    let block1 = create_block_at_height(
        1,
        genesis.header.block_hash,
        vec![
            wallet_registration_tx(sender_wallet, &sender_pk),
            wallet_registration_tx(recipient_wallet, &recipient_pk),
            token_mint_tx(&sender_pk, sov_token_id, sender_wallet, 10_000),
        ],
    );
    executor.apply_block(&block1)?;
    
    // Create and apply block 2 with transfer (separate block due to read-your-writes limitation)
    let block2 = create_block_at_height(
        2,
        block1.header.block_hash,
        vec![token_transfer_tx(
            &sender_pk,
            sov_token_id,
            sender_wallet,
            recipient_wallet,
            1_500,
            0,
        )],
    );
    executor.apply_block(&block2)?;

    let reloaded = lib_blockchain::Blockchain::load_from_store(store)?
        .expect("Expected blockchain to load from committed block replay");

    let token = reloaded
        .token_contracts
        .get(&sov_token_id)
        .expect("SOV token must be reconstructed from committed block replay");
    assert_eq!(token.balance_of(&wallet_key(&sender_wallet)), 8_500);
    assert_eq!(token.balance_of(&wallet_key(&recipient_wallet)), 1_500);
    assert_eq!(reloaded.get_token_nonce(&sov_token_id, &sender_wallet), 1);

    // Verify nonce was properly incremented in sled (now tracked via sled, not in-memory)
    assert_eq!(reloaded.get_token_nonce(&sov_token_id, &sender_wallet), 1);

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

    // Create and apply genesis first
    let genesis = create_genesis_block();
    let executor = BlockExecutor::from_config(Arc::clone(&store), ExecutorConfig::default());
    executor.apply_block(&genesis)?;
    
    // Create and apply block 1 with wallet registrations and mint
    let block1 = create_block_at_height(
        1,
        genesis.header.block_hash,
        vec![
            wallet_registration_tx(sender_wallet, &sender_pk),
            wallet_registration_tx(recipient_wallet, &recipient_pk),
            token_mint_tx(&sender_pk, sov_token_id, sender_wallet, 20_000),
        ],
    );
    executor.apply_block(&block1)?;
    
    // Create and apply block 2 with transfer (separate block due to read-your-writes limitation)
    let block2 = create_block_at_height(
        2,
        block1.header.block_hash,
        vec![token_transfer_tx(
            &sender_pk,
            sov_token_id,
            sender_wallet,
            recipient_wallet,
            2_500,
            0,
        )],
    );
    executor.apply_block(&block2)?;

    let node_a =
        lib_blockchain::Blockchain::load_from_store(store.clone())?.expect("node A should load");
    let node_b = lib_blockchain::Blockchain::load_from_store(store)?.expect("node B should load");

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
fn test_restart_preserves_sov_supply_and_recipient_count() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let signer = test_pubkey(7);
    let alice_wallet = [0x71u8; 32];
    let bob_wallet = [0x72u8; 32];
    let carol_wallet = [0x73u8; 32];
    let sov_token_id = generate_lib_token_id();

    // Create and apply genesis first
    let genesis = create_genesis_block();
    let executor = BlockExecutor::from_config(Arc::clone(&store), ExecutorConfig::default());
    executor.apply_block(&genesis)?;
    
    // Create and apply block 1 with wallet registrations and mint
    let block1 = create_block_at_height(
        1,
        genesis.header.block_hash,
        vec![
            wallet_registration_tx(alice_wallet, &signer),
            wallet_registration_tx(bob_wallet, &test_pubkey(8)),
            wallet_registration_tx(carol_wallet, &test_pubkey(9)),
            token_mint_tx(&signer, sov_token_id, alice_wallet, 30_000),
        ],
    );
    executor.apply_block(&block1)?;
    
    // Create and apply block 2 with first transfer
    let block2 = create_block_at_height(
        2,
        block1.header.block_hash,
        vec![token_transfer_tx(&signer, sov_token_id, alice_wallet, bob_wallet, 5_000, 0)],
    );
    executor.apply_block(&block2)?;
    
    // Create and apply block 3 with second transfer (separate block due to nonce increment)
    let block3 = create_block_at_height(
        3,
        block2.header.block_hash,
        vec![token_transfer_tx(&signer, sov_token_id, alice_wallet, carol_wallet, 2_000, 1)],
    );
    executor.apply_block(&block3)?;

    let before_restart = lib_blockchain::Blockchain::load_from_store(store.clone())?
        .expect("before restart should load from committed replay");
    let after_restart = lib_blockchain::Blockchain::load_from_store(store)?
        .expect("after restart should load from committed replay");

    let before_token = before_restart
        .token_contracts
        .get(&sov_token_id)
        .expect("before restart SOV token should exist");
    let after_token = after_restart
        .token_contracts
        .get(&sov_token_id)
        .expect("after restart SOV token should exist");

    assert_eq!(
        before_token.total_supply, 30_000,
        "committed replay should preserve minted supply"
    );
    assert_eq!(
        after_token.total_supply, before_token.total_supply,
        "restart must not create or destroy SOV supply"
    );
    assert_eq!(
        funded_recipient_count(after_token),
        funded_recipient_count(before_token),
        "restart must not create extra funded SOV recipients"
    );
    assert_eq!(
        after_token.balance_of(&wallet_key(&alice_wallet)),
        before_token.balance_of(&wallet_key(&alice_wallet))
    );
    assert_eq!(
        after_token.balance_of(&wallet_key(&bob_wallet)),
        before_token.balance_of(&wallet_key(&bob_wallet))
    );
    assert_eq!(
        after_token.balance_of(&wallet_key(&carol_wallet)),
        before_token.balance_of(&wallet_key(&carol_wallet))
    );

    Ok(())
}

#[test]
fn test_uncommitted_block_does_not_leak_token_state_after_restart() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let db_path = tmp.path().to_path_buf();

    let sender_pk = test_pubkey(3);
    let recipient_pk = test_pubkey(4);
    let sender_wallet = [0x55u8; 32];
    let recipient_wallet = [0x66u8; 32];
    let sov_token_id = generate_lib_token_id();

    let committed_store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(&db_path)?);
    
    // Create and apply genesis first
    let genesis = create_genesis_block();
    let executor = BlockExecutor::from_config(Arc::clone(&committed_store), ExecutorConfig::default());
    executor.apply_block(&genesis)?;
    
    // Create and apply block 1 with token transactions
    let test_block = create_block_at_height(
        1,
        genesis.header.block_hash,
        vec![
            wallet_registration_tx(sender_wallet, &sender_pk),
            wallet_registration_tx(recipient_wallet, &recipient_pk),
            token_mint_tx(&sender_pk, sov_token_id, sender_wallet, 9_000),
        ],
    );
    executor.apply_block(&test_block)?;
    // Ensure store is fully closed before reopening
    drop(executor);
    drop(committed_store);
    // Small delay to ensure file locks are released
    std::thread::sleep(std::time::Duration::from_millis(10));

    let crashing_store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(&db_path)?);
    crashing_store.begin_block(2)?;
    let crash_block = create_block_at_height(
        2,
        test_block.header.block_hash,
        vec![token_transfer_tx(
            &sender_pk,
            sov_token_id,
            sender_wallet,
            recipient_wallet,
            1_000,
            0,
        )],
    );
    crashing_store.append_block(&crash_block)?;
    // Intentionally do not commit block 2 to simulate crash.
    drop(crashing_store);
    // Small delay to ensure file locks are released
    std::thread::sleep(std::time::Duration::from_millis(10));

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
    assert_eq!(recovered.height, 1);

    Ok(())
}
