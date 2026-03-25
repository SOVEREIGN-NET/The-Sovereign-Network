use anyhow::Result;
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_blockchain::types::mining::get_mining_config_from_env;
use lib_blockchain::types::transaction_type::TransactionType;
use lib_blockchain::{Block, BlockHeader, Blockchain, Transaction};

fn test_public_key(id: u8) -> PublicKey {
    PublicKey::new(vec![id; 2592])
}

fn test_signature(signer: &PublicKey) -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: signer.clone(),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    }
}

fn create_init_tx(signer: &PublicKey, cbe: PublicKey, nonprofit: PublicKey) -> Transaction {
    Transaction::new_init_entity_registry(
        1,
        cbe,
        nonprofit,
        123,
        0,
        test_signature(signer),
    )
}

fn create_block(blockchain: &Blockchain, transactions: Vec<Transaction>) -> Block {
    let mining_config = get_mining_config_from_env();
    let merkle_root = if transactions.is_empty() {
        lib_blockchain::Hash::default()
    } else {
        lib_blockchain::transaction::hashing::calculate_transaction_merkle_root(&transactions)
    };

    let header = BlockHeader::new(
        1,
        blockchain.latest_block().unwrap().hash(),
        merkle_root,
        blockchain.latest_block().unwrap().timestamp() + 10,
        mining_config.difficulty,
        blockchain.height + 1,
        transactions.len() as u32,
        transactions.iter().map(|tx| tx.size()).sum::<usize>() as u32,
        mining_config.difficulty,
    );

    Block::new(header, transactions)
}

#[test]
fn test_entity_registry_second_init_in_same_block_errors() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    let signer = test_public_key(1);
    let block = create_block(
        &blockchain,
        vec![
            create_init_tx(&signer, test_public_key(2), test_public_key(3)),
            create_init_tx(&signer, test_public_key(4), test_public_key(5)),
        ],
    );

    let error = blockchain
        .process_entity_registry_transactions(&block)
        .expect_err("second InitEntityRegistry must fail the block");

    assert!(error.to_string().contains("already initialized"));
    assert!(block
        .transactions
        .iter()
        .all(|tx| tx.transaction_type == TransactionType::InitEntityRegistry));
    Ok(())
}

#[test]
fn test_entity_registry_persists_after_save_load() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut blockchain = Blockchain::new()?;
    blockchain.entity_registry = Some(lib_blockchain::contracts::governance::EntityRegistry::new());
    blockchain
        .entity_registry
        .as_mut()
        .unwrap()
        .init(test_public_key(6), test_public_key(7))
        .expect("entity registry init should succeed");

    let tmp = NamedTempFile::new()?;
    blockchain.save_to_file(tmp.path())?;

    let loaded = Blockchain::load_from_file(tmp.path())?;
    let registry = loaded
        .entity_registry
        .expect("entity registry should persist");
    assert!(registry.is_initialized());
    assert_eq!(
        hex::encode(
            registry
                .cbe_treasury()
                .expect("cbe treasury should exist")
                .as_bytes()
        ),
        hex::encode(test_public_key(6).as_bytes())
    );
    assert_eq!(
        hex::encode(
            registry
                .nonprofit_treasury()
                .expect("nonprofit treasury should exist")
                .as_bytes()
        ),
        hex::encode(test_public_key(7).as_bytes())
    );
    Ok(())
}
