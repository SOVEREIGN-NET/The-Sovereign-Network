//! On-chain UBI registration gap regression tests.
//!
//! Client-style citizen registration emits the identity transaction with
//! `owned_wallets: vec![]` and a separate `WalletRegistration` carrying
//! `owner_identity_id`. These tests prove that the wallet is linked back into the
//! owner's `owned_wallets` and that `register_for_ubi` fires for the Primary
//! wallet, producing a UBI mint entry to the Primary wallet.

use lib_blockchain::block::BlockBuilder;
use lib_blockchain::integration::crypto_integration::{Signature, SignatureAlgorithm};
use lib_blockchain::transaction::{IdentityTransactionData, Transaction, WalletTransactionData};
use lib_blockchain::types::Difficulty;
use lib_blockchain::types::Hash;
use lib_blockchain::Blockchain;

fn signature() -> Signature {
    Signature {
        signature: vec![],
        public_key: lib_blockchain::integration::crypto_integration::PublicKey::new([0u8; 2592]),
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: 0,
    }
}

fn identity_tx(did: &str, identity_type: &str, owned_wallets: Vec<String>) -> Transaction {
    let data = IdentityTransactionData {
        did: did.to_string(),
        display_name: "citizen".to_string(),
        public_key: vec![1u8; 32],
        ownership_proof: vec![],
        identity_type: identity_type.to_string(),
        did_document_hash: Hash::zero(),
        created_at: 0,
        registration_fee: 0,
        dao_fee: 0,
        controlled_nodes: vec![],
        owned_wallets,
        kyber_public_key: vec![],
    };
    Transaction::new_identity_registration(data, vec![], signature(), b"identity".to_vec())
}

fn wallet_tx(wallet_id: [u8; 32], owner: Option<Hash>) -> Transaction {
    let data = WalletTransactionData {
        wallet_id: Hash::new(wallet_id),
        wallet_type: "Primary".to_string(),
        wallet_name: "Primary Wallet".to_string(),
        alias: Some("primary".to_string()),
        public_key: vec![2u8; 32],
        kyber_public_key: vec![],
        owner_identity_id: owner,
        seed_commitment: Hash::default(),
        created_at: 0,
        registration_fee: 0,
        capabilities: 0,
        initial_balance: 0,
    };
    Transaction::new_wallet_registration(data, vec![], signature(), b"wallet".to_vec())
}

fn block_from(blockchain: &Blockchain, txs: Vec<Transaction>) -> lib_blockchain::block::Block {
    let prev_hash = blockchain.blocks.last().unwrap().hash();
    BlockBuilder::new(prev_hash, 1, Difficulty::default())
        .version(1)
        .timestamp(1001)
        .transactions(txs)
        .build()
        .expect("block build should succeed")
}

#[test]
fn register_for_ubi_creates_registry_entry() {
    let mut blockchain = Blockchain::new().expect("blockchain construct");
    let did = "did:zhtp:0101010101010101010101010101010101010101010101010101010101010101";
    let wallet_hex = hex::encode([9u8; 32]);

    blockchain
        .register_for_ubi(did.to_string(), wallet_hex.clone(), 5)
        .expect("register_for_ubi should succeed");

    let entry = blockchain.ubi_registry.get(did).expect("entry present");
    assert_eq!(entry.primary_wallet_id, wallet_hex);
    assert_eq!(entry.registered_at_block, 5);

    let again = blockchain.register_for_ubi(did.to_string(), wallet_hex, 6);
    assert!(again.is_err(), "duplicate registration must be rejected");
}

#[test]
fn client_style_registration_links_primary_wallet_and_mints_ubi() {
    let mut blockchain = Blockchain::new().expect("blockchain construct");

    let identity_id_bytes = [7u8; 32];
    let did = format!("did:zhtp:{}", hex::encode(identity_id_bytes));
    let owner = Hash::new(identity_id_bytes);

    let wallet_id_bytes = [9u8; 32];
    let wallet_id_hex = hex::encode(wallet_id_bytes);

    // Client-style: identity tx with empty owned_wallets + companion wallet tx.
    let identity = identity_tx(&did, "citizen", vec![]);
    let wallet = wallet_tx(wallet_id_bytes, Some(owner));

    let block = block_from(&blockchain, vec![identity, wallet]);

    blockchain
        .process_identity_transactions(&block)
        .expect("identity processing succeeds");
    blockchain
        .process_wallet_transactions(&block)
        .expect("wallet processing succeeds");

    // (a) wallet linked into owner's owned_wallets
    let identity_data = blockchain
        .get_all_identities()
        .get(&did)
        .expect("identity present");
    assert_eq!(identity_data.owned_wallets, vec![wallet_id_hex.clone()]);

    // (b) on-chain UBI registry entry targeting the Primary wallet
    let entry = blockchain
        .ubi_registry
        .get(&did)
        .expect("ubi entry present");
    assert_eq!(entry.primary_wallet_id, wallet_id_hex);

    // (c) collect_ubi_mint_entries emits a mint to the Primary wallet
    let entries = blockchain.collect_ubi_mint_entries(1);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].identity_id, did);
    assert_eq!(entries[0].wallet_id, wallet_id_hex);
    assert_eq!(entries[0].recipient_wallet_id, wallet_id_bytes);
    assert!(entries[0].payout > 0);
}
