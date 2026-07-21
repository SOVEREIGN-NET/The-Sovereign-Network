//! #1985 / #1999 / #2002 — identity projection rebuild equivalence after restart.
//!
//! After block-scan replay, sled identity trees must match the registry derived
//! from committed blocks (not stale pre-existing projection content).

use std::sync::Arc;

use anyhow::Result;
use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::storage::{
    did_to_hash, BlockchainStore, IdentityMetadata, SledStore,
};
use lib_blockchain::transaction::{IdentityTransactionData, Transaction, TransactionPayload};
use lib_blockchain::types::{Hash, TransactionType};
use lib_crypto::types::signatures::Signature;

mod common;

fn test_pubkey(seed: u8) -> PublicKey {
    common::crypto_fixtures::seeded_public_key(seed)
}

fn test_signature(pubkey: &PublicKey) -> Signature {
    common::crypto_fixtures::signature_for(pubkey)
}

fn identity_data(did: &str, owner: &PublicKey, display_name: &str, kyber: Vec<u8>) -> IdentityTransactionData {
    IdentityTransactionData {
        did: did.to_string(),
        display_name: display_name.to_string(),
        public_key: owner.dilithium_pk.to_vec(),
        ownership_proof: vec![],
        identity_type: "human".to_string(),
        did_document_hash: Hash::zero(),
        created_at: 1_700_000_000,
        registration_fee: 0,
        dao_fee: 0,
        controlled_nodes: vec![],
        owned_wallets: vec![],
        kyber_public_key: kyber,
    }
}

fn identity_tx(data: IdentityTransactionData, owner: &PublicKey) -> Transaction {
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::IdentityRegistration,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(owner),
        memo: Vec::new(),
        payload: TransactionPayload::Identity(data),
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
fn test_identity_projection_rebuilt_from_blocks_after_stale_sled() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let owner = test_pubkey(7);
    let did = "did:zhtp:phase2-identity-rebuild";
    let kyber = vec![0xAB; 32];
    let data = identity_data(did, &owner, "Canonical Name", kyber.clone());
    let did_hash = did_to_hash(did);

    store.begin_block(0)?;
    store.append_block(&block(
        0,
        vec![identity_tx(data.clone(), &owner)],
    ))?;
    store.commit_block()?;

    // Stale projection: wrong display name / empty kyber, missing owner index.
    let stale = IdentityMetadata {
        did: did.to_string(),
        display_name: "STALE NAME".to_string(),
        public_key: owner.dilithium_pk.to_vec(),
        kyber_public_key: Vec::new(),
        ownership_proof: vec![],
        controlled_nodes: vec![],
        owned_wallets: vec![],
        attributes: vec![],
    };
    store.put_identity_metadata_direct(&did_hash, &stale)?;

    let loaded =
        lib_blockchain::Blockchain::load_from_store(store.clone())?.expect("load after replay");

    assert_eq!(
        loaded.identity_display_name(did).as_deref(),
        Some("Canonical Name")
    );
    assert_eq!(loaded.identity_kyber_public_key(did), Some(kyber.clone()));
    assert_eq!(loaded.identity_blocks.get(did), Some(&0));

    let meta = store
        .get_identity_metadata(&did_hash)?
        .expect("metadata rebuilt");
    assert_eq!(meta.display_name, "Canonical Name");
    assert_eq!(meta.kyber_public_key, kyber);

    let consensus = store.get_identity(&did_hash)?.expect("consensus rebuilt");
    assert_eq!(consensus.registered_at_height, 0);

    let owner_addr = lib_blockchain::storage::derive_address_from_public_key(&owner.dilithium_pk);
    assert_eq!(
        store.get_identity_by_owner(&owner_addr)?,
        Some(did_hash),
        "owner index must be rebuilt"
    );

    Ok(())
}

#[test]
fn test_identity_registry_matches_across_two_load_from_store_passes() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let owner = test_pubkey(9);
    let did = "did:zhtp:phase2-identity-equiv";
    let data = identity_data(did, &owner, "Equivalence", vec![0xCD; 16]);

    store.begin_block(0)?;
    store.append_block(&block(0, vec![identity_tx(data, &owner)]))?;
    store.commit_block()?;

    let a = lib_blockchain::Blockchain::load_from_store(store.clone())?.expect("load A");
    let b = lib_blockchain::Blockchain::load_from_store(store)?.expect("load B");

    assert_eq!(
        a.identity_transaction_data(did),
        b.identity_transaction_data(did)
    );
    assert_eq!(a.identity_blocks.get(did), b.identity_blocks.get(did));
    assert_eq!(a.height, b.height);

    Ok(())
}
