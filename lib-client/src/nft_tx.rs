//! NFT transaction builders for lib-client.

use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_blockchain::transaction::{
    NftBurnData, NftCreateCollectionData, NftMintData, NftTransferData, Transaction,
    TransactionPayload, TX_VERSION_V8,
};
use lib_blockchain::types::transaction_type::TransactionType;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn empty_sig(pk: PublicKey) -> Signature {
    Signature {
        signature: Vec::new(),
        public_key: pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: now_secs(),
    }
}

/// Build a signed NftCreateCollection transaction.
pub fn build_nft_create_collection_tx(
    identity: &crate::Identity,
    name: String,
    symbol: String,
    max_supply: Option<u64>,
    chain_id: u8,
) -> Result<String, String> {
    let signer_pk = crate::token_tx::create_public_key_with_kyber(
        identity.public_key.clone(),
        identity.kyber_public_key.clone(),
    );

    let data = NftCreateCollectionData {
        name,
        symbol,
        max_supply,
    };

    let mut tx = Transaction {
        version: TX_VERSION_V8,
        chain_id,
        transaction_type: TransactionType::NftCreateCollection,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: empty_sig(signer_pk.clone()),
        memo: b"nft:create_collection".to_vec(),
        payload: TransactionPayload::NftCreateCollection(data),
    };

    let tx_hash = tx.signing_hash();
    let sig_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: sig_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: now_secs(),
    };

    bincode::serialize(&tx)
        .map(hex::encode)
        .map_err(|e| format!("Failed to serialize: {}", e))
}

/// Build a signed NftMint transaction.
pub fn build_nft_mint_tx(
    identity: &crate::Identity,
    collection_id: [u8; 32],
    recipient: [u8; 32],
    name: String,
    description: String,
    image_cid: String,
    attributes: Vec<(String, String)>,
    chain_id: u8,
) -> Result<String, String> {
    let signer_pk = crate::token_tx::create_public_key_with_kyber(
        identity.public_key.clone(),
        identity.kyber_public_key.clone(),
    );

    let data = NftMintData {
        collection_id,
        recipient,
        name,
        description,
        image_cid,
        attributes,
    };

    let mut tx = Transaction {
        version: TX_VERSION_V8,
        chain_id,
        transaction_type: TransactionType::NftMint,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: empty_sig(signer_pk.clone()),
        memo: b"nft:mint".to_vec(),
        payload: TransactionPayload::NftMint(data),
    };

    let tx_hash = tx.signing_hash();
    let sig_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: sig_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: now_secs(),
    };

    bincode::serialize(&tx)
        .map(hex::encode)
        .map_err(|e| format!("Failed to serialize: {}", e))
}

/// Build a signed NftTransfer transaction.
pub fn build_nft_transfer_tx(
    identity: &crate::Identity,
    collection_id: [u8; 32],
    token_id: u64,
    from: [u8; 32],
    to: [u8; 32],
    chain_id: u8,
) -> Result<String, String> {
    let signer_pk = crate::token_tx::create_public_key_with_kyber(
        identity.public_key.clone(),
        identity.kyber_public_key.clone(),
    );

    let data = NftTransferData {
        collection_id,
        token_id,
        from,
        to,
    };

    let mut tx = Transaction {
        version: TX_VERSION_V8,
        chain_id,
        transaction_type: TransactionType::NftTransfer,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: empty_sig(signer_pk.clone()),
        memo: b"nft:transfer".to_vec(),
        payload: TransactionPayload::NftTransfer(data),
    };

    let tx_hash = tx.signing_hash();
    let sig_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: sig_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: now_secs(),
    };

    bincode::serialize(&tx)
        .map(hex::encode)
        .map_err(|e| format!("Failed to serialize: {}", e))
}

/// Build a signed NftBurn transaction.
pub fn build_nft_burn_tx(
    identity: &crate::Identity,
    collection_id: [u8; 32],
    token_id: u64,
    owner: [u8; 32],
    chain_id: u8,
) -> Result<String, String> {
    let signer_pk = crate::token_tx::create_public_key_with_kyber(
        identity.public_key.clone(),
        identity.kyber_public_key.clone(),
    );

    let data = NftBurnData {
        collection_id,
        token_id,
        owner,
    };

    let mut tx = Transaction {
        version: TX_VERSION_V8,
        chain_id,
        transaction_type: TransactionType::NftBurn,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: empty_sig(signer_pk.clone()),
        memo: b"nft:burn".to_vec(),
        payload: TransactionPayload::NftBurn(data),
    };

    let tx_hash = tx.signing_hash();
    let sig_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: sig_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: now_secs(),
    };

    bincode::serialize(&tx)
        .map(hex::encode)
        .map_err(|e| format!("Failed to serialize: {}", e))
}
