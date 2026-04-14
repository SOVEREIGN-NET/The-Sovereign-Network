use anyhow::Result;
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_blockchain::transaction::TokenMintData;
use lib_blockchain::Transaction;

/// Build a signed SOV token mint transaction using the node's validator key.
pub async fn build_sov_mint_tx(
    recipient_wallet_id: &[u8; 32],
    amount: u128,
    memo: Vec<u8>,
) -> Result<Transaction> {
    let validator_kp = load_validator_keypair_from_keystore().await?;
    let chain_id = chain_id_from_env();

    let token_mint_data = TokenMintData {
        token_id: lib_blockchain::contracts::utils::generate_lib_token_id(),
        to: *recipient_wallet_id,
        amount,
    };

    let mut tx = Transaction::new_token_mint_with_chain_id(
        chain_id,
        token_mint_data,
        Signature {
            signature: Vec::new(),
            public_key: PublicKey::new([0u8; 2592]),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: current_timestamp(),
        },
        memo,
    );

    let signing_hash = tx.signing_hash();
    let sig = lib_crypto::sign_message(&validator_kp, signing_hash.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to sign TokenMint: {}", e))?;
    tx.signature = sig;

    Ok(tx)
}

fn chain_id_from_env() -> u8 {
    std::env::var("ZHTP_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0x03)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) async fn load_validator_keypair_from_keystore() -> Result<lib_crypto::KeyPair> {
    use crate::keyfile_names::{KeystorePrivateKey, NODE_PRIVATE_KEY_FILENAME};
    use std::path::PathBuf;

    let keystore_dir = std::env::var("ZHTP_KEYSTORE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::node_data_dir().join("keystore"));

    let key_path = keystore_dir.join(NODE_PRIVATE_KEY_FILENAME);
    let key_json = tokio::fs::read_to_string(&key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read validator key: {}", e))?;
    let keystore_key: KeystorePrivateKey = serde_json::from_str(&key_json)
        .map_err(|e| anyhow::anyhow!("Invalid keystore key JSON {:?}: {}", key_path, e))?;

    // Note: KeystorePrivateKey uses fixed arrays, so length checks are technically
    // redundant but kept for defense-in-depth in case deserialization changes.
    let dilithium_pk: [u8; 2592] = keystore_key
        .dilithium_pk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid dilithium_pk length, expected 2592 bytes"))?;
    let dilithium_sk: [u8; 4896] = keystore_key
        .dilithium_sk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid dilithium_sk length, expected 4896 bytes"))?;
    let kyber_sk: [u8; 3168] = keystore_key
        .kyber_sk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid kyber_sk length, expected 3168 bytes"))?;
    let master_seed: [u8; 64] = keystore_key
        .master_seed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid master_seed length, expected 64 bytes"))?;
    let public_key = lib_crypto::PublicKey::new(dilithium_pk);
    let private_key = lib_crypto::PrivateKey {
        dilithium_sk,
        dilithium_pk,
        kyber_sk,
        master_seed,
    };

    Ok(lib_crypto::KeyPair {
        public_key,
        private_key,
    })
}
