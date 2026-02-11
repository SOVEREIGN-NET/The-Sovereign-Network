use anyhow::Result;
use lib_blockchain::Transaction;
use lib_blockchain::transaction::TokenMintData;
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};

/// Build a signed SOV token mint transaction using the node's validator key.
pub async fn build_sov_mint_tx(recipient_wallet_id: &[u8; 32], amount: u64, memo: Vec<u8>) -> Result<Transaction> {
    let validator_kp = load_validator_keypair_from_keystore().await?;
    let chain_id = chain_id_from_env();

    let token_mint_data = TokenMintData {
        token_id: lib_blockchain::contracts::utils::generate_lib_token_id(),
        to: *recipient_wallet_id,
        amount: amount as u128,
    };

    let mut tx = Transaction::new_token_mint_with_chain_id(
        chain_id,
        token_mint_data,
        Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(Vec::new()),
            algorithm: SignatureAlgorithm::Dilithium5,
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
    use crate::keystore_names::{KeystorePrivateKey, NODE_PRIVATE_KEY_FILENAME};
    use std::path::PathBuf;

    let keystore_dir = std::env::var("ZHTP_KEYSTORE_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".zhtp").join("keystore")))
        .ok_or_else(|| anyhow::anyhow!("Could not determine keystore directory"))?;

    let key_path = keystore_dir.join(NODE_PRIVATE_KEY_FILENAME);
    let key_json = tokio::fs::read_to_string(&key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read validator key: {}", e))?;
    let keystore_key: KeystorePrivateKey = serde_json::from_str(&key_json)
        .map_err(|e| anyhow::anyhow!("Invalid keystore key JSON {:?}: {}", key_path, e))?;

    let public_key = lib_crypto::PublicKey::new(keystore_key.dilithium_pk.clone());
    let private_key = lib_crypto::PrivateKey {
        dilithium_sk: keystore_key.dilithium_sk,
        dilithium_pk: keystore_key.dilithium_pk,
        kyber_sk: keystore_key.kyber_sk,
        master_seed: keystore_key.master_seed,
    };

    Ok(lib_crypto::KeyPair { public_key, private_key })
}
