//! DAO Transaction Builder
//!
//! Provides functions for building signed DAO system transactions.
//! iOS/Android clients call these to get hex-encoded transactions ready for the API.
//!
//! Covers: InitEntityRegistry (Bootstrap Council only — one-time, irreversible)

use lib_blockchain::integration::crypto_integration::{PublicKey, Signature};
use lib_blockchain::Transaction;
use lib_crypto::types::SignatureAlgorithm;

/// Build a signed InitEntityRegistry transaction.
///
/// # Arguments
/// - `identity` — Bootstrap Council member's identity (used for signing)
/// - `cbe_treasury_pk` — Raw bytes of the CBE (for-profit) treasury public key
/// - `nonprofit_treasury_pk` — Raw bytes of the Nonprofit treasury public key
/// - `chain_id` — Chain identifier (1 = mainnet)
/// - `block_height` — Current block height (used as `initialized_at_height`)
///
/// # Returns
/// Hex-encoded, bincode-serialized, signed `Transaction` ready to POST
/// to `POST /api/v1/dao/entity-registry/init` as `signed_tx`.
pub fn build_init_entity_registry_tx(
    identity: &crate::Identity,
    cbe_treasury_pk: Vec<u8>,
    nonprofit_treasury_pk: Vec<u8>,
    chain_id: u8,
    block_height: u64,
) -> Result<String, String> {
    let signer_pk = crate::token_tx::create_public_key(identity.public_key.clone());
    let cbe_pk = crate::token_tx::create_public_key(cbe_treasury_pk);
    let nonprofit_pk = crate::token_tx::create_public_key(nonprofit_treasury_pk);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut tx = Transaction::new_init_entity_registry(
        chain_id,
        cbe_pk,
        nonprofit_pk,
        now,
        block_height,
        Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        },
    );
    tx.fee = 0; // System transaction — no fee

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: now,
    };

    let final_tx_bytes =
        bincode::serialize(&tx).map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}
