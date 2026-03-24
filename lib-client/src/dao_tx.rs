//! DAO Transaction Builder
//!
//! Provides functions for building signed DAO system transactions.
//! iOS/Android clients call these to get hex-encoded transactions ready for the API.
//!
//! Covers: InitEntityRegistry (Bootstrap Council only — one-time, irreversible)

use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::{ApprovalDomain, ThresholdApproval, ThresholdApprovals, Transaction};

/// Build an InitEntityRegistry transaction with Bootstrap Council threshold approvals.
///
/// # Arguments
/// - `cbe_treasury_pk` — Raw bytes of the CBE (for-profit) treasury public key
/// - `nonprofit_treasury_pk` — Raw bytes of the Nonprofit treasury public key
/// - `chain_id` — Chain identifier (1 = mainnet)
/// - `block_height` — Current block height (used as `initialized_at_height`)
/// - `approvals` — Bootstrap Council threshold approvals (T-of-N Dilithium signatures)
///
/// # Returns
/// Hex-encoded, bincode-serialized `Transaction` ready to POST
/// to `POST /api/v1/dao/entity-registry/init` as `signed_tx`.
pub fn build_init_entity_registry_tx(
    cbe_treasury_pk: Vec<u8>,
    nonprofit_treasury_pk: Vec<u8>,
    chain_id: u8,
    block_height: u64,
    council_approvals: Vec<(Vec<u8>, Vec<u8>)>, // (dilithium_pk, signature) pairs
) -> Result<String, String> {
    let cbe_pk = crate::token_tx::create_public_key(cbe_treasury_pk);
    let nonprofit_pk = crate::token_tx::create_public_key(nonprofit_treasury_pk);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let approvals = ThresholdApprovals {
        domain: ApprovalDomain::BootstrapCouncil,
        approvals: council_approvals
            .into_iter()
            .map(|(dilithium_pk, signature)| ThresholdApproval {
                dilithium_pk,
                signature,
            })
            .collect(),
    };

    let tx = Transaction::new_init_entity_registry(
        chain_id,
        cbe_pk,
        nonprofit_pk,
        now,
        block_height,
        approvals,
    );

    let final_tx_bytes =
        bincode::serialize(&tx).map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

#[cfg(test)]
mod tests {
    use super::build_init_entity_registry_tx;
    use lib_blockchain::types::transaction_type::TransactionType;

    #[test]
    fn test_build_init_entity_registry_tx_round_trip() {
        // Build with empty approvals (no real signers — just round-trip structure test)
        let signed_tx = build_init_entity_registry_tx(
            vec![0x11; 2592],
            vec![0x22; 2592],
            1,
            42,
            vec![],
        )
        .unwrap();

        let tx_bytes = hex::decode(signed_tx).unwrap();
        let tx: lib_blockchain::Transaction = bincode::deserialize(&tx_bytes).unwrap();

        assert_eq!(tx.transaction_type, TransactionType::InitEntityRegistry);
        assert_eq!(tx.fee, 0);

        let data = tx.init_entity_registry_data().expect("init payload").clone();
        assert_eq!(data.initialized_at_height, 42);
        assert_eq!(data.cbe_treasury.dilithium_pk, vec![0x11; 2592]);
        assert_eq!(data.nonprofit_treasury.dilithium_pk, vec![0x22; 2592]);
    }
}
