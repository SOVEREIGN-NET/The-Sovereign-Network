//! DAO Transaction Builder
//!
//! Provides functions for building signed DAO system transactions.
//! iOS/Android clients call these to get hex-encoded transactions ready for the API.
//!
//! Covers:
//! - InitEntityRegistry   (Bootstrap Council only — one-time, irreversible)
//! - RecordOnRampTrade    (Oracle Committee attested fiat→CBE trades)
//! - TreasuryAllocation   (Bootstrap Council approved SOV transfers)

use lib_blockchain::transaction::{RecordOnRampTradeData, TreasuryAllocationData};
use lib_blockchain::{
    Approval, ApprovalDomain, ThresholdApprovalSet, Transaction,
};
use lib_crypto::types::signatures::SignatureAlgorithm;

fn build_approval_set(
    domain: ApprovalDomain,
    approvals: Vec<(Vec<u8>, Vec<u8>)>,
) -> ThresholdApprovalSet {
    ThresholdApprovalSet {
        domain,
        approvals: approvals
            .into_iter()
            .map(|(dilithium_pk, signature)| Approval {
                public_key: crate::token_tx::create_public_key(dilithium_pk),
                algorithm: SignatureAlgorithm::Dilithium5,
                signature,
            })
            .collect(),
    }
}

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
    _council_approvals: Vec<(Vec<u8>, Vec<u8>)>, // (dilithium_pk, signature) pairs — reserved for future multi-sig flow
) -> Result<String, String> {
    let cbe_pk = crate::token_tx::create_public_key(cbe_treasury_pk);
    let nonprofit_pk = crate::token_tx::create_public_key(nonprofit_treasury_pk);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let tx = Transaction::new_init_entity_registry(
        chain_id,
        cbe_pk,
        nonprofit_pk,
        now,
        block_height,
        Default::default(),
    );

    let final_tx_bytes =
        bincode::serialize(&tx).map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

/// Build a `RecordOnRampTrade` transaction attested by the Oracle Committee.
///
/// # Arguments
/// - `chain_id` — Chain identifier (1 = mainnet)
/// - `epoch_id` — Oracle epoch during which the trade occurred
/// - `cbe_amount` — CBE received (atomic units, 18 decimals)
/// - `usdc_amount` — USDC paid (atomic units, 6 decimals)
/// - `traded_at` — Unix timestamp of the off-chain trade
/// - `oracle_approvals` — Oracle Committee threshold approvals: `(dilithium_pk, signature)` pairs
///
/// # Returns
/// Hex-encoded, bincode-serialized `Transaction` ready to POST.
pub fn build_record_on_ramp_trade_tx(
    chain_id: u8,
    epoch_id: u64,
    cbe_amount: u128,
    usdc_amount: u128,
    traded_at: u64,
    oracle_approvals: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<String, String> {
    let approvals = build_approval_set(ApprovalDomain::OracleCommittee, oracle_approvals);

    let data = RecordOnRampTradeData {
        epoch_id,
        cbe_amount,
        usdc_amount,
        traded_at,
        approvals,
    };

    let tx = Transaction::new_record_on_ramp_trade(chain_id, data);
    let bytes =
        bincode::serialize(&tx).map_err(|e| format!("Failed to serialize: {}", e))?;
    Ok(hex::encode(bytes))
}

/// Build a `TreasuryAllocation` transaction approved by the Bootstrap Council.
///
/// # Arguments
/// - `chain_id` — Chain identifier (1 = mainnet)
/// - `source_treasury_key_id` — 32-byte key_id of the CBE treasury (must match entity registry)
/// - `destination_key_id` — 32-byte key_id of the destination DAO treasury wallet
/// - `amount` — SOV to transfer (atomic units)
/// - `spending_category` — Governance-defined category (e.g. "Operations")
/// - `proposal_id` — 32-byte on-chain proposal ID that authorised this allocation
/// - `council_approvals` — Bootstrap Council threshold approvals: `(dilithium_pk, signature)` pairs
///
/// # Returns
/// Hex-encoded, bincode-serialized `Transaction` ready to POST.
pub fn build_treasury_allocation_tx(
    chain_id: u8,
    source_treasury_key_id: [u8; 32],
    destination_key_id: [u8; 32],
    amount: u64,
    spending_category: String,
    proposal_id: [u8; 32],
    council_approvals: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<String, String> {
    let approvals = build_approval_set(ApprovalDomain::BootstrapCouncil, council_approvals);

    let data = TreasuryAllocationData {
        source_treasury_key_id,
        destination_key_id,
        amount,
        spending_category,
        proposal_id,
        approvals,
    };

    let tx = Transaction::new_treasury_allocation(chain_id, data);
    let bytes =
        bincode::serialize(&tx).map_err(|e| format!("Failed to serialize: {}", e))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        build_init_entity_registry_tx, build_record_on_ramp_trade_tx,
        build_treasury_allocation_tx,
    };
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

    #[test]
    fn test_build_record_on_ramp_trade_tx_round_trip() {
        let signed_tx =
            build_record_on_ramp_trade_tx(1, 7, 1_000_000_000_000_000_000, 500_000_000, 1_700_000_000, vec![])
                .unwrap();

        let tx_bytes = hex::decode(signed_tx).unwrap();
        let tx: lib_blockchain::Transaction = bincode::deserialize(&tx_bytes).unwrap();

        assert_eq!(tx.transaction_type, TransactionType::RecordOnRampTrade);
        let data = tx.record_on_ramp_trade_data().expect("payload");
        assert_eq!(data.epoch_id, 7);
        assert_eq!(data.cbe_amount, 1_000_000_000_000_000_000);
        assert_eq!(data.usdc_amount, 500_000_000);
        assert_eq!(data.traded_at, 1_700_000_000);
        assert!(data.approvals.approvals.is_empty());
    }

    #[test]
    fn test_build_treasury_allocation_tx_round_trip() {
        let source = [0x01u8; 32];
        let dest = [0x02u8; 32];
        let proposal = [0x03u8; 32];
        let signed_tx = build_treasury_allocation_tx(
            1,
            source,
            dest,
            5_000_000,
            "Operations".to_string(),
            proposal,
            vec![],
        )
        .unwrap();

        let tx_bytes = hex::decode(signed_tx).unwrap();
        let tx: lib_blockchain::Transaction = bincode::deserialize(&tx_bytes).unwrap();

        assert_eq!(tx.transaction_type, TransactionType::TreasuryAllocation);
        let data = tx.treasury_allocation_data().expect("payload");
        assert_eq!(data.source_treasury_key_id, source);
        assert_eq!(data.destination_key_id, dest);
        assert_eq!(data.amount, 5_000_000);
        assert_eq!(data.spending_category, "Operations");
        assert_eq!(data.proposal_id, proposal);
        assert!(data.approvals.approvals.is_empty());
    }
}
