//! CBE Transaction Builders
//!
//! Builds signed transactions for CBE token infrastructure:
//! - `InitCbeToken` — one-time bootstrap, assigns pool addresses and distributes supply
//! - `CreateEmploymentContract` — records an on-chain employment contract
//! - `ProcessPayroll` — executes a payroll period and triggers CBE transfer

use lib_blockchain::integration::crypto_integration::{PublicKey, Signature};
use lib_blockchain::Transaction;
use lib_crypto::types::SignatureAlgorithm;

fn empty_sig(signer_pk: PublicKey) -> Signature {
    Signature {
        signature: vec![],
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: 0,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build a signed `InitCbeToken` transaction.
///
/// Assigns the 4 CBE distribution pool addresses and mints the full supply.
/// This is a one-time Bootstrap Council operation.
///
/// # Arguments
/// - `identity` — Bootstrap Council signer
/// - `compensation_key_id` — 32-byte key_id for the 40% compensation pool wallet
/// - `operational_key_id`  — 32-byte key_id for the 30% operational pool wallet
/// - `performance_key_id`  — 32-byte key_id for the 20% performance pool wallet
/// - `strategic_key_id`    — 32-byte key_id for the 10% strategic pool wallet
/// - `chain_id`            — Chain identifier (3 = testnet)
/// - `block_height`        — Current block height
///
/// # Returns
/// Hex-encoded bincode `Transaction` ready to POST to `POST /api/v1/cbe/init`.
pub fn build_init_cbe_token_tx(
    identity: &crate::Identity,
    compensation_key_id: [u8; 32],
    operational_key_id: [u8; 32],
    performance_key_id: [u8; 32],
    strategic_key_id: [u8; 32],
    chain_id: u8,
    block_height: u64,
) -> Result<String, String> {
    let signer_pk = crate::token_tx::create_public_key_with_kyber(
        identity.public_key.clone(),
        identity.kyber_public_key.clone(),
    );
    let now = now_secs();

    let mut tx = Transaction::new_init_cbe_token(
        chain_id,
        compensation_key_id,
        operational_key_id,
        performance_key_id,
        strategic_key_id,
        now,
        block_height,
        empty_sig(signer_pk.clone()),
    );

    let tx_hash = tx.signing_hash();
    let sig_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign InitCbeToken tx: {}", e))?;

    tx.signature = Signature {
        signature: sig_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: now,
    };

    bincode::serialize(&tx)
        .map(hex::encode)
        .map_err(|e| format!("Failed to serialize InitCbeToken tx: {}", e))
}

/// Build a signed `CreateEmploymentContract` transaction.
///
/// # Arguments
/// - `identity`                — Signer (DAO authorized HR role)
/// - `dao_id`                  — 32-byte DAO identifier
/// - `employee_key_id`         — 32-byte key_id of the employee's wallet
/// - `contract_type`           — 0 = PublicAccess, 1 = Employment
/// - `compensation_amount`     — Per-period compensation in base units
/// - `payment_period`          — 0 = Monthly, 1 = Quarterly, 2 = Annually
/// - `tax_rate_basis_points`   — Tax rate (0–5000, max 50%)
/// - `tax_jurisdiction`        — ISO country code, e.g. "US"
/// - `profit_share_percentage` — Profit share in basis points (0–2000, max 20%)
/// - `chain_id`                — Chain identifier
///
/// # Returns
/// Hex-encoded bincode `Transaction` ready to POST to `POST /api/v1/cbe/employment/create`.
pub fn build_create_employment_contract_tx(
    identity: &crate::Identity,
    dao_id: [u8; 32],
    employee_key_id: [u8; 32],
    contract_type: u8,
    compensation_amount: u128,
    payment_period: u8,
    tax_rate_basis_points: u16,
    tax_jurisdiction: String,
    profit_share_percentage: u16,
    chain_id: u8,
) -> Result<String, String> {
    let signer_pk = crate::token_tx::create_public_key_with_kyber(
        identity.public_key.clone(),
        identity.kyber_public_key.clone(),
    );
    let now = now_secs();

    let mut tx = Transaction::new_create_employment_contract(
        chain_id,
        dao_id,
        employee_key_id,
        contract_type,
        compensation_amount,
        payment_period,
        tax_rate_basis_points,
        tax_jurisdiction,
        profit_share_percentage,
        empty_sig(signer_pk.clone()),
    );

    let tx_hash = tx.signing_hash();
    let sig_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign CreateEmploymentContract tx: {}", e))?;

    tx.signature = Signature {
        signature: sig_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: now,
    };

    bincode::serialize(&tx)
        .map(hex::encode)
        .map_err(|e| format!("Failed to serialize CreateEmploymentContract tx: {}", e))
}

/// Build a signed `ProcessPayroll` transaction (CBE bonding curve §6 payroll mint).
///
/// Triggers a synthetic curve event: gross ≈ 2.083X CBE is minted and split
/// 20% SOV treasury / 32% locked reserve / 48% collaborator (= X).
/// A PRE_BACKED entry is recorded for the full gross.  Signer must be a
/// Bootstrap Council member (governance guard).
///
/// # Arguments
/// - `identity`              — Signer (must be Bootstrap Council member)
/// - `contract_id`           — 32-byte employment contract identifier
/// - `amount_cbe`            — CBE amount the collaborator earns (X, 18-decimal atoms)
/// - `collaborator_address`  — Wallet address that receives X CBE
/// - `deliverable_hash`      — Blake3 hash of the governance-approved deliverable
/// - `chain_id`              — Chain identifier
///
/// # Returns
/// Hex-encoded bincode `Transaction` ready to POST to `POST /api/v1/cbe/payroll/process`.
pub fn build_process_payroll_tx(
    identity: &crate::Identity,
    contract_id: [u8; 32],
    amount_cbe: u128,
    collaborator_address: [u8; 32],
    deliverable_hash: [u8; 32],
    chain_id: u8,
) -> Result<String, String> {
    let signer_pk = crate::token_tx::create_public_key_with_kyber(
        identity.public_key.clone(),
        identity.kyber_public_key.clone(),
    );
    let now = now_secs();

    let mut tx = Transaction::new_process_payroll(
        chain_id,
        contract_id,
        amount_cbe,
        collaborator_address,
        deliverable_hash,
        empty_sig(signer_pk.clone()),
    );

    let tx_hash = tx.signing_hash();
    let sig_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign ProcessPayroll tx: {}", e))?;

    tx.signature = Signature {
        signature: sig_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: now,
    };

    bincode::serialize(&tx)
        .map(hex::encode)
        .map_err(|e| format!("Failed to serialize ProcessPayroll tx: {}", e))
}
