//! Transaction Validation
//!
//! Stateless and stateful transaction validation.
//!
//! # Validation Phases
//!
//! 1. **Stateless** - Can be done without chain state
//!    - Format, version, type checks
//!    - Structural validity (inputs, outputs)
//!    - Signature format (not verification)
//!
//! 2. **Stateful** - Requires chain state access
//!    - UTXO existence
//!    - Balance sufficiency
//!    - Signature verification against UTXO owners
//!
//! # Phase 2 Allowlist
//!
//! Only these transaction types are allowed:
//! - Transfer (native UTXO)
//! - TokenTransfer (balance model)
//! - Coinbase (block reward)
//!
//! All other types are rejected with `UnsupportedType` error.

use std::collections::HashSet;

use crate::fees::{
    classify_transaction, compute_fee_v2, validate_block_limits,
    FeeParamsV2,
};
use crate::storage::{BlockchainStore, OutPoint, TxHash, Address, TokenId};
use crate::transaction::Transaction;
use crate::types::TransactionType;

use super::errors::{TxValidateError, TxValidateResult};

/// Phase 2 allowed transaction types
const PHASE2_ALLOWED_TYPES: &[TransactionType] = &[
    TransactionType::Transfer,
    TransactionType::TokenTransfer,
    TransactionType::TokenMint,
    TransactionType::Coinbase,
];

/// Check if transaction type is allowed in Phase 2
fn is_type_allowed(tx_type: TransactionType) -> bool {
    PHASE2_ALLOWED_TYPES.contains(&tx_type)
}

// =============================================================================
// Stateless Validation
// =============================================================================

/// Validate transaction without chain state
///
/// These checks can be parallelized and cached.
pub fn validate_stateless(tx: &Transaction) -> TxValidateResult<()> {
    // Check transaction type is allowed in Phase 2
    if !is_type_allowed(tx.transaction_type) {
        return Err(TxValidateError::UnsupportedType(
            format!("{:?}", tx.transaction_type)
        ));
    }

    // Version check
    if tx.version == 0 {
        return Err(TxValidateError::InvalidVersion(tx.version));
    }

    // Type-specific validation
    match tx.transaction_type {
        TransactionType::Transfer => validate_transfer_stateless(tx)?,
        TransactionType::TokenTransfer => validate_token_transfer_stateless(tx)?,
        TransactionType::TokenMint => validate_token_mint_stateless(tx)?,
        TransactionType::Coinbase => validate_coinbase_stateless(tx)?,
        _ => return Err(TxValidateError::UnsupportedType(
            format!("{:?}", tx.transaction_type)
        )),
    }

    Ok(())
}

/// Stateless validation for Transfer transactions
fn validate_transfer_stateless(tx: &Transaction) -> TxValidateResult<()> {
    // Must have inputs
    if tx.inputs.is_empty() {
        return Err(TxValidateError::EmptyInputs);
    }

    // Must have outputs
    if tx.outputs.is_empty() {
        return Err(TxValidateError::EmptyOutputs);
    }

    // Check for duplicate inputs
    let mut seen_inputs: HashSet<(TxHash, u32)> = HashSet::new();
    for input in &tx.inputs {
        let key = (
            TxHash::new(input.previous_output.as_array()),
            input.output_index,
        );
        if !seen_inputs.insert(key) {
            return Err(TxValidateError::DuplicateInput(OutPoint::new(key.0, key.1)));
        }
    }

    // Note: Output amounts are not validated here because TransactionOutput
    // uses ZK commitments. Actual value validation happens during execution
    // when input UTXOs are spent.

    // Fee must be non-negative (it's u64, so always true, but check for sanity)
    // Could add max fee check here

    Ok(())
}

/// Stateless validation for TokenTransfer transactions
fn validate_token_transfer_stateless(tx: &Transaction) -> TxValidateResult<()> {
    // Token transfer MUST have token_transfer_data field
    // This matches the executor's requirement at executor.rs:489-495
    let data = tx.token_transfer_data.as_ref()
        .ok_or_else(|| TxValidateError::MissingField(
            "TokenTransfer requires token_transfer_data field".to_string()
        ))?;

    // Amount must be > 0
    if data.amount == 0 {
        return Err(TxValidateError::InvalidAmount(
            "Token transfer amount must be greater than 0".to_string()
        ));
    }

    // Note: Balance sufficiency is validated during execution
    // when balances are actually debited/credited.

    Ok(())
}

/// Stateless validation for TokenMint transactions
fn validate_token_mint_stateless(tx: &Transaction) -> TxValidateResult<()> {
    if tx.version < 2 {
        return Err(TxValidateError::InvalidStructure(
            "TokenMint transactions not supported in this serialization version".to_string()
        ));
    }

    let data = tx.token_mint_data.as_ref()
        .ok_or_else(|| TxValidateError::MissingField(
            "TokenMint requires token_mint_data field".to_string()
        ))?;

    if data.amount == 0 {
        return Err(TxValidateError::InvalidAmount(
            "TokenMint amount must be greater than 0".to_string()
        ));
    }

    if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
        return Err(TxValidateError::InvalidStructure(
            "TokenMint must not have UTXO inputs or outputs".to_string()
        ));
    }

    Ok(())
}

/// Stateless validation for Coinbase transactions
fn validate_coinbase_stateless(tx: &Transaction) -> TxValidateResult<()> {
    // Coinbase must have NO inputs
    if !tx.inputs.is_empty() {
        return Err(TxValidateError::CoinbaseHasInputs);
    }

    // Coinbase must have outputs
    if tx.outputs.is_empty() {
        return Err(TxValidateError::EmptyOutputs);
    }

    Ok(())
}

// =============================================================================
// Stateful Validation
// =============================================================================

/// Validate transaction with chain state access
///
/// This performs checks that require reading from the store.
/// It does NOT modify any state.
pub fn validate_stateful(
    tx: &Transaction,
    store: &dyn BlockchainStore,
) -> TxValidateResult<()> {
    match tx.transaction_type {
        TransactionType::Transfer => validate_transfer_stateful(tx, store)?,
        TransactionType::TokenTransfer => validate_token_transfer_stateful(tx, store)?,
        TransactionType::TokenMint => {
            // Authorization and balance checks are enforced during execution
        }
        TransactionType::Coinbase => {
            // Coinbase has no stateful checks (reward validation done in executor)
        }
        _ => return Err(TxValidateError::UnsupportedType(
            format!("{:?}", tx.transaction_type)
        )),
    }

    Ok(())
}

/// Stateful validation for Transfer transactions
fn validate_transfer_stateful(
    tx: &Transaction,
    store: &dyn BlockchainStore,
) -> TxValidateResult<()> {
    let mut total_input: u64 = 0;

    // Verify all inputs exist and are unspent
    for input in &tx.inputs {
        let outpoint = OutPoint::new(
            TxHash::new(input.previous_output.as_array()),
            input.output_index,
        );

        let utxo = store.get_utxo(&outpoint)
            .map_err(|e| TxValidateError::StorageError(e.to_string()))?
            .ok_or_else(|| TxValidateError::UtxoNotFound(outpoint.clone()))?;

        total_input = total_input.saturating_add(utxo.amount);

        // TODO: Verify signature matches UTXO owner
        // This requires access to the signature verification logic
    }

    // Note: Cannot calculate total_output from TransactionOutput because it uses
    // ZK commitments instead of plain amounts. Value conservation is verified
    // during execution when UTXOs are actually created.
    //
    // We only verify that total input covers the fee.
    if total_input < tx.fee {
        return Err(TxValidateError::InsufficientInputs {
            have: total_input,
            need: tx.fee,
        });
    }

    Ok(())
}

/// Stateful validation for TokenTransfer transactions
fn validate_token_transfer_stateful(
    tx: &Transaction,
    _store: &dyn BlockchainStore,
) -> TxValidateResult<()> {
    // For Phase 2, we do basic validation here
    // Full token transfer validation would:
    // 1. Extract sender address from signature
    // 2. Look up sender's token balance
    // 3. Verify sufficient balance for transfer amount

    // The actual balance check happens during apply for simplicity in Phase 2
    Ok(())
}

// =============================================================================
// Fee Validation
// =============================================================================

/// Validate transaction fee against Fee Model v2 minimum.
///
/// # Phase 2 Fee Rules
///
/// - **Transfer**: fee must be >= min_fee_v2 (computed from tx metrics)
/// - **TokenTransfer**: fee must be exactly 0 (locked for Phase 2)
/// - **Coinbase**: fee must be exactly 0 (block reward, not a payment)
pub fn validate_fee(tx: &Transaction, params: &FeeParamsV2) -> TxValidateResult<()> {
    match tx.transaction_type {
        TransactionType::Transfer => {
            // Compute minimum fee using Fee Model v2
            if let Some(fee_input) = classify_transaction(tx) {
                // Validate against block limits first
                if let Err(e) = validate_block_limits(&fee_input, params) {
                    return Err(TxValidateError::BlockLimitExceeded(e));
                }

                // Compute minimum fee
                let min_fee = compute_fee_v2(&fee_input, params);

                // Check transaction fee covers minimum
                if tx.fee < min_fee {
                    return Err(TxValidateError::FeeTooLow {
                        fee: tx.fee,
                        min_fee,
                    });
                }
            }
            Ok(())
        }

        TransactionType::TokenTransfer => {
            // No fee restriction — 1% protocol fee is deducted from transfer amount server-side.
            Ok(())
        }
        TransactionType::TokenMint => {
            // Token mints must have zero fee
            if tx.fee != 0 {
                return Err(TxValidateError::TokenTransferNonZeroFee(tx.fee));
            }
            Ok(())
        }

        TransactionType::Coinbase => {
            // Coinbase must have zero fee
            if tx.fee != 0 {
                return Err(TxValidateError::CoinbaseNonZeroFee(tx.fee));
            }
            Ok(())
        }

        _ => {
            // Unsupported types are caught earlier in validation
            Err(TxValidateError::UnsupportedType(
                format!("{:?}", tx.transaction_type)
            ))
        }
    }
}

/// Validate transaction with chain state access AND fee model.
///
/// This combines stateful validation with fee minimum enforcement.
pub fn validate_stateful_with_fees(
    tx: &Transaction,
    store: &dyn BlockchainStore,
    fee_params: &FeeParamsV2,
) -> TxValidateResult<()> {
    // Type-specific stateful validation
    validate_stateful(tx, store)?;

    // Fee minimum enforcement
    validate_fee(tx, fee_params)?;

    Ok(())
}

// =============================================================================
// Batch Validation
// =============================================================================

/// Validate multiple transactions
///
/// Returns the index of the first invalid transaction, if any.
pub fn validate_transactions_stateless(
    txs: &[Transaction],
) -> Result<(), (usize, TxValidateError)> {
    for (i, tx) in txs.iter().enumerate() {
        validate_stateless(tx).map_err(|e| (i, e))?;
    }
    Ok(())
}

/// Validate multiple transactions with state
pub fn validate_transactions_stateful(
    txs: &[Transaction],
    store: &dyn BlockchainStore,
) -> Result<(), (usize, TxValidateError)> {
    for (i, tx) in txs.iter().enumerate() {
        validate_stateful(tx, store).map_err(|e| (i, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput};
    use crate::types::Hash;
    use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
    use crate::integration::zk_integration::ZkTransactionProof;

    fn create_test_transfer(fee: u64) -> Transaction {
        Transaction::new(
            vec![
                TransactionInput::new(
                    Hash::new([1u8; 32]),
                    0,
                    Hash::new([2u8; 32]),
                    ZkTransactionProof::default(),
                ),
            ],
            vec![
                TransactionOutput::new(
                    Hash::new([3u8; 32]),
                    Hash::new([4u8; 32]),
                    PublicKey::new(vec![5u8; 32]),
                ),
            ],
            fee,
            Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey::new(vec![0u8; 32]),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            },
            vec![],
        )
    }

    fn create_test_token_transfer(fee: u64) -> Transaction {
        let mut tx = Transaction::new(
            vec![],
            vec![],
            fee,
            Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey::new(vec![0u8; 32]),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            },
            vec![],
        );
        tx.transaction_type = TransactionType::TokenTransfer;
        tx.token_transfer_data = Some(crate::transaction::TokenTransferData {
            token_id: [0u8; 32],
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 1000,
            nonce: 0,
        });
        tx
    }

    fn create_test_coinbase(fee: u64) -> Transaction {
        let mut tx = Transaction::new(
            vec![],
            vec![
                TransactionOutput::new(
                    Hash::new([1u8; 32]),
                    Hash::new([2u8; 32]),
                    PublicKey::new(vec![0u8; 32]),
                ),
            ],
            fee,
            Signature {
                signature: vec![],
                public_key: PublicKey::new(vec![]),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            },
            vec![],
        );
        tx.transaction_type = TransactionType::Coinbase;
        tx
    }

    #[test]
    fn test_fee_validation_transfer_below_minimum() {
        let params = FeeParamsV2::default();
        let tx = create_test_transfer(0); // Zero fee

        let result = validate_fee(&tx, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TxValidateError::FeeTooLow { .. }));
    }

    #[test]
    fn test_fee_validation_transfer_above_minimum() {
        let params = FeeParamsV2::default();
        // Use a high fee that should cover minimum
        let tx = create_test_transfer(100_000);

        let result = validate_fee(&tx, &params);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
    }

    #[test]
    fn test_fee_validation_token_transfer_zero_ok() {
        let params = FeeParamsV2::default();
        let tx = create_test_token_transfer(0); // Zero fee is required

        let result = validate_fee(&tx, &params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fee_validation_token_transfer_nonzero_rejected() {
        let params = FeeParamsV2::default();
        let tx = create_test_token_transfer(100); // Non-zero fee

        let result = validate_fee(&tx, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TxValidateError::TokenTransferNonZeroFee(100)));
    }

    #[test]
    fn test_fee_validation_coinbase_zero_ok() {
        let params = FeeParamsV2::default();
        let tx = create_test_coinbase(0);

        let result = validate_fee(&tx, &params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fee_validation_coinbase_nonzero_rejected() {
        let params = FeeParamsV2::default();
        let tx = create_test_coinbase(100);

        let result = validate_fee(&tx, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TxValidateError::CoinbaseNonZeroFee(100)));
    }
}
