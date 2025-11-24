//! Transaction validation logic
//! 
//! Validates transaction integrity, fee calculations, and DAO fee compliance.

use anyhow::Result;
use crate::transactions::Transaction;
use crate::models::EconomicModel;

/// Validate that DAO fee was properly calculated and paid
pub fn validate_dao_fee(transaction: &Transaction, _economic_model: &EconomicModel) -> Result<bool> {
    match transaction.tx_type {
        crate::types::TransactionType::UbiDistribution | 
        crate::types::TransactionType::WelfareDistribution => {
            // These should have zero DAO fee
            Ok(transaction.dao_fee == 0)
        }
        _ => {
            // Calculate expected DAO fee
            let expected_dao_fee = (transaction.amount * crate::DEFAULT_DAO_FEE_RATE) / 10000; // 2.00%
            let expected_dao_fee = expected_dao_fee.max(crate::MINIMUM_DAO_FEE); // Minimum 5 tokens
            
            Ok(transaction.dao_fee >= expected_dao_fee)
        }
    }
}

/// Validate transaction structure and integrity
pub fn validate_transaction_structure(transaction: &Transaction) -> Result<bool> {
    // Check basic structure
    if transaction.amount == 0 && !matches!(transaction.tx_type, 
        crate::types::TransactionType::NetworkFee | 
        crate::types::TransactionType::DaoFee
    ) {
        return Ok(false);
    }
    
    // Check fee consistency
    if transaction.total_fee != transaction.base_fee + transaction.dao_fee {
        return Ok(false);
    }
    
    // Check DAO fee proof presence
    if transaction.dao_fee > 0 && transaction.dao_fee_proof.is_none() {
        return Ok(false);
    }
    
    Ok(true)
}

/// Comprehensive transaction validation
pub fn validate_transaction(transaction: &Transaction, economic_model: &EconomicModel) -> Result<bool> {
    let structure_valid = validate_transaction_structure(transaction)?;
    let dao_fee_valid = validate_dao_fee(transaction, economic_model)?;
    
    Ok(structure_valid && dao_fee_valid)
}
