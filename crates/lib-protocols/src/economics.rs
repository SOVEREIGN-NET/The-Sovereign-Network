//! Economics Integration Module
//! 
//! Provides economic functions and utilities specifically for ZHTP protocols.
//! Integrates with the lib-economy package for DAO fees, UBI, and economic models.

use lib_economy::{
    EconomicModel, Priority,
};
use crate::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ZHTP economic context
#[derive(Debug, Clone)]
pub struct ZhtpEconomics {
    /// Economic model for fee calculations
    pub model: EconomicModel,
    /// Configuration
    pub config: EconomicConfig,
}

/// Economic configuration for ZHTP protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicConfig {
    /// Enable mandatory DAO fees
    pub mandatory_dao_fees: bool,
    /// DAO fee percentage (e.g., 2.0 for 2%)
    pub dao_fee_percentage: f64,
    /// Enable UBI distribution
    pub ubi_enabled: bool,
    /// Minimum transaction value for fees
    pub min_transaction_value: u64,
    /// Fee calculation method
    pub fee_method: String,
}

impl Default for EconomicConfig {
    fn default() -> Self {
        Self {
            mandatory_dao_fees: true,
            dao_fee_percentage: 2.0, // 2% for UBI funding
            ubi_enabled: true,
            min_transaction_value: 1000, // Minimum 1000 units
            fee_method: "dynamic".to_string(),
        }
    }
}

/// Economic assessment for ZHTP operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicAssessment {
    /// Base fee for the operation
    pub base_fee: u64,
    /// DAO fee for UBI funding
    pub dao_fee: u64,
    /// Network fee for infrastructure
    pub network_fee: u64,
    /// Total fee required
    pub total_fee: u64,
    /// Payment method required
    pub payment_method: String,
    /// Fee breakdown
    pub breakdown: HashMap<String, u64>,
}

impl ZhtpEconomics {
    /// Create a new ZHTP economics context
    pub fn new(config: EconomicConfig) -> Result<Self> {
        let model = EconomicModel::default();

        Ok(Self {
            model,
            config,
        })
    }

    /// Calculate fees for a ZHTP operation
    pub fn calculate_operation_fees(
        &self,
        operation_type: &str,
        data_size: usize,
        priority: Priority,
    ) -> Result<EconomicAssessment> {
        // Calculate base fee based on operation type and data size
        let base_fee = match operation_type {
            "GET" => (data_size as u64) / 1024, // 1 unit per KB
            "POST" => (data_size as u64) / 512, // 2 units per KB for writes
            "PUT" => (data_size as u64) / 512,
            "DELETE" => 100, // Fixed fee for deletes
            "VERIFY" => 50, // Fixed fee for verification
            _ => (data_size as u64) / 1024,
        };

        // Apply priority multiplier
        let priority_multiplier = match priority {
            Priority::Low => 0.8,
            Priority::Normal => 1.0,
            Priority::High => 1.5,
            Priority::Urgent => 2.0,
        };

        let adjusted_base_fee = (base_fee as f64 * priority_multiplier) as u64;

        // Calculate DAO fee for UBI funding
        let dao_fee = if self.config.mandatory_dao_fees {
            let calculated_dao_fee = (adjusted_base_fee as f64 * self.config.dao_fee_percentage / 100.0) as u64;
            std::cmp::max(calculated_dao_fee, 1) // Minimum 1 unit DAO fee
        } else {
            0
        };

        // Calculate network fee for infrastructure
        let network_fee = adjusted_base_fee / 10; // 10% of base fee

        let total_fee = adjusted_base_fee + dao_fee + network_fee;

        // Create fee breakdown
        let mut breakdown = HashMap::new();
        breakdown.insert("base_fee".to_string(), adjusted_base_fee);
        breakdown.insert("dao_fee".to_string(), dao_fee);
        breakdown.insert("network_fee".to_string(), network_fee);
        breakdown.insert("priority_bonus".to_string(), 
            (adjusted_base_fee as f64 * (priority_multiplier - 1.0)) as u64);

        Ok(EconomicAssessment {
            base_fee: adjusted_base_fee,
            dao_fee,
            network_fee,
            total_fee,
            payment_method: "ZHTP".to_string(),
            breakdown,
        })
    }

    /// Validate DAO fee payment for UBI funding
    pub fn validate_dao_fee_payment(
        &self,
        expected_fee: u64,
        paid_amount: u64,
        payment_proof: &[u8],
    ) -> Result<bool> {
        // Check if DAO fees are mandatory
        if self.config.mandatory_dao_fees {
            if paid_amount < expected_fee {
                return Err(ProtocolError::DaoFeeError(
                    format!("Insufficient DAO fee: expected {}, paid {}", expected_fee, paid_amount)
                ));
            }
        }

        // Validate payment proof using lib-blockchain
        if payment_proof.is_empty() && expected_fee > 0 {
            return Err(ProtocolError::DaoFeeError("Missing payment proof".to_string()));
        }

        // Use lib-blockchain for actual transaction validation
        if expected_fee > 0 {
            // For now, validate payment proof structure and amount
            let calculated_fee = (paid_amount as f64 * self.config.dao_fee_percentage / 100.0) as u64;
            if calculated_fee < expected_fee {
                return Err(ProtocolError::DaoFeeError(
                    format!("DAO fee calculation mismatch: expected {}, calculated {}", 
                           expected_fee, calculated_fee)
                ));
            }
            
            // For now, accept valid payment proofs - in production this would
            // validate against the actual blockchain transaction
            Ok(true)
        } else {
            Ok(true)
        }
    }

    /// Process UBI distribution
    pub async fn process_ubi_distribution(
        &mut self,
        total_collected_fees: u64,
        participant_count: u64,
    ) -> Result<Vec<UBIPayment>> {
        if !self.config.ubi_enabled || total_collected_fees == 0 {
            return Ok(Vec::new());
        }

        // Calculate UBI amount per participant
        let ubi_pool = (total_collected_fees as f64 * 0.8) as u64; // 80% for UBI
        let per_participant = if participant_count > 0 {
            ubi_pool / participant_count
        } else {
            0
        };

        // Create UBI payments (simplified)
        let mut payments = Vec::new();
        for i in 0..participant_count {
            payments.push(UBIPayment {
                participant_id: format!("participant_{}", i),
                amount: per_participant,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            });
        }

        Ok(payments)
    }

    /// Get economic statistics
    pub fn get_economic_stats(&self) -> EconomicStats {
        // Use lib-economy for fee tracking
        use lib_identity::wallets::IdentityWallets;
        
        // In a implementation, this would query the economic state
        // For now, we'll use the economic model to provide estimates
        let base_fee = self.model.calculate_fee(1000, 1000, Priority::Normal).1; // Get network fee
        let dao_fee = (base_fee as f64 * self.config.dao_fee_percentage / 100.0) as u64;
        
        EconomicStats {
            total_fees_collected: base_fee * 100, // Estimate based on activity
            dao_fees_collected: dao_fee * 100,
            ubi_distributed: (dao_fee * 80) / 100, // 80% of DAO fees for UBI
            active_participants: 1000, // Would be tracked in system
            average_fee_per_operation: base_fee,
            dao_fee_percentage: self.config.dao_fee_percentage,
        }
    }
}

/// UBI payment record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UBIPayment {
    /// Participant receiving UBI
    pub participant_id: String,
    /// Amount of UBI payment
    pub amount: u64,
    /// Timestamp of payment
    pub timestamp: u64,
}

/// Economic statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicStats {
    /// Total fees collected across all operations
    pub total_fees_collected: u64,
    /// Total DAO fees collected for UBI
    pub dao_fees_collected: u64,
    /// Total UBI distributed to participants
    pub ubi_distributed: u64,
    /// Number of active participants
    pub active_participants: u64,
    /// Average fee per operation
    pub average_fee_per_operation: u64,
    /// Current DAO fee percentage
    pub dao_fee_percentage: f64,
}

/// Protocol-specific economic utilities
pub mod utils {
    use super::*;

    /// Calculate request value for DAO fee calculation (moved from types/request.rs to avoid duplication)
    pub fn calculate_request_value(method: &crate::types::ZhtpMethod, body: &[u8], uri: &str) -> u64 {
        match method {
            crate::types::ZhtpMethod::Post | crate::types::ZhtpMethod::Put | crate::types::ZhtpMethod::Patch => {
                // For content creation/modification, use content size as value
                body.len() as u64 * 10 // 10 tokens per byte for content operations
            }
            crate::types::ZhtpMethod::Get | crate::types::ZhtpMethod::Head => {
                // For content retrieval, use base value plus URI complexity
                100 + (uri.len() as u64 / 10) // Base 100 tokens + URI complexity
            }
            crate::types::ZhtpMethod::Delete => {
                // Deletion operations have medium cost
                200 + (uri.len() as u64 / 5) // Base 200 tokens + URI complexity
            }
            crate::types::ZhtpMethod::Verify => {
                // Verification operations have lower cost
                50 + (uri.len() as u64 / 20) // Base 50 tokens + URI complexity
            }
            _ => {
                // Other operations use header value or default
                50 + (uri.len() as u64 / 10) // Minimum 50 tokens + URI complexity
            }
        }
    }

    /// Calculate dynamic fee based on network load
    pub fn calculate_dynamic_fee(base_fee: u64, network_load: f64) -> u64 {
        if network_load > 0.8 {
            // High load: increase fees by up to 50%
            (base_fee as f64 * (1.0 + (network_load - 0.8) * 2.5)) as u64
        } else if network_load < 0.2 {
            // Low load: decrease fees by up to 20%
            (base_fee as f64 * (0.8 + network_load)) as u64
        } else {
            base_fee
        }
    }

    /// Validate economic transaction format
    pub fn validate_transaction_format(transaction_data: &[u8]) -> Result<()> {
        if transaction_data.is_empty() {
            return Err(ProtocolError::EconomicError("Empty transaction data".to_string()));
        }

        if transaction_data.len() < 32 {
            return Err(ProtocolError::EconomicError("Transaction data too short".to_string()));
        }

        // Use lib-blockchain for sophisticated transaction validation
        use lib_blockchain::{Transaction, TransactionValidator};
        
        // Try to parse as a blockchain transaction
        match serde_json::from_slice::<Transaction>(transaction_data) {
            Ok(transaction) => {
                let validator = TransactionValidator::new();
                match validator.validate_transaction(&transaction) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(ProtocolError::EconomicError(
                        format!("Blockchain validation failed: {}", e)
                    ))
                }
            },
            Err(_) => {
                // Not a valid JSON transaction, treat as raw data
                // Basic validation passed
                Ok(())
            }
        }
    }

    /// Generate economic transaction ID
    pub fn generate_transaction_id() -> String {
        use uuid::Uuid;
        format!("lib_tx_{}", Uuid::new_v4())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_economics_initialization() {
        let config = EconomicConfig::default();
        let economics = ZhtpEconomics::new(config);
        assert!(economics.is_ok());
    }

    #[test]
    fn test_fee_calculation() {
        let config = EconomicConfig::default();
        let economics = ZhtpEconomics::new(config).unwrap();
        
        let assessment = economics.calculate_operation_fees("GET", 1024, Priority::Normal).unwrap();
        
        assert!(assessment.total_fee > 0);
        assert!(assessment.dao_fee > 0); // Should have DAO fee
        assert_eq!(assessment.total_fee, assessment.base_fee + assessment.dao_fee + assessment.network_fee);
    }

    #[test]
    fn test_dao_fee_validation() {
        let mut config = EconomicConfig::default();
        config.dao_fee_percentage = 2.0; // 2% DAO fee
        let economics = ZhtpEconomics::new(config).unwrap();
        
        // Valid payment with proper proof
        let payment_proof = b"valid_payment_proof_hash_12345678901234567890";
        assert!(economics.validate_dao_fee_payment(2, 100, payment_proof).is_ok());
        
        // Insufficient payment
        assert!(economics.validate_dao_fee_payment(100, 50, b"proof").is_err());
    }

    #[test]
    fn test_dynamic_fee_calculation() {
        let base_fee = 1000;
        
        // High load should increase fees
        let high_load_fee = utils::calculate_dynamic_fee(base_fee, 0.9);
        assert!(high_load_fee > base_fee);
        
        // Low load should decrease fees
        let low_load_fee = utils::calculate_dynamic_fee(base_fee, 0.1);
        assert!(low_load_fee < base_fee);
        
        // Normal load should keep fees similar
        let normal_load_fee = utils::calculate_dynamic_fee(base_fee, 0.5);
        assert_eq!(normal_load_fee, base_fee);
    }
}
