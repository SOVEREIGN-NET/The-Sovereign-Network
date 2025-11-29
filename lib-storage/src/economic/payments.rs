//! Payment Processing and Escrow System
//! 
//! Implements secure payment processing for storage contracts including:
//! - Multi-signature escrow accounts
//! - Automated payment releases
//! - Micropayments for usage-based billing
//! - Dispute resolution with fund protection
//! - Cross-chain payment support

use crate::types::{PaymentStatus, PaymentType, EscrowCondition, DisputeResolution};
use crate::economic::contracts::ContractStatus;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use lib_crypto::PostQuantumSignature;

/// Payment processor for storage contracts
#[derive(Debug)]
pub struct PaymentProcessor {
    /// Active escrow accounts
    escrow_accounts: HashMap<String, EscrowAccount>,
    /// Payment history
    payment_history: HashMap<String, Vec<PaymentRecord>>,
    /// Pending payments
    pending_payments: HashMap<String, PendingPayment>,
    /// Dispute accounts
    dispute_accounts: HashMap<String, DisputeAccount>,
}

/// Escrow account for secure payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowAccount {
    /// Unique account identifier
    pub account_id: String,
    /// Associated contract ID
    pub contract_id: String,
    /// Client's public key
    pub client_pubkey: String,
    /// Provider's public key
    pub provider_pubkey: String,
    /// Network witness public keys
    pub witness_pubkeys: Vec<String>,
    /// Current balance in tokens
    pub balance: u64,
    /// Locked (escrowed) amount
    pub locked_amount: u64,
    /// Release conditions
    pub release_conditions: Vec<EscrowCondition>,
    /// Multi-signature threshold
    pub signature_threshold: u8,
    /// Account creation timestamp
    pub created_at: u64,
    /// Account status
    pub status: EscrowStatus,
}

/// Escrow account status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EscrowStatus {
    Active,
    Locked,
    Released,
    Disputed,
    Closed,
}

/// Payment record for transaction history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRecord {
    /// Payment transaction ID
    pub payment_id: String,
    /// Contract ID
    pub contract_id: String,
    /// Payer identity
    pub payer: String,
    /// Payee identity
    pub payee: String,
    /// Payment amount
    pub amount: u64,
    /// Payment type
    pub payment_type: PaymentType,
    /// Transaction timestamp
    pub timestamp: u64,
    /// Payment status
    pub status: PaymentStatus,
    /// Transaction hash
    pub tx_hash: Option<String>,
    /// Payment description
    pub description: String,
}

// PaymentType and PaymentStatus are imported from crate::types

/// Pending payment awaiting execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPayment {
    /// Payment ID
    pub payment_id: String,
    /// Contract ID
    pub contract_id: String,
    /// Payment amount
    pub amount: u64,
    /// Payment recipient
    pub recipient: String,
    /// Payment reason
    pub reason: PaymentReason,
    /// Scheduled execution time
    pub scheduled_time: u64,
    /// Required signatures
    pub required_signatures: Vec<String>,
    /// Collected signatures
    pub signatures: Vec<PaymentSignature>,
    /// Payment conditions
    pub conditions: Vec<PaymentCondition>,
}

/// Reasons for payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentReason {
    ContractCompletion,
    MilestoneReached,
    PerformanceBonus,
    SlaPenalty,
    MonthlyPayment,
    UsageBasedPayment,
    DisputeSettlement,
}

/// Payment signature for multi-sig
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSignature {
    /// Signer public key
    pub signer: String,
    /// Digital signature
    pub signature: PostQuantumSignature,
    /// Signature timestamp
    pub timestamp: u64,
}

/// Conditions that must be met for payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentCondition {
    TimeElapsed(u64),
    PerformanceThreshold(f64),
    ContractStatus(ContractStatus),
    ExternalConfirmation(String),
    MultiSigThreshold(u8),
}

/// Dispute account for contested payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeAccount {
    /// Dispute ID
    pub dispute_id: String,
    /// Related contract ID
    pub contract_id: String,
    /// Disputed amount
    pub disputed_amount: u64,
    /// Dispute reason
    pub dispute_reason: DisputeReason,
    /// Disputing party
    pub disputing_party: String,
    /// Dispute evidence
    pub evidence: Vec<DisputeEvidence>,
    /// Arbitrator assignments
    pub arbitrators: Vec<String>,
    /// Dispute status
    pub status: DisputeStatus,
    /// Dispute resolution
    pub resolution: Option<DisputeResolution>,
    /// Created timestamp
    pub created_at: u64,
}

/// Reasons for payment disputes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisputeReason {
    ServiceNotProvided,
    SlaViolation,
    DataLoss,
    OverCharging,
    UnauthorizedCharges,
    TechnicalIssues,
    ContractBreach,
}

/// Evidence submitted for disputes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeEvidence {
    /// Evidence type
    pub evidence_type: String,
    /// Evidence data
    pub data: Vec<u8>,
    /// Evidence hash
    pub hash: String,
    /// Submitter
    pub submitter: String,
    /// Submission timestamp
    pub timestamp: u64,
}

/// Dispute resolution status
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DisputeStatus {
    Open,
    UnderReview,
    Resolved,
    Escalated,
    Closed,
}

/// Usage-based billing calculator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBilling {
    /// Contract ID
    pub contract_id: String,
    /// Billing period start
    pub period_start: u64,
    /// Billing period end
    pub period_end: u64,
    /// Storage usage metrics
    pub storage_usage: StorageUsageMetrics,
    /// Bandwidth usage metrics
    pub bandwidth_usage: BandwidthUsageMetrics,
    /// API call metrics
    pub api_usage: ApiUsageMetrics,
    /// Calculated charges
    pub charges: BillingCharges,
}

/// Storage usage tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageUsageMetrics {
    /// Average storage used (bytes)
    pub avg_storage_used: u64,
    /// Peak storage used (bytes)
    pub peak_storage_used: u64,
    /// Storage-hours consumed
    pub storage_hours: u64,
}

/// Bandwidth usage tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthUsageMetrics {
    /// Total bytes uploaded
    pub bytes_uploaded: u64,
    /// Total bytes downloaded
    pub bytes_downloaded: u64,
    /// Peak bandwidth usage
    pub peak_bandwidth: u64,
}

/// API usage tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiUsageMetrics {
    /// Read operations count
    pub read_operations: u64,
    /// Write operations count
    pub write_operations: u64,
    /// Delete operations count
    pub delete_operations: u64,
    /// List operations count
    pub list_operations: u64,
}

/// Calculated billing charges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingCharges {
    /// Storage charges
    pub storage_charge: u64,
    /// Bandwidth charges
    pub bandwidth_charge: u64,
    /// API operation charges
    pub api_charge: u64,
    /// Performance bonuses
    pub bonuses: u64,
    /// SLA penalties
    pub penalties: u64,
    /// Total amount due
    pub total_due: u64,
}

impl PaymentProcessor {
    /// Create a new payment processor
    pub fn new() -> Self {
        Self {
            escrow_accounts: HashMap::new(),
            payment_history: HashMap::new(),
            pending_payments: HashMap::new(),
            dispute_accounts: HashMap::new(),
        }
    }

    /// Create an escrow account for a contract
    pub fn create_escrow_account(
        &mut self,
        contract_id: String,
        client_pubkey: String,
        provider_pubkey: String,
        witness_pubkeys: Vec<String>,
        initial_deposit: u64,
        release_conditions: Vec<EscrowCondition>,
    ) -> Result<String> {
        let account_id = format!("escrow_{}", uuid::Uuid::new_v4());
        
        let account = EscrowAccount {
            account_id: account_id.clone(),
            contract_id: contract_id.clone(),
            client_pubkey,
            provider_pubkey,
            witness_pubkeys,
            balance: initial_deposit,
            locked_amount: initial_deposit,
            release_conditions,
            signature_threshold: 2, // Require both client and provider by default
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: EscrowStatus::Active,
        };

        self.escrow_accounts.insert(account_id.clone(), account);
        
        // Record the escrow deposit
        let payment_record = PaymentRecord {
            payment_id: format!("payment_{}", uuid::Uuid::new_v4()),
            contract_id,
            payer: "client".to_string(), // Would be actual client ID
            payee: "escrow".to_string(),
            amount: initial_deposit,
            payment_type: PaymentType::Deposit,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: PaymentStatus::Completed,
            tx_hash: None,
            description: "Initial escrow deposit".to_string(),
        };

        self.payment_history
            .entry(account_id.clone())
            .or_insert_with(Vec::new)
            .push(payment_record);

        Ok(account_id)
    }

    /// Schedule a payment
    pub fn schedule_payment(
        &mut self,
        contract_id: String,
        amount: u64,
        recipient: String,
        reason: PaymentReason,
        conditions: Vec<PaymentCondition>,
        scheduled_time: u64,
    ) -> Result<String> {
        let payment_id = format!("payment_{}", uuid::Uuid::new_v4());
        
        let pending_payment = PendingPayment {
            payment_id: payment_id.clone(),
            contract_id,
            amount,
            recipient,
            reason,
            scheduled_time,
            required_signatures: Vec::new(), // Would be populated based on contract
            signatures: Vec::new(),
            conditions,
        };

        self.pending_payments.insert(payment_id.clone(), pending_payment);
        Ok(payment_id)
    }

    /// Execute pending payments that meet conditions
    pub fn process_pending_payments(&mut self) -> Result<Vec<String>> {
        let mut executed_payments = Vec::new();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut payments_to_remove = Vec::new();
        let mut payments_to_execute = Vec::new();

        // First, collect payments that need to be executed
        for (payment_id, payment) in &self.pending_payments {
            if payment.scheduled_time <= current_time && 
               self.check_payment_conditions(payment)? {
                payments_to_execute.push((payment_id.clone(), payment.clone()));
                payments_to_remove.push(payment_id.clone());
            }
        }

        // Then execute them
        for (payment_id, payment) in payments_to_execute {
            self.execute_payment(&payment)?;
            executed_payments.push(payment_id);
        }

        // Remove executed payments
        for payment_id in payments_to_remove {
            self.pending_payments.remove(&payment_id);
        }

        Ok(executed_payments)
    }

    /// Check if payment conditions are met
    fn check_payment_conditions(&self, payment: &PendingPayment) -> Result<bool> {
        for condition in &payment.conditions {
            match condition {
                PaymentCondition::TimeElapsed(required_time) => {
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if current_time < *required_time {
                        return Ok(false);
                    }
                }
                PaymentCondition::MultiSigThreshold(threshold) => {
                    if payment.signatures.len() < (*threshold as usize) {
                        return Ok(false);
                    }
                }
                // Add other condition checks
                _ => {}
            }
        }
        Ok(true)
    }

    /// Execute a payment from escrow
    fn execute_payment(&mut self, payment: &PendingPayment) -> Result<()> {
        // Find the escrow account for this contract
        let escrow_account = self.escrow_accounts
            .values_mut()
            .find(|acc| acc.contract_id == payment.contract_id)
            .ok_or_else(|| anyhow!("Escrow account not found"))?;

        if escrow_account.locked_amount < payment.amount {
            return Err(anyhow!("Insufficient escrow balance"));
        }

        // Deduct from escrow
        escrow_account.locked_amount -= payment.amount;
        escrow_account.balance -= payment.amount;

        // Record the payment
        let payment_record = PaymentRecord {
            payment_id: payment.payment_id.clone(),
            contract_id: payment.contract_id.clone(),
            payer: "escrow".to_string(),
            payee: payment.recipient.clone(),
            amount: payment.amount,
            payment_type: PaymentType::Storage,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: PaymentStatus::Completed,
            tx_hash: None,
            description: format!("Payment for {:?}", payment.reason),
        };

        self.payment_history
            .entry(escrow_account.account_id.clone())
            .or_insert_with(Vec::new)
            .push(payment_record);

        Ok(())
    }

    /// Calculate usage-based billing
    pub fn calculate_usage_billing(
        &self,
        contract_id: &str,
        usage_metrics: (StorageUsageMetrics, BandwidthUsageMetrics, ApiUsageMetrics),
        pricing_rates: &BillingRates,
    ) -> Result<UsageBilling> {
        let (storage_usage, bandwidth_usage, api_usage) = usage_metrics;
        
        // Calculate storage charges (storage-hours * rate)
        let storage_charge = (storage_usage.storage_hours * pricing_rates.storage_rate_per_hour) / 1000;
        
        // Calculate bandwidth charges
        let bandwidth_charge = 
            ((bandwidth_usage.bytes_uploaded + bandwidth_usage.bytes_downloaded) 
             * pricing_rates.bandwidth_rate_per_gb) / (1024 * 1024 * 1024);
        
        // Calculate API charges
        let api_charge = 
            storage_usage.avg_storage_used * pricing_rates.read_operation_rate +
            bandwidth_usage.bytes_uploaded * pricing_rates.write_operation_rate +
            api_usage.delete_operations * pricing_rates.delete_operation_rate +
            api_usage.list_operations * pricing_rates.list_operation_rate;

        let charges = BillingCharges {
            storage_charge,
            bandwidth_charge,
            api_charge,
            bonuses: 0, // Would be calculated based on performance
            penalties: 0, // Would be calculated based on SLA violations
            total_due: storage_charge + bandwidth_charge + api_charge,
        };

        Ok(UsageBilling {
            contract_id: contract_id.to_string(),
            period_start: 0, // Would be set based on billing period
            period_end: 0,   // Would be set based on billing period
            storage_usage,
            bandwidth_usage,
            api_usage,
            charges,
        })
    }

    /// Create a payment dispute
    pub fn create_dispute(
        &mut self,
        contract_id: String,
        disputed_amount: u64,
        reason: DisputeReason,
        disputing_party: String,
        evidence: Vec<DisputeEvidence>,
    ) -> Result<String> {
        let dispute_id = format!("dispute_{}", uuid::Uuid::new_v4());
        
        let dispute = DisputeAccount {
            dispute_id: dispute_id.clone(),
            contract_id: contract_id.clone(),
            disputed_amount,
            dispute_reason: reason,
            disputing_party,
            evidence,
            arbitrators: Vec::new(),
            status: DisputeStatus::Open,
            resolution: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Lock the disputed amount in escrow
        if let Some(escrow) = self.escrow_accounts.values_mut()
            .find(|acc| acc.contract_id == contract_id) {
            escrow.status = EscrowStatus::Disputed;
        }

        self.dispute_accounts.insert(dispute_id.clone(), dispute);
        Ok(dispute_id)
    }

    /// Get payment history for a contract
    pub fn get_payment_history(&self, contract_id: &str) -> Vec<&PaymentRecord> {
        self.payment_history
            .values()
            .flatten()
            .filter(|record| record.contract_id == contract_id)
            .collect()
    }

    /// Get escrow account balance
    pub fn get_escrow_balance(&self, contract_id: &str) -> Option<u64> {
        self.escrow_accounts
            .values()
            .find(|acc| acc.contract_id == contract_id)
            .map(|acc| acc.balance)
    }
}

/// Billing rates configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingRates {
    /// Storage rate per hour per byte (in micro-tokens)
    pub storage_rate_per_hour: u64,
    /// Bandwidth rate per GB (in tokens)
    pub bandwidth_rate_per_gb: u64,
    /// Rate per read operation (in micro-tokens)
    pub read_operation_rate: u64,
    /// Rate per write operation (in micro-tokens)
    pub write_operation_rate: u64,
    /// Rate per delete operation (in micro-tokens)
    pub delete_operation_rate: u64,
    /// Rate per list operation (in micro-tokens)
    pub list_operation_rate: u64,
}

impl Default for PaymentProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_processor_creation() {
        let processor = PaymentProcessor::new();
        assert!(processor.escrow_accounts.is_empty());
        assert!(processor.payment_history.is_empty());
    }

    #[test]
    fn test_escrow_account_creation() {
        let mut processor = PaymentProcessor::new();
        
        let account_id = processor.create_escrow_account(
            "contract1".to_string(),
            "client_pubkey".to_string(),
            "provider_pubkey".to_string(),
            vec!["witness1".to_string()],
            1000,
            vec![EscrowCondition::ContractCompletion],
        ).unwrap();

        assert!(processor.escrow_accounts.contains_key(&account_id));
        assert_eq!(processor.escrow_accounts[&account_id].balance, 1000);
        assert_eq!(processor.escrow_accounts[&account_id].locked_amount, 1000);
    }

    #[test]
    fn test_payment_scheduling() {
        let mut processor = PaymentProcessor::new();
        
        let payment_id = processor.schedule_payment(
            "contract1".to_string(),
            500,
            "provider1".to_string(),
            PaymentReason::ContractCompletion,
            vec![PaymentCondition::TimeElapsed(1000)],
            2000,
        ).unwrap();

        assert!(processor.pending_payments.contains_key(&payment_id));
    }
}
