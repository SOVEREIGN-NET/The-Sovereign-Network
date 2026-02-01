//! Unified ZK Integration for ZHTP Blockchain
//! 
//! Eliminates redundant transaction and consensus proof generation by using
//! unified, composite proofs that cover all blockchain-related verifications.

use anyhow::{Result, anyhow};
use std::sync::Arc;
use tracing::{info, debug, warn};

use crate::types::TransactionId;
use crate::transaction::Transaction;
use crate::blockchain::Blockchain;

/// Enhanced blockchain manager with unified ZK proof coordination
pub struct UnifiedZkBlockchainManager {
    /// Base blockchain instance
    blockchain: Blockchain,
    /// Reference to the unified ZK coordinator
    zk_coordinator: Option<Arc<zhtp::ZkProofCoordinator>>,
}

impl UnifiedZkBlockchainManager {
    /// Create a new unified ZK blockchain manager
    pub fn new() -> Result<Self> {
        Ok(Self {
            blockchain: Blockchain::new()?,
            zk_coordinator: None,
        })
    }

    /// Set the ZK coordinator reference
    pub fn set_zk_coordinator(&mut self, coordinator: Arc<zhtp::ZkProofCoordinator>) {
        self.zk_coordinator = Some(coordinator);
    }

    /// Create a transaction with unified ZK proof (replaces multiple redundant proofs)
    pub async fn create_unified_transaction(
        &self,
        sender: TransactionId,
        recipient: TransactionId, 
        amount: u64,
        fee: u64,
        data: Vec<u8>,
    ) -> Result<zhtp::CompositeTransactionProof> {
        let coordinator = self.zk_coordinator.as_ref()
            .ok_or_else(|| anyhow!("ZK coordinator not set"))?;

        info!("Creating unified transaction proof for amount: {} (fee: {})", amount, fee);

        // Create comprehensive transaction data
        let transaction_data = self.create_transaction_data_for_proof(
            sender.clone(),
            recipient.clone(),
            amount,
            fee,
            &data,
        ).await?;

        // Generate unified proof requirements
        let requirements = zhtp::ProofRequirements {
            subsystem: zhtp::Subsystem::Blockchain,
            operation_type: zhtp::OperationType::Transaction,
            required_capabilities: vec![], // No special capabilities needed for basic transactions
            access_level: None,
            validity_duration: tokio::time::Duration::from_secs(600), // 10 minutes
        };

        // Generate or retrieve cached composite proof
        let composite_proof = coordinator.get_or_generate_transaction_proof(
            &format!("{}_{}", hex::encode(sender.0), hex::encode(recipient.0)),
            &requirements,
            &transaction_data,
        ).await?;

        info!("Generated unified transaction proof covering validity, fees, and economics");
        Ok(composite_proof)
    }

    /// Verify a unified transaction proof (replaces multiple separate verifications)
    pub async fn verify_unified_transaction(
        &self,
        proof: &zhtp::CompositeTransactionProof,
        expected_amount: u64,
        expected_fee: u64,
    ) -> Result<bool> {
        let coordinator = self.zk_coordinator.as_ref()
            .ok_or_else(|| anyhow!("ZK coordinator not set"))?;

        info!("Verifying unified transaction proof");

        // Verify the composite proof
        let unified_proof_type = zhtp::UnifiedProofType::Transaction(proof.clone());
        let verification_result = coordinator.verify_proof(&unified_proof_type).await?;

        if !verification_result {
            warn!("Error: Unified transaction proof verification failed");
            return Ok(false);
        }

        // Verify fee calculation is consistent
        if proof.fee_proof.calculated_fee != expected_fee {
            warn!("Error:Fee calculation mismatch: expected {}, got {}", 
                  expected_fee, proof.fee_proof.calculated_fee);
            return Ok(false);
        }

        // Verify economic impact is positive (for reward-generating transactions)
        if proof.economic_proof.reward_eligibility && proof.economic_proof.economic_impact < 0 {
            warn!("Error: Negative economic impact for reward-eligible transaction");
            return Ok(false);
        }

        info!("Unified transaction proof verified successfully");
        Ok(true)
    }

    /// Generate unified consensus proof (replaces multiple consensus-related proofs)
    pub async fn generate_unified_consensus_proof(
        &self,
        validator_id: &str,
        stake_amount: u64,
        minimum_stake: u64,
        block_height: u64,
    ) -> Result<zhtp::ConsensusProof> {
        let coordinator = self.zk_coordinator.as_ref()
            .ok_or_else(|| anyhow!("ZK coordinator not set"))?;

        info!("Generating unified consensus proof for validator: {}", validator_id);

        // Generate stake range proof (proves sufficient stake without revealing exact amount)
        let stake_proof = coordinator.get_or_generate_range_proof(
            &format!("stake_{}", validator_id),
            zhtp::RangeProofType::Stake,
            stake_amount,      // secret value
            minimum_stake,     // minimum required
            None,              // no maximum
            format!("consensus_stake_{}", block_height).as_bytes(),
        ).await?;

        // Generate validator selection proof (proves valid selection without revealing algorithm)
        let selection_proof = coordinator.get_or_generate_range_proof(
            &format!("selection_{}", validator_id),
            zhtp::RangeProofType::Custom("validator_selection".to_string()),
            block_height % 1000, // simplified selection value
            0,                   // minimum
            Some(999),           // maximum
            format!("validator_selection_{}", block_height).as_bytes(),
        ).await?;

        // Generate voting power proof
        let voting_power = self.calculate_voting_power(stake_amount, minimum_stake);
        let voting_power_proof = coordinator.get_or_generate_range_proof(
            &format!("voting_power_{}", validator_id),
            zhtp::RangeProofType::VotingPower,
            voting_power,
            1, // minimum voting power
            Some(1000), // maximum voting power
            format!("voting_power_{}", block_height).as_bytes(),
        ).await?;

        let consensus_proof = zhtp::ConsensusProof {
            stake_proof: stake_proof.range_proof,
            selection_proof: lib_proofs::merkle::MerkleProof::default(), // Placeholder
            voting_power_proof: voting_power_proof.range_proof,
        };

        info!("Generated unified consensus proof for validator: {}", validator_id);
        Ok(consensus_proof)
    }

    /// Verify unified consensus proof
    pub async fn verify_unified_consensus_proof(
        &self,
        proof: &zhtp::ConsensusProof,
        validator_id: &str,
        minimum_stake: u64,
    ) -> Result<bool> {
        let coordinator = self.zk_coordinator.as_ref()
            .ok_or_else(|| anyhow!("ZK coordinator not set"))?;

        info!("Verifying unified consensus proof for validator: {}", validator_id);

        // Verify stake proof
        if !coordinator.verify_proof(&zhtp::UnifiedProofType::Range(zhtp::GenericRangeProof {
            range_type: zhtp::RangeProofType::Stake,
            range_proof: proof.stake_proof.clone(),
            context_data: vec![],
            min_value: minimum_stake,
            max_value: None,
        })).await? {
            warn!("Stake proof verification failed for validator: {}", validator_id);
            return Ok(false);
        }

        // Verify voting power proof
        if !coordinator.verify_proof(&zhtp::UnifiedProofType::Range(zhtp::GenericRangeProof {
            range_type: zhtp::RangeProofType::VotingPower,
            range_proof: proof.voting_power_proof.clone(),
            context_data: vec![],
            min_value: 1,
            max_value: Some(1000),
        })).await? {
            warn!("Voting power proof verification failed for validator: {}", validator_id);
            return Ok(false);
        }

        info!("Unified consensus proof verified for validator: {}", validator_id);
        Ok(true)
    }

    /// Add transaction to blockchain with unified proof verification
    pub async fn add_verified_transaction(
        &mut self,
        transaction: Transaction,
        proof: &zhtp::CompositeTransactionProof,
    ) -> Result<()> {
        // Verify the unified proof first
        let amount = 1000; // Placeholder - would extract from transaction
        let fee = proof.fee_proof.calculated_fee;
        
        if !self.verify_unified_transaction(proof, amount, fee).await? {
            return Err(anyhow!("Transaction proof verification failed"));
        }

        // Add to blockchain (simplified)
        self.blockchain.add_transaction(transaction)?;
        
        info!("Transaction added to blockchain with verified unified proof");
        Ok(())
    }

    /// Analyze transaction requirements to minimize proof generation
    pub fn analyze_transaction_requirements(
        &self,
        transaction_type: &str,
        involves_economics: bool,
        involves_consensus: bool,
    ) -> zhtp::SystemOperation {
        let mut potential_redundant_proofs = 1; // Base transaction proof

        if involves_economics {
            potential_redundant_proofs += 2; // Fee proof + reward proof
        }
        if involves_consensus {
            potential_redundant_proofs += 1; // Consensus weight proof
        }

        zhtp::SystemOperation {
            operation_type: zhtp::OperationType::Transaction,
            subsystem: zhtp::Subsystem::Blockchain,
            required_capabilities: vec![],
            access_level: zhtp::AccessLevel::Write,
            potential_redundant_proofs,
        }
    }

    /// Get blockchain statistics including ZK optimization metrics
    pub async fn get_blockchain_stats_with_zk_metrics(&self) -> Result<BlockchainStatsWithZk> {
        let coordinator = self.zk_coordinator.as_ref()
            .ok_or_else(|| anyhow!("ZK coordinator not set"))?;

        let zk_stats = coordinator.get_stats().await;
        let blockchain_height = self.blockchain.get_height();

        Ok(BlockchainStatsWithZk {
            block_height: blockchain_height,
            total_transactions: self.blockchain.get_transaction_count(),
            unified_proofs_generated: zk_stats.total_proofs_generated,
            proof_cache_hits: zk_stats.cache_hits,
            redundancy_eliminated: zk_stats.redundancy_eliminated,
            average_proof_time_ms: zk_stats.average_generation_time_ms,
        })
    }

    // Delegate to blockchain methods
    pub fn get_blockchain(&self) -> &Blockchain {
        &self.blockchain
    }

    pub fn get_height(&self) -> u64 {
        self.blockchain.get_height()
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<()> {
        self.blockchain.add_transaction(transaction)
    }

    pub fn get_balance(&self, address: &TransactionId) -> u64 {
        self.blockchain.get_balance(address)
    }

    // Private helper methods

    /// Create transaction data for ZK proof generation
    async fn create_transaction_data_for_proof(
        &self,
        sender: TransactionId,
        recipient: TransactionId,
        amount: u64,
        fee: u64,
        data: &[u8],
    ) -> Result<zhtp::TransactionData> {
        let sender_balance = self.blockchain.get_balance(&sender);
        
        // Calculate economic impact
        let contribution_score = if data.len() > 100 { 85 } else { 50 }; // Simplified scoring
        let economic_impact = if amount > 1000 { 100 } else { amount as i64 };
        
        // Calculate fee components
        let base_fee_rate = 1; // Base fee per byte
        let congestion_multiplier = 1.0 + (self.blockchain.get_pending_transaction_count() as f64 / 1000.0);
        let complexity_factor = 1.0 + (data.len() as f64 / 1000.0);

        Ok(zhtp::TransactionData {
            secret_amount: amount,
            secret_fee: fee,
            secret_nonce: self.blockchain.get_next_nonce(&sender),
            sender_balance,
            recipient_id: hex::encode(recipient.0),
            base_fee_rate,
            congestion_multiplier,
            complexity_factor,
            generates_rewards: amount > 100, // Simplified reward logic
            contribution_score,
            economic_impact,
        })
    }

    /// Calculate voting power based on stake
    fn calculate_voting_power(&self, stake_amount: u64, minimum_stake: u64) -> u64 {
        if stake_amount < minimum_stake {
            return 0;
        }
        
        // Logarithmic voting power to prevent excessive concentration
        let stake_ratio = stake_amount as f64 / minimum_stake as f64;
        let voting_power = (stake_ratio.ln() * 100.0) as u64;
        
        // Cap voting power at 1000
        std::cmp::min(voting_power, 1000)
    }
}

/// Blockchain statistics including ZK optimization metrics
#[derive(Debug, Clone)]
pub struct BlockchainStatsWithZk {
    pub block_height: u64,
    pub total_transactions: u64,
    pub unified_proofs_generated: u64,
    pub proof_cache_hits: u64,
    pub redundancy_eliminated: u64,
    pub average_proof_time_ms: f64,
}

/// Extension trait for existing Blockchain to add unified ZK capabilities
pub trait BlockchainZkExtension {
    /// Create transaction with unified proof
    fn create_unified_transaction_proof(
        &self,
        transaction_data: &TransactionData,
        coordinator: &zhtp::ZkProofCoordinator,
    ) -> impl std::future::Future<Output = Result<zhtp::CompositeTransactionProof>> + Send;

    /// Verify transaction with unified proof
    fn verify_unified_transaction_proof(
        &self,
        transaction: &Transaction,
        proof: &zhtp::CompositeTransactionProof,
        coordinator: &zhtp::ZkProofCoordinator,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

impl BlockchainZkExtension for Blockchain {
    async fn create_unified_transaction_proof(
        &self,
        transaction_data: &TransactionData,
        coordinator: &zhtp::ZkProofCoordinator,
    ) -> Result<zhtp::CompositeTransactionProof> {
        info!("Creating unified transaction proof for blockchain");

        let requirements = zhtp::ProofRequirements {
            subsystem: zhtp::Subsystem::Blockchain,
            operation_type: zhtp::OperationType::Transaction,
            required_capabilities: vec![],
            access_level: None,
            validity_duration: tokio::time::Duration::from_secs(600),
        };

        let proof = coordinator.get_or_generate_transaction_proof(
            &format!("blockchain_tx_{}", transaction_data.secret_nonce),
            &requirements,
            transaction_data,
        ).await?;

        info!("Created unified transaction proof for blockchain");
        Ok(proof)
    }

    async fn verify_unified_transaction_proof(
        &self,
        transaction: &Transaction,
        proof: &zhtp::CompositeTransactionProof,
        coordinator: &zhtp::ZkProofCoordinator,
    ) -> Result<bool> {
        info!("Verifying unified transaction proof for blockchain");

        let unified_proof_type = zhtp::UnifiedProofType::Transaction(proof.clone());
        let verification_result = coordinator.verify_proof(&unified_proof_type).await?;

        if !verification_result {
            warn!("Unified transaction proof verification failed");
            return Ok(false);
        }

        // Additional blockchain-specific validations
        if proof.fee_proof.calculated_fee < 1 {
            warn!("Fee too low for blockchain transaction");
            return Ok(false);
        }

        // Check if transaction would create valid state transition
        let sender_balance = self.get_balance(&transaction.sender);
        let total_cost = proof.fee_proof.calculated_fee + 1000; // Simplified amount extraction
        
        if sender_balance < total_cost {
            warn!("Insufficient balance for transaction");
            return Ok(false);
        }

        info!("Unified transaction proof verified for blockchain");
        Ok(true)
    }
}

impl Default for UnifiedZkBlockchainManager {
    fn default() -> Self {
        Self::new().expect("Failed to create unified ZK blockchain manager")
    }
}
