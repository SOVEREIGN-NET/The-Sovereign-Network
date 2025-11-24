//! Economic Storage Manager
//! 
//! Central coordination point for all economic storage operations including:
//! - Contract lifecycle management
//! - Payment processing
//! - Reputation updates
//! - Market operations

use crate::types::{ContentHash, PenaltyType, RewardTier, EconomicManagerConfig, 
                   EconomicStorageRequest, EconomicQuote, EconomicStats, QualityMetrics, CostBreakdown, PenaltyClause,
                   StorageTier, EncryptionLevel, AccessPattern, QualityViolation,
                   PricingRequest}; // Add missing enum imports
use crate::economic::{contracts::*, pricing::*, market::*, reputation::*, payments::*, 
                      incentives::{IncentiveSystem, IncentiveConfig}, quality::*, penalties::*, rewards::*};
use anyhow::{Result, anyhow};

use lib_crypto::Hash;


/// Economic storage manager that coordinates all economic activities
#[derive(Debug)]
pub struct EconomicStorageManager {
    /// Configuration
    config: EconomicManagerConfig,
    /// Contract manager
    contract_manager: ContractManager,
    /// Pricing engine
    pricing_engine: PricingEngine,
    /// Market manager
    market_manager: MarketManager,
    /// Reputation system
    reputation_system: ReputationSystem,
    /// Payment processor
    payment_processor: PaymentProcessor,
    /// Incentive manager
    incentive_manager: IncentiveSystem,
    /// Quality assurance
    quality_assurance: QualityAssurance,
    /// Penalty enforcer
    penalty_enforcer: PenaltyEnforcer,
    /// Storage reward tracker (metrics only)
    reward_tracker: StorageRewardTracker,
}

impl EconomicStorageManager {
    /// Create new economic storage manager
    pub fn new(config: EconomicManagerConfig) -> Self {
        Self {
            config: config.clone(),
            contract_manager: ContractManager::new(),
            pricing_engine: PricingEngine::new(),
            market_manager: MarketManager::new(),
            reputation_system: ReputationManager::new(ReputationConfig::default()),
            payment_processor: PaymentProcessor::new(),
            incentive_manager: IncentiveSystem::new(IncentiveConfig::default()),
            quality_assurance: QualityAssurance::new(QualityConfig::default()),
            penalty_enforcer: PenaltyEnforcer::new(),
            reward_tracker: StorageRewardTracker::new(),
        }
    }

    /// Process economic storage request
    pub async fn process_storage_request(&mut self, request: EconomicStorageRequest) -> Result<EconomicQuote> {
        // Calculate pricing
        let _pricing_request = PricingRequest {
            data_size: request.content.len() as u64,
            duration_days: request.requirements.duration_days,
            preferred_tier: request.preferred_tier,
            quality_requirements: request.requirements.quality_requirements.clone(),
            budget_constraints: Some(request.requirements.budget_constraints.clone()),
            geographic_preferences: request.requirements.geographic_preferences.clone(),
        };

        // Convert to pricing-compatible request structure
        let storage_request = StorageRequest {
            size: request.content.len() as u64,
            tier: request.preferred_tier,
            duration: (request.requirements.duration_days as u64) * 24 * 3600, // Convert days to seconds
            quality_level: QualityLevel::Basic, // Default for now
            geographic_region: request.requirements.geographic_preferences.first().cloned(),
            urgency: UrgencyLevel::Normal, // Default for now
            replication_factor: request.requirements.replication_factor,
        };

        // Calculate storage price
        let price_quote = self.pricing_engine.calculate_quote(&storage_request)?;

        // Find suitable storage providers using quality requirements
        let storage_nodes = self.market_manager.find_storage_providers_with_quality(
            request.content.len() as u64,
            request.requirements.duration_days,
            &request.requirements.quality_requirements,
        );

        if storage_nodes.is_empty() {
            return Err(anyhow!("No suitable storage providers found"));
        }

        // Create cost breakdown
        let base_cost = price_quote.final_price;
        let quality_premium = (base_cost as f64 * 0.1) as u64; // 10% quality premium
        let network_fees = (base_cost as f64 * 0.05) as u64; // 5% network fees
        let escrow_fees = if request.payment_preferences.escrow_preferences.use_escrow {
            (base_cost as f64 * 0.02) as u64 // 2% escrow fees
        } else {
            0
        };

        let total_cost = base_cost + quality_premium + network_fees + escrow_fees;

        // Check budget constraints
        if total_cost > request.requirements.budget_constraints.max_total_cost {
            return Err(anyhow!("Quote exceeds budget constraints"));
        }

        let _cost_breakdown = CostBreakdown {
            base_storage_cost: base_cost,
            quality_premium,
            network_fees,
            escrow_fees,
            total_cost,
        };

        // Calculate quality metrics
        let quality_metrics = self.calculate_expected_quality(&storage_nodes).await?;

        let quote = EconomicQuote {
            quote_id: hex::encode(&Hash::from_bytes(&rand::random::<[u8; 32]>()).as_bytes()[..8]),
            total_cost,
            cost_per_gb_day: base_cost / ((request.content.len() as u64 / (1024 * 1024 * 1024)).max(1) * request.requirements.duration_days as u64),
            duration_days: request.requirements.duration_days,
            recommended_nodes: storage_nodes.into_iter()
                .map(|node_str| Hash::from_bytes(hex::decode(node_str).unwrap_or_default().as_slice()))
                .collect(),
            estimated_quality: quality_metrics,
            valid_until: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 3600, // Valid for 1 hour
            terms: vec![
                "Standard storage terms apply".to_string(),
                "Payment due within 24 hours".to_string(),
                "Data encryption included".to_string(),
            ],
        };

        Ok(quote)
    }

    /// Create storage contract from quote
    pub async fn create_contract(&mut self, quote: EconomicQuote, content_hash: ContentHash, content_size: u64) -> Result<Hash> {
        // Verify quote is still valid
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > quote.valid_until {
            return Err(anyhow!("Quote has expired"));
        }

        // Create contract
        let client_id = content_hash.to_string();
        let provider_id = quote.recommended_nodes.first()
            .ok_or_else(|| anyhow!("No storage nodes in quote"))?
            .to_string();
        
        let terms = ContractTerms {
            storage_size: content_size,
            duration: 30 * 24 * 60 * 60, // 30 days in seconds (default)
            tier: StorageTier::Hot, // Default tier
            replication_factor: 3,
            geographic_requirements: vec![],
            encryption_level: EncryptionLevel::Standard,
            expected_access_pattern: AccessPattern::Frequent,
            erasure_coding: ErasureCodingParams {
                data_shards: 6,
                parity_shards: 3,
                threshold: 6,
            },
            provider_nodes: quote.recommended_nodes.iter().map(|id| hex::encode(id.as_bytes())).collect(),
        };
        
        let sla = ServiceLevelAgreement::default();
        let payment = PaymentTerms::default();
        
        let contract_id = self.contract_manager.create_contract(
            client_id,
            provider_id,
            terms,
            sla,
            payment,
        )?;

        // Setup payment schedule
        let provider_id = quote.recommended_nodes.first()
            .ok_or_else(|| anyhow::anyhow!("No storage provider nodes available"))?
            .to_string();
            
        self.payment_processor.schedule_payment(
            contract_id.clone(),
            quote.total_cost,
            provider_id, // Use the actual provider ID from the quote
            crate::economic::payments::PaymentReason::ContractCompletion,
            vec![],
            quote.duration_days as u64 * 24 * 3600, // Convert days to seconds
        )?;

        // Add penalty clauses
        let penalties = self.create_default_penalties();
        let contract_hash = lib_crypto::Hash::from_bytes(contract_id.as_bytes());
        self.penalty_enforcer.add_contract_penalties(contract_hash, penalties);

        // Update market data
        self.market_manager.record_contract_creation(contract_id.clone(), quote.total_cost).await?;

        Ok(lib_crypto::Hash::from_bytes(contract_id.as_bytes()))
    }

    /// Process payment for contract
    pub async fn process_payment(&mut self, contract_id: Hash, payment_amount: u64) -> Result<()> {
        // Process pending payments
        self.payment_processor.process_pending_payments()?;

        // Update contract status
        self.contract_manager.update_payment_status(contract_id.clone(), payment_amount).await?;

        // Distribute rewards to storage providers
        if let Some(contract) = self.contract_manager.get_contract(&contract_id.to_string()) {
            let base_reward_per_node = payment_amount / contract.nodes.len() as u64;
            
            for node_id in &contract.nodes {
                // Get provider's current performance for incentive calculation
                if let Some(metrics) = self.quality_assurance.get_node_metrics(node_id).await? {
                    let performance_snapshot = crate::types::PerformanceSnapshot::new(
                        metrics.uptime,
                        metrics.avg_response_time,
                        metrics.data_integrity,
                        (metrics.bandwidth_utilization * 1_000_000.0) as u64, // Convert bandwidth utilization to throughput
                        0.01, // Default low error rate
                    );

                    // Calculate performance-based bonus from incentive system
                    let performance_bonus = self.incentive_manager.calculate_payment_bonus(
                        &node_id.to_string(),
                        performance_snapshot,
                        base_reward_per_node,
                    ).await?;

                    let total_reward = base_reward_per_node + performance_bonus;

                    // Distribute base reward
                    self.reward_tracker.distribute_rewards(
                        node_id.clone(),
                        total_reward,
                        format!("Payment with performance bonus for contract {}", contract_id),
                    )?;

                    // Update incentive system with successful payment
                    self.incentive_manager.record_successful_payment(
                        &node_id.to_string(),
                        total_reward,
                        format!("Contract {} payment", contract_id),
                    ).await?;
                } else {
                    // Fallback to base reward if no metrics available
                    self.reward_tracker.distribute_rewards(
                        node_id.clone(),
                        base_reward_per_node,
                        format!("Payment for contract {}", contract_id),
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Monitor contract performance
    pub async fn monitor_contract_performance(&mut self, contract_id: Hash) -> Result<()> {
        let contract_id_str = contract_id.to_string();
        let contract = self.contract_manager.get_contract(&contract_id_str)
            .ok_or_else(|| anyhow!("Contract not found"))?;

        for node_id in &contract.nodes {
            // Get performance metrics from quality assurance
            if let Some(metrics) = self.quality_assurance.get_node_metrics(node_id).await? {
                // Create performance snapshot for incentive system
                let performance_snapshot = crate::types::PerformanceSnapshot::new(
                    metrics.uptime,
                    metrics.avg_response_time,
                    metrics.data_integrity,
                    (metrics.bandwidth_utilization * 1_000_000.0) as u64, // Convert bandwidth utilization to throughput
                    0.01, // Default low error rate
                );

                // Calculate incentive rewards based on performance with reputation integration
                let incentive_reward = self.incentive_manager.calculate_performance_rewards_with_reputation(
                    &node_id.to_string(),
                    performance_snapshot,
                    &self.reputation_system,
                ).await?;

                // Distribute incentive rewards if performance meets thresholds
                if incentive_reward > 0 {
                    self.reward_tracker.distribute_rewards(
                        node_id.clone(),
                        incentive_reward,
                        format!("Performance incentive for contract {}", contract_id),
                    )?;
                }

                // Check for violations
                let violations = self.penalty_enforcer.check_violations(&Hash::from_bytes(contract.contract_id.as_bytes()), node_id)?;

                if !violations.is_empty() {
                    // Enforce penalties
                    for violation in violations {
                        let penalty_amount = self.calculate_penalty_amount(&violation, contract.total_cost);
                        
                        self.penalty_enforcer.enforce_penalty(
                            Hash::from_bytes(contract.contract_id.as_bytes()),
                            node_id.clone(),
                            violation.clone(),
                            penalty_amount,
                            format!("Performance violation: {:?}", violation),
                        )?;

                        // Update reputation
                        let quality_violation = QualityViolation {
                            violation_type: format!("{:?}", violation),
                            severity: match violation {
                                PenaltyType::DataLoss => 0.8,
                                PenaltyType::Unavailability => 0.6,
                                PenaltyType::SlowResponse => 0.3,
                                PenaltyType::ContractBreach => 0.9,
                                PenaltyType::QualityDegradation => 0.5,
                            },
                            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                            details: format!("Performance violation: {:?}", violation),
                        };
                        self.reputation_system.record_violation(node_id.clone(), quality_violation).await?;

                        // Update incentive system with penalty information
                        self.incentive_manager.record_penalty(
                            &node_id.to_string(),
                            penalty_amount,
                            format!("Penalty for {:?}", violation),
                        ).await?;
                    }
                }

                // Update node performance for rewards
                let performance = ProviderPerformance {
                    node_id: node_id.clone(),
                    reputation: self.reputation_system.get_reputation(&node_id.to_string()).map(|r| r.overall_score).unwrap_or(0.5),
                    uptime: metrics.uptime,
                    data_integrity: metrics.data_integrity,
                    avg_response_time: metrics.avg_response_time,
                    total_storage_provided: metrics.bandwidth_utilization as u64 * 1_000_000, // Convert to bytes
                    contracts_fulfilled: self.contract_manager.get_node_contract_count(node_id).await? as u32,
                    current_tier: RewardTier::Basic, // Will be determined by reward tracker
                };

                self.reward_tracker.update_provider_performance(performance);
            }
        }

        Ok(())
    }

    /// Calculate expected quality metrics
    async fn calculate_expected_quality(&self, nodes: &[String]) -> Result<QualityMetrics> {
        let mut total_reliability = 0.0;
        let mut total_availability = 0.0;
        let mut total_response_time = 0;
        let mut total_integrity = 0.0;

        for node_id in nodes {
            let reputation = self.reputation_system.get_reputation(node_id)
                .ok_or_else(|| anyhow!("Could not get reputation for node"))?;
            total_reliability += reputation.overall_score;
            
            if let Some(metrics) = self.quality_assurance.get_node_metrics(&lib_crypto::Hash::from_bytes(node_id.as_bytes())).await? {
                total_availability += metrics.availability * 100.0; // Convert to percentage
                total_response_time += metrics.avg_response_time;
                total_integrity += metrics.data_integrity;
            } else {
                // Default values for new nodes
                total_availability += 95.0;
                total_response_time += 1000;
                total_integrity += 0.95;
            }
        }

        let node_count = nodes.len() as f64;

        Ok(QualityMetrics {
            current_uptime: total_availability / node_count / 100.0,
            avg_response_time: (total_response_time as f64 / node_count) as u64,
            current_replication: 3, // Default replication
            quality_violations: 0, // Start with no violations
            last_quality_check: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            quality_score: (total_reliability / node_count) * 0.5 + (total_availability / node_count / 100.0) * 0.3 + (total_integrity / node_count) * 0.2,
            data_integrity: total_integrity / node_count,
            availability: total_availability / node_count / 100.0,
            performance: 0.9, // Default performance score
            reliability: total_reliability / node_count,
            security: 0.95, // Default security score
            responsiveness: (1000.0 / ((total_response_time as f64 / node_count).max(1.0))).min(1.0),
            overall_score: (total_reliability / node_count) * 0.5 + (total_availability / node_count / 100.0) * 0.3 + (total_integrity / node_count) * 0.2,
            confidence: 0.8, // Default confidence
            uptime: total_availability / node_count / 100.0,
            bandwidth_utilization: 0.7, // Default bandwidth utilization
            response_time: (total_response_time as f64 / node_count) as u64,
        })
    }

    /// Create default penalty clauses
    fn create_default_penalties(&self) -> Vec<PenaltyClause> {
        vec![
            PenaltyClause {
                penalty_type: PenaltyType::DataLoss,
                penalty_amount: 10000, // 10,000 ZHTP tokens
                conditions: "Data integrity below 99%".to_string(),
                grace_period: 3600, // 1 hour grace period
                max_applications: 3, // Maximum 3 applications per day
            },
            PenaltyClause {
                penalty_type: PenaltyType::Unavailability,
                penalty_amount: 5000, // 5,000 ZHTP tokens
                conditions: "Uptime below 95%".to_string(),
                grace_period: 1800, // 30 minute grace period
                max_applications: 5, // Maximum 5 applications per day
            },
            PenaltyClause {
                penalty_type: PenaltyType::SlowResponse,
                penalty_amount: 1000, // 1,000 ZHTP tokens
                conditions: "Response time above 5 seconds".to_string(),
                grace_period: 300, // 5 minute grace period
                max_applications: 10, // Maximum 10 applications per day
            },
            PenaltyClause {
                penalty_type: PenaltyType::ContractBreach,
                penalty_amount: 20000, // 20,000 ZHTP tokens
                conditions: "Bandwidth utilization below 80%".to_string(),
                grace_period: 0, // No grace period for breaches
                max_applications: 1, // Maximum 1 application per day
            },
        ]
    }

    /// Calculate penalty amount based on violation type
    fn calculate_penalty_amount(&self, penalty_type: &PenaltyType, contract_value: u64) -> u64 {
        match penalty_type {
            PenaltyType::DataLoss => contract_value / 2, // 50% of contract value
            PenaltyType::Unavailability => contract_value / 10, // 10% of contract value
            PenaltyType::SlowResponse => contract_value / 20, // 5% of contract value
            PenaltyType::ContractBreach => contract_value, // 100% of contract value
            PenaltyType::QualityDegradation => contract_value / 5, // 20% of contract value
        }
    }

    /// Get economic statistics
    pub async fn get_statistics(&self) -> Result<EconomicStats> {
        let contract_stats = self.contract_manager.get_statistics().await?;
        let penalty_stats = self.penalty_enforcer.get_penalty_stats();
        let reward_stats = self.reward_tracker.get_reward_stats();

        Ok(EconomicStats {
            total_contracts: contract_stats.total_contracts,
            total_storage: contract_stats.total_storage_under_contract,
            total_value_locked: contract_stats.total_contract_value,
            average_contract_value: if contract_stats.total_contracts > 0 {
                contract_stats.total_contract_value / contract_stats.total_contracts
            } else {
                0
            },
            total_penalties: penalty_stats.total_penalty_amount,
            total_rewards: reward_stats.total_rewards_distributed,
        })
    }

    /// Update configuration
    pub fn update_config(&mut self, config: EconomicManagerConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &EconomicManagerConfig {
        &self.config
    }
}

impl Default for EconomicStorageManager {
    fn default() -> Self {
        Self::new(EconomicManagerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_economic_manager_creation() {
        let config = EconomicManagerConfig::default();
        let manager = EconomicStorageManager::new(config);
        
        assert_eq!(manager.config.default_duration_days, 30);
    }

    #[tokio::test]
    async fn test_storage_request_processing() {
        let mut manager = EconomicStorageManager::new(EconomicManagerConfig::default());
        
        let request = EconomicStorageRequest {
            content: vec![1u8; 1_000_000], // 1 MB of test data
            filename: "test_file.txt".to_string(),
            content_type: "text/plain".to_string(),
            description: "Test file description".to_string(),
            preferred_tier: StorageTier::Cold,
            requirements: crate::types::StorageRequirements::default(),
            payment_preferences: PaymentPreferences::default(),
            requester: create_test_identity(),
        };

        // This test would need proper setup of market manager and pricing engine
        // For now, just test that the function exists and has correct signature
        let result = manager.process_storage_request(request).await;
        // Test completed - full implementation would verify quote details and provider matching
    }

    /// Helper function to create test identity for testing
    fn create_test_identity() -> crate::ZhtpIdentity {
        use lib_identity::types::{IdentityType, AccessLevel};
        use lib_proofs::ZeroKnowledgeProof;
        use std::collections::HashMap;
        use lib_identity::IdentityId;
        use lib_identity::wallets::WalletManager;

        let identity_id = IdentityId::from_bytes(&[1u8; 32]);
        crate::ZhtpIdentity {
            id: identity_id.clone(),
            identity_type: IdentityType::Human,
            public_key: vec![1, 2, 3, 4, 5],
            ownership_proof: ZeroKnowledgeProof {
                proof_system: "test".to_string(),
                proof_data: vec![],
                public_inputs: vec![],
                verification_key: vec![],
                plonky2_proof: None,
                proof: vec![],
            },
            credentials: HashMap::new(),
            reputation: 100,
            age: Some(25),
            access_level: AccessLevel::FullCitizen,
            metadata: HashMap::new(),
            private_data_id: None,
            wallet_manager: WalletManager::new(identity_id),
            did_document_hash: None,
            attestations: vec![],
            created_at: 1234567890,
            last_active: 1234567890,
            recovery_keys: vec![],
        }
    }
}
