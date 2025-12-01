//! Storage Contracts and Service Level Agreements
//! 
//! Implements a comprehensive contract system for storage services including:
//! - Smart contracts for storage agreements
//! - Service Level Agreements (SLAs)
//! - Performance monitoring and enforcement
//! - Dispute resolution mechanisms
//! - Automated contract execution

use crate::types::*;
use crate::types::economic_types::{PaymentSchedule, DisputeResolution};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use lib_crypto::{Hash, PostQuantumSignature};
use uuid::Uuid;

/// Erasure coding parameters for data redundancy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureCodingParams {
    /// Number of data shards
    pub data_shards: usize,
    /// Number of parity shards for recovery
    pub parity_shards: usize,
    /// Minimum shards needed for reconstruction
    pub threshold: usize,
}

/// Storage contract between client and provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageContract {
    /// Unique contract identifier
    pub contract_id: String,
    /// Client identity
    pub client_id: String,
    /// Storage provider identity
    pub provider_id: String,
    /// Contract terms and conditions
    pub terms: ContractTerms,
    /// Service level agreement
    pub sla: ServiceLevelAgreement,
    /// Payment details
    pub payment: PaymentTerms,
    /// Contract status
    pub status: ContractStatus,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// Contract creation timestamp
    pub created_at: u64,
    /// Contract expiration timestamp
    pub expires_at: u64,
    /// Digital signatures
    pub signatures: ContractSignatures,
    /// Storage provider nodes
    pub nodes: Vec<NodeId>,
    /// Total contract cost
    pub total_cost: u64,
}

/// Contract terms and conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTerms {
    /// Storage size in bytes
    pub storage_size: u64,
    /// Storage duration in seconds
    pub duration: u64,
    /// Storage tier
    pub tier: StorageTier,
    /// Replication requirements
    pub replication_factor: u8,
    /// Geographic restrictions
    pub geographic_requirements: Vec<String>,
    /// Data encryption requirements
    pub encryption_level: EncryptionLevel,
    /// Access patterns
    pub expected_access_pattern: AccessPattern,
    /// Erasure coding parameters
    pub erasure_coding: ErasureCodingParams,
    /// Storage provider nodes
    pub provider_nodes: Vec<String>,
}

/// Service Level Agreement specifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLevelAgreement {
    /// Minimum uptime percentage (0.0-1.0)
    pub min_uptime: f64,
    /// Maximum response time for read requests (ms)
    pub max_read_latency: u64,
    /// Maximum response time for write requests (ms)
    pub max_write_latency: u64,
    /// Minimum throughput (bytes/second)
    pub min_throughput: u64,
    /// Data durability guarantee (0.0-1.0)
    pub data_durability: f64,
    /// Recovery time objective in case of failure (seconds)
    pub recovery_time_objective: u64,
    /// Recovery point objective (max data loss in seconds)
    pub recovery_point_objective: u64,
    /// Penalties for SLA violations
    pub violation_penalties: HashMap<SlaViolationType, PenaltyTerms>,
}

/// Payment terms for the contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentTerms {
    /// Total contract value in tokens
    pub total_amount: u64,
    /// Amount paid so far
    pub paid_amount: u64,
    /// Payment status
    pub status: PaymentStatus,
    /// Payment schedule
    pub payment_schedule: PaymentSchedule,
    /// Escrow terms
    pub escrow_terms: EscrowTerms,
    /// Performance bonuses
    pub performance_bonuses: HashMap<PerformanceMetric, BonusTerms>,
    /// Penalty deductions
    pub penalty_terms: HashMap<SlaViolationType, PenaltyTerms>,
}

impl Default for ServiceLevelAgreement {
    fn default() -> Self {
        Self {
            min_uptime: 0.99,
            max_read_latency: 100,
            max_write_latency: 500,
            min_throughput: 1_000_000,
            data_durability: 0.999999,
            recovery_time_objective: 3600,
            recovery_point_objective: 600,
            violation_penalties: HashMap::new(),
        }
    }
}

impl Default for PaymentTerms {
    fn default() -> Self {
        Self {
            total_amount: 0,
            paid_amount: 0,
            status: PaymentStatus::Pending,
            payment_schedule: PaymentSchedule::Upfront,
            escrow_terms: EscrowTerms::default(),
            performance_bonuses: HashMap::new(),
            penalty_terms: HashMap::new(),
        }
    }
}

impl Default for EscrowTerms {
    fn default() -> Self {
        Self {
            escrow_amount: 0,
            release_conditions: Vec::new(),
            dispute_resolution: DisputeResolution::Arbitration,
        }
    }
}

// PaymentSchedule moved to economic_types.rs to avoid duplication

/// Escrow terms for payment security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowTerms {
    /// Amount held in escrow
    pub escrow_amount: u64,
    /// Escrow release conditions
    pub release_conditions: Vec<EscrowCondition>,
    /// Dispute resolution process
    pub dispute_resolution: DisputeResolution,
}

/// Contract execution status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContractStatus {
    /// Contract created but not signed
    Draft,
    /// Contract signed and active
    Active,
    /// Contract completed successfully
    Completed,
    /// Contract terminated early
    Terminated,
    /// Contract in dispute
    Disputed,
    /// Contract expired
    Expired,
    /// Contract breached (SLA violations)
    Breached,
}

/// Performance metrics tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Actual uptime percentage
    pub uptime: f64,
    /// Average read latency (ms)
    pub avg_read_latency: u64,
    /// Average write latency (ms)
    pub avg_write_latency: u64,
    /// Average throughput (bytes/second)
    pub avg_throughput: u64,
    /// Data integrity check results
    pub integrity_checks: Vec<IntegrityCheckResult>,
    /// SLA violations
    pub sla_violations: Vec<SlaViolation>,
    /// Performance score (0.0-1.0)
    pub performance_score: f64,
}

/// Digital signatures for contract validity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSignatures {
    /// Client signature
    pub client_signature: Option<PostQuantumSignature>,
    /// Provider signature
    pub provider_signature: Option<PostQuantumSignature>,
    /// Network witness signatures
    pub witness_signatures: Vec<PostQuantumSignature>,
}

/// SLA violation types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlaViolationType {
    UptimeViolation,
    LatencyViolation,
    ThroughputViolation,
    DataLoss,
    AvailabilityViolation,
    RecoveryTimeViolation,
}

/// Penalty terms for violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyTerms {
    /// Penalty amount or percentage
    pub penalty_amount: u64,
    /// Whether penalty is fixed amount or percentage
    pub is_percentage: bool,
    /// Maximum penalty cap
    pub max_penalty: Option<u64>,
    /// Grace period before penalty applies
    pub grace_period: u64,
}

/// Performance metrics for bonuses
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PerformanceMetric {
    ExceptionalUptime,
    LowLatency,
    HighThroughput,
    ZeroDataLoss,
    EarlyCompletion,
}

/// Bonus terms for exceptional performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BonusTerms {
    /// Bonus amount
    pub bonus_amount: u64,
    /// Performance threshold
    pub threshold: f64,
    /// Maximum bonus cap
    pub max_bonus: Option<u64>,
}

/// Payment milestone for custom schedules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMilestone {
    /// Milestone description
    pub description: String,
    /// Payment amount
    pub amount: u64,
    /// Milestone deadline
    pub deadline: u64,
    /// Completion criteria
    pub completion_criteria: Vec<String>,
}

// EscrowCondition and DisputeResolution moved to economic_types.rs to avoid duplication

/// Data integrity check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheckResult {
    /// Check timestamp
    pub timestamp: u64,
    /// Check type
    pub check_type: String,
    /// Success status
    pub success: bool,
    /// Error details if failed
    pub error_details: Option<String>,
    /// Data hash verified
    pub data_hash: String,
}

/// SLA violation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaViolation {
    /// Violation timestamp
    pub timestamp: u64,
    /// Type of violation
    pub violation_type: SlaViolationType,
    /// Severity level
    pub severity: ViolationSeverity,
    /// Description
    pub description: String,
    /// Impact assessment
    pub impact: String,
    /// Resolution status
    pub resolved: bool,
}

/// Severity levels for violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Minor,
    Moderate,
    Major,
    Critical,
}

/// Contract manager for handling storage contracts
#[derive(Debug)]
pub struct ContractManager {
    /// Active contracts
    contracts: HashMap<String, StorageContract>,
    /// Contract templates
    templates: HashMap<String, ContractTemplate>,
    /// Performance monitoring
    monitors: HashMap<String, PerformanceMonitor>,
}

/// Contract template for common configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTemplate {
    /// Template name
    pub name: String,
    /// Default terms
    pub default_terms: ContractTerms,
    /// Default SLA
    pub default_sla: ServiceLevelAgreement,
    /// Template description
    pub description: String,
    /// Supported storage tiers
    pub supported_tiers: Vec<StorageTier>,
}

/// Performance monitoring for contracts
#[derive(Debug)]
pub struct PerformanceMonitor {
    /// Contract being monitored
    pub contract_id: String,
    /// Monitoring start time
    pub start_time: u64,
    /// Last check time
    pub last_check: u64,
    /// Accumulated metrics
    pub metrics: PerformanceMetrics,
}

impl ContractManager {
    /// Create a new contract manager
    pub fn new() -> Self {
        Self {
            contracts: HashMap::new(),
            templates: HashMap::new(),
            monitors: HashMap::new(),
        }
    }

    /// Create a new storage contract
    pub fn create_contract(
        &mut self,
        client_id: String,
        provider_id: String,
        terms: ContractTerms,
        sla: ServiceLevelAgreement,
        payment: PaymentTerms,
    ) -> Result<String> {
        let contract_id = format!("contract_{}", Uuid::new_v4());
        
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + terms.duration;
        
        let contract = StorageContract {
            contract_id: contract_id.clone(),
            client_id,
            provider_id,
            terms,
            sla,
            payment,
            status: ContractStatus::Draft,
            performance: PerformanceMetrics {
                uptime: 0.0,
                avg_read_latency: 0,
                avg_write_latency: 0,
                avg_throughput: 0,
                integrity_checks: Vec::new(),
                sla_violations: Vec::new(),
                performance_score: 0.0,
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires_at,
            signatures: ContractSignatures {
                client_signature: None,
                provider_signature: None,
                witness_signatures: Vec::new(),
            },
            nodes: Vec::new(), // Will be populated during provider selection
            total_cost: 0, // Will be calculated during pricing
        };

        self.contracts.insert(contract_id.clone(), contract);
        Ok(contract_id)
    }

    /// Sign a contract
    pub fn sign_contract(
        &mut self,
        contract_id: &str,
        signer_type: SignerType,
        signature: PostQuantumSignature,
    ) -> Result<()> {
        let contract = self.contracts.get_mut(contract_id)
            .ok_or_else(|| anyhow!("Contract not found"))?;

        match signer_type {
            SignerType::Client => {
                contract.signatures.client_signature = Some(signature);
            }
            SignerType::Provider => {
                contract.signatures.provider_signature = Some(signature);
            }
            SignerType::Witness => {
                contract.signatures.witness_signatures.push(signature);
            }
        }

        // Activate contract if both parties have signed
        if contract.signatures.client_signature.is_some() && 
           contract.signatures.provider_signature.is_some() {
            contract.status = ContractStatus::Active;
            
            // Start performance monitoring
            let monitor = PerformanceMonitor {
                contract_id: contract_id.to_string(),
                start_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                last_check: 0,
                metrics: PerformanceMetrics {
                    uptime: 1.0,
                    avg_read_latency: 0,
                    avg_write_latency: 0,
                    avg_throughput: 0,
                    integrity_checks: Vec::new(),
                    sla_violations: Vec::new(),
                    performance_score: 1.0,
                },
            };
            self.monitors.insert(contract_id.to_string(), monitor);
        }

        Ok(())
    }

    /// Update performance metrics for a contract
    pub fn update_performance(
        &mut self,
        contract_id: &str,
        metrics_update: PerformanceUpdate,
    ) -> Result<()> {
        let monitor = self.monitors.get_mut(contract_id)
            .ok_or_else(|| anyhow!("Performance monitor not found"))?;
        
        let contract = self.contracts.get_mut(contract_id)
            .ok_or_else(|| anyhow!("Contract not found"))?;

        // Update metrics based on the update type
        match metrics_update {
            PerformanceUpdate::Uptime(uptime) => {
                monitor.metrics.uptime = uptime;
                contract.performance.uptime = uptime;
                
                // Check for uptime SLA violation
                if uptime < contract.sla.min_uptime {
                    let violation = SlaViolation {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        violation_type: SlaViolationType::UptimeViolation,
                        severity: if uptime < contract.sla.min_uptime * 0.9 {
                            ViolationSeverity::Major
                        } else {
                            ViolationSeverity::Minor
                        },
                        description: format!("Uptime {} below SLA requirement {}", 
                                           uptime, contract.sla.min_uptime),
                        impact: "Service availability below agreed levels".to_string(),
                        resolved: false,
                    };
                    contract.performance.sla_violations.push(violation);
                }
            }
            PerformanceUpdate::Latency { read, write } => {
                monitor.metrics.avg_read_latency = read;
                monitor.metrics.avg_write_latency = write;
                contract.performance.avg_read_latency = read;
                contract.performance.avg_write_latency = write;
                
                // Check for latency SLA violations
                if read > contract.sla.max_read_latency {
                    let violation = SlaViolation {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        violation_type: SlaViolationType::LatencyViolation,
                        severity: ViolationSeverity::Moderate,
                        description: format!("Read latency {} ms exceeds SLA limit {} ms", 
                                           read, contract.sla.max_read_latency),
                        impact: "User experience degraded".to_string(),
                        resolved: false,
                    };
                    contract.performance.sla_violations.push(violation);
                }
            }
            PerformanceUpdate::Throughput(throughput) => {
                monitor.metrics.avg_throughput = throughput;
                contract.performance.avg_throughput = throughput;
                
                if throughput < contract.sla.min_throughput {
                    let violation = SlaViolation {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        violation_type: SlaViolationType::ThroughputViolation,
                        severity: ViolationSeverity::Moderate,
                        description: format!("Throughput {} below SLA requirement {}", 
                                           throughput, contract.sla.min_throughput),
                        impact: "Data transfer performance below expectations".to_string(),
                        resolved: false,
                    };
                    contract.performance.sla_violations.push(violation);
                }
            }
        }

        // Calculate performance score separately to avoid borrowing conflict
        let performance_metrics = contract.performance.clone();
        let sla_metrics = contract.sla.clone();
        let performance_score = Self::calculate_performance_score_static(&performance_metrics, &sla_metrics);
        contract.performance.performance_score = performance_score;
        
        Ok(())
    }

    /// Calculate overall performance score (static version to avoid borrowing conflicts)
    fn calculate_performance_score_static(performance: &PerformanceMetrics, sla: &ServiceLevelAgreement) -> f64 {
        let uptime_score = performance.uptime;
        
        let latency_score = if performance.avg_read_latency <= sla.max_read_latency {
            1.0
        } else {
            (sla.max_read_latency as f64) / (performance.avg_read_latency as f64)
        };
        
        let throughput_score = if performance.avg_throughput >= sla.min_throughput {
            1.0
        } else {
            (performance.avg_throughput as f64) / (sla.min_throughput as f64)
        };
        
        // Penalty for violations
        let violation_penalty = performance.sla_violations.len() as f64 * 0.1;
        
        // Combined score
        let base_score = (uptime_score + latency_score + throughput_score) / 3.0;
        (base_score - violation_penalty).max(0.0).min(1.0)
    }

    /// Calculate overall performance score
    fn calculate_performance_score(&self, contract: &StorageContract) -> f64 {
        Self::calculate_performance_score_static(&contract.performance, &contract.sla)
    }

    /// Get contract by ID
    pub fn get_contract(&self, contract_id: &str) -> Option<&StorageContract> {
        self.contracts.get(contract_id)
    }

    /// List active contracts
    pub fn list_active_contracts(&self) -> Vec<&StorageContract> {
        self.contracts.values()
            .filter(|c| c.status == ContractStatus::Active)
            .collect()
    }

    // Template Management Methods

    /// Create a new contract template
    pub fn create_template(
        &mut self,
        name: String,
        description: String,
        default_terms: ContractTerms,
        default_sla: ServiceLevelAgreement,
        supported_tiers: Vec<StorageTier>,
    ) -> Result<String> {
        let template_id = format!("template_{}", Uuid::new_v4());
        
        let template = ContractTemplate {
            name,
            default_terms,
            default_sla,
            description,
            supported_tiers,
        };

        self.templates.insert(template_id.clone(), template);
        Ok(template_id)
    }

    /// Get a contract template by ID
    pub fn get_template(&self, template_id: &str) -> Option<&ContractTemplate> {
        self.templates.get(template_id)
    }

    /// List all available templates
    pub fn list_templates(&self) -> Vec<&ContractTemplate> {
        self.templates.values().collect()
    }

    /// Update an existing template
    pub fn update_template(
        &mut self,
        template_id: &str,
        name: Option<String>,
        description: Option<String>,
        default_terms: Option<ContractTerms>,
        default_sla: Option<ServiceLevelAgreement>,
        supported_tiers: Option<Vec<StorageTier>>,
    ) -> Result<()> {
        let template = self.templates.get_mut(template_id)
            .ok_or_else(|| anyhow!("Template not found"))?;

        if let Some(name) = name {
            template.name = name;
        }
        if let Some(description) = description {
            template.description = description;
        }
        if let Some(terms) = default_terms {
            template.default_terms = terms;
        }
        if let Some(sla) = default_sla {
            template.default_sla = sla;
        }
        if let Some(tiers) = supported_tiers {
            template.supported_tiers = tiers;
        }

        Ok(())
    }

    /// Delete a template
    pub fn delete_template(&mut self, template_id: &str) -> Result<()> {
        self.templates.remove(template_id)
            .ok_or_else(|| anyhow!("Template not found"))?;
        Ok(())
    }

    /// Create a contract from a template
    pub fn create_contract_from_template(
        &mut self,
        template_id: &str,
        client_id: String,
        provider_id: String,
        payment_terms: PaymentTerms,
        customizations: Option<ContractCustomizations>,
    ) -> Result<String> {
        let template = self.templates.get(template_id)
            .ok_or_else(|| anyhow!("Template not found"))?;

        let mut terms = template.default_terms.clone();
        let mut sla = template.default_sla.clone();

        // Apply customizations if provided
        if let Some(custom) = customizations {
            if let Some(storage_size) = custom.storage_size {
                terms.storage_size = storage_size;
            }
            if let Some(duration) = custom.duration {
                terms.duration = duration;
            }
            if let Some(tier) = custom.tier {
                // Validate that the tier is supported by the template
                if !template.supported_tiers.contains(&tier) {
                    return Err(anyhow!("Storage tier {:?} not supported by template", tier));
                }
                terms.tier = tier;
            }
            if let Some(replication_factor) = custom.replication_factor {
                terms.replication_factor = replication_factor;
            }
            if let Some(geographic_requirements) = custom.geographic_requirements {
                terms.geographic_requirements = geographic_requirements;
            }
            if let Some(min_uptime) = custom.min_uptime {
                sla.min_uptime = min_uptime;
            }
            if let Some(max_read_latency) = custom.max_read_latency {
                sla.max_read_latency = max_read_latency;
            }
            if let Some(max_write_latency) = custom.max_write_latency {
                sla.max_write_latency = max_write_latency;
            }
        }

        self.create_contract(client_id, provider_id, terms, sla, payment_terms)
    }

    /// Find templates by storage tier
    pub fn find_templates_by_tier(&self, tier: &StorageTier) -> Vec<&ContractTemplate> {
        self.templates.values()
            .filter(|template| template.supported_tiers.contains(tier))
            .collect()
    }

    /// Validate template compatibility with requirements
    pub fn validate_template_compatibility(
        &self,
        template_id: &str,
        required_tier: &StorageTier,
        min_uptime: f64,
        max_latency: u64,
    ) -> Result<bool> {
        let template = self.templates.get(template_id)
            .ok_or_else(|| anyhow!("Template not found"))?;

        let tier_supported = template.supported_tiers.contains(required_tier);
        let uptime_compatible = template.default_sla.min_uptime >= min_uptime;
        let latency_compatible = template.default_sla.max_read_latency <= max_latency;

        Ok(tier_supported && uptime_compatible && latency_compatible)
    }
}

/// Contract customizations for template-based contract creation
#[derive(Debug, Clone)]
pub struct ContractCustomizations {
    /// Custom storage size
    pub storage_size: Option<u64>,
    /// Custom contract duration
    pub duration: Option<u64>,
    /// Custom storage tier
    pub tier: Option<StorageTier>,
    /// Custom replication factor
    pub replication_factor: Option<u8>,
    /// Custom geographic requirements
    pub geographic_requirements: Option<Vec<String>>,
    /// Custom minimum uptime requirement
    pub min_uptime: Option<f64>,
    /// Custom maximum read latency
    pub max_read_latency: Option<u64>,
    /// Custom maximum write latency
    pub max_write_latency: Option<u64>,
}

/// Contract signer types
#[derive(Debug, Clone)]
pub enum SignerType {
    Client,
    Provider,
    Witness,
}

/// Performance update types
#[derive(Debug, Clone)]
pub enum PerformanceUpdate {
    Uptime(f64),
    Latency { read: u64, write: u64 },
    Throughput(u64),
}

impl ContractManager {
    /// Get contract statistics
    pub async fn get_statistics(&self) -> anyhow::Result<ContractStats> {
        let total_contracts = self.contracts.len() as u64;
        let active_contracts = self.contracts.values()
            .filter(|c| c.expires_at > std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs())
            .count() as u64;
        
        let total_storage_under_contract = self.contracts.values()
            .map(|c| c.terms.storage_size)
            .sum();
            
        let total_contract_value = self.contracts.values()
            .map(|c| c.payment.total_amount)
            .sum();
        
        Ok(ContractStats {
            total_contracts,
            total_storage_under_contract,
            total_contract_value,
            active_contracts,
            expired_contracts: total_contracts - active_contracts,
            breached_contracts: self.contracts.values()
                .filter(|contract| matches!(contract.status, ContractStatus::Breached))
                .count() as u64,
        })
    }

    /// Evaluate contract performance and get detailed performance report
    pub fn evaluate_contract_performance(&self, contract_id: &str) -> anyhow::Result<ContractPerformanceReport> {
        let contract = self.get_contract(contract_id)
            .ok_or_else(|| anyhow::anyhow!("Contract not found"))?;

        let performance_score = self.calculate_performance_score(contract);
        
        let performance_category = if performance_score >= 0.9 {
            "Excellent"
        } else if performance_score >= 0.8 {
            "Good"
        } else if performance_score >= 0.7 {
            "Satisfactory" 
        } else if performance_score >= 0.6 {
            "Needs Improvement"
        } else {
            "Poor"
        };

        let recommendations = self.generate_performance_recommendations(contract, performance_score);

        Ok(ContractPerformanceReport {
            contract_id: contract_id.to_string(),
            performance_score,
            performance_category: performance_category.to_string(),
            sla_compliance: 1.0 - (contract.performance.sla_violations.len() as f64 / 10.0).min(1.0), // Calculate from violations
            uptime_percentage: contract.performance.uptime,
            avg_response_time: (contract.performance.avg_read_latency + contract.performance.avg_write_latency) / 2,
            data_integrity_score: if contract.performance.integrity_checks.is_empty() { 1.0 } else {
                contract.performance.integrity_checks.iter()
                    .map(|check| if check.success { 1.0 } else { 0.0 })
                    .sum::<f64>() / contract.performance.integrity_checks.len() as f64
            },
            recommendations,
            evaluation_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Generate performance improvement recommendations
    fn generate_performance_recommendations(&self, contract: &StorageContract, performance_score: f64) -> Vec<String> {
        let mut recommendations = Vec::new();

        if contract.performance.uptime < 0.99 {
            recommendations.push("Improve uptime reliability - consider redundant systems".to_string());
        }

        if (contract.performance.avg_read_latency + contract.performance.avg_write_latency) / 2 > 1000 {
            recommendations.push("Optimize response times - consider network optimization".to_string());
        }

        // Check data integrity based on integrity check results
        let integrity_score = if contract.performance.integrity_checks.is_empty() { 1.0 } else {
            contract.performance.integrity_checks.iter()
                .map(|check| if check.success { 1.0 } else { 0.0 })
                .sum::<f64>() / contract.performance.integrity_checks.len() as f64
        };
        
        if integrity_score < 0.999 {
            recommendations.push("Enhance data integrity measures - implement additional checksums".to_string());
        }

        if performance_score < 0.8 {
            recommendations.push("Overall performance below target - comprehensive review needed".to_string());
        }

        let sla_compliance = 1.0 - (contract.performance.sla_violations.len() as f64 / 10.0).min(1.0);
        if sla_compliance < 0.95 {
            recommendations.push("SLA compliance issues detected - review service delivery processes".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("Performance is excellent - maintain current standards".to_string());
        }

        recommendations
    }

    /// Update payment status for a contract
    pub async fn update_payment_status(&mut self, contract_id: Hash, payment_amount: u64) -> anyhow::Result<()> {
        let contract_id_str = hex::encode(contract_id.as_bytes());
        
        if let Some(contract) = self.contracts.get_mut(&contract_id_str) {
            // Update payment status
            contract.payment.paid_amount += payment_amount;
            
            // Check if contract is fully paid
            if contract.payment.paid_amount >= contract.payment.total_amount {
                contract.payment.status = PaymentStatus::Completed;
            } else {
                contract.payment.status = PaymentStatus::Partial;
            }
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("Contract not found: {}", contract_id_str))
        }
    }

    /// Get contract count for a specific node
    pub async fn get_node_contract_count(&self, node_id: &Hash) -> anyhow::Result<u64> {
        let node_id_str = hex::encode(node_id.as_bytes());
        
        let count = self.contracts.values()
            .filter(|contract| {
                contract.terms.provider_nodes.iter()
                    .any(|provider_node| provider_node == &node_id_str)
            })
            .count() as u64;
            
        Ok(count)
    }
}

impl Default for ContractManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_creation() {
        let mut manager = ContractManager::new();
        
        let terms = ContractTerms {
            storage_size: 1024 * 1024 * 1024, // 1 GB
            duration: 86400 * 30, // 30 days
            tier: StorageTier::Cold,
            replication_factor: 3,
            geographic_requirements: vec!["US".to_string()],
            encryption_level: EncryptionLevel::Standard,
            expected_access_pattern: AccessPattern::Rare,
            erasure_coding: ErasureCodingParams {
                data_shards: 4,
                parity_shards: 2,
                threshold: 3,
            },
            provider_nodes: vec!["test_provider".to_string()],
        };

        let sla = ServiceLevelAgreement {
            min_uptime: 0.99,
            max_read_latency: 1000,
            max_write_latency: 2000,
            min_throughput: 1024 * 1024, // 1 MB/s
            data_durability: 0.999999,
            recovery_time_objective: 3600,
            recovery_point_objective: 60,
            violation_penalties: HashMap::new(),
        };

        let payment = PaymentTerms {
            total_amount: 1000,
            paid_amount: 0,
            status: PaymentStatus::Pending,
            payment_schedule: PaymentSchedule::Upfront,
            escrow_terms: EscrowTerms {
                escrow_amount: 100,
                release_conditions: vec![EscrowCondition::ContractCompletion],
                dispute_resolution: DisputeResolution::Arbitration,
            },
            performance_bonuses: HashMap::new(),
            penalty_terms: HashMap::new(),
        };

        let contract_id = manager.create_contract(
            "client1".to_string(),
            "provider1".to_string(),
            terms,
            sla,
            payment,
        ).unwrap();

        assert!(manager.get_contract(&contract_id).is_some());
        assert_eq!(manager.get_contract(&contract_id).unwrap().status, ContractStatus::Draft);
    }

    #[test]
    fn test_template_management() {
        let mut manager = ContractManager::new();
        
        // Create a template
        let terms = ContractTerms {
            storage_size: 1024 * 1024 * 1024, // 1 GB
            duration: 86400 * 30, // 30 days
            tier: StorageTier::Cold,
            replication_factor: 3,
            geographic_requirements: vec!["US".to_string()],
            encryption_level: EncryptionLevel::Standard,
            expected_access_pattern: AccessPattern::Rare,
            erasure_coding: ErasureCodingParams {
                data_shards: 4,
                parity_shards: 2,
                threshold: 3,
            },
            provider_nodes: vec!["template_provider".to_string()],
        };

        let sla = ServiceLevelAgreement {
            min_uptime: 0.99,
            max_read_latency: 1000,
            max_write_latency: 2000,
            min_throughput: 1024 * 1024,
            data_durability: 0.999999,
            recovery_time_objective: 3600,
            recovery_point_objective: 60,
            violation_penalties: HashMap::new(),
        };

        let template_id = manager.create_template(
            "Cold Storage Template".to_string(),
            "Standard template for cold storage contracts".to_string(),
            terms,
            sla,
            vec![StorageTier::Cold, StorageTier::Archive],
        ).unwrap();

        // Test template retrieval
        assert!(manager.get_template(&template_id).is_some());
        assert_eq!(manager.list_templates().len(), 1);

        // Test template-based contract creation
        let payment = PaymentTerms {
            total_amount: 1000,
            paid_amount: 0,
            status: PaymentStatus::Pending,
            payment_schedule: PaymentSchedule::Upfront,
            escrow_terms: EscrowTerms {
                escrow_amount: 100,
                release_conditions: vec![EscrowCondition::ContractCompletion],
                dispute_resolution: DisputeResolution::Arbitration,
            },
            performance_bonuses: HashMap::new(),
            penalty_terms: HashMap::new(),
        };

        let customizations = ContractCustomizations {
            storage_size: Some(2 * 1024 * 1024 * 1024), // 2 GB
            duration: Some(86400 * 60), // 60 days
            tier: Some(StorageTier::Archive),
            replication_factor: None,
            geographic_requirements: None,
            min_uptime: None,
            max_read_latency: None,
            max_write_latency: None,
        };

        let contract_id = manager.create_contract_from_template(
            &template_id,
            "client1".to_string(),
            "provider1".to_string(),
            payment,
            Some(customizations),
        ).unwrap();

        // Verify the contract was created with customizations
        let contract = manager.get_contract(&contract_id).unwrap();
        assert_eq!(contract.terms.storage_size, 2 * 1024 * 1024 * 1024);
        assert_eq!(contract.terms.duration, 86400 * 60);
        assert_eq!(contract.terms.tier, StorageTier::Archive);
    }

    #[test]
    fn test_template_tier_filtering() {
        let mut manager = ContractManager::new();
        
        // Create templates with different tier support
        let terms = ContractTerms {
            storage_size: 1024 * 1024 * 1024,
            duration: 86400 * 30,
            tier: StorageTier::Hot,
            replication_factor: 3,
            geographic_requirements: vec!["US".to_string()],
            encryption_level: EncryptionLevel::Standard,
            expected_access_pattern: AccessPattern::Frequent,
            erasure_coding: ErasureCodingParams {
                data_shards: 4,
                parity_shards: 2,
                threshold: 3,
            },
            provider_nodes: vec!["template_provider".to_string()],
        };

        let sla = ServiceLevelAgreement {
            min_uptime: 0.999,
            max_read_latency: 100,
            max_write_latency: 200,
            min_throughput: 10 * 1024 * 1024,
            data_durability: 0.999999,
            recovery_time_objective: 300,
            recovery_point_objective: 10,
            violation_penalties: HashMap::new(),
        };

        manager.create_template(
            "Hot Storage Template".to_string(),
            "Template for hot storage".to_string(),
            terms,
            sla,
            vec![StorageTier::Hot],
        ).unwrap();

        let cold_terms = ContractTerms {
            storage_size: 1024 * 1024 * 1024,
            duration: 86400 * 30,
            tier: StorageTier::Cold,
            replication_factor: 3,
            geographic_requirements: vec!["US".to_string()],
            encryption_level: EncryptionLevel::Standard,
            expected_access_pattern: AccessPattern::Rare,
            erasure_coding: ErasureCodingParams {
                data_shards: 4,
                parity_shards: 2,
                threshold: 3,
            },
            provider_nodes: vec!["template_provider".to_string()],
        };

        let cold_sla = ServiceLevelAgreement {
            min_uptime: 0.99,
            max_read_latency: 1000,
            max_write_latency: 2000,
            min_throughput: 1024 * 1024,
            data_durability: 0.999999,
            recovery_time_objective: 3600,
            recovery_point_objective: 60,
            violation_penalties: HashMap::new(),
        };

        manager.create_template(
            "Cold Storage Template".to_string(),
            "Template for cold storage".to_string(),
            cold_terms,
            cold_sla,
            vec![StorageTier::Cold, StorageTier::Archive],
        ).unwrap();

        // Test tier filtering
        let hot_templates = manager.find_templates_by_tier(&StorageTier::Hot);
        assert_eq!(hot_templates.len(), 1);
        assert_eq!(hot_templates[0].name, "Hot Storage Template");

        let cold_templates = manager.find_templates_by_tier(&StorageTier::Cold);
        assert_eq!(cold_templates.len(), 1);
        assert_eq!(cold_templates[0].name, "Cold Storage Template");

        let archive_templates = manager.find_templates_by_tier(&StorageTier::Archive);
        assert_eq!(archive_templates.len(), 1);
        assert_eq!(archive_templates[0].name, "Cold Storage Template");
    }
}
