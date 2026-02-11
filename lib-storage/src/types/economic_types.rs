//! Economic storage type definitions
//! 
//! Contains all types related to the economic layer of the storage system,
//! including contracts, payments, penalties, rewards, and market mechanisms.

use crate::types::{ContentHash, NodeId};
use crate::types::dht_types::StorageTier;
use lib_crypto::Hash;
use lib_identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};

/// Storage contract between user and nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageContract {
    /// Contract identifier
    pub id: Hash,
    /// Content hash being stored
    pub content_hash: ContentHash,
    /// Storage nodes involved
    pub nodes: Vec<NodeId>,
    /// Contract duration (days)
    pub duration_days: u32,
    /// Total cost (SOV tokens)
    pub total_cost: u64,
    /// Payment schedule
    pub payment_schedule: Vec<Payment>,
    /// Contract start timestamp
    pub start_time: u64,
    /// Contract end timestamp
    pub end_time: u64,
    /// Penalty clauses
    pub penalties: Vec<PenaltyClause>,
    /// Contract status
    pub status: ContractStatus,
    /// Storage requirements
    pub storage_requirements: StorageRequirements,
    /// Quality metrics
    pub quality_metrics: QualityMetrics,
}

/// Contract execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContractStatus {
    /// Contract is active and being fulfilled
    Active,
    /// Contract has been completed successfully
    Completed,
    /// Contract has expired
    Expired,
    /// Contract has been breached
    Breached,
    /// Contract has been terminated early
    Terminated,
    /// Contract is pending approval
    Pending,
}

/// Payment in a storage contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    /// Payment amount (SOV tokens)
    pub amount: u64,
    /// Payment due timestamp
    pub due_at: u64,
    /// Payment status
    pub paid: bool,
    /// Transaction hash (if paid)
    pub tx_hash: Option<Hash>,
    /// Payment type
    pub payment_type: PaymentType,
}

/// Types of payments in storage contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentType {
    /// Regular storage payment
    Storage,
    /// Performance bonus
    Bonus,
    /// Penalty payment
    Penalty,
    /// Escrow deposit
    Deposit,
    /// Refund
    Refund,
}

/// Penalty clause for storage contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyClause {
    /// Penalty type
    pub penalty_type: PenaltyType,
    /// Penalty amount (SOV tokens)
    pub penalty_amount: u64,
    /// Conditions for penalty
    pub conditions: String,
    /// Grace period before penalty applies
    pub grace_period: u64,
    /// Maximum penalty applications
    pub max_applications: u32,
}

/// Types of penalties in storage contracts
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PenaltyType {
    /// Data loss penalty
    DataLoss,
    /// Unavailability penalty
    Unavailability,
    /// Slow response penalty
    SlowResponse,
    /// Contract breach penalty
    ContractBreach,
    /// Quality degradation penalty
    QualityDegradation,
}

/// Storage requirements for economic contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRequirements {
    /// Contract duration in days
    pub duration_days: u32,
    /// Quality requirements
    pub quality_requirements: QualityRequirements,
    /// Budget constraints
    pub budget_constraints: BudgetConstraints,
    /// Replication factor
    pub replication_factor: u8,
    /// Geographic preferences
    pub geographic_preferences: Vec<String>,
}

/// Quality requirements for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityRequirements {
    /// Minimum uptime percentage (0.0 to 1.0)
    pub min_uptime: f64,
    /// Maximum response time in milliseconds
    pub max_response_time: u64,
    /// Minimum replication factor
    pub min_replication: u8,
    /// Geographic distribution requirements
    pub geographic_distribution: Option<Vec<String>>,
    /// Required certifications
    pub required_certifications: Vec<String>,
}

/// Budget constraints for storage contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConstraints {
    /// Maximum total cost (SOV tokens)
    pub max_total_cost: u64,
    /// Maximum cost per GB per day
    pub max_cost_per_gb_day: u64,
    /// Payment schedule preference
    pub payment_schedule: PaymentSchedule,
    /// Acceptable price volatility percentage
    pub max_price_volatility: f64,
}

/// Payment schedule preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentSchedule {
    /// Pay everything upfront
    Upfront,
    /// Monthly payments
    Monthly,
    /// Weekly payments
    Weekly,
    /// Daily payments
    Daily,
    /// Pay on completion
    OnCompletion,
}

/// Quality metrics tracking for contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    /// Current uptime percentage
    pub current_uptime: f64,
    /// Average response time in milliseconds
    pub avg_response_time: u64,
    /// Current replication factor
    pub current_replication: u8,
    /// Number of quality violations
    pub quality_violations: u32,
    /// Last quality check timestamp
    pub last_quality_check: u64,
    /// Overall quality score (0.0 to 1.0)
    pub quality_score: f64,
    /// Data integrity score (0.0 to 1.0)
    pub data_integrity: f64,
    /// Availability score (0.0 to 1.0)
    pub availability: f64,
    /// Performance score (0.0 to 1.0)
    pub performance: f64,
    /// Reliability score (0.0 to 1.0)
    pub reliability: f64,
    /// Security score (0.0 to 1.0)
    pub security: f64,
    /// Responsiveness score (0.0 to 1.0)
    pub responsiveness: f64,
    /// Overall combined score (0.0 to 1.0)
    pub overall_score: f64,
    /// Confidence in the metrics (0.0 to 1.0)
    pub confidence: f64,
    /// Uptime percentage over monitoring period
    pub uptime: f64,
    /// Bandwidth utilization percentage
    pub bandwidth_utilization: f64,
    /// Response time in milliseconds
    pub response_time: u64,
}

/// Economic storage request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicStorageRequest {
    /// Content to store
    pub content: Vec<u8>,
    /// Content metadata
    pub filename: String,
    pub content_type: String,
    pub description: String,
    /// Storage tier preference
    pub preferred_tier: StorageTier,
    /// Storage requirements
    pub requirements: StorageRequirements,
    /// Payment preferences  
    pub payment_preferences: PaymentPreferences,
    /// Requester identity
    pub requester: ZhtpIdentity,
}

/// Economic quote for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicQuote {
    /// Quote identifier
    pub quote_id: String,
    /// Total cost estimate (SOV tokens)
    pub total_cost: u64,
    /// Cost per GB per day
    pub cost_per_gb_day: u64,
    /// Contract duration in days
    pub duration_days: u32,
    /// Recommended storage nodes
    pub recommended_nodes: Vec<NodeId>,
    /// Estimated quality metrics
    pub estimated_quality: QualityMetrics,
    /// Quote validity period
    pub valid_until: u64,
    /// Terms and conditions
    pub terms: Vec<String>,
}

/// Economic statistics for the storage system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicStats {
    /// Total number of contracts
    pub total_contracts: u64,
    /// Total storage under economic management (bytes)
    pub total_storage: u64,
    /// Total value locked in contracts (SOV tokens)
    pub total_value_locked: u64,
    /// Average contract value (SOV tokens)
    pub average_contract_value: u64,
    /// Total penalties issued
    pub total_penalties: u64,
    /// Total rewards distributed
    pub total_rewards: u64,
}

/// Market pricing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketPricing {
    /// Current base price per GB per day
    pub base_price_per_gb_day: u64,
    /// Price for different storage tiers
    pub tier_pricing: std::collections::HashMap<StorageTier, f64>,
    /// Regional price adjustments
    pub regional_adjustments: std::collections::HashMap<String, f64>,
    /// Demand-based price multiplier
    pub demand_multiplier: f64,
    /// Last price update timestamp
    pub last_updated: u64,
}

/// Reward distribution for storage providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    /// Node receiving reward
    pub node_id: NodeId,
    /// Reward amount (SOV tokens)
    pub amount: u64,
    /// Reward type
    pub reward_type: RewardType,
    /// Reason for reward
    pub reason: String,
    /// Distribution timestamp
    pub distributed_at: u64,
}

/// Types of rewards in the economic system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RewardType {
    /// Base storage reward
    StorageReward,
    /// Performance bonus
    PerformanceBonus,
    /// Uptime bonus
    UptimeBonus,
    /// Quality bonus
    QualityBonus,
    /// Network contribution reward
    NetworkContribution,
}

/// Reward tiers for storage providers
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RewardTier {
    /// Basic tier for new providers
    Basic,
    /// Bronze tier for consistent providers
    Bronze,
    /// Silver tier for high-quality providers
    Silver,
    /// Gold tier for excellent providers
    Gold,
    /// Platinum tier for exceptional providers
    Platinum,
}

/// Reward thresholds for tier advancement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardThreshold {
    /// Minimum reputation score
    pub min_reputation: f64,
    /// Minimum uptime percentage
    pub min_uptime: f64,
    /// Minimum contracts fulfilled
    pub min_contracts: u32,
    /// Minimum storage provided (bytes)
    pub min_storage: u64,
    /// Minimum data integrity score
    pub min_data_integrity: f64,
    /// Base reward multiplier
    pub base_multiplier: f64,
    /// Bonus reward multiplier
    pub bonus_multiplier: f64,
}

/// Quality violation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityViolation {
    /// Violation type
    pub violation_type: String,
    /// Severity of the violation (0.0 to 1.0)
    pub severity: f64,
    /// Timestamp when violation occurred
    pub timestamp: u64,
    /// Additional details about the violation
    pub details: String,
}

/// Pricing request for storage services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingRequest {
    /// Data size in bytes
    pub data_size: u64,
    /// Contract duration in days
    pub duration_days: u32,
    /// Storage tier preference
    pub preferred_tier: StorageTier,
    /// Quality requirements
    pub quality_requirements: QualityRequirements,
    /// Budget constraints
    pub budget_constraints: Option<BudgetConstraints>,
    /// Geographic preferences
    pub geographic_preferences: Vec<String>,
}

/// Escrow release conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscrowCondition {
    /// Contract completion
    ContractCompletion,
    /// Time-based release
    TimeRelease(u64),
    /// Quality threshold met
    QualityThreshold(f64),
    /// Manual release by parties
    ManualRelease,
}

/// Dispute resolution methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisputeResolution {
    /// Automated arbitration
    Arbitration,
    /// Community voting
    CommunityVoting,
    /// Expert panel review
    ExpertPanel,
    /// Mediation
    Mediation,
}

/// Payment status tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PaymentStatus {
    /// Payment is pending
    Pending,
    /// Payment completed successfully
    Completed,
    /// Partial payment made
    Partial,
    /// Payment failed
    Failed,
    /// Payment disputed
    Disputed,
    /// Payment refunded
    Refunded,
}

/// Cost breakdown for storage quotes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostBreakdown {
    /// Base storage cost
    pub base_storage_cost: u64,
    /// Quality premium
    pub quality_premium: u64,
    /// Network fees
    pub network_fees: u64,
    /// Escrow fees
    pub escrow_fees: u64,
    /// Total cost
    pub total_cost: u64,
}

/// Economic manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicManagerConfig {
    /// Default contract duration in days
    pub default_duration_days: u32,
    /// Base price per GB per day
    pub base_price_per_gb_day: u64,
    /// Enable escrow system
    pub enable_escrow: bool,
    /// Escrow release threshold (percentage)
    pub escrow_release_threshold: f64,
    /// Maximum contract duration in days
    pub max_contract_duration: u32,
    /// Minimum contract value (SOV tokens)
    pub min_contract_value: u64,
    /// Quality monitoring interval (seconds)
    pub quality_monitoring_interval: u64,
    /// Penalty enforcement enabled
    pub penalty_enforcement_enabled: bool,
    /// Reward distribution enabled
    pub reward_distribution_enabled: bool,
    /// Market-based pricing enabled
    pub market_pricing_enabled: bool,
}

impl Default for QualityRequirements {
    fn default() -> Self {
        Self {
            min_uptime: 0.99,
            max_response_time: 5000,
            min_replication: 3,
            geographic_distribution: None,
            required_certifications: vec![],
        }
    }
}

impl Default for BudgetConstraints {
    fn default() -> Self {
        Self {
            max_total_cost: 10000,
            max_cost_per_gb_day: 100,
            payment_schedule: PaymentSchedule::Monthly,
            max_price_volatility: 0.2,
        }
    }
}

impl Default for StorageRequirements {
    fn default() -> Self {
        Self {
            duration_days: 30,
            quality_requirements: QualityRequirements::default(),
            budget_constraints: BudgetConstraints::default(),
            replication_factor: 3,
            geographic_preferences: vec!["global".to_string()],
        }
    }
}

impl Default for QualityMetrics {
    fn default() -> Self {
        Self {
            current_uptime: 1.0,
            avg_response_time: 1000,
            current_replication: 3,
            quality_violations: 0,
            last_quality_check: 0,
            quality_score: 1.0,
            data_integrity: 1.0,
            availability: 1.0,
            performance: 1.0,
            reliability: 1.0,
            security: 1.0,
            responsiveness: 1.0,
            overall_score: 1.0,
            confidence: 1.0,
            uptime: 1.0,
            bandwidth_utilization: 0.8,
            response_time: 1000,
        }
    }
}

impl Default for EconomicStats {
    fn default() -> Self {
        Self {
            total_contracts: 0,
            total_storage: 0,
            total_value_locked: 0,
            average_contract_value: 0,
            total_penalties: 0,
            total_rewards: 0,
        }
    }
}

impl Default for EconomicManagerConfig {
    fn default() -> Self {
        Self {
            default_duration_days: 30,
            base_price_per_gb_day: 100,
            enable_escrow: true,
            escrow_release_threshold: 0.8,
            max_contract_duration: 365,
            min_contract_value: 100,
            quality_monitoring_interval: 3600,
            penalty_enforcement_enabled: true,
            reward_distribution_enabled: true,
            market_pricing_enabled: true,
        }
    }
}

/// Payment preferences for economic storage requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPreferences {
    /// Escrow preferences
    pub escrow_preferences: EscrowPreferences,
    /// Payment schedule preference
    pub payment_schedule: PaymentSchedule,
    /// Maximum upfront payment percentage
    pub max_upfront_percentage: f64,
}

/// Escrow preferences for payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowPreferences {
    /// Whether to use escrow
    pub use_escrow: bool,
    /// Escrow release threshold (percentage)
    pub release_threshold: f64,
    /// Dispute resolution method
    pub dispute_resolution: DisputeResolution,
}

impl Default for PaymentPreferences {
    fn default() -> Self {
        Self {
            escrow_preferences: EscrowPreferences::default(),
            payment_schedule: PaymentSchedule::Upfront,
            max_upfront_percentage: 1.0,
        }
    }
}

impl Default for EscrowPreferences {
    fn default() -> Self {
        Self {
            use_escrow: true,
            release_threshold: 0.8,
            dispute_resolution: DisputeResolution::Arbitration,
        }
    }
}

/// Performance snapshot for incentive calculations
/// 
/// Captures key performance metrics at a point in time for reward calculations
/// and quality assessment in the economic incentive system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    /// Node uptime as a ratio (0.0 to 1.0)
    /// Example: 0.99 = 99% uptime
    pub uptime: f64,
    
    /// Average response time in milliseconds
    /// Lower values indicate better performance
    pub avg_response_time: u64,
    
    /// Data integrity score as a ratio (0.0 to 1.0)
    /// Example: 0.9999 = 99.99% data integrity
    pub data_integrity: f64,
    
    /// Throughput in bytes per second
    /// Higher values indicate better performance
    pub throughput: u64,
    
    /// Error rate as a ratio (0.0 to 1.0)
    /// Example: 0.001 = 0.1% error rate
    pub error_rate: f64,
}

impl Default for PerformanceSnapshot {
    fn default() -> Self {
        Self {
            uptime: 0.95,           // 95% uptime baseline
            avg_response_time: 200, // 200ms baseline response time
            data_integrity: 0.999,  // 99.9% data integrity baseline
            throughput: 1_000_000,  // 1 MB/s baseline throughput
            error_rate: 0.01,       // 1% error rate baseline
        }
    }
}

impl PerformanceSnapshot {
    /// Create a new performance snapshot with specified metrics
    pub fn new(
        uptime: f64,
        avg_response_time: u64,
        data_integrity: f64,
        throughput: u64,
        error_rate: f64,
    ) -> Self {
        Self {
            uptime,
            avg_response_time,
            data_integrity,
            throughput,
            error_rate,
        }
    }
    
    /// Calculate an overall performance score (0.0 to 1.0)
    /// This provides a single metric combining all performance aspects
    pub fn overall_score(&self) -> f64 {
        // Weighted average of performance metrics
        let uptime_weight = 0.3;
        let latency_weight = 0.25;
        let integrity_weight = 0.3;
        let throughput_weight = 0.1;
        let error_weight = 0.05;
        
        // Normalize latency (lower is better, cap at 1000ms)
        let latency_score = (1000.0 - self.avg_response_time.min(1000) as f64) / 1000.0;
        
        // Normalize throughput (higher is better, baseline at 1MB/s)
        let throughput_score = (self.throughput as f64 / 1_000_000.0).min(1.0);
        
        // Error rate (lower is better)
        let error_score = (1.0 - self.error_rate).max(0.0);
        
        self.uptime * uptime_weight +
        latency_score * latency_weight +
        self.data_integrity * integrity_weight +
        throughput_score * throughput_weight +
        error_score * error_weight
    }
    
    /// Check if this performance snapshot meets basic quality thresholds
    pub fn meets_basic_quality(&self) -> bool {
        self.uptime >= 0.95 &&
        self.avg_response_time <= 1000 &&
        self.data_integrity >= 0.99 &&
        self.error_rate <= 0.05
    }
    
    /// Check if this performance snapshot qualifies for premium incentives
    pub fn qualifies_for_premium(&self) -> bool {
        self.uptime >= 0.99 &&
        self.avg_response_time <= 100 &&
        self.data_integrity >= 0.999 &&
        self.error_rate <= 0.001
    }
}
