//! Economic primitives for the Sovereign Network.
//!
//! Pure data types for the post-scarcity economics system.
//! Behavior (calculation methods) lives in lib-economy via extension traits.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

// =============================================================================
// CORE ECONOMIC ENUMS
// =============================================================================

/// Priority levels for transaction processing with QoS-style pricing
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Priority {
    /// Background processing - 50% discount for non-urgent transactions
    Low,
    /// Standard priority - normal network processing
    Normal,
    /// Premium service - 50% premium for faster processing
    High,
    /// Emergency priority - 100% premium for critical transactions
    Urgent,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

/// Types of economic transactions in the SOV network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TransactionType {
    /// Reward payment for network services (routing, storage, compute)
    Reward,
    /// Standard payment between users
    Payment,
    /// Staking tokens for consensus participation or infrastructure investment
    Stake,
    /// Unstaking tokens from consensus or infrastructure
    Unstake,
    /// Network infrastructure fee payment
    NetworkFee,
    /// DAO fee for Universal Basic Income fund (mandatory 2% on transactions)
    DaoFee,
    /// Token burning (for deflationary mechanics if needed)
    Burn,
    /// Universal Basic Income payment to verified citizens
    UbiDistribution,
    /// Welfare service funding (healthcare, education, infrastructure)
    WelfareDistribution,
    /// DAO proposal voting transaction
    ProposalVote,
    /// DAO proposal execution transaction
    ProposalExecution,
}

/// Treasury fund categories for tracking different purposes
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TreasuryFund {
    /// General operational fund
    Operations,
    /// Universal Basic Income distribution fund
    UbiDistribution,
    /// Infrastructure development fund
    Infrastructure,
    /// Community governance fund
    Governance,
    /// Research and development fund
    Research,
    /// Emergency reserve fund
    EmergencyReserve,
    /// Validator reward pool
    ValidatorRewards,
    /// ISP Bypass service fund
    IspBypassFund,
    /// Mesh discovery incentive fund
    MeshDiscoveryFund,
    /// Bridge operation fund
    BridgeFund,
    /// Smart contract development fund
    SmartContractFund,
}

/// Types of treasury operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum TreasuryOperationType {
    /// Allocation from main treasury to fund
    Allocation,
    /// Distribution from fund to beneficiaries
    Distribution,
    /// Reallocation between funds
    Reallocation,
    /// Emergency fund access
    EmergencyAccess,
    /// Governance-approved expenditure
    GovernanceExpenditure,
    /// Automatic distribution (UBI)
    AutomaticDistribution,
    /// Fund replenishment from network fees
    Replenishment,
    /// Cross-chain treasury operation
    CrossChain,
}

/// UBI recipient categories for targeted distribution
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UbiRecipientCategory {
    /// Individual verified users
    Individual,
    /// Community development projects
    CommunityProject,
    /// Open source contributors
    OpenSourceContributor,
    /// Network infrastructure providers
    InfrastructureProvider,
    /// Educational institutions
    EducationalInstitution,
    /// Non-profit organizations
    NonProfit,
    /// Research institutions
    ResearchInstitution,
    /// Small businesses using SOV
    SmallBusiness,
}

// =============================================================================
// WORK METRICS (Pure Data)
// =============================================================================

/// General work metrics for network services
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkMetrics {
    /// Amount of routing work performed (bytes routed)
    pub routing_work: u64,
    /// Amount of storage work performed (bytes stored)
    pub storage_work: u64,
    /// Amount of computational work performed (operations executed)
    pub compute_work: u64,
    /// Quality score of services provided (0.0-1.0)
    pub quality_score: f64,
    /// Hours of uptime provided
    pub uptime_hours: u64,
}

impl WorkMetrics {
    /// Create new work metrics with all zeros
    pub fn new() -> Self {
        WorkMetrics {
            routing_work: 0,
            storage_work: 0,
            compute_work: 0,
            quality_score: 0.0,
            uptime_hours: 0,
        }
    }
}

impl Default for WorkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// ISP Bypass Work Metrics - measures work done to replace ISPs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IspBypassWork {
    /// Internet bandwidth shared with other users (GB)
    pub bandwidth_shared_gb: u64,
    /// Packets routed through mesh network (MB)
    pub packets_routed_mb: u64,
    /// Hours of connectivity uptime provided
    pub uptime_hours: u64,
    /// Connection quality score (0.0-1.0)
    pub connection_quality: f64,
    /// Number of users served through shared connection
    pub users_served: u64,
    /// Cost savings provided to community (USD equivalent)
    pub cost_savings_provided: u64,
}

impl IspBypassWork {
    /// Create new ISP bypass work metrics with all zeros
    pub fn new() -> Self {
        IspBypassWork {
            bandwidth_shared_gb: 0,
            packets_routed_mb: 0,
            uptime_hours: 0,
            connection_quality: 0.0,
            users_served: 0,
            cost_savings_provided: 0,
        }
    }
}

impl Default for IspBypassWork {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// NETWORK STATS (Pure Data)
// =============================================================================

/// Network statistics for economic parameter adjustment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkStats {
    /// Network utilization percentage (0.0-1.0)
    pub utilization: f64,
    /// Average service quality across the network (0.0-1.0)
    pub avg_quality: f64,
    /// Total number of active nodes
    pub total_nodes: u64,
    /// Total number of transactions processed
    pub total_transactions: u64,
}

impl NetworkStats {
    /// Create new network statistics with all zeros
    pub fn new() -> Self {
        NetworkStats {
            utilization: 0.0,
            avg_quality: 0.0,
            total_nodes: 0,
            total_transactions: 0,
        }
    }
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TREASURY DATA STRUCTS
// =============================================================================

/// Treasury fund allocation and balance information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreasuryFundData {
    /// Fund category
    pub fund: TreasuryFund,
    /// Current balance in SOV
    pub current_balance: u64,
    /// Allocated percentage of total treasury
    pub allocated_percentage: f64,
    /// Total amount ever allocated to this fund
    pub total_allocated: u64,
    /// Total amount spent from this fund
    pub total_spent: u64,
    /// Pending expenditures awaiting approval
    pub pending_expenditures: u64,
    /// Last allocation timestamp
    pub last_allocation: u64,
    /// Fund utilization rate (spent / allocated)
    pub utilization_rate: f64,
    /// Average monthly expenditure
    pub average_monthly_expenditure: f64,
    /// Fund efficiency metrics
    pub efficiency_metrics: FundEfficiencyMetrics,
}

/// Fund efficiency and performance metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FundEfficiencyMetrics {
    /// Return on investment for this fund
    pub roi_percentage: f64,
    /// Cost per beneficiary (for distribution funds)
    pub cost_per_beneficiary: Option<f64>,
    /// Success rate of funded projects
    pub project_success_rate: f64,
    /// Average time to deployment for funded initiatives
    pub average_deployment_time_days: f64,
    /// Impact score (subjective measure of fund effectiveness)
    pub impact_score: f64,
}

impl Default for FundEfficiencyMetrics {
    fn default() -> Self {
        Self {
            roi_percentage: 0.0,
            cost_per_beneficiary: None,
            project_success_rate: 80.0,
            average_deployment_time_days: 30.0,
            impact_score: 75.0,
        }
    }
}

/// UBI distribution statistics and metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UbiDistributionStats {
    /// Total UBI recipients currently active
    pub active_recipients: u64,
    /// Total UBI distributed to date
    pub total_distributed: u64,
    /// Monthly UBI distribution amount
    pub monthly_distribution: u64,
    /// Average UBI per recipient per month
    pub average_ubi_per_recipient: f64,
    /// UBI distribution efficiency
    pub distribution_efficiency: f64,
    /// Geographic distribution of UBI recipients
    pub geographic_distribution: HashMap<String, u64>,
    /// UBI recipient categories
    pub recipient_categories: HashMap<UbiRecipientCategory, u64>,
    /// Distribution timeline
    pub distribution_timeline: BTreeMap<String, MonthlyUbiData>,
    /// UBI impact metrics
    pub impact_metrics: UbiImpactMetrics,
}

/// Monthly UBI distribution data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MonthlyUbiData {
    /// Month identifier (YYYY-MM)
    pub month: String,
    /// Total amount distributed this month
    pub total_distributed: u64,
    /// Number of recipients this month
    pub recipient_count: u64,
    /// Average distribution per recipient
    pub average_per_recipient: f64,
    /// New recipients added this month
    pub new_recipients: u64,
    /// Distribution completion rate
    pub completion_rate: f64,
}

/// UBI impact and effectiveness metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UbiImpactMetrics {
    /// Economic activity generated by UBI (estimated)
    pub economic_activity_multiplier: f64,
    /// Network adoption rate correlation with UBI
    pub adoption_correlation: f64,
    /// Retention rate of UBI recipients
    pub recipient_retention_rate: f64,
    /// Community development projects funded
    pub community_projects_funded: u64,
    /// Open source contributions incentivized
    pub open_source_contributions: u64,
    /// Educational impact score
    pub educational_impact_score: f64,
}

impl Default for UbiImpactMetrics {
    fn default() -> Self {
        Self {
            economic_activity_multiplier: 1.5,
            adoption_correlation: 0.8,
            recipient_retention_rate: 85.0,
            community_projects_funded: 0,
            open_source_contributions: 0,
            educational_impact_score: 70.0,
        }
    }
}

/// Treasury operation and transaction record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreasuryOperation {
    /// Operation ID
    pub operation_id: [u8; 32],
    /// Operation type
    pub operation_type: TreasuryOperationType,
    /// Associated fund
    pub fund: TreasuryFund,
    /// Operation amount
    pub amount: u64,
    /// Transaction fees
    pub fees: u64,
    /// Blockchain transaction hash
    pub blockchain_tx_hash: Option<[u8; 32]>,
    /// Block height when operation occurred
    pub block_height: u64,
    /// Operation timestamp
    pub timestamp: u64,
    /// Governance approval status
    pub governance_approval: Option<GovernanceApproval>,
    /// Operation description/purpose
    pub description: String,
    /// Operation beneficiaries
    pub beneficiaries: Vec<[u8; 32]>,
    /// Operation metadata
    pub metadata: HashMap<String, String>,
}

/// Governance approval record for treasury operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GovernanceApproval {
    /// Proposal ID
    pub proposal_id: [u8; 32],
    /// Voting results
    pub votes_for: u64,
    pub votes_against: u64,
    pub votes_abstain: u64,
    /// Approval status
    pub approved: bool,
    /// Approval timestamp
    pub approval_timestamp: u64,
    /// Required majority threshold met
    pub threshold_met: bool,
}

/// Treasury health and stability metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreasuryHealthMetrics {
    /// Monthly burn rate (spending rate)
    pub monthly_burn_rate: f64,
    /// Runway in months at current burn rate
    pub runway_months: f64,
    /// Revenue growth rate
    pub revenue_growth_rate: f64,
    /// Fund diversification score
    pub diversification_score: f64,
    /// Risk assessment score
    pub risk_score: f64,
    /// Sustainability index
    pub sustainability_index: f64,
    /// Emergency fund adequacy ratio
    pub emergency_fund_ratio: f64,
}

/// Treasury management settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreasurySettings {
    /// Minimum emergency fund ratio
    pub minimum_emergency_ratio: f64,
    /// Maximum single expenditure without governance
    pub max_auto_expenditure: u64,
    /// UBI distribution frequency in seconds
    pub ubi_distribution_frequency: u64,
    /// Fund rebalancing frequency in seconds
    pub rebalancing_frequency: u64,
    /// Enable automatic fund rebalancing
    pub auto_rebalancing_enabled: bool,
    /// Governance approval threshold percentage
    pub governance_threshold: f64,
    /// Treasury health check frequency
    pub health_check_frequency: u64,
}

impl Default for TreasurySettings {
    fn default() -> Self {
        Self {
            minimum_emergency_ratio: 0.1,      // 10%
            max_auto_expenditure: 1_000_000,   // 1M SOV
            ubi_distribution_frequency: 86400 * 30, // Monthly
            rebalancing_frequency: 86400 * 7,  // Weekly
            auto_rebalancing_enabled: true,
            governance_threshold: 66.0,        // 66% majority
            health_check_frequency: 86400,     // Daily
        }
    }
}

/// Comprehensive DAO Treasury Statistics Manager
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreasuryStats {
    /// Total treasury balance across all funds
    pub total_treasury_balance: u64,
    /// Individual fund data
    pub fund_data: HashMap<TreasuryFund, TreasuryFundData>,
    /// UBI distribution statistics
    pub ubi_stats: UbiDistributionStats,
    /// Treasury operation history
    pub operations_history: Vec<TreasuryOperation>,
    /// Treasury health metrics
    pub health_metrics: TreasuryHealthMetrics,
    /// Last update timestamp
    pub last_updated: u64,
    /// Treasury configuration settings
    pub settings: TreasurySettings,
}

// =============================================================================
// ECONOMIC CONSTANTS
// =============================================================================

/// Total SOV supply: 1 trillion tokens (fixed, not inflationary)
pub const SOV_TOTAL_SUPPLY: u64 = 1_000_000_000_000;

/// Transaction fee rate: 1% (expressed in basis points)
pub const TRANSACTION_FEE_RATE: u64 = 100;

/// Fee allocation percentages (sum to 100%)
pub const UBI_ALLOCATION_PERCENTAGE: u64 = 45;
pub const SECTOR_DAO_ALLOCATION_PERCENTAGE: u64 = 30;
pub const EMERGENCY_ALLOCATION_PERCENTAGE: u64 = 15;
pub const DEV_GRANT_ALLOCATION_PERCENTAGE: u64 = 10;

/// ISP replacement economic rates
pub const DEFAULT_ROUTING_RATE: u64 = 1; // SOV per MB routed
pub const DEFAULT_STORAGE_RATE: u64 = 10; // SOV per GB stored per month
pub const DEFAULT_COMPUTE_RATE: u64 = 5; // SOV per validation
pub const ISP_BYPASS_CONNECTIVITY_RATE: u64 = 100; // SOV per GB shared
pub const ISP_BYPASS_MESH_RATE: u64 = 1; // SOV per MB routed
pub const ISP_BYPASS_UPTIME_BONUS: u64 = 10; // SOV per hour uptime

/// Quality and uptime bonus thresholds
pub const QUALITY_BONUS_THRESHOLD: f64 = 0.95;
pub const UPTIME_BONUS_THRESHOLD: u64 = 23; // 23 hours (99%+ uptime)

/// Network utilization thresholds for reward adjustments
pub const HIGH_UTILIZATION_THRESHOLD: f64 = 0.9; // 90%
pub const LOW_UTILIZATION_THRESHOLD: f64 = 0.3;
pub const HIGH_UTILIZATION_ADJUSTMENT: u64 = 105; // +5%
pub const LOW_UTILIZATION_ADJUSTMENT: u64 = 98;   // -2%

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_default() {
        assert_eq!(Priority::default(), Priority::Normal);
    }

    #[test]
    fn test_priority_variants() {
        let priorities = vec![
            Priority::Low,
            Priority::Normal,
            Priority::High,
            Priority::Urgent,
        ];
        for p in priorities {
            let serialized = serde_json::to_string(&p).unwrap();
            let deserialized: Priority = serde_json::from_str(&serialized).unwrap();
            assert_eq!(p, deserialized);
        }
    }

    #[test]
    fn test_transaction_type_variants() {
        let types = vec![
            TransactionType::Reward,
            TransactionType::Payment,
            TransactionType::Stake,
            TransactionType::Unstake,
            TransactionType::NetworkFee,
            TransactionType::DaoFee,
            TransactionType::Burn,
            TransactionType::UbiDistribution,
            TransactionType::WelfareDistribution,
            TransactionType::ProposalVote,
            TransactionType::ProposalExecution,
        ];
        for tt in types {
            let serialized = serde_json::to_string(&tt).unwrap();
            let deserialized: TransactionType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(tt, deserialized);
        }
    }

    #[test]
    fn test_treasury_fund_variants() {
        let funds = vec![
            TreasuryFund::Operations,
            TreasuryFund::UbiDistribution,
            TreasuryFund::Infrastructure,
            TreasuryFund::Governance,
            TreasuryFund::Research,
            TreasuryFund::EmergencyReserve,
            TreasuryFund::ValidatorRewards,
            TreasuryFund::IspBypassFund,
            TreasuryFund::MeshDiscoveryFund,
            TreasuryFund::BridgeFund,
            TreasuryFund::SmartContractFund,
        ];
        for fund in funds {
            let serialized = serde_json::to_string(&fund).unwrap();
            let deserialized: TreasuryFund = serde_json::from_str(&serialized).unwrap();
            assert_eq!(fund, deserialized);
        }
    }

    #[test]
    fn test_work_metrics_new() {
        let metrics = WorkMetrics::new();
        assert_eq!(metrics.routing_work, 0);
        assert_eq!(metrics.storage_work, 0);
        assert_eq!(metrics.compute_work, 0);
        assert_eq!(metrics.quality_score, 0.0);
        assert_eq!(metrics.uptime_hours, 0);
    }

    #[test]
    fn test_isp_bypass_work_new() {
        let work = IspBypassWork::new();
        assert_eq!(work.bandwidth_shared_gb, 0);
        assert_eq!(work.packets_routed_mb, 0);
        assert_eq!(work.uptime_hours, 0);
        assert_eq!(work.connection_quality, 0.0);
        assert_eq!(work.users_served, 0);
        assert_eq!(work.cost_savings_provided, 0);
    }

    #[test]
    fn test_network_stats_new() {
        let stats = NetworkStats::new();
        assert_eq!(stats.utilization, 0.0);
        assert_eq!(stats.avg_quality, 0.0);
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.total_transactions, 0);
    }

    #[test]
    fn test_sov_total_supply() {
        assert_eq!(SOV_TOTAL_SUPPLY, 1_000_000_000_000);
    }

    #[test]
    fn test_transaction_fee_rate() {
        assert_eq!(TRANSACTION_FEE_RATE, 100); // 1% in basis points
    }

    #[test]
    fn test_allocation_percentages_sum() {
        let total = UBI_ALLOCATION_PERCENTAGE
            + SECTOR_DAO_ALLOCATION_PERCENTAGE
            + EMERGENCY_ALLOCATION_PERCENTAGE
            + DEV_GRANT_ALLOCATION_PERCENTAGE;
        assert_eq!(total, 100);
    }

    #[test]
    fn test_fund_efficiency_metrics_default() {
        let metrics = FundEfficiencyMetrics::default();
        assert_eq!(metrics.roi_percentage, 0.0);
        assert_eq!(metrics.project_success_rate, 80.0);
        assert_eq!(metrics.average_deployment_time_days, 30.0);
        assert_eq!(metrics.impact_score, 75.0);
        assert!(metrics.cost_per_beneficiary.is_none());
    }

    #[test]
    fn test_ubi_impact_metrics_default() {
        let metrics = UbiImpactMetrics::default();
        assert_eq!(metrics.economic_activity_multiplier, 1.5);
        assert_eq!(metrics.adoption_correlation, 0.8);
        assert_eq!(metrics.recipient_retention_rate, 85.0);
        assert_eq!(metrics.community_projects_funded, 0);
        assert_eq!(metrics.open_source_contributions, 0);
        assert_eq!(metrics.educational_impact_score, 70.0);
    }

    #[test]
    fn test_treasury_settings_default() {
        let settings = TreasurySettings::default();
        assert_eq!(settings.minimum_emergency_ratio, 0.1);
        assert_eq!(settings.max_auto_expenditure, 1_000_000);
        assert_eq!(settings.ubi_distribution_frequency, 86400 * 30);
        assert_eq!(settings.rebalancing_frequency, 86400 * 7);
        assert!(settings.auto_rebalancing_enabled);
        assert_eq!(settings.governance_threshold, 66.0);
        assert_eq!(settings.health_check_frequency, 86400);
    }

    #[test]
    fn test_treasury_operation_type_variants() {
        let op_types = vec![
            TreasuryOperationType::Allocation,
            TreasuryOperationType::Distribution,
            TreasuryOperationType::Reallocation,
            TreasuryOperationType::EmergencyAccess,
            TreasuryOperationType::GovernanceExpenditure,
            TreasuryOperationType::AutomaticDistribution,
            TreasuryOperationType::Replenishment,
            TreasuryOperationType::CrossChain,
        ];
        for ot in op_types {
            let serialized = serde_json::to_string(&ot).unwrap();
            let deserialized: TreasuryOperationType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(ot, deserialized);
        }
    }

    #[test]
    fn test_ubi_recipient_category_variants() {
        let categories = vec![
            UbiRecipientCategory::Individual,
            UbiRecipientCategory::CommunityProject,
            UbiRecipientCategory::OpenSourceContributor,
            UbiRecipientCategory::InfrastructureProvider,
            UbiRecipientCategory::EducationalInstitution,
            UbiRecipientCategory::NonProfit,
            UbiRecipientCategory::ResearchInstitution,
            UbiRecipientCategory::SmallBusiness,
        ];
        for cat in categories {
            let serialized = serde_json::to_string(&cat).unwrap();
            let deserialized: UbiRecipientCategory = serde_json::from_str(&serialized).unwrap();
            assert_eq!(cat, deserialized);
        }
    }

    #[test]
    fn test_monthly_ubi_data_serialization() {
        let data = MonthlyUbiData {
            month: "2024-01".to_string(),
            total_distributed: 1_000_000,
            recipient_count: 1000,
            average_per_recipient: 1000.0,
            new_recipients: 50,
            completion_rate: 0.98,
        };
        let serialized = serde_json::to_string(&data).unwrap();
        let deserialized: MonthlyUbiData = serde_json::from_str(&serialized).unwrap();
        assert_eq!(data.month, deserialized.month);
        assert_eq!(data.total_distributed, deserialized.total_distributed);
    }
}
