//! DAO types and data structures

use serde::{Deserialize, Serialize};
use lib_crypto::Hash;
use lib_identity::IdentityId;

/// DAO proposal for governance decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoProposal {
    /// Unique proposal identifier
    pub id: Hash,
    /// Proposal title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Proposer identity
    pub proposer: IdentityId,
    /// Type of proposal
    pub proposal_type: DaoProposalType,
    /// Current status
    pub status: DaoProposalStatus,
    /// Voting start time
    pub voting_start_time: u64,
    /// Voting end time
    pub voting_end_time: u64,
    /// Minimum quorum required (percentage)
    pub quorum_required: u8,
    /// Current vote tally
    pub vote_tally: DaoVoteTally,
    /// Proposal creation timestamp
    pub created_at: u64,
    /// Block height when proposal was created
    pub created_at_height: u64,
    /// Execution parameters (if passed)
    pub execution_params: Option<Vec<u8>>,
    /// Expected UBI impact (number of beneficiaries)
    pub ubi_impact: Option<u64>,
    /// Expected economic impact metrics
    pub economic_impact: Option<ImpactMetrics>,
    /// Privacy level for proposal data
    pub privacy_level: PrivacyLevel,
}

/// Types of DAO proposals
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DaoProposalType {
    /// Universal Basic Income parameter changes
    UbiDistribution,
    /// Welfare services funding (healthcare, education, public services)
    WelfareAllocation,
    /// Protocol upgrade proposals
    ProtocolUpgrade,
    /// Treasury fund allocation
    TreasuryAllocation,
    /// Validator set changes
    ValidatorUpdate,
    /// Economic parameter adjustments
    EconomicParams,
    /// Network governance rules
    GovernanceRules,
    /// Modify transaction fee structure
    FeeStructure,
    /// Emergency protocol changes
    Emergency,
    /// Community development funds
    CommunityFunding,
    /// Research and development grants
    ResearchGrants,
}

/// DAO proposal status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DaoProposalStatus {
    /// Proposal is in draft state
    Draft,
    /// Proposal is active and accepting votes
    Active,
    /// Proposal has passed and is ready for execution
    Passed,
    /// Proposal has failed (rejected or insufficient quorum)
    Failed,
    /// Proposal has been executed
    Executed,
    /// Proposal has been cancelled
    Cancelled,
    /// Proposal has expired without sufficient participation
    Expired,
}

/// Vote tally for a DAO proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoVoteTally {
    /// Total number of votes cast
    pub total_votes: u64,
    /// Number of "yes" votes
    pub yes_votes: u64,
    /// Number of "no" votes
    pub no_votes: u64,
    /// Number of "abstain" votes
    pub abstain_votes: u64,
    /// Total eligible voting power
    pub total_eligible_power: u64,
    /// Weighted yes votes (considering voting power)
    pub weighted_yes: u64,
    /// Weighted no votes (considering voting power)
    pub weighted_no: u64,
    /// Weighted abstain votes (considering voting power)
    pub weighted_abstain: u64,
}

/// Individual DAO vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoVote {
    /// Vote identifier
    pub id: Hash,
    /// Proposal being voted on
    pub proposal_id: Hash,
    /// Voter identity
    pub voter: Hash,
    /// Vote choice
    pub vote_choice: DaoVoteChoice,
    /// Voting power used
    pub voting_power: u64,
    /// Vote timestamp
    pub timestamp: u64,
    /// Vote signature
    pub signature: lib_crypto::Signature,
    /// Optional justification for the vote
    pub justification: Option<String>,
}

/// DAO vote choices
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DaoVoteChoice {
    /// Vote in favor of the proposal
    Yes,
    /// Vote against the proposal
    No,
    /// Abstain from voting (counted for quorum but not for/against)
    Abstain,
    /// Delegate vote to another participant
    Delegate(IdentityId),
}

impl DaoVoteChoice {
    /// Convert vote choice to u8 for serialization
    pub fn to_u8(&self) -> u8 {
        match self {
            DaoVoteChoice::Yes => 1,
            DaoVoteChoice::No => 2,
            DaoVoteChoice::Abstain => 3,
            DaoVoteChoice::Delegate(_) => 4,
        }
    }
}

/// DAO treasury management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoTreasury {
    /// Total treasury balance (ZHTP tokens)
    pub total_balance: u64,
    /// Available balance for allocation
    pub available_balance: u64,
    /// Currently allocated funds
    pub allocated_funds: u64,
    /// Reserved funds (cannot be allocated)
    pub reserved_funds: u64,
    /// Treasury transaction history
    pub transaction_history: Vec<TreasuryTransaction>,
    /// Annual budget allocations
    pub annual_budgets: Vec<AnnualBudget>,
}

/// Treasury transaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryTransaction {
    /// Transaction identifier
    pub id: Hash,
    /// Transaction type
    pub transaction_type: TreasuryTransactionType,
    /// Amount transferred
    pub amount: u64,
    /// Recipient (for outgoing transactions)
    pub recipient: Option<IdentityId>,
    /// Source (for incoming transactions)
    pub source: Option<IdentityId>,
    /// Associated proposal (if any)
    pub proposal_id: Option<Hash>,
    /// Transaction timestamp
    pub timestamp: u64,
    /// Transaction description
    pub description: String,
}

/// Types of treasury transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TreasuryTransactionType {
    /// Incoming funds (from protocol fees, donations, etc.)
    Deposit,
    /// Outgoing allocation to approved proposal
    Allocation,
    /// UBI distribution
    UbiDistribution,
    /// Validator rewards
    ValidatorRewards,
    /// Emergency fund usage
    Emergency,
    /// Community development funding
    CommunityFunding,
    /// Research grants
    ResearchGrant,
}

/// Annual budget allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnualBudget {
    /// Budget year
    pub year: u32,
    /// Total allocated budget
    pub total_allocation: u64,
    /// UBI allocation
    pub ubi_allocation: u64,
    /// Community development allocation
    pub community_allocation: u64,
    /// Research and development allocation
    pub research_allocation: u64,
    /// Emergency reserve allocation
    pub emergency_allocation: u64,
    /// Validator incentive allocation
    pub validator_allocation: u64,
    /// Spent amount so far
    pub spent_amount: u64,
    /// Budget approval proposal ID
    pub approval_proposal_id: Hash,
}

impl Default for DaoVoteTally {
    fn default() -> Self {
        Self {
            total_votes: 0,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_eligible_power: 0,
            weighted_yes: 0,
            weighted_no: 0,
            weighted_abstain: 0,
        }
    }
}

impl DaoVoteTally {
    /// Calculate approval percentage
    pub fn approval_percentage(&self) -> f64 {
        if self.total_votes == 0 {
            return 0.0;
        }
        (self.yes_votes as f64 / self.total_votes as f64) * 100.0
    }
    
    /// Calculate quorum percentage
    pub fn quorum_percentage(&self) -> f64 {
        if self.total_eligible_power == 0 {
            return 0.0;
        }
        (self.total_votes as f64 / self.total_eligible_power as f64) * 100.0
    }
    
    /// Calculate weighted approval percentage
    pub fn weighted_approval_percentage(&self) -> f64 {
        let total_weighted = self.weighted_yes + self.weighted_no;
        if total_weighted == 0 {
            return 0.0;
        }
        (self.weighted_yes as f64 / total_weighted as f64) * 100.0
    }
}

// ============================================================================
// Welfare Service Registry
// ============================================================================

/// Types of welfare services that can receive funding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WelfareServiceType {
    /// Healthcare services (hospitals, clinics, mental health)
    Healthcare,
    /// Education services (schools, training, digital literacy)
    Education,
    /// Infrastructure services (nodes, maintenance, security)
    Infrastructure,
    /// Public services (identity verification, dispute resolution)
    PublicService,
    /// Emergency response services
    EmergencyResponse,
    /// Community development projects
    CommunityDevelopment,
    /// Housing and shelter services
    Housing,
    /// Food security and nutrition programs
    FoodSecurity,
    /// Environmental protection and sustainability
    Environmental,
    /// Arts, culture, and recreation
    CulturalServices,
}

/// Registered welfare service provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelfareService {
    /// Unique service identifier
    pub service_id: String,
    /// Human-readable service name
    pub service_name: String,
    /// DID of service provider
    pub provider_identity: String,
    /// Type of service provided
    pub service_type: WelfareServiceType,
    /// Blockchain address for receiving funds
    pub service_address: [u8; 32],
    /// Registration timestamp
    pub registration_timestamp: u64,
    /// Registration block height
    pub registration_block: u64,
    /// Total amount received from DAO
    pub total_received: u64,
    /// Number of funding proposals received
    pub proposal_count: u64,
    /// Is service currently active and accepting funding
    pub is_active: bool,
    /// Service reputation score (0-100)
    pub reputation_score: u8,
    /// Geographic region served (optional)
    pub region: Option<String>,
    /// Service description
    pub description: String,
    /// Contact/verification info
    pub metadata: serde_json::Value,
    /// Zero-knowledge proof of provider credentials (serialized ZkCredentialProof)
    pub credential_proof: Option<Vec<u8>>,
}

/// Service allocation within a welfare proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAllocation {
    /// Service receiving funds
    pub service_id: String,
    /// Service type for categorization
    pub service_type: WelfareServiceType,
    /// Service address
    pub service_address: [u8; 32],
    /// Amount allocated to this service
    pub amount: u64,
    /// Purpose/justification for allocation
    pub purpose: String,
    /// Expected beneficiary count
    pub expected_beneficiaries: u64,
    /// Duration of funding (in blocks)
    pub funding_duration: u64,
}

/// Detailed welfare funding proposal data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelfareFundingDetails {
    /// Multiple service allocations
    pub services: Vec<ServiceAllocation>,
    /// Total amount across all services
    pub total_amount: u64,
    /// Funding period type (one-time, monthly, quarterly)
    pub funding_period: FundingPeriod,
    /// Expected total beneficiaries across all services
    pub total_expected_beneficiaries: u64,
    /// Impact assessment metrics
    pub impact_metrics: ImpactMetrics,
}

/// Funding period types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FundingPeriod {
    /// One-time funding
    OneTime,
    /// Monthly recurring (specify number of months)
    Monthly(u64),
    /// Quarterly recurring (specify number of quarters)
    Quarterly(u64),
    /// Annual recurring (specify number of years)
    Annual(u64),
}

/// Impact assessment for welfare proposals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactMetrics {
    /// Impact on UBI system (low, medium, high)
    pub ubi_impact: ImpactLevel,
    /// Overall economic impact
    pub economic_impact: ImpactLevel,
    /// Social welfare impact
    pub social_impact: ImpactLevel,
    /// Privacy/transparency level (0-100, higher = more transparent)
    pub privacy_level: u8,
    /// Expected outcome description
    pub expected_outcomes: String,
    /// Success metrics definition
    pub success_criteria: Vec<String>,
}

/// Impact level classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Privacy level for proposal visibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrivacyLevel {
    /// Fully public proposal with all details visible
    Public,
    /// Partial details hidden (amounts, identities protected)
    PartiallyPrivate,
    /// Only aggregate data visible
    Private,
    /// Emergency proposals with restricted visibility
    Restricted,
}

// ============================================================================
// Audit Trail System
// ============================================================================

/// Welfare distribution audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelfareAuditEntry {
    /// Unique audit entry ID
    pub audit_id: Hash,
    /// Service that received funds
    pub service_id: String,
    /// Service type for categorization
    pub service_type: WelfareServiceType,
    /// Proposal that authorized the distribution
    pub proposal_id: Hash,
    /// Amount distributed
    pub amount_distributed: u64,
    /// Distribution transaction hash
    pub transaction_hash: Hash,
    /// Timestamp of distribution
    pub distribution_timestamp: u64,
    /// Block height of distribution
    pub distribution_block: u64,
    /// Number of beneficiaries served
    pub beneficiary_count: u64,
    /// Zero-knowledge proof of valid distribution
    pub verification_proof: Option<Vec<u8>>,
    /// Service provider's report
    pub service_report: Option<String>,
    /// Impact verification status
    pub verification_status: VerificationStatus,
    /// Auditor notes (if audited)
    pub auditor_notes: Option<String>,
}

/// Verification status for welfare distributions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationStatus {
    /// Pending verification
    Pending,
    /// Verified by automated system
    AutoVerified,
    /// Verified by community auditor
    CommunityVerified,
    /// Flagged for review
    Flagged,
    /// Verified as fraudulent
    Fraudulent,
    /// Verification disputed
    Disputed,
}

// ============================================================================
// Outcome Measurement System
// ============================================================================

/// Service performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePerformanceMetrics {
    /// Service identifier
    pub service_id: String,
    /// Service name
    pub service_name: String,
    /// Service type
    pub service_type: WelfareServiceType,
    /// Utilization rate (0-100%)
    pub service_utilization_rate: f64,
    /// Average beneficiary satisfaction (0-100)
    pub beneficiary_satisfaction: f64,
    /// Cost efficiency (beneficiaries per ZHTP)
    pub cost_efficiency: f64,
    /// Geographic coverage (regions served)
    pub geographic_coverage: Vec<String>,
    /// Total beneficiaries served
    pub total_beneficiaries: u64,
    /// Success rate based on defined criteria (0-100%)
    pub success_rate: f64,
    /// Number of outcome reports submitted
    pub outcome_reports_count: u64,
    /// Last audit timestamp
    pub last_audit_timestamp: u64,
    /// Reputation trend (improving, stable, declining)
    pub reputation_trend: ReputationTrend,
}

/// Service reputation trend
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReputationTrend {
    Improving,
    Stable,
    Declining,
    Volatile,
}

/// Detailed outcome report for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeReport {
    /// Report identifier
    pub report_id: Hash,
    /// Service being reported on
    pub service_id: String,
    /// Reporting period start
    pub period_start: u64,
    /// Reporting period end
    pub period_end: u64,
    /// Funds utilized during period
    pub funds_utilized: u64,
    /// Beneficiaries served during period
    pub beneficiaries_served: u64,
    /// Success metrics achieved
    pub metrics_achieved: Vec<MetricAchievement>,
    /// Qualitative impact description
    pub impact_description: String,
    /// Challenges encountered
    pub challenges: Vec<String>,
    /// Recommendations for improvement
    pub recommendations: Vec<String>,
    /// Supporting evidence (hashes of documents/photos)
    pub evidence_hashes: Vec<Hash>,
    /// Reporter identity
    pub reporter_identity: Hash,
    /// Report timestamp
    pub report_timestamp: u64,
    /// Community verification votes (if applicable)
    pub verification_votes: u64,
}

/// Achievement of a specific success metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricAchievement {
    /// Metric name
    pub metric_name: String,
    /// Target value
    pub target_value: f64,
    /// Actual value achieved
    pub actual_value: f64,
    /// Achievement percentage
    pub achievement_percentage: f64,
    /// Notes on achievement
    pub notes: String,
}

// ============================================================================
// Welfare Dashboard Statistics
// ============================================================================

/// Comprehensive welfare system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelfareStatistics {
    /// Total welfare funds allocated (lifetime)
    pub total_allocated: u64,
    /// Total welfare funds distributed (lifetime)
    pub total_distributed: u64,
    /// Current available welfare balance
    pub available_balance: u64,
    /// Number of active services
    pub active_services_count: u64,
    /// Total registered services (all time)
    pub total_services_registered: u64,
    /// Number of welfare proposals submitted
    pub total_proposals: u64,
    /// Number of welfare proposals passed
    pub passed_proposals: u64,
    /// Number of welfare proposals executed
    pub executed_proposals: u64,
    /// Total beneficiaries served (all time)
    pub total_beneficiaries_served: u64,
    /// Distribution by service type
    pub distribution_by_type: std::collections::HashMap<WelfareServiceType, u64>,
    /// Average distribution amount
    pub average_distribution: u64,
    /// Welfare system efficiency (distributed / allocated %)
    pub efficiency_percentage: f64,
    /// Last distribution timestamp
    pub last_distribution_timestamp: u64,
    /// Pending audit entries
    pub pending_audits: u64,
}

/// Funding history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingHistoryEntry {
    /// Entry timestamp
    pub timestamp: u64,
    /// Block height
    pub block_height: u64,
    /// Proposal that authorized funding
    pub proposal_id: Hash,
    /// Service that received funding
    pub service_id: String,
    /// Service type
    pub service_type: WelfareServiceType,
    /// Amount funded
    pub amount: u64,
    /// Transaction hash
    pub transaction_hash: Hash,
    /// Current status
    pub status: FundingStatus,
}

/// Status of a funding allocation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FundingStatus {
    /// Proposal passed, not yet executed
    Approved,
    /// Funds distributed
    Distributed,
    /// Distribution verified
    Verified,
    /// Under audit review
    UnderReview,
    /// Disputed/flagged
    Disputed,
    /// Completed successfully
    Completed,
}

