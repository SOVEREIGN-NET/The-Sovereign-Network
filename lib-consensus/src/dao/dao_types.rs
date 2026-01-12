//! DAO types and data structures

use lib_crypto::Hash;
use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};

/// DAO proposal for governance decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoProposal {
    /// Unique proposal identifier
    id: Hash,
    /// Proposal title
    title: String,
    /// Detailed description
    description: String,
    /// Proposer identity
    proposer: IdentityId,
    /// Type of proposal
    proposal_type: DaoProposalType,
    /// Current status
    status: DaoProposalStatus,
    /// Voting start time
    voting_start_time: u64,
    /// Voting end time
    voting_end_time: u64,
    /// Minimum quorum required (percentage)
    quorum_required: u8,
    /// Current vote tally
    vote_tally: DaoVoteTally,
    /// Proposal creation timestamp
    created_at: u64,
    /// Block height when proposal was created
    created_at_height: u64,
    /// Execution parameters (if passed)
    execution_params: Option<Vec<u8>>,
    /// Expected UBI impact (number of beneficiaries)
    ubi_impact: Option<u64>,
    /// Expected economic impact metrics
    economic_impact: Option<ImpactMetrics>,
    /// Privacy level for proposal data
    privacy_level: PrivacyLevel,
}

impl DaoProposal {
    /// Create a new DAO proposal with validation
    ///
    /// # Errors
    /// Returns error if:
    /// - voting_end_time <= voting_start_time (voting window must be positive)
    /// - quorum_required > 100 (quorum must be valid percentage)
    pub fn new(
        id: Hash,
        title: String,
        description: String,
        proposer: IdentityId,
        proposal_type: DaoProposalType,
        status: DaoProposalStatus,
        voting_start_time: u64,
        voting_end_time: u64,
        quorum_required: u8,
        vote_tally: DaoVoteTally,
        created_at: u64,
        created_at_height: u64,
        execution_params: Option<Vec<u8>>,
        ubi_impact: Option<u64>,
        economic_impact: Option<ImpactMetrics>,
        privacy_level: PrivacyLevel,
    ) -> Result<Self, String> {
        // Validate temporal ordering invariant
        if voting_end_time <= voting_start_time {
            return Err("voting_end_time must be after voting_start_time".to_string());
        }

        // Validate quorum invariant
        if quorum_required > 100 {
            return Err("quorum_required must be between 0 and 100".to_string());
        }

        Ok(DaoProposal {
            id,
            title,
            description,
            proposer,
            proposal_type,
            status,
            voting_start_time,
            voting_end_time,
            quorum_required,
            vote_tally,
            created_at,
            created_at_height,
            execution_params,
            ubi_impact,
            economic_impact,
            privacy_level,
        })
    }

    /// Validate status transition
    pub fn transition_to(&mut self, new_status: DaoProposalStatus) -> Result<(), String> {
        match (&self.status, &new_status) {
            (DaoProposalStatus::Draft, DaoProposalStatus::Active) => {},
            (DaoProposalStatus::Active, DaoProposalStatus::Passed) => {},
            (DaoProposalStatus::Active, DaoProposalStatus::Failed) => {},
            (DaoProposalStatus::Passed, DaoProposalStatus::Executed) => {},
            (DaoProposalStatus::Active, DaoProposalStatus::Expired) => {},
            (s, DaoProposalStatus::Cancelled) => {
                if !matches!(s, DaoProposalStatus::Executed) {
                    // Can cancel from most states except Executed
                } else {
                    return Err("Cannot cancel executed proposal".to_string());
                }
            },
            _ => return Err(format!("Invalid transition from {:?} to {:?}", self.status, new_status)),
        }
        self.status = new_status;
        Ok(())
    }

    /// Check if proposal is currently votable
    pub fn is_votable(&self, current_time: u64) -> bool {
        matches!(self.status, DaoProposalStatus::Active)
            && current_time >= self.voting_start_time
            && current_time < self.voting_end_time
    }

    // Accessor methods (immutable)
    pub fn id(&self) -> &Hash { &self.id }
    pub fn title(&self) -> &str { &self.title }
    pub fn description(&self) -> &str { &self.description }
    pub fn proposer(&self) -> &IdentityId { &self.proposer }
    pub fn proposal_type(&self) -> &DaoProposalType { &self.proposal_type }
    pub fn status(&self) -> &DaoProposalStatus { &self.status }
    pub fn voting_start_time(&self) -> u64 { self.voting_start_time }
    pub fn voting_end_time(&self) -> u64 { self.voting_end_time }
    pub fn quorum_required(&self) -> u8 { self.quorum_required }
    pub fn vote_tally(&self) -> &DaoVoteTally { &self.vote_tally }
    pub fn created_at(&self) -> u64 { self.created_at }
    pub fn created_at_height(&self) -> u64 { self.created_at_height }
    pub fn execution_params(&self) -> Option<&Vec<u8>> { self.execution_params.as_ref() }
    pub fn ubi_impact(&self) -> Option<u64> { self.ubi_impact }
    pub fn economic_impact(&self) -> Option<&ImpactMetrics> { self.economic_impact.as_ref() }
    pub fn privacy_level(&self) -> &PrivacyLevel { &self.privacy_level }

    // Mutable accessor for tally
    pub fn vote_tally_mut(&mut self) -> &mut DaoVoteTally { &mut self.vote_tally }
}

/// DAO execution parameters for proposal application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoExecutionParams {
    pub action: DaoExecutionAction,
}

/// Execution action for a DAO proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaoExecutionAction {
    /// Governance parameter update
    GovernanceParameterUpdate(GovernanceParameterUpdate),
}

/// Governance parameter update payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceParameterUpdate {
    pub updates: Vec<GovernanceParameterValue>,
}

/// Supported governance parameter updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceParameterValue {
    MinStake(u64),
    MinStorage(u64),
    MaxValidators(u32),
    BlockTime(u64),
    EpochLengthBlocks(u64),
    ProposeTimeout(u64),
    PrevoteTimeout(u64),
    PrecommitTimeout(u64),
    MaxTransactionsPerBlock(u32),
    MaxDifficulty(u64),
    TargetDifficulty(u64),
    ByzantineThreshold(f64),
    SlashDoubleSign(u8),
    SlashLiveness(u8),
    DevelopmentMode(bool),
    // Blockchain difficulty parameters (owned by consensus, used by blockchain)
    /// Initial difficulty for new chains (Bitcoin-style compact representation)
    BlockchainInitialDifficulty(u32),
    /// Number of blocks between difficulty adjustments
    BlockchainAdjustmentInterval(u64),
    /// Target time for difficulty adjustment interval (seconds)
    BlockchainTargetTimespan(u64),
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
    total_votes: u64,
    /// Number of "yes" votes
    yes_votes: u64,
    /// Number of "no" votes
    no_votes: u64,
    /// Number of "abstain" votes
    abstain_votes: u64,
    /// Total eligible voting power
    total_eligible_power: u64,
    /// Weighted yes votes (considering voting power)
    weighted_yes: u64,
    /// Weighted no votes (considering voting power)
    weighted_no: u64,
    /// Weighted abstain votes (considering voting power)
    weighted_abstain: u64,
}

impl DaoVoteTally {
    /// Create a new vote tally with validation
    pub fn new(total_eligible_power: u64) -> Self {
        Self {
            total_votes: 0,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_eligible_power,
            weighted_yes: 0,
            weighted_no: 0,
            weighted_abstain: 0,
        }
    }

    /// Record a vote and validate invariants
    pub fn record_vote(&mut self, choice: &DaoVoteChoice, power: u64) -> Result<(), String> {
        // Check power constraint
        if self.total_votes + 1 > self.total_eligible_power {
            return Err("Cannot exceed total eligible voting power".to_string());
        }

        match choice {
            DaoVoteChoice::Yes => {
                self.yes_votes = self.yes_votes.saturating_add(1);
                self.weighted_yes = self.weighted_yes.saturating_add(power);
            },
            DaoVoteChoice::No => {
                self.no_votes = self.no_votes.saturating_add(1);
                self.weighted_no = self.weighted_no.saturating_add(power);
            },
            DaoVoteChoice::Abstain => {
                self.abstain_votes = self.abstain_votes.saturating_add(1);
                self.weighted_abstain = self.weighted_abstain.saturating_add(power);
            },
            DaoVoteChoice::Delegate(_) => {
                // Delegates don't contribute to votes directly
            },
        }

        self.total_votes = self.total_votes.saturating_add(1);
        self.validate()?;
        Ok(())
    }

    /// Validate vote tally invariants
    fn validate(&self) -> Result<(), String> {
        // Invariant: vote sum consistency
        if self.yes_votes + self.no_votes + self.abstain_votes != self.total_votes {
            return Err("Vote counts don't sum to total_votes".to_string());
        }

        // Invariant: votes don't exceed eligible power
        if self.total_votes > self.total_eligible_power {
            return Err("Votes exceed total eligible voting power".to_string());
        }

        // Invariant: weighted votes don't exceed eligible power
        let total_weighted = self.weighted_yes + self.weighted_no + self.weighted_abstain;
        if total_weighted > self.total_eligible_power {
            return Err("Weighted votes exceed total eligible voting power".to_string());
        }

        Ok(())
    }

    // Accessor methods
    pub fn total_votes(&self) -> u64 { self.total_votes }
    pub fn yes_votes(&self) -> u64 { self.yes_votes }
    pub fn no_votes(&self) -> u64 { self.no_votes }
    pub fn abstain_votes(&self) -> u64 { self.abstain_votes }
    pub fn total_eligible_power(&self) -> u64 { self.total_eligible_power }
    pub fn weighted_yes(&self) -> u64 { self.weighted_yes }
    pub fn weighted_no(&self) -> u64 { self.weighted_no }
    pub fn weighted_abstain(&self) -> u64 { self.weighted_abstain }
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
