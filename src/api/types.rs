//! ZHTP API Types
//! 
//! Type definitions for the orchestrator API

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// API request context
#[derive(Debug, Clone)]
pub struct ApiContext {
    /// Request ID
    pub request_id: String,
    /// User ID (if authenticated)
    pub user_id: Option<String>,
    /// API key (if provided)
    pub api_key: Option<String>,
    /// User tier
    pub user_tier: crate::api::config::ApiTier,
    /// Geographic info
    pub geo_info: Option<GeoInfo>,
    /// Economic assessment
    pub economic_assessment: EconomicAssessment,
    /// Rate limit info
    pub rate_limit_info: RateLimitInfo,
}

/// Geographic information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    /// Country code
    pub country: String,
    /// Region
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// ISP
    pub isp: Option<String>,
}

/// Economic assessment for API call
#[derive(Debug, Clone)]
pub struct EconomicAssessment {
    /// Total fee for this call
    pub total_fee: u64,
    /// DAO fee portion
    pub dao_fee: u64,
    /// UBI contribution
    pub ubi_contribution: u64,
    /// User balance impact
    pub balance_impact: i64,
}

/// Rate limit information
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Requests remaining in current window
    pub remaining: u32,
    /// Total limit per window
    pub limit: u32,
    /// Window reset time
    pub reset_time: u64,
    /// Retry after seconds (if limited)
    pub retry_after: Option<u64>,
}

/// Rate limiting state
#[derive(Debug, Clone)]
pub struct RateLimitState {
    /// Requests in current window
    pub requests: u32,
    /// Window start time
    pub window_start: u64,
    /// Window duration in seconds
    pub window_duration: u64,
    /// Request limit per window
    pub limit: u32,
}

/// API usage statistics
#[derive(Debug, Clone, Default)]
pub struct ApiStats {
    /// Total API calls
    pub total_calls: u64,
    /// Calls by endpoint
    pub endpoint_stats: HashMap<String, EndpointStats>,
    /// Economic metrics
    pub economic_stats: EconomicStats,
    /// Error statistics
    pub error_stats: HashMap<String, u64>,
    /// Geographic distribution
    pub geographic_stats: HashMap<String, u64>,
}

/// Statistics per endpoint
#[derive(Debug, Clone, Default)]
pub struct EndpointStats {
    /// Total calls to this endpoint
    pub total_calls: u64,
    /// Average response time
    pub avg_response_time_ms: f64,
    /// Success rate
    pub success_rate: f64,
    /// Total fees collected
    pub total_fees: u64,
    /// Peak requests per minute
    pub peak_rpm: u32,
}

/// Economic statistics
#[derive(Debug, Clone, Default)]
pub struct EconomicStats {
    /// Total fees collected
    pub total_fees_collected: u64,
    /// Total DAO fees
    pub total_dao_fees: u64,
    /// Total UBI contributions
    pub total_ubi_contributions: u64,
    /// Revenue by tier
    pub revenue_by_tier: HashMap<crate::api::config::ApiTier, u64>,
}

/// Wallet operation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletOperationRequest {
    /// Operation type
    pub operation: WalletOperation,
    /// Wallet address
    pub wallet_address: String,
    /// Amount (for transfer operations)
    pub amount: Option<u64>,
    /// Recipient address (for transfers)
    pub recipient: Option<String>,
    /// Additional parameters
    pub parameters: HashMap<String, String>,
}

/// Wallet operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletOperation {
    /// Get wallet balance
    GetBalance,
    /// Transfer funds
    Transfer,
    /// Get transaction history
    GetHistory,
    /// Create new wallet
    CreateWallet,
    /// Import existing wallet
    ImportWallet,
    /// Export wallet
    ExportWallet,
    /// Sign transaction
    SignTransaction,
    /// Verify signature
    VerifySignature,
    /// Stake tokens
    Stake,
    /// Unstake tokens
    Unstake,
    /// Delegate voting power
    Delegate,
}

/// DAO operation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoOperationRequest {
    /// Operation type
    pub operation: DaoOperation,
    /// DAO ID
    pub dao_id: String,
    /// Proposal ID (for proposal operations)
    pub proposal_id: Option<String>,
    /// Vote choice (for voting)
    pub vote: Option<VoteChoice>,
    /// Additional parameters
    pub parameters: HashMap<String, String>,
}

/// DAO operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaoOperation {
    /// Get DAO information
    GetInfo,
    /// Create new proposal
    CreateProposal,
    /// Vote on proposal
    Vote,
    /// Execute proposal
    ExecuteProposal,
    /// Get voting history
    GetVotingHistory,
    /// Get treasury information
    GetTreasury,
    /// Claim UBI
    ClaimUbi,
    /// Join DAO
    JoinDao,
    /// Leave DAO
    LeaveDao,
}

/// Vote choices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteChoice {
    /// Vote yes
    Yes,
    /// Vote no
    No,
    /// Abstain from voting
    Abstain,
}

/// Identity verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRequest {
    /// Verification type
    pub verification_type: IdentityVerificationType,
    /// Identity data
    pub identity_data: Vec<u8>,
    /// Additional proof data
    pub proof_data: Option<Vec<u8>>,
    /// Verification parameters
    pub parameters: HashMap<String, String>,
}

/// Identity verification types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityVerificationType {
    /// Zero-knowledge identity proof
    ZeroKnowledge,
    /// Biometric verification
    Biometric,
    /// Document verification
    Document,
    /// Social verification
    Social,
    /// Blockchain verification
    Blockchain,
    /// Multi-factor verification
    MultiFactor,
}
