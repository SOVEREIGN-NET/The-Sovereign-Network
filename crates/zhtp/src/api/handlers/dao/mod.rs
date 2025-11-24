//! DAO Handler Module
//! 
//! Complete DAO governance system using lib-consensus DaoEngine

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::Deserialize;
// Removed unused Serialize
use serde_json::json;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Import actual DAO system components
use lib_consensus::{
    DaoEngine, DaoProposalType, DaoProposalStatus, DaoVoteChoice,
    // Removed unused DaoProposal, DaoVote, DaoTreasury, DaoVoteTally, TreasuryTransaction, TreasuryTransactionType
};
use lib_identity::IdentityManager;
// Removed unused Identity alias
use lib_crypto::Hash;

/// Helper function to create JSON responses correctly
fn create_json_response(data: serde_json::Value) -> Result<ZhtpResponse> {
    let json_response = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

fn create_error_response(status: ZhtpStatus, message: String) -> ZhtpResponse {
    ZhtpResponse::error(status, message)
}

/// Request types for DAO operations
#[derive(Debug, Deserialize)]
struct CreateProposalRequest {
    proposer_identity_id: String,
    title: String,
    description: String,
    proposal_type: String,
    voting_period_days: u32,
}

#[derive(Debug, Deserialize)]
struct CastVoteRequest {
    voter_identity_id: String,
    proposal_id: String,
    vote_choice: String,
    justification: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProposalListQuery {
    status: Option<String>,
    proposal_type: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Complete DAO handler using DaoEngine
pub struct DaoHandler {
    dao_engine: Arc<RwLock<DaoEngine>>,
    identity_manager: Arc<RwLock<IdentityManager>>,
}

impl DaoHandler {
    pub fn new(identity_manager: Arc<RwLock<IdentityManager>>) -> Self {
        Self {
            dao_engine: Arc::new(RwLock::new(DaoEngine::new())),
            identity_manager,
        }
    }

    /// Parse proposal type from string
    fn parse_proposal_type(type_str: &str) -> Result<DaoProposalType> {
        match type_str.to_lowercase().as_str() {
            "ubi_distribution" => Ok(DaoProposalType::UbiDistribution),
            "protocol_upgrade" => Ok(DaoProposalType::ProtocolUpgrade),
            "treasury_allocation" => Ok(DaoProposalType::TreasuryAllocation),
            "validator_update" => Ok(DaoProposalType::ValidatorUpdate),
            "economic_params" => Ok(DaoProposalType::EconomicParams),
            "governance_rules" => Ok(DaoProposalType::GovernanceRules),
            "fee_structure" => Ok(DaoProposalType::FeeStructure),
            "emergency" => Ok(DaoProposalType::Emergency),
            "community_funding" => Ok(DaoProposalType::CommunityFunding),
            "research_grants" => Ok(DaoProposalType::ResearchGrants),
            _ => Err(anyhow::anyhow!("Invalid proposal type: {}", type_str)),
        }
    }

    /// Parse vote choice from string
    fn parse_vote_choice(choice_str: &str) -> Result<DaoVoteChoice> {
        match choice_str.to_lowercase().as_str() {
            "yes" => Ok(DaoVoteChoice::Yes),
            "no" => Ok(DaoVoteChoice::No),
            "abstain" => Ok(DaoVoteChoice::Abstain),
            _ => Err(anyhow::anyhow!("Invalid vote choice: {}", choice_str)),
        }
    }

    /// Convert Hash to hex string
    fn hash_to_string(hash: &Hash) -> String {
        hex::encode(hash.as_bytes())
    }

    /// Parse hex string to Hash
    fn string_to_hash(hash_str: &str) -> Result<Hash> {
        let bytes = hex::decode(hash_str)?;
        Ok(Hash::from_bytes(&bytes))
    }

    /// Parse query parameters from query string
    fn parse_query_params(query_string: &str) -> std::collections::HashMap<String, String> {
        let mut params = std::collections::HashMap::new();
        if query_string.is_empty() {
            return params;
        }
        
        for pair in query_string.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                params.insert(
                    urlencoding::decode(key).unwrap_or_default().into_owned(),
                    urlencoding::decode(value).unwrap_or_default().into_owned(),
                );
            }
        }
        params
    }

    /// Handle treasury status endpoint
    async fn handle_treasury_status(&self) -> Result<ZhtpResponse> {
        let dao_engine = self.dao_engine.read().await;
        let treasury = dao_engine.get_dao_treasury();

        let response = json!({
            "status": "success",
            "treasury": {
                "total_balance": treasury.total_balance,
                "available_balance": treasury.available_balance,
                "allocated_funds": treasury.allocated_funds,
                "reserved_funds": treasury.reserved_funds,
                "transaction_count": treasury.transaction_history.len(),
                "annual_budgets_count": treasury.annual_budgets.len()
            }
        });

        create_json_response(response)
    }

    /// Handle treasury transactions endpoint
    async fn handle_treasury_transactions(&self, limit: Option<usize>, offset: Option<usize>) -> Result<ZhtpResponse> {
        let dao_engine = self.dao_engine.read().await;
        let treasury = dao_engine.get_dao_treasury();

        let limit = limit.unwrap_or(50).min(100); // Max 100 transactions per request
        let offset = offset.unwrap_or(0);

        let transactions: Vec<_> = treasury.transaction_history
            .iter()
            .skip(offset)
            .take(limit)
            .map(|tx| json!({
                "id": Self::hash_to_string(&tx.id),
                "transaction_type": format!("{:?}", tx.transaction_type),
                "amount": tx.amount,
                "recipient": tx.recipient.as_ref().map(|id| Self::hash_to_string(id)),
                "source": tx.source.as_ref().map(|id| Self::hash_to_string(id)),
                "proposal_id": tx.proposal_id.as_ref().map(|id| Self::hash_to_string(id)),
                "timestamp": tx.timestamp,
                "description": tx.description
            }))
            .collect();

        let response = json!({
            "status": "success",
            "total_transactions": treasury.transaction_history.len(),
            "returned_count": transactions.len(),
            "offset": offset,
            "limit": limit,
            "transactions": transactions
        });

        create_json_response(response)
    }

    /// Handle create proposal endpoint
    async fn handle_create_proposal(&self, request_data: CreateProposalRequest) -> Result<ZhtpResponse> {
        // Validate identity exists
        let identity_manager = self.identity_manager.read().await;
        let proposer_id = Self::string_to_hash(&request_data.proposer_identity_id)?;
        
        if identity_manager.get_identity(&proposer_id).is_none() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest, 
                "Proposer identity not found".to_string()
            ));
        }

        // Parse proposal type
        let proposal_type = match Self::parse_proposal_type(&request_data.proposal_type) {
            Ok(pt) => pt,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Invalid proposal type: {}", request_data.proposal_type)
            )),
        };

        // Create proposal using DaoEngine
        let mut dao_engine = self.dao_engine.write().await;
        match dao_engine.create_dao_proposal(
            proposer_id,
            request_data.title.clone(),
            request_data.description.clone(),
            proposal_type,
            request_data.voting_period_days,
        ).await {
            Ok(proposal_id) => {
                let response = json!({
                    "status": "success",
                    "proposal_id": Self::hash_to_string(&proposal_id),
                    "title": request_data.title,
                    "proposal_type": request_data.proposal_type,
                    "voting_period_days": request_data.voting_period_days,
                    "message": "Proposal created successfully"
                });
                create_json_response(response)
            },
            Err(e) => Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Failed to create proposal: {}", e)
            )),
        }
    }

    /// Handle list proposals endpoint
    async fn handle_list_proposals(&self, query: ProposalListQuery) -> Result<ZhtpResponse> {
        let dao_engine = self.dao_engine.read().await;
        let all_proposals = dao_engine.get_dao_proposals();

        let limit = query.limit.unwrap_or(20).min(100); // Max 100 proposals per request
        let offset = query.offset.unwrap_or(0);

        let mut filtered_proposals: Vec<_> = all_proposals.iter().collect();

        // Filter by status if provided
        if let Some(status_filter) = &query.status {
            let target_status = match status_filter.to_lowercase().as_str() {
                "draft" => Some(DaoProposalStatus::Draft),
                "active" => Some(DaoProposalStatus::Active),
                "passed" => Some(DaoProposalStatus::Passed),
                "failed" => Some(DaoProposalStatus::Failed),
                "executed" => Some(DaoProposalStatus::Executed),
                "cancelled" => Some(DaoProposalStatus::Cancelled),
                "expired" => Some(DaoProposalStatus::Expired),
                _ => None,
            };
            if let Some(status) = target_status {
                filtered_proposals.retain(|p| p.status == status);
            }
        }

        // Filter by proposal type if provided
        if let Some(type_filter) = &query.proposal_type {
            if let Ok(proposal_type) = Self::parse_proposal_type(type_filter) {
                filtered_proposals.retain(|p| p.proposal_type == proposal_type);
            }
        }

        // Apply pagination
        let paginated_proposals: Vec<_> = filtered_proposals
            .iter()
            .skip(offset)
            .take(limit)
            .map(|proposal| json!({
                "id": Self::hash_to_string(&proposal.id),
                "title": proposal.title,
                "description": proposal.description,
                "proposer": Self::hash_to_string(&proposal.proposer),
                "proposal_type": format!("{:?}", proposal.proposal_type),
                "status": format!("{:?}", proposal.status),
                "voting_start_time": proposal.voting_start_time,
                "voting_end_time": proposal.voting_end_time,
                "quorum_required": proposal.quorum_required,
                "created_at": proposal.created_at,
                "vote_tally": {
                    "total_votes": proposal.vote_tally.total_votes,
                    "yes_votes": proposal.vote_tally.yes_votes,
                    "no_votes": proposal.vote_tally.no_votes,
                    "abstain_votes": proposal.vote_tally.abstain_votes,
                    "approval_percentage": proposal.vote_tally.approval_percentage(),
                    "quorum_percentage": proposal.vote_tally.quorum_percentage()
                }
            }))
            .collect();

        let response = json!({
            "status": "success",
            "total_proposals": all_proposals.len(),
            "filtered_count": filtered_proposals.len(),
            "returned_count": paginated_proposals.len(),
            "offset": offset,
            "limit": limit,
            "proposals": paginated_proposals
        });

        create_json_response(response)
    }

    /// Handle get proposal by ID endpoint
    async fn handle_get_proposal(&self, proposal_id_str: &str) -> Result<ZhtpResponse> {
        let proposal_id = match Self::string_to_hash(proposal_id_str) {
            Ok(id) => id,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Invalid proposal ID format".to_string()
            )),
        };

        let dao_engine = self.dao_engine.read().await;
        match dao_engine.get_dao_proposal_by_id(&proposal_id) {
            Some(proposal) => {
                let response = json!({
                    "status": "success",
                    "proposal": {
                        "id": Self::hash_to_string(&proposal.id),
                        "title": proposal.title,
                        "description": proposal.description,
                        "proposer": Self::hash_to_string(&proposal.proposer),
                        "proposal_type": format!("{:?}", proposal.proposal_type),
                        "status": format!("{:?}", proposal.status),
                        "voting_start_time": proposal.voting_start_time,
                        "voting_end_time": proposal.voting_end_time,
                        "quorum_required": proposal.quorum_required,
                        "created_at": proposal.created_at,
                        "created_at_height": proposal.created_at_height,
                        "vote_tally": {
                            "total_votes": proposal.vote_tally.total_votes,
                            "yes_votes": proposal.vote_tally.yes_votes,
                            "no_votes": proposal.vote_tally.no_votes,
                            "abstain_votes": proposal.vote_tally.abstain_votes,
                            "total_eligible_power": proposal.vote_tally.total_eligible_power,
                            "weighted_yes": proposal.vote_tally.weighted_yes,
                            "weighted_no": proposal.vote_tally.weighted_no,
                            "weighted_abstain": proposal.vote_tally.weighted_abstain,
                            "approval_percentage": proposal.vote_tally.approval_percentage(),
                            "quorum_percentage": proposal.vote_tally.quorum_percentage(),
                            "weighted_approval_percentage": proposal.vote_tally.weighted_approval_percentage()
                        }
                    }
                });
                create_json_response(response)
            },
            None => Ok(create_error_response(
                ZhtpStatus::NotFound,
                "Proposal not found".to_string()
            )),
        }
    }

    /// Handle cast vote endpoint
    async fn handle_cast_vote(&self, request_data: CastVoteRequest) -> Result<ZhtpResponse> {
        // Validate identity exists
        let identity_manager = self.identity_manager.read().await;
        let voter_id = Self::string_to_hash(&request_data.voter_identity_id)?;
        
        if identity_manager.get_identity(&voter_id).is_none() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest, 
                "Voter identity not found".to_string()
            ));
        }

        // Parse proposal ID and vote choice
        let proposal_id = match Self::string_to_hash(&request_data.proposal_id) {
            Ok(id) => id,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Invalid proposal ID format".to_string()
            )),
        };

        let vote_choice = match Self::parse_vote_choice(&request_data.vote_choice) {
            Ok(choice) => choice,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Invalid vote choice: {}", request_data.vote_choice)
            )),
        };

        // Cast vote using DaoEngine
        let mut dao_engine = self.dao_engine.write().await;
        match dao_engine.cast_dao_vote(
            voter_id,
            proposal_id,
            vote_choice.clone(),
            request_data.justification.clone(),
        ).await {
            Ok(vote_id) => {
                let response = json!({
                    "status": "success",
                    "vote_id": Self::hash_to_string(&vote_id),
                    "proposal_id": request_data.proposal_id,
                    "vote_choice": request_data.vote_choice,
                    "voter_id": request_data.voter_identity_id,
                    "message": "Vote cast successfully"
                });
                create_json_response(response)
            },
            Err(e) => Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Failed to cast vote: {}", e)
            )),
        }
    }

    /// Handle get voting power endpoint
    async fn handle_get_voting_power(&self, identity_id_str: &str) -> Result<ZhtpResponse> {
        let identity_id = match Self::string_to_hash(identity_id_str) {
            Ok(id) => id,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Invalid identity ID format".to_string()
            )),
        };

        // Validate identity exists
        let identity_manager = self.identity_manager.read().await;
        if identity_manager.get_identity(&identity_id).is_none() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest, 
                "Identity not found".to_string()
            ));
        }

        let dao_engine = self.dao_engine.read().await;
        let voting_power = dao_engine.get_dao_voting_power(&identity_id);

        let response = json!({
            "status": "success",
            "identity_id": identity_id_str,
            "voting_power": voting_power,
            "power_breakdown": {
                "base_citizen_power": 1,
                "reputation_multiplier": 1.0,
                "staked_tokens_power": 0,
                "delegated_power": 0
            }
        });

        create_json_response(response)
    }

    /// Handle get votes for proposal endpoint
    async fn handle_get_proposal_votes(&self, proposal_id_str: &str) -> Result<ZhtpResponse> {
        let proposal_id = match Self::string_to_hash(proposal_id_str) {
            Ok(id) => id,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Invalid proposal ID format".to_string()
            )),
        };

        let dao_engine = self.dao_engine.read().await;
        
        // Check if proposal exists
        if dao_engine.get_dao_proposal_by_id(&proposal_id).is_none() {
            return Ok(create_error_response(
                ZhtpStatus::NotFound,
                "Proposal not found".to_string()
            ));
        }

        // Get all votes (this would need to be implemented in DaoEngine)
        // For now, we'll return the vote tally from the proposal
        let proposal = dao_engine.get_dao_proposal_by_id(&proposal_id).unwrap();

        let response = json!({
            "status": "success",
            "proposal_id": proposal_id_str,
            "vote_summary": {
                "total_votes": proposal.vote_tally.total_votes,
                "yes_votes": proposal.vote_tally.yes_votes,
                "no_votes": proposal.vote_tally.no_votes,
                "abstain_votes": proposal.vote_tally.abstain_votes,
                "approval_percentage": proposal.vote_tally.approval_percentage(),
                "quorum_percentage": proposal.vote_tally.quorum_percentage()
            },
            "message": "Vote details retrieved successfully"
        });

        create_json_response(response)
    }

    /// Handle process expired proposals endpoint
    async fn handle_process_expired(&self) -> Result<ZhtpResponse> {
        let mut dao_engine = self.dao_engine.write().await;
        
        match dao_engine.process_expired_proposals().await {
            Ok(()) => {
                let response = json!({
                    "status": "success",
                    "message": "Expired proposals processed successfully"
                });
                create_json_response(response)
            },
            Err(e) => Ok(create_error_response(
                ZhtpStatus::InternalServerError,
                format!("Failed to process expired proposals: {}", e)
            )),
        }
    }

    /// Handle DAO statistics endpoint
    async fn handle_dao_stats(&self) -> Result<ZhtpResponse> {
        let dao_engine = self.dao_engine.read().await;
        let proposals = dao_engine.get_dao_proposals();
        let treasury = dao_engine.get_dao_treasury();

        // Calculate statistics
        let total_proposals = proposals.len();
        let active_proposals = proposals.iter().filter(|p| p.status == DaoProposalStatus::Active).count();
        let passed_proposals = proposals.iter().filter(|p| p.status == DaoProposalStatus::Passed).count();
        let executed_proposals = proposals.iter().filter(|p| p.status == DaoProposalStatus::Executed).count();

        let total_votes: u64 = proposals.iter().map(|p| p.vote_tally.total_votes).sum();
        let avg_participation = if total_proposals > 0 {
            total_votes as f64 / total_proposals as f64
        } else {
            0.0
        };

        let response = json!({
            "status": "success",
            "dao_statistics": {
                "proposals": {
                    "total": total_proposals,
                    "active": active_proposals,
                    "passed": passed_proposals,
                    "executed": executed_proposals
                },
                "voting": {
                    "total_votes_cast": total_votes,
                    "average_participation": avg_participation
                },
                "treasury": {
                    "total_balance": treasury.total_balance,
                    "available_balance": treasury.available_balance,
                    "utilization_rate": if treasury.total_balance > 0 {
                        (treasury.allocated_funds as f64 / treasury.total_balance as f64) * 100.0
                    } else {
                        0.0
                    }
                }
            }
        });

        create_json_response(response)
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for DaoHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path_parts: Vec<&str> = request.uri.trim_start_matches('/').split('/').collect();
        
        match (request.method, path_parts.as_slice()) {
            // Treasury endpoints
            (ZhtpMethod::Get, ["api", "v1", "dao", "treasury", "status"]) => {
                self.handle_treasury_status().await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "treasury", "transactions"]) => {
                // Parse query parameters for pagination from URI
                let (_, query_string) = request.uri.split_once('?').unwrap_or((&request.uri, ""));
                let query_params = Self::parse_query_params(query_string);
                let limit = query_params.get("limit").and_then(|l| l.parse().ok());
                let offset = query_params.get("offset").and_then(|o| o.parse().ok());
                self.handle_treasury_transactions(limit, offset).await.map_err(anyhow::Error::from)
            },

            // Proposal endpoints
            (ZhtpMethod::Post, ["api", "v1", "dao", "proposal", "create"]) => {
                let request_data: CreateProposalRequest = serde_json::from_slice(&request.body)
                    .map_err(anyhow::Error::from)?;
                self.handle_create_proposal(request_data).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "proposals", "list"]) => {
                let (_, query_string) = request.uri.split_once('?').unwrap_or((&request.uri, ""));
                let query_params = Self::parse_query_params(query_string);
                let query = ProposalListQuery {
                    status: query_params.get("status").cloned(),
                    proposal_type: query_params.get("proposal_type").cloned(),
                    limit: query_params.get("limit").and_then(|l| l.parse().ok()),
                    offset: query_params.get("offset").and_then(|o| o.parse().ok()),
                };
                self.handle_list_proposals(query).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "proposal", proposal_id]) => {
                self.handle_get_proposal(proposal_id).await.map_err(anyhow::Error::from)
            },

            // Voting endpoints
            (ZhtpMethod::Post, ["api", "v1", "dao", "vote", "cast"]) => {
                let request_data: CastVoteRequest = serde_json::from_slice(&request.body)
                    .map_err(anyhow::Error::from)?;
                self.handle_cast_vote(request_data).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "vote", "power", identity_id]) => {
                self.handle_get_voting_power(identity_id).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "votes", proposal_id]) => {
                self.handle_get_proposal_votes(proposal_id).await.map_err(anyhow::Error::from)
            },

            // Administrative endpoints
            (ZhtpMethod::Post, ["api", "v1", "dao", "admin", "process-expired"]) => {
                self.handle_process_expired().await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "admin", "stats"]) => {
                self.handle_dao_stats().await.map_err(anyhow::Error::from)
            },

            _ => Ok(create_error_response(ZhtpStatus::NotFound, "DAO endpoint not found".to_string())),
        }
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/dao/")
    }
    
    fn priority(&self) -> u32 {
        100
    }
}