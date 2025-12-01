//! DAO Handler Module
//! 
//! Complete DAO governance system using lib-consensus DaoEngine

use std::cmp::Reverse;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, anyhow};
use serde::Deserialize;
// Removed unused Serialize
use serde_json::json;
use base64::{engine::general_purpose, Engine as _};

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Import actual DAO system components
use lib_consensus::{
    DaoEngine, DaoProposalType, DaoVoteChoice,
    // Removed unused DaoProposal, DaoVote, DaoTreasury, DaoVoteTally, TreasuryTransaction, TreasuryTransactionType
};
use lib_identity::IdentityManager;
// Removed unused Identity alias
use lib_crypto::Hash;
use lib_proofs::{ProofEnvelope, ProofType};
use lib_blockchain::{Blockchain, transaction::{DaoProposalData, DaoVoteData}};
use lib_blockchain::types::Hash as BlockchainHash;
use crate::runtime::blockchain_provider::get_global_blockchain;

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
    ownership_proof: String,
}

#[derive(Debug, Deserialize)]
struct CastVoteRequest {
    voter_identity_id: String,
    proposal_id: String,
    vote_choice: String,
    justification: Option<String>,
    ownership_proof: String,
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

    fn decode_identity_proof(&self, proof_str: &str) -> Result<ProofEnvelope> {
        let trimmed = proof_str.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Ownership proof is required"));
        }

        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed)
                .map_err(|e| anyhow!("Invalid ownership proof JSON: {}", e));
        }

        let candidates = [
            general_purpose::STANDARD.decode(trimmed).ok(),
            hex::decode(trimmed).ok(),
            Some(trimmed.as_bytes().to_vec()),
        ];

        for candidate in candidates.into_iter().flatten() {
            if let Ok(proof) = serde_json::from_slice::<ProofEnvelope>(&candidate) {
                return Ok(proof);
            }
            if let Ok(proof) = bincode::deserialize::<ProofEnvelope>(&candidate) {
                return Ok(proof);
            }
        }

        Err(anyhow!(
            "Unable to decode ownership proof; expected base64(JSON) or raw JSON text"
        ))
    }

    fn validate_identity_proof(
        &self,
        identity: &lib_identity::ZhtpIdentity,
        proof: &ProofEnvelope,
    ) -> Result<()> {
        const ALLOWED: [ProofType; 2] = [ProofType::SignaturePopV1, ProofType::DeviceDelegationV1];
        if !ALLOWED.contains(&proof.proof_type) {
            return Err(anyhow!(
                "Unexpected proof type {:?}; expected ownership proof",
                proof.proof_type
            ));
        }

        if proof.public_inputs != identity.id.as_bytes() {
            return Err(anyhow!("Ownership proof does not match identity"));
        }

        if let Some(vk) = &proof.verification_key {
            if vk != identity.public_key.as_bytes() {
                return Err(anyhow!(
                    "Ownership proof verification key does not match identity public key"
                ));
            }
        }

        if proof.proof_data.is_empty() {
            return Err(anyhow!("Ownership proof missing proof bytes"));
        }

        Ok(())
    }

    fn crypto_hash_to_blockchain(hash: &Hash) -> BlockchainHash {
        BlockchainHash::from_slice(hash.as_bytes())
    }

    fn blockchain_hash_to_string(hash: &BlockchainHash) -> String {
        hex::encode(hash.as_bytes())
    }

    fn classify_proposal_status(blockchain: &Blockchain, proposal: &DaoProposalData) -> String {
        if blockchain
            .get_dao_executions()
            .into_iter()
            .any(|exec| exec.proposal_id == proposal.proposal_id)
        {
            return "Executed".to_string();
        }

        let voting_end = proposal.created_at_height + proposal.voting_period_blocks;
        if blockchain.height < voting_end {
            return "Active".to_string();
        }

        if let Ok(true) = blockchain.has_proposal_passed(&proposal.proposal_id, proposal.quorum_required as u32) {
            "Passed".to_string()
        } else if let Ok(false) = blockchain.has_proposal_passed(&proposal.proposal_id, proposal.quorum_required as u32) {
            "Failed".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn build_vote_summary(blockchain: &Blockchain, proposal_id: &BlockchainHash) -> serde_json::Value {
        let (yes_votes, no_votes, abstain_votes, total_power) = blockchain.tally_dao_votes(proposal_id);
        let approval_percentage = if total_power > 0 {
            (yes_votes.saturating_mul(100)) / total_power
        } else {
            0
        };
        json!({
            "total_votes": total_power,
            "yes_votes": yes_votes,
            "no_votes": no_votes,
            "abstain_votes": abstain_votes,
            "approval_percentage": approval_percentage
        })
    }

    /// Handle treasury status endpoint
    async fn handle_treasury_status(&self) -> Result<ZhtpResponse> {
        let blockchain = get_global_blockchain().await?;
        let blockchain = blockchain.read().await;

        let treasury_balance = blockchain.get_dao_treasury_balance().unwrap_or(0);
        let treasury_wallet = blockchain.get_dao_treasury_wallet().ok();
        let treasury_wallet_id = treasury_wallet
            .map(|wallet| hex::encode(wallet.wallet_id.as_bytes()));

        let response = json!({
            "status": "success",
            "treasury": {
                "wallet_id": treasury_wallet_id,
                "total_balance": treasury_balance,
                "available_balance": treasury_balance,
                "allocated_funds": 0u64,
                "reserved_funds": 0u64,
                "transaction_count": blockchain.get_dao_executions().len(),
                "last_updated_height": blockchain.height,
            }
        });

        create_json_response(response)
    }

    /// Handle treasury transactions endpoint
    async fn handle_treasury_transactions(&self, limit: Option<usize>, offset: Option<usize>) -> Result<ZhtpResponse> {
        let blockchain = get_global_blockchain().await?;
        let blockchain = blockchain.read().await;

        let limit = limit.unwrap_or(50).min(100);
        let offset = offset.unwrap_or(0);

        let mut executions = blockchain.get_dao_executions();
        executions.sort_by_key(|exec| exec.executed_at);

        let total_transactions = executions.len();
        let transactions: Vec<_> = executions
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|exec| {
                json!({
                    "proposal_id": Self::blockchain_hash_to_string(&exec.proposal_id),
                    "executor": exec.executor,
                    "execution_type": exec.execution_type,
                    "recipient": exec.recipient,
                    "amount": exec.amount,
                    "executed_at": exec.executed_at,
                    "executed_at_height": exec.executed_at_height,
                })
            })
            .collect();

        let response = json!({
            "status": "success",
            "total_transactions": total_transactions,
            "returned_count": transactions.len(),
            "offset": offset,
            "limit": limit,
            "transactions": transactions
        });

        create_json_response(response)
    }

    /// Handle create proposal endpoint
    async fn handle_create_proposal(&self, request_data: CreateProposalRequest) -> Result<ZhtpResponse> {
        let proposer_id = Self::string_to_hash(&request_data.proposer_identity_id)?;
        let ownership_proof = match self.decode_identity_proof(&request_data.ownership_proof) {
            Ok(proof) => proof,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid ownership proof: {}", e)
                ));
            }
        };

        let identity_manager = self.identity_manager.read().await;
        let proposer_identity = match identity_manager.get_identity(&proposer_id) {
            Some(identity) => identity,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Proposer identity not found".to_string()
                ));
            }
        };

        if let Err(err) = self.validate_identity_proof(proposer_identity, &ownership_proof) {
            return Ok(create_error_response(
                ZhtpStatus::Unauthorized,
                format!("Ownership proof validation failed: {}", err)
            ));
        }
        drop(identity_manager);

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
        let blockchain = get_global_blockchain().await?;
        let blockchain = blockchain.read().await;

        let mut proposals = blockchain.get_dao_proposals();
        let total_proposals = proposals.len();

        // Sort newest first for consistent pagination
        proposals.sort_by_key(|proposal| Reverse(proposal.created_at));

        if let Some(status_filter) = &query.status {
            let expected = status_filter.to_lowercase();
            proposals.retain(|proposal| {
                Self::classify_proposal_status(&blockchain, proposal)
                    .to_lowercase()
                    == expected
            });
        }

        if let Some(type_filter) = &query.proposal_type {
            let expected = type_filter.to_lowercase();
            proposals.retain(|proposal| proposal.proposal_type.to_lowercase() == expected);
        }

        let limit = query.limit.unwrap_or(20).min(100);
        let offset = query.offset.unwrap_or(0);

        let paginated: Vec<_> = proposals
            .iter()
            .skip(offset)
            .take(limit)
            .map(|proposal| {
                let status = Self::classify_proposal_status(&blockchain, proposal);
                let vote_summary = Self::build_vote_summary(&blockchain, &proposal.proposal_id);
                json!({
                    "id": Self::blockchain_hash_to_string(&proposal.proposal_id),
                    "title": proposal.title,
                    "description": proposal.description,
                    "proposer": proposal.proposer,
                    "proposal_type": proposal.proposal_type,
                    "status": status,
                    "created_at": proposal.created_at,
                    "created_at_height": proposal.created_at_height,
                    "voting_period_blocks": proposal.voting_period_blocks,
                    "voting_end_height": proposal.created_at_height + proposal.voting_period_blocks,
                    "quorum_required": proposal.quorum_required,
                    "execution_params": proposal.execution_params.as_ref().map(hex::encode),
                    "vote_summary": vote_summary
                })
            })
            .collect();

        let response = json!({
            "status": "success",
            "total_proposals": total_proposals,
            "filtered_count": proposals.len(),
            "returned_count": paginated.len(),
            "offset": offset,
            "limit": limit,
            "proposals": paginated
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

        let blockchain = get_global_blockchain().await?;
        let blockchain = blockchain.read().await;
        let bc_proposal_id = Self::crypto_hash_to_blockchain(&proposal_id);

        match blockchain.get_dao_proposal(&bc_proposal_id) {
            Some(proposal) => {
                let status = Self::classify_proposal_status(&blockchain, &proposal);
                let vote_summary = Self::build_vote_summary(&blockchain, &proposal.proposal_id);
                let detailed_votes = blockchain
                    .get_dao_votes_for_proposal(&proposal.proposal_id)
                    .into_iter()
                    .map(|vote| {
                        json!({
                            "vote_id": Self::blockchain_hash_to_string(&vote.vote_id),
                            "voter": vote.voter,
                            "vote_choice": vote.vote_choice,
                            "voting_power": vote.voting_power,
                            "justification": vote.justification,
                            "timestamp": vote.timestamp
                        })
                    })
                    .collect::<Vec<_>>();

                let response = json!({
                    "status": "success",
                    "proposal": {
                        "id": Self::blockchain_hash_to_string(&proposal.proposal_id),
                        "title": proposal.title,
                        "description": proposal.description,
                        "proposer": proposal.proposer,
                        "proposal_type": proposal.proposal_type,
                        "status": status,
                        "created_at": proposal.created_at,
                        "created_at_height": proposal.created_at_height,
                        "voting_period_blocks": proposal.voting_period_blocks,
                        "voting_end_height": proposal.created_at_height + proposal.voting_period_blocks,
                        "quorum_required": proposal.quorum_required,
                        "execution_params": proposal.execution_params.as_ref().map(hex::encode),
                        "vote_summary": vote_summary,
                        "votes": detailed_votes
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
        let voter_id = Self::string_to_hash(&request_data.voter_identity_id)?;
        let ownership_proof = match self.decode_identity_proof(&request_data.ownership_proof) {
            Ok(proof) => proof,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid ownership proof: {}", e)
                ));
            }
        };

        let identity_manager = self.identity_manager.read().await;
        let voter_identity = match identity_manager.get_identity(&voter_id) {
            Some(identity) => identity,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Voter identity not found".to_string()
                ));
            }
        };

        if let Err(err) = self.validate_identity_proof(voter_identity, &ownership_proof) {
            return Ok(create_error_response(
                ZhtpStatus::Unauthorized,
                format!("Ownership proof validation failed: {}", err)
            ));
        }
        drop(identity_manager);

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

        let blockchain = get_global_blockchain().await?;
        let blockchain = blockchain.read().await;
        let bc_proposal_id = Self::crypto_hash_to_blockchain(&proposal_id);
        let proposal = match blockchain.get_dao_proposal(&bc_proposal_id) {
            Some(proposal) => proposal,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    "Proposal not found".to_string()
                ));
            }
        };

        if Self::classify_proposal_status(&blockchain, &proposal) != "Active" {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Proposal is no longer accepting votes".to_string()
            ));
        }

        let voter_hex = Self::hash_to_string(&voter_id);
        if blockchain
            .get_dao_votes_for_proposal(&proposal.proposal_id)
            .into_iter()
            .any(|vote| vote.voter.eq_ignore_ascii_case(&voter_hex))
        {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Identity has already voted on this proposal".to_string()
            ));
        }

        let voting_power = blockchain.calculate_user_voting_power(&voter_id);
        drop(blockchain);

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
                    "voting_power": voting_power,
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

        let blockchain = get_global_blockchain().await?;
        let blockchain = blockchain.read().await;
        let voting_power = blockchain.calculate_user_voting_power(&identity_id);

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

        let blockchain = get_global_blockchain().await?;
        let blockchain = blockchain.read().await;
        let bc_proposal_id = Self::crypto_hash_to_blockchain(&proposal_id);

        let proposal = match blockchain.get_dao_proposal(&bc_proposal_id) {
            Some(proposal) => proposal,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    "Proposal not found".to_string()
                ));
            }
        };

        let votes = blockchain.get_dao_votes_for_proposal(&proposal.proposal_id);
        let vote_summary = Self::build_vote_summary(&blockchain, &proposal.proposal_id);

        let response = json!({
            "status": "success",
            "proposal_id": proposal_id_str,
            "vote_summary": vote_summary,
            "votes": votes.into_iter().map(|vote| json!({
                "vote_id": Self::blockchain_hash_to_string(&vote.vote_id),
                "voter": vote.voter,
                "vote_choice": vote.vote_choice,
                "voting_power": vote.voting_power,
                "timestamp": vote.timestamp,
                "justification": vote.justification
            })).collect::<Vec<_>>()
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
        let blockchain = get_global_blockchain().await?;
        let blockchain = blockchain.read().await;
        let proposals = blockchain.get_dao_proposals();

        let mut active = 0usize;
        let mut passed = 0usize;
        let mut executed = 0usize;
        let mut failed = 0usize;
        let mut total_votes = 0u64;

        for proposal in &proposals {
            match Self::classify_proposal_status(&blockchain, proposal).as_str() {
                "Active" => active += 1,
                "Passed" => passed += 1,
                "Executed" => executed += 1,
                "Failed" => failed += 1,
                _ => {}
            }

            let (_yes, _no, _abstain, total_power) = blockchain.tally_dao_votes(&proposal.proposal_id);
            total_votes += total_power;
        }

        let total_proposals = proposals.len();
        let avg_participation = if total_proposals > 0 {
            total_votes as f64 / total_proposals as f64
        } else {
            0.0
        };

        let treasury_balance = blockchain.get_dao_treasury_balance().unwrap_or(0);
        let allocated = 0f64; // Placeholder until treasury allocations tracked on-chain
        let utilization_rate = if treasury_balance > 0 {
            allocated / treasury_balance as f64 * 100.0
        } else {
            0.0
        };

        let response = json!({
            "status": "success",
            "dao_statistics": {
                "proposals": {
                    "total": total_proposals,
                    "active": active,
                    "passed": passed,
                    "executed": executed,
                    "failed": failed
                },
                "voting": {
                    "total_votes_cast": total_votes,
                    "average_participation": avg_participation
                },
                "treasury": {
                    "total_balance": treasury_balance,
                    "available_balance": treasury_balance,
                    "utilization_rate": utilization_rate
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