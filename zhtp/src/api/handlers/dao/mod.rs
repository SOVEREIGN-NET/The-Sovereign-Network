//! DAO Handler Module
//! 
//! DAO governance handler backed by canonical blockchain state

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Import actual DAO system components
use lib_consensus::{
    DaoProposalType, DaoVoteChoice,
};
use lib_blockchain::transaction::{DaoExecutionData, DaoProposalData, DaoVoteData, Transaction};
use lib_blockchain::integration::crypto_integration::{Signature, SignatureAlgorithm};
use lib_blockchain::types::Hash as BcHash;
use lib_identity::IdentityManager;
use lib_crypto::Hash as CryptoHash;

use crate::session_manager::SessionManager;

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

/// Helper to extract client IP from request
fn extract_client_ip(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("X-Real-IP")
        .or_else(|| request.headers.get("X-Forwarded-For").and_then(|f| f.split(',').next().map(|s| s.trim().to_string())))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Helper to extract user agent from request
fn extract_user_agent(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string())
}

fn validate_did_format(did: &str) -> Result<()> {
    if !did.starts_with("did:zhtp:") && !did.starts_with("did:") {
        return Err(anyhow::anyhow!("Invalid DID format"));
    }
    if did.len() < 10 || did.len() > 200 {
        return Err(anyhow::anyhow!("DID length must be between 10 and 200 characters"));
    }
    Ok(())
}

fn validate_delegate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow::anyhow!("Name cannot be empty"));
    }
    if name.len() > 100 {
        return Err(anyhow::anyhow!("Name must be 100 characters or less"));
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c.is_whitespace() || c == '-' || c == '_' || c == '.' || c == '\'') {
        return Err(anyhow::anyhow!("Name contains invalid characters"));
    }
    Ok(())
}

fn validate_delegate_bio(bio: &str) -> Result<()> {
    if bio.len() > 500 {
        return Err(anyhow::anyhow!("Bio must be 500 characters or less"));
    }
    Ok(())
}

fn validate_spending_proposal(title: &str, description: &str, recipient: &str, amount: u64) -> Result<()> {
    if title.is_empty() || title.len() > 200 {
        return Err(anyhow::anyhow!("Title must be 1-200 characters"));
    }
    if description.is_empty() || description.len() > 2000 {
        return Err(anyhow::anyhow!("Description must be 1-2000 characters"));
    }
    validate_did_format(recipient)?;
    if amount == 0 {
        return Err(anyhow::anyhow!("Amount must be greater than 0"));
    }
    if amount > 1_000_000_000 {
        return Err(anyhow::anyhow!("Amount too large (max 1 billion)"));
    }
    Ok(())
}

/// Request types for DAO operations
#[derive(Debug, Deserialize)]
struct CreateProposalRequest {
    proposer_identity_id: Option<String>,
    title: String,
    description: String,
    proposal_type: Option<String>,
    voting_period_days: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct CastVoteRequest {
    voter_identity_id: Option<String>,
    proposal_id: String,
    vote_choice: Option<String>,
    choice: Option<String>,
    justification: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProposalListQuery {
    status: Option<String>,
    proposal_type: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RegisterDelegateRequest {
    user_did: String,
    delegate_info: DelegateInfo,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DelegateInfo {
    name: String,
    bio: String,
}

#[derive(Debug, Deserialize)]
struct RevokeDelegateRequest {
    user_did: String,
}

/// Spending proposal request (Issue #118)
#[derive(Debug, Deserialize)]
struct SpendingProposalRequest {
    title: String,
    amount: u64,
    recipient: String,
    description: String,
}

/// DAO handler backed by canonical blockchain state
pub struct DaoHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
}

impl DaoHandler {
    const DAO_DELEGATE_REGISTER_EXEC: &'static str = "dao_delegate_register_v1";
    const DAO_DELEGATE_REVOKE_EXEC: &'static str = "dao_delegate_revoke_v1";

    pub fn new(
        identity_manager: Arc<RwLock<IdentityManager>>,
        session_manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            identity_manager,
            session_manager,
        }
    }

    async fn get_blockchain(&self) -> Result<Arc<RwLock<lib_blockchain::Blockchain>>> {
        crate::runtime::blockchain_provider::get_global_blockchain().await
            .map_err(|e| anyhow::anyhow!("Failed to access blockchain: {}", e))
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
            "difficulty_parameter_update" => Ok(DaoProposalType::DifficultyParameterUpdate),
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

    /// Convert blockchain hash to hex string
    fn hash_to_string(hash: &BcHash) -> String {
        hex::encode(hash.as_bytes())
    }

    /// Parse hex string to blockchain Hash
    fn string_to_bc_hash(hash_str: &str) -> Result<BcHash> {
        BcHash::from_hex(hash_str)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))
    }

    /// Parse hex string to identity hash (lib-crypto)
    fn string_to_identity_hash(hash_str: &str) -> Result<CryptoHash> {
        let bytes = hex::decode(hash_str)
            .map_err(|e| anyhow::anyhow!("Invalid identity ID hex: {}", e))?;
        Ok(CryptoHash::from_bytes(&bytes))
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
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let treasury_balance = blockchain.get_dao_treasury_balance().unwrap_or(0);
        let treasury_wallet = blockchain.get_dao_treasury_wallet_id().cloned();
        let execution_count = blockchain.get_dao_executions().len();

        let response = json!({
            "status": "success",
            "treasury": {
                "total_balance": treasury_balance,
                "available_balance": treasury_balance,
                "allocated_funds": 0u64,
                "reserved_funds": 0u64,
                "transaction_count": execution_count,
                "annual_budgets_count": 0u64,
                "treasury_wallet_id": treasury_wallet
            }
        });

        create_json_response(response)
    }

    /// Handle treasury transactions endpoint
    async fn handle_treasury_transactions(&self, limit: Option<usize>, offset: Option<usize>) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let executions = blockchain.get_dao_executions();

        let limit = limit.unwrap_or(50).min(100); // Max 100 transactions per request
        let offset = offset.unwrap_or(0);

        let transactions: Vec<_> = executions
            .iter()
            .skip(offset)
            .take(limit)
            .map(|exec| json!({
                "id": Self::hash_to_string(&exec.proposal_id),
                "transaction_type": exec.execution_type,
                "amount": exec.amount,
                "recipient": exec.recipient,
                "source": exec.executor,
                "proposal_id": Self::hash_to_string(&exec.proposal_id),
                "timestamp": exec.executed_at,
                "description": format!("Execution for proposal {}", Self::hash_to_string(&exec.proposal_id))
            }))
            .collect();

        let response = json!({
            "status": "success",
            "total_transactions": executions.len(),
            "returned_count": transactions.len(),
            "offset": offset,
            "limit": limit,
            "transactions": transactions
        });

        create_json_response(response)
    }

    /// Returns the minimum percentage of voting power required for the given proposal type to pass.
    fn proposal_quorum_required(proposal_type: &DaoProposalType) -> u8 {
        match proposal_type {
            DaoProposalType::TreasuryAllocation => 25,
            DaoProposalType::WelfareAllocation => 22,
            DaoProposalType::ProtocolUpgrade => 30,
            DaoProposalType::UbiDistribution => 20,
            DaoProposalType::DifficultyParameterUpdate => 30,
            _ => 10,
        }
    }

    /// Converts a `DaoProposalType` enum value to its canonical string representation
    /// used for storage in blockchain transactions.
    fn proposal_type_to_string(proposal_type: &DaoProposalType) -> String {
        match proposal_type {
            DaoProposalType::UbiDistribution => "ubi_distribution".to_string(),
            DaoProposalType::ProtocolUpgrade => "protocol_upgrade".to_string(),
            DaoProposalType::TreasuryAllocation => "treasury_allocation".to_string(),
            DaoProposalType::ValidatorUpdate => "validator_update".to_string(),
            DaoProposalType::EconomicParams => "economic_params".to_string(),
            DaoProposalType::GovernanceRules => "governance_rules".to_string(),
            DaoProposalType::FeeStructure => "fee_structure".to_string(),
            DaoProposalType::Emergency => "emergency".to_string(),
            DaoProposalType::CommunityFunding => "community_funding".to_string(),
            DaoProposalType::ResearchGrants => "research_grants".to_string(),
            DaoProposalType::DifficultyParameterUpdate => "difficulty_parameter_update".to_string(),
            DaoProposalType::WelfareAllocation => "welfare_allocation".to_string(),
            DaoProposalType::MintBurnAuthorization => "mint_burn_authorization".to_string(),
        }
    }

    /// Deterministically generates a proposal ID by concatenating and hashing the provided byte slices.
    ///
    /// All slices in `parts` are appended in order into a single byte buffer, which is then
    /// hashed using BLAKE3 to produce a stable `BcHash` identifier for the proposal.
    fn proposal_id_from_parts(parts: &[&[u8]]) -> BcHash {
        let mut bytes = Vec::new();
        for p in parts {
            bytes.extend_from_slice(p);
        }
        BcHash::from_slice(&lib_crypto::hash_blake3(&bytes))
    }

    async fn handle_create_proposal_from_identity(
        &self,
        authenticated_identity_id: CryptoHash,
        request_data: CreateProposalRequest,
    ) -> Result<ZhtpResponse> {
        let proposer_hex = hex::encode(authenticated_identity_id.as_bytes());
        if let Some(proposer_identity_id) = request_data.proposer_identity_id.as_ref() {
            if proposer_identity_id.to_lowercase() != proposer_hex {
                return Ok(create_error_response(
                    ZhtpStatus::Forbidden,
                    "proposer_identity_id must match authenticated identity".to_string(),
                ));
            }
        }

        if request_data.title.trim().is_empty() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Proposal title cannot be empty".to_string(),
            ));
        }
        if request_data.description.trim().is_empty() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Proposal description cannot be empty".to_string(),
            ));
        }

        let proposal_type_str = request_data
            .proposal_type
            .clone()
            .unwrap_or_else(|| "community_funding".to_string());
        let voting_period_days = request_data.voting_period_days.unwrap_or(7);
        if voting_period_days == 0 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "voting_period_days must be greater than 0".to_string(),
            ));
        }

        let proposal_type = match Self::parse_proposal_type(&proposal_type_str) {
            Ok(pt) => pt,
            Err(_) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid proposal type: {}", proposal_type_str),
                ))
            }
        };

        let identity_manager = self.identity_manager.read().await;
        let proposer_identity = match identity_manager.get_identity(&authenticated_identity_id).cloned() {
            Some(i) => i,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Proposer identity not found".to_string(),
                ))
            }
        };
        drop(identity_manager);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("System time error: {}", e))?
            .as_secs();
        let blockchain_arc = self.get_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;
        let current_height = blockchain.get_height();

        let proposal_id = BcHash::from_slice(&lib_crypto::hash_blake3(&[
            authenticated_identity_id.as_bytes(),
            request_data.title.as_bytes(),
            request_data.description.as_bytes(),
            Self::proposal_type_to_string(&proposal_type).as_bytes(),
            &now.to_le_bytes(),
        ].concat()));

        let proposal_data = DaoProposalData {
            proposal_id,
            proposer: proposer_identity.did.clone(),
            title: request_data.title.clone(),
            description: request_data.description.clone(),
            proposal_type: Self::proposal_type_to_string(&proposal_type),
            voting_period_blocks: (voting_period_days as u64).saturating_mul(14_400),
            quorum_required: Self::proposal_quorum_required(&proposal_type),
            execution_params: None,
            created_at: now,
            created_at_height: current_height,
        };

        let mut proposal_tx = Transaction::new_dao_proposal(
            proposal_data,
            Vec::new(),
            Vec::new(),
            0,
            Signature {
                signature: Vec::new(),
                public_key: proposer_identity.public_key.clone(),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: now,
            },
            format!("dao:proposal:{}", request_data.title).into_bytes(),
        );

        if let Some(private_key) = proposer_identity.private_key.clone() {
            let keypair = lib_crypto::KeyPair {
                public_key: proposer_identity.public_key.clone(),
                private_key,
            };
            let sig = lib_crypto::sign_message(&keypair, proposal_tx.signing_hash().as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to sign DAO proposal tx: {}", e))?;
            proposal_tx.signature.signature = sig.signature;
        } else {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Proposer private key unavailable on node".to_string(),
            ));
        }

        blockchain.add_pending_transaction(proposal_tx)
            .map_err(|e| anyhow::anyhow!("Failed to submit proposal transaction: {}", e))?;

        let response = json!({
            "status": "success",
            "proposal_id": Self::hash_to_string(&proposal_id),
            "title": request_data.title,
            "proposal_type": proposal_type_str,
            "voting_period_days": voting_period_days,
            "message": "Proposal submitted to mempool"
        });
        create_json_response(response)
    }

    async fn submit_delegate_execution(
        &self,
        authenticated_identity_id: CryptoHash,
        user_did: String,
        execution_type: &str,
        metadata: serde_json::Value,
    ) -> Result<ZhtpResponse> {
        let identity_manager = self.identity_manager.read().await;
        let identity = match identity_manager.get_identity(&authenticated_identity_id).cloned() {
            Some(i) => i,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Authenticated identity not found".to_string(),
                ))
            }
        };
        drop(identity_manager);

        if identity.did != user_did {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Cannot mutate delegate state for another identity".to_string(),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("System time error: {}", e))?
            .as_secs();
        let blockchain_arc = self.get_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;
        let height = blockchain.get_height();
        let proposal_id = Self::proposal_id_from_parts(&[
            execution_type.as_bytes(),
            user_did.as_bytes(),
            &now.to_le_bytes(),
        ]);
        let metadata_bytes = serde_json::to_vec(&metadata)?;

        let execution_data = DaoExecutionData {
            proposal_id,
            executor: identity.did.clone(),
            execution_type: execution_type.to_string(),
            recipient: Some(user_did.clone()),
            amount: None,
            executed_at: now,
            executed_at_height: height,
            multisig_signatures: vec![metadata_bytes],
        };

        let mut tx = Transaction::new_dao_execution(
            execution_data,
            Vec::new(),
            Vec::new(),
            0,
            Signature {
                signature: Vec::new(),
                public_key: identity.public_key.clone(),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: now,
            },
            format!("dao:delegate:{}", execution_type).into_bytes(),
        );

        if let Some(private_key) = identity.private_key.clone() {
            let keypair = lib_crypto::KeyPair {
                public_key: identity.public_key.clone(),
                private_key,
            };
            let sig = lib_crypto::sign_message(&keypair, tx.signing_hash().as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to sign delegate execution tx: {}", e))?;
            tx.signature.signature = sig.signature;
        } else {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Delegate private key unavailable on node".to_string(),
            ));
        }

        blockchain.add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("Failed to submit delegate execution transaction: {}", e))?;

        create_json_response(json!({
            "status": "success",
            "delegate_event_id": Self::hash_to_string(&proposal_id),
            "did": user_did,
            "execution_type": execution_type,
            "message": "Delegate operation submitted to mempool"
        }))
    }

    /// Handle create proposal endpoint
    async fn handle_create_proposal(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let session_token = match request.headers.get("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
            Some(token) => token,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Missing or invalid Authorization header".to_string(),
                ));
            }
        };

        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);
        let session = self.session_manager
            .validate_session(&session_token, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

        let request_data: CreateProposalRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;
        self.handle_create_proposal_from_identity(session.identity_id, request_data).await
    }

    /// Handle list proposals endpoint
    async fn handle_list_proposals(&self, query: ProposalListQuery) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let all_proposals = blockchain.get_dao_proposals();
        let all_executions = blockchain.get_dao_executions();

        let limit = query.limit.unwrap_or(20).min(100); // Max 100 proposals per request
        let offset = query.offset.unwrap_or(0);

        let mut filtered_proposals: Vec<_> = all_proposals.iter().collect();

        // Filter by status if provided
        if let Some(status_filter) = &query.status {
            let wanted = status_filter.trim().to_lowercase();
            const SUPPORTED_STATUS_FILTERS: &[&str] = &["active", "passed", "executed"];
            if !SUPPORTED_STATUS_FILTERS.contains(&wanted.as_str()) {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!(
                        "Unsupported status filter '{}'. Supported values: {}",
                        status_filter,
                        SUPPORTED_STATUS_FILTERS.join(", ")
                    ),
                ));
            }
            filtered_proposals.retain(|p| {
                let executed = all_executions.iter().any(|e| e.proposal_id == p.proposal_id);
                let passed = blockchain.has_proposal_passed(&p.proposal_id, p.quorum_required as u32).unwrap_or(false);
                let status = if executed { "executed" } else if passed { "passed" } else { "active" };
                status == wanted
            });
        }

        // Filter by proposal type if provided
        if let Some(type_filter) = &query.proposal_type {
            let wanted = type_filter.to_lowercase();
            filtered_proposals.retain(|p| p.proposal_type.to_lowercase() == wanted);
        }

        // Apply pagination
        let paginated_proposals: Vec<_> = filtered_proposals
            .iter()
            .skip(offset)
            .take(limit)
            .map(|proposal| {
                let (yes_votes, no_votes, abstain_votes, total_votes) =
                    blockchain.tally_dao_votes(&proposal.proposal_id);
                let approval_percentage = if total_votes > 0 {
                    (yes_votes as f64 * 100.0) / total_votes as f64
                } else {
                    0.0
                };
                let quorum_percentage = approval_percentage;
                let executed = all_executions.iter().any(|e| e.proposal_id == proposal.proposal_id);
                let passed = blockchain.has_proposal_passed(&proposal.proposal_id, proposal.quorum_required as u32).unwrap_or(false);
                let status = if executed { "executed" } else if passed { "passed" } else { "active" };

                json!({
                    "id": Self::hash_to_string(&proposal.proposal_id),
                    "title": proposal.title,
                    "description": proposal.description,
                    "proposer": proposal.proposer,
                    "proposal_type": proposal.proposal_type,
                    "status": status,
                    "voting_start_time": proposal.created_at,
                    "voting_end_time": proposal.created_at + proposal.voting_period_blocks.saturating_mul(6),
                    "quorum_required": proposal.quorum_required,
                    "created_at": proposal.created_at,
                    "vote_tally": {
                        "total_votes": total_votes,
                        "yes_votes": yes_votes,
                        "no_votes": no_votes,
                        "abstain_votes": abstain_votes,
                        "approval_percentage": approval_percentage,
                        "quorum_percentage": quorum_percentage
                    }
                })
            })
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
        let proposal_id = match Self::string_to_bc_hash(proposal_id_str) {
            Ok(id) => id,
            Err(_) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Invalid proposal ID format".to_string(),
                ))
            }
        };

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        match blockchain.get_dao_proposal(&proposal_id) {
            Some(proposal) => {
                let (yes_votes, no_votes, abstain_votes, total_votes) =
                    blockchain.tally_dao_votes(&proposal.proposal_id);
                let approval_percentage = if total_votes > 0 {
                    (yes_votes as f64 * 100.0) / total_votes as f64
                } else {
                    0.0
                };
                let executions = blockchain.get_dao_executions();
                let executed = executions.iter().any(|e| e.proposal_id == proposal.proposal_id);
                let passed = blockchain
                    .has_proposal_passed(&proposal.proposal_id, proposal.quorum_required as u32)
                    .unwrap_or(false);
                let status = if executed { "executed" } else if passed { "passed" } else { "active" };

                let response = json!({
                    "status": "success",
                    "proposal": {
                        "id": Self::hash_to_string(&proposal.proposal_id),
                        "title": proposal.title,
                        "description": proposal.description,
                        "proposer": proposal.proposer,
                        "proposal_type": proposal.proposal_type,
                        "status": status,
                        "voting_start_time": proposal.created_at,
                        "voting_end_time": proposal.created_at + proposal.voting_period_blocks.saturating_mul(6),
                        "quorum_required": proposal.quorum_required,
                        "created_at": proposal.created_at,
                        "created_at_height": proposal.created_at_height,
                        "vote_tally": {
                            "total_votes": total_votes,
                            "yes_votes": yes_votes,
                            "no_votes": no_votes,
                            "abstain_votes": abstain_votes,
                            "total_eligible_power": total_votes,
                            "weighted_yes": yes_votes,
                            "weighted_no": no_votes,
                            "weighted_abstain": abstain_votes,
                            "approval_percentage": approval_percentage,
                            "quorum_percentage": approval_percentage,
                            "weighted_approval_percentage": approval_percentage
                        }
                    }
                });
                create_json_response(response)
            }
            None => Ok(create_error_response(
                ZhtpStatus::NotFound,
                "Proposal not found".to_string(),
            )),
        }
    }

    /// Handle cast vote endpoint
    async fn handle_cast_vote(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let session_token = match request.headers.get("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
            Some(token) => token,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Missing or invalid Authorization header".to_string(),
                ));
            }
        };

        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);
        let session = self.session_manager
            .validate_session(&session_token, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;
        let authenticated_identity_id = session.identity_id;
        let authenticated_hex = hex::encode(authenticated_identity_id.as_bytes());

        let request_data: CastVoteRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;
        if let Some(voter_identity_id) = request_data.voter_identity_id.as_ref() {
            if voter_identity_id.to_lowercase() != authenticated_hex {
                return Ok(create_error_response(
                    ZhtpStatus::Forbidden,
                    "voter_identity_id must match authenticated identity".to_string(),
                ));
            }
        }

        let proposal_id = match Self::string_to_bc_hash(&request_data.proposal_id) {
            Ok(id) => id,
            Err(_) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Invalid proposal ID format".to_string(),
                ))
            }
        };

        let vote_choice_raw = request_data
            .vote_choice
            .as_deref()
            .or(request_data.choice.as_deref())
            .ok_or_else(|| anyhow::anyhow!("Missing vote_choice (or legacy choice) field"))?;
        let vote_choice = match Self::parse_vote_choice(vote_choice_raw) {
            Ok(choice) => choice,
            Err(_) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid vote choice: {}", vote_choice_raw),
                ))
            }
        };

        let identity_manager = self.identity_manager.read().await;
        let voter_identity = match identity_manager.get_identity(&authenticated_identity_id).cloned() {
            Some(i) => i,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Voter identity not found".to_string(),
                ))
            }
        };
        drop(identity_manager);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("System time error: {}", e))?
            .as_secs();

        let blockchain_arc = self.get_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;
        if blockchain.get_dao_proposal(&proposal_id).is_none() {
            return Ok(create_error_response(
                ZhtpStatus::NotFound,
                "Proposal not found".to_string(),
            ));
        }

        let vote_choice_str = match vote_choice {
            DaoVoteChoice::Yes => "Yes".to_string(),
            DaoVoteChoice::No => "No".to_string(),
            DaoVoteChoice::Abstain => "Abstain".to_string(),
            DaoVoteChoice::Delegate(delegate) => format!("Delegate({})", hex::encode(delegate.as_bytes())),
        };

        let already_voted_confirmed = blockchain
            .get_dao_votes_for_proposal(&proposal_id)
            .iter()
            .any(|v| v.voter == voter_identity.did);
        let already_voted_pending = blockchain.pending_transactions.iter().any(|tx| {
            tx.transaction_type == lib_blockchain::TransactionType::DaoVote
                && tx.dao_vote_data.as_ref().map(|v| v.proposal_id == proposal_id && v.voter == voter_identity.did).unwrap_or(false)
        });
        if already_voted_confirmed || already_voted_pending {
            return Ok(create_error_response(
                ZhtpStatus::Conflict,
                "User has already voted on this proposal".to_string(),
            ));
        }

        let vote_id = BcHash::from_slice(&lib_crypto::hash_blake3(&[
            proposal_id.as_bytes(),
            authenticated_identity_id.as_bytes(),
            vote_choice_str.as_bytes(),
            &now.to_le_bytes(),
        ].concat()));

        let vote_data = DaoVoteData {
            vote_id,
            proposal_id,
            voter: voter_identity.did.clone(),
            vote_choice: vote_choice_str,
            voting_power: 1,
            justification: request_data.justification.clone(),
            timestamp: now,
        };

        let mut vote_tx = Transaction::new_dao_vote(
            vote_data,
            Vec::new(),
            Vec::new(),
            0,
            Signature {
                signature: Vec::new(),
                public_key: voter_identity.public_key.clone(),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: now,
            },
            b"dao:vote".to_vec(),
        );

        if let Some(private_key) = voter_identity.private_key.clone() {
            let keypair = lib_crypto::KeyPair {
                public_key: voter_identity.public_key.clone(),
                private_key,
            };
            let sig = lib_crypto::sign_message(&keypair, vote_tx.signing_hash().as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to sign DAO vote tx: {}", e))?;
            vote_tx.signature.signature = sig.signature;
        } else {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Voter private key unavailable on node".to_string(),
            ));
        }

        blockchain.add_pending_transaction(vote_tx)
            .map_err(|e| anyhow::anyhow!("Failed to submit vote transaction: {}", e))?;

        let response = json!({
            "status": "success",
            "vote_id": Self::hash_to_string(&vote_id),
            "proposal_id": request_data.proposal_id,
            "vote_choice": vote_choice_raw,
            "voter_id": authenticated_hex,
            "message": "Vote submitted to mempool"
        });
        create_json_response(response)
    }

    /// Handle get voting power endpoint
    async fn handle_get_voting_power(&self, identity_id_str: &str) -> Result<ZhtpResponse> {
        let identity_id = match Self::string_to_identity_hash(identity_id_str) {
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

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let voting_power = blockchain.calculate_user_voting_power(&identity_id);

        let response = json!({
            "status": "success",
            "identity_id": identity_id_str,
            "voting_power": voting_power,
            "power_breakdown": {
                "base_citizen_power": voting_power,
                "reputation_multiplier": 1.0,
                "staked_tokens_power": 0,
                "delegated_power": voting_power.saturating_sub(1)
            }
        });

        create_json_response(response)
    }

    /// Handle get votes for proposal endpoint
    async fn handle_get_proposal_votes(&self, proposal_id_str: &str) -> Result<ZhtpResponse> {
        let proposal_id = match Self::string_to_bc_hash(proposal_id_str) {
            Ok(id) => id,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Invalid proposal ID format".to_string()
            )),
        };

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        if blockchain.get_dao_proposal(&proposal_id).is_none() {
            return Ok(create_error_response(
                ZhtpStatus::NotFound,
                "Proposal not found".to_string()
            ));
        }

        let votes = blockchain.get_dao_votes_for_proposal(&proposal_id);
        let (yes_votes, no_votes, abstain_votes, total_votes) = blockchain.tally_dao_votes(&proposal_id);
        let approval_percentage = if total_votes > 0 {
            (yes_votes as f64 * 100.0) / total_votes as f64
        } else {
            0.0
        };
        let vote_details: Vec<_> = votes.iter().map(|v| json!({
            "vote_id": Self::hash_to_string(&v.vote_id),
            "voter": v.voter,
            "vote_choice": v.vote_choice,
            "voting_power": v.voting_power,
            "justification": v.justification,
            "timestamp": v.timestamp
        })).collect();

        let response = json!({
            "status": "success",
            "proposal_id": proposal_id_str,
            "vote_summary": {
                "total_votes": total_votes,
                "yes_votes": yes_votes,
                "no_votes": no_votes,
                "abstain_votes": abstain_votes,
                "approval_percentage": approval_percentage,
                "quorum_percentage": approval_percentage
            },
            "votes": vote_details,
            "message": "Vote details retrieved successfully"
        });

        create_json_response(response)
    }

    /// Handle process expired proposals endpoint
    async fn handle_process_expired(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let session_token = match request.headers.get("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
            Some(token) => token,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Missing or invalid Authorization header".to_string(),
                ));
            }
        };

        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);
        self.session_manager
            .validate_session(&session_token, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

        let blockchain_arc = self.get_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;
        blockchain
            .process_approved_governance_proposals()
            .map_err(|e| anyhow::anyhow!("Failed to process approved proposals: {}", e))?;

        let response = json!({
            "status": "success",
            "message": "Approved governance proposals processed successfully"
        });
        create_json_response(response)
    }

    /// Handle GET /api/v1/dao/data - DAO general data/statistics
    async fn handle_dao_data(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        // Security: Extract and validate session token
        let session_token = match request.headers.get("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
            Some(token) => token,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Missing or invalid Authorization header".to_string(),
                ));
            }
        };

        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);

        // Security: Validate session
        self.session_manager
            .validate_session(&session_token, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let proposals = blockchain.get_dao_proposals();
        let treasury_balance = blockchain.get_dao_treasury_balance().unwrap_or(0);
        let total_members = blockchain.get_all_identities().len();
        let total_proposals = proposals.len();
        let executions = blockchain.get_dao_executions();
        let active_proposals = proposals
            .iter()
            .filter(|p| {
                let executed = executions.iter().any(|e| e.proposal_id == p.proposal_id);
                let passed = blockchain.has_proposal_passed(&p.proposal_id, p.quorum_required as u32).unwrap_or(false);
                !executed && !passed
            })
            .count();

        let response = json!({
            "total_members": total_members,
            "total_proposals": total_proposals,
            "treasury_balance": treasury_balance,
            "active_proposals": active_proposals
        });

        create_json_response(response)
    }

    /// Handle GET /api/v1/dao/delegates - List DAO delegates
    async fn handle_list_delegates(&self) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let executions = blockchain.get_dao_executions();

        let mut delegates: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
        for exec in executions {
            let Some(did) = exec.recipient.clone() else {
                continue;
            };
            if exec.execution_type == Self::DAO_DELEGATE_REGISTER_EXEC {
                let metadata = exec.multisig_signatures.first()
                    .and_then(|raw| serde_json::from_slice::<serde_json::Value>(raw).ok())
                    .unwrap_or_else(|| json!({}));
                let name = metadata.get("name").and_then(|v| v.as_str()).unwrap_or("Unnamed");
                let bio = metadata.get("bio").and_then(|v| v.as_str()).unwrap_or("");
                let delegate_id = metadata.get("delegate_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| Self::hash_to_string(&exec.proposal_id));

                let identity_id_opt = {
                    let identity_manager = self.identity_manager.read().await;
                    identity_manager.get_identity_id_by_did(&did)
                };
                let voting_power = identity_id_opt
                    .map(|id| blockchain.calculate_user_voting_power(&id))
                    .unwrap_or(0);

                delegates.insert(did.clone(), json!({
                    "delegate_id": delegate_id,
                    "user_did": did,
                    "name": name,
                    "bio": bio,
                    "voting_power": voting_power,
                    "registered_at": exec.executed_at,
                    "status": "active",
                }));
            } else if exec.execution_type == Self::DAO_DELEGATE_REVOKE_EXEC {
                delegates.remove(&did);
            }
        }

        let delegate_list: Vec<_> = delegates.into_values().collect();
        create_json_response(json!({
            "status": "success",
            "delegates": delegate_list,
            "count": delegate_list.len()
        }))
    }

    /// Handle POST /api/v1/dao/delegates/register - Register as delegate
    async fn handle_register_delegate(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let session_token = match request.headers.get("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
            Some(token) => token,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Missing or invalid Authorization header".to_string(),
                ));
            }
        };

        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);
        let session = self.session_manager
            .validate_session(&session_token, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

        let request_data: RegisterDelegateRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;
        validate_did_format(&request_data.user_did)?;
        validate_delegate_name(&request_data.delegate_info.name)?;
        validate_delegate_bio(&request_data.delegate_info.bio)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("System time error: {}", e))?
            .as_secs();
        let delegate_id = hex::encode(lib_crypto::hash_blake3(
            format!("delegate:{}:{}:{}", request_data.user_did, request_data.delegate_info.name, now).as_bytes(),
        ));

        self.submit_delegate_execution(
            session.identity_id,
            request_data.user_did,
            Self::DAO_DELEGATE_REGISTER_EXEC,
            json!({
                "version": 1,
                "delegate_id": delegate_id,
                "name": request_data.delegate_info.name,
                "bio": request_data.delegate_info.bio,
            }),
        ).await
    }

    /// Handle POST /api/v1/dao/delegates/revoke - Revoke delegate status
    async fn handle_revoke_delegate(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let session_token = match request.headers.get("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
            Some(token) => token,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Missing or invalid Authorization header".to_string(),
                ));
            }
        };

        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);
        let session = self.session_manager
            .validate_session(&session_token, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

        let request_data: RevokeDelegateRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;
        validate_did_format(&request_data.user_did)?;

        self.submit_delegate_execution(
            session.identity_id,
            request_data.user_did,
            Self::DAO_DELEGATE_REVOKE_EXEC,
            json!({
                "version": 1,
                "reason": "user_requested",
            }),
        ).await
    }

    /// Handle POST /api/v1/dao/proposals/spending - Create spending proposal (Issue #118)
    /// Convenience wrapper around create_proposal for TreasuryAllocation type
    async fn handle_spending_proposal(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        // Security: Extract and validate session token
        let session_token = match request.headers.get("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
            Some(token) => token,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Missing or invalid Authorization header".to_string(),
                ));
            }
        };

        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);

        // Security: Validate session
        let session_token_obj = self.session_manager
            .validate_session(&session_token, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

        let authenticated_identity_id = session_token_obj.identity_id;

        // Parse request
        let request_data: SpendingProposalRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        // Security: Validate inputs
        validate_spending_proposal(
            &request_data.title,
            &request_data.description,
            &request_data.recipient,
            request_data.amount,
        )?;

        // Use authenticated identity as proposer (not first identity!)
        let proposer_id = hex::encode(authenticated_identity_id.as_bytes());

        // Create treasury allocation proposal
        let create_request = CreateProposalRequest {
            proposer_identity_id: Some(proposer_id.to_string()),
            title: request_data.title.clone(),
            description: format!(
                "{}\n\nAmount: {}\nRecipient: {}",
                request_data.description,
                request_data.amount,
                request_data.recipient
            ),
            proposal_type: Some("treasury_allocation".to_string()),
            voting_period_days: Some(7),
        };

        self.handle_create_proposal_from_identity(authenticated_identity_id, create_request).await
    }

    /// Handle DAO statistics endpoint
    async fn handle_dao_stats(&self) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let proposals = blockchain.get_dao_proposals();
        let treasury_balance = blockchain.get_dao_treasury_balance().unwrap_or(0);
        let executions = blockchain.get_dao_executions();

        // Calculate statistics
        let total_proposals = proposals.len();
        let executed_proposals = proposals
            .iter()
            .filter(|p| executions.iter().any(|e| e.proposal_id == p.proposal_id))
            .count();
        let passed_proposals = proposals
            .iter()
            .filter(|p| {
                !executions.iter().any(|e| e.proposal_id == p.proposal_id)
                    && blockchain.has_proposal_passed(&p.proposal_id, p.quorum_required as u32).unwrap_or(false)
            })
            .count();
        let active_proposals = total_proposals.saturating_sub(passed_proposals + executed_proposals);

        let total_votes: u64 = proposals
            .iter()
            .map(|p| blockchain.tally_dao_votes(&p.proposal_id).3)
            .sum();
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
                    "total_balance": treasury_balance,
                    "available_balance": treasury_balance,
                    "utilization_rate": 0.0
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
                self.handle_create_proposal(&request).await.map_err(anyhow::Error::from)
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
                self.handle_cast_vote(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "vote", "power", identity_id]) => {
                self.handle_get_voting_power(identity_id).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "votes", proposal_id]) => {
                self.handle_get_proposal_votes(proposal_id).await.map_err(anyhow::Error::from)
            },

            // Delegate endpoints (Issue #118)
            (ZhtpMethod::Get, ["api", "v1", "dao", "data"]) => {
                self.handle_dao_data(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "delegates"]) => {
                self.handle_list_delegates().await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Post, ["api", "v1", "dao", "delegates", "register"]) => {
                self.handle_register_delegate(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Post, ["api", "v1", "dao", "delegates", "revoke"]) => {
                self.handle_revoke_delegate(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Post, ["api", "v1", "dao", "proposals", "spending"]) => {
                self.handle_spending_proposal(&request).await.map_err(anyhow::Error::from)
            },

            // Administrative endpoints
            (ZhtpMethod::Post, ["api", "v1", "dao", "admin", "process-expired"]) => {
                self.handle_process_expired(&request).await.map_err(anyhow::Error::from)
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
