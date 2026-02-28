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
use lib_blockchain::contracts::{DAORegistry, DAOEntry, TokenContract, derive_dao_id};
use lib_blockchain::transaction::{DaoExecutionData, DaoProposalData, DaoVoteData, Transaction};
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_blockchain::types::Hash as BcHash;
use lib_blockchain::types::dao::DAOType;
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

#[derive(Debug, Deserialize)]
struct RegisterDaoRequest {
    token_id: String,
    class: String,
    metadata_hash: String,
    treasury_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DaoFactoryCreateRequest {
    token_id: String,
    class: String,
    metadata_hash: String,
    treasury_key_id: Option<String>,
    governance_config_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DaoRegistryRegisterEvent {
    token_id: String,
    class: String,
    metadata_hash: String,
    treasury_key_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DaoFactoryCreateEventV1 {
    schema_version: u8,
    token_id: String,
    class: String,
    metadata_hash: String,
    treasury_key_id: String,
    dao_id: String,
    governance_config_hash: Option<String>,
}

/// Spending proposal request (Issue #118)
#[derive(Debug, Deserialize)]
struct SpendingProposalRequest {
    title: String,
    amount: u64,
    recipient: String,
    description: String,
}

/// Council member registration request (dao-1)
#[derive(Debug, Deserialize)]
struct RegisterCouncilMemberRequest {
    /// DID of the new member
    identity_id: String,
    /// Hex wallet ID of the new member
    wallet_id: String,
    /// SOV stake amount
    stake_amount: u64,
    /// DIDs of existing council members co-signing this registration
    council_signatures: Vec<String>,
}

/// Emergency state activation request (dao-2)
#[derive(Debug, Deserialize)]
struct EmergencyActivateRequest {
    /// DIDs of council members co-signing emergency activation
    council_signatures: Vec<String>,
    /// DID of the initiating council member
    activated_by: String,
}

/// DAO handler backed by canonical blockchain state
pub struct DaoHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
}

impl DaoHandler {
    const DAO_DELEGATE_REGISTER_EXEC: &'static str = "dao_delegate_register_v1";
    const DAO_DELEGATE_REVOKE_EXEC: &'static str = "dao_delegate_revoke_v1";
    const DAO_REGISTRY_REGISTER_EXEC: &'static str = "dao_registry_register_v1";
    const DAO_FACTORY_CREATE_EXEC: &'static str = "dao_factory_create_v1";
    const DAO_FACTORY_CREATE_SCHEMA_V1: u8 = 1;

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

    fn parse_hex_32(value: &str, field_name: &str) -> Result<[u8; 32]> {
        let hex_str = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(hex_str)
            .map_err(|e| anyhow::anyhow!("Invalid {} hex: {}", field_name, e))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "{} must be exactly 32 bytes (64 hex chars)",
                field_name
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn parse_optional_hex_32(
        value: Option<&str>,
        field_name: &str,
    ) -> Result<Option<[u8; 32]>> {
        value.map(|v| Self::parse_hex_32(v, field_name)).transpose()
    }

    fn parse_dao_class(value: &str) -> Result<DAOType> {
        // Accept both underscore ("non_profit") and hyphen ("non-profit") forms to
        // align with DAOType::from_str() which uses underscore variants internally.
        match value.trim().to_ascii_lowercase().as_str() {
            "np" | "nonprofit" | "non-profit" | "non_profit" => Ok(DAOType::NP),
            "fp" | "forprofit" | "for-profit" | "for_profit" => Ok(DAOType::FP),
            _ => Err(anyhow::anyhow!("class must be 'np' or 'fp'")),
        }
    }

    /// Create a `PublicKey` with only `key_id` populated for registry look-up purposes.
    ///
    /// **IMPORTANT**: The returned key has empty `dilithium_pk` and `kyber_pk` fields.
    /// It must NOT be used for cryptographic verification. Its only valid use is as a
    /// `HashMap` key within `DAORegistry`, where equality is determined by `key_id`.
    fn public_key_from_key_id(key_id: [u8; 32]) -> PublicKey {
        PublicKey {
            dilithium_pk: Vec::new(),
            kyber_pk: Vec::new(),
            key_id,
        }
    }

    fn is_registry_registration_authorized(
        token_contract: &TokenContract,
        identity_did: &str,
        identity_key_id: &[u8; 32],
    ) -> bool {
        token_contract.creator.key_id == *identity_key_id
            || token_contract.creator_did.as_deref() == Some(identity_did)
    }

    fn decode_registry_event_payload(
        execution_type: &str,
        event_bytes: &[u8],
        block_height: u64,
    ) -> Option<(String, String, String, String, Option<String>)> {
        match execution_type {
            Self::DAO_REGISTRY_REGISTER_EXEC => {
                let Ok(event) = serde_json::from_slice::<DaoRegistryRegisterEvent>(event_bytes) else {
                    tracing::warn!(
                        "DAO registry replay: failed to deserialize legacy registry event payload at height {}",
                        block_height
                    );
                    return None;
                };
                Some((
                    event.token_id,
                    event.class,
                    event.metadata_hash,
                    event.treasury_key_id,
                    None,
                ))
            }
            Self::DAO_FACTORY_CREATE_EXEC => {
                let Ok(event) = serde_json::from_slice::<DaoFactoryCreateEventV1>(event_bytes) else {
                    tracing::warn!(
                        "DAO registry replay: failed to deserialize factory event payload at height {}",
                        block_height
                    );
                    return None;
                };
                if event.schema_version != Self::DAO_FACTORY_CREATE_SCHEMA_V1 {
                    tracing::warn!(
                        "DAO registry replay: unsupported factory schema_version={} at height {}",
                        event.schema_version,
                        block_height
                    );
                    return None;
                }
                Some((
                    event.token_id,
                    event.class,
                    event.metadata_hash,
                    event.treasury_key_id,
                    Some(event.dao_id),
                ))
            }
            _ => None,
        }
    }

    fn apply_registry_registration_from_tx(
        registry: &mut DAORegistry,
        tx: &Transaction,
        block_height: u64,
    ) {
        if tx.transaction_type != lib_blockchain::types::transaction_type::TransactionType::DaoExecution {
            return;
        }
        let Some(exec) = tx.dao_execution_data.as_ref() else {
            return;
        };
        if exec.execution_type != Self::DAO_REGISTRY_REGISTER_EXEC
            && exec.execution_type != Self::DAO_FACTORY_CREATE_EXEC
        {
            return;
        }
        let Some(event_bytes) = exec.multisig_signatures.first() else {
            tracing::warn!("DAO registry replay: DaoExecution at height {} missing event payload", block_height);
            return;
        };
        let Some((token_id_hex, class_str, metadata_hash_hex, treasury_key_id_hex, event_dao_id_hex)) =
            Self::decode_registry_event_payload(&exec.execution_type, event_bytes, block_height)
        else {
            return;
        };
        let token_id = match Self::parse_hex_32(&token_id_hex, "token_id") {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("DAO registry replay: invalid token_id at height {}: {}", block_height, e);
                return;
            }
        };
        let metadata_hash = match Self::parse_hex_32(&metadata_hash_hex, "metadata_hash") {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("DAO registry replay: invalid metadata_hash at height {}: {}", block_height, e);
                return;
            }
        };
        let treasury_key_id = match Self::parse_hex_32(&treasury_key_id_hex, "treasury_key_id") {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("DAO registry replay: invalid treasury_key_id at height {}: {}", block_height, e);
                return;
            }
        };
        let class = match Self::parse_dao_class(&class_str) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("DAO registry replay: invalid class at height {}: {}", block_height, e);
                return;
            }
        };
        let token_addr = Self::public_key_from_key_id(token_id);
        let treasury = Self::public_key_from_key_id(treasury_key_id);
        let derived_dao_id = derive_dao_id(&token_addr, class, &treasury);
        if let Some(dao_id_hex) = event_dao_id_hex.as_deref() {
            match Self::parse_hex_32(dao_id_hex, "dao_id") {
                Ok(event_dao_id) => {
                    if event_dao_id != derived_dao_id {
                        tracing::warn!(
                            "DAO registry replay: dao_id mismatch at height {} (event={}, derived={})",
                            block_height,
                            hex::encode(event_dao_id),
                            hex::encode(derived_dao_id)
                        );
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "DAO registry replay: invalid dao_id at height {}: {}",
                        block_height,
                        e
                    );
                    return;
                }
            }
        }
        let owner = tx.signature.public_key.clone();
        // Duplicate registration is silently ignored for idempotent replay: the same
        // DaoExecution transaction processed twice must not alter the registered state.
        if let Err(e) = registry.register_dao(
            token_addr,
            class,
            treasury,
            metadata_hash,
            owner,
            block_height,
        ) {
            tracing::debug!(
                "DAO registry replay: register_dao skipped at height {}: {}",
                block_height,
                e
            );
        }
    }

    /// Rebuild the DAO registry by replaying all DaoExecution transactions from the chain.
    ///
    /// **Performance note**: This is O(blocks × txs_per_block) and is called on every
    /// registry query (list, get, register). As the chain grows this will become slow.
    /// A future improvement should maintain the registry in a cached, incrementally-updated
    /// in-memory structure (e.g. an `Arc<RwLock<DAORegistry>>`) rather than rebuilding from
    /// scratch on each request.
    fn rebuild_dao_registry(blockchain: &lib_blockchain::Blockchain) -> Result<DAORegistry> {
        let mut registry = DAORegistry::new();
        for block in &blockchain.blocks {
            for tx in &block.transactions {
                Self::apply_registry_registration_from_tx(&mut registry, tx, block.header.height);
            }
        }
        Ok(registry)
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
        if let Some(ref proposer_id) = request_data.proposer_identity_id {
            if proposer_id.to_lowercase() != proposer_hex {
                return Ok(create_error_response(
                    ZhtpStatus::Forbidden,
                    "proposer_identity_id must match authenticated identity".to_string(),
                ));
            }
        }

        let proposal_type_raw = request_data
            .proposal_type
            .as_deref()
            .unwrap_or("community_funding");
        let proposal_type = match Self::parse_proposal_type(proposal_type_raw) {
            Ok(pt) => pt,
            Err(_) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid proposal type: {}", proposal_type_raw),
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
            voting_period_blocks: (request_data.voting_period_days.unwrap_or(7) as u64).saturating_mul(14_400),
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
            "proposal_type": request_data.proposal_type,
            "voting_period_days": request_data.voting_period_days,
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
        if let Some(ref voter_identity_id) = request_data.voter_identity_id {
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
            .map(str::trim)
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

        // Phase 0 gate: only Bootstrap Council members may vote
        if blockchain.governance_phase == lib_blockchain::dao::GovernancePhase::Bootstrap
            && !blockchain.is_council_member(&voter_identity.did)
        {
            return Ok(create_error_response(
                ZhtpStatus::Unauthorized,
                "Phase 0: voting restricted to Bootstrap Council".to_string(),
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
            // calculate_user_voting_power already applies voting_power_mode.
            voting_power: blockchain.calculate_user_voting_power(&authenticated_identity_id).max(1),
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
            "voter_id": request_data.voter_identity_id.unwrap_or(authenticated_hex),
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
            "voting_power_mode": format!("{:?}", blockchain.voting_power_mode),
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

    // =========================================================================
    // Bootstrap Council handlers (dao-1)
    // =========================================================================

    /// GET /api/v1/dao/council/members
    async fn handle_get_council_members(&self) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let phase_str = match blockchain.governance_phase {
            lib_blockchain::dao::GovernancePhase::Bootstrap => "bootstrap",
            lib_blockchain::dao::GovernancePhase::Hybrid => "hybrid",
            lib_blockchain::dao::GovernancePhase::FullDao => "full_dao",
        };

        let members: Vec<serde_json::Value> = blockchain.get_council_members().iter().map(|m| {
            json!({
                "identity_id": m.identity_id,
                "wallet_id": m.wallet_id,
                "stake_amount": m.stake_amount,
                "joined_at_height": m.joined_at_height,
            })
        }).collect();

        create_json_response(json!({
            "status": "success",
            "governance_phase": phase_str,
            "council_threshold": blockchain.council_threshold,
            "members": members,
        }))
    }

    /// POST /api/v1/dao/council/register
    ///
    /// Council membership is established at genesis via `ensure_council_bootstrap()`.
    /// Post-genesis registration requires cryptographic multisig verification that is
    /// not yet implemented; this endpoint validates input but rejects all writes until
    /// proper Dilithium verification is in place.
    async fn handle_register_council_member(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: RegisterCouncilMemberRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        // ── input validation ──────────────────────────────────────────────────
        if !req.identity_id.starts_with("did:zhtp:") {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "identity_id must be a valid did:zhtp: DID".to_string(),
            ));
        }
        if req.wallet_id.trim().is_empty() || !req.wallet_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "wallet_id must be a non-empty hex string".to_string(),
            ));
        }
        if req.stake_amount == 0 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "stake_amount must be greater than zero".to_string(),
            ));
        }

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // ── first-bootstrap gate ──────────────────────────────────────────────
        // Accepting the first council member over an unauthenticated public API
        // would let any client take over an empty council.  Council members must
        // be seeded via genesis configuration (`ensure_council_bootstrap`).
        if blockchain.council_members.is_empty() {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Council bootstrap must be performed via genesis configuration \
                 (ensure_council_bootstrap). Runtime registration is not permitted."
                    .to_string(),
            ));
        }

        // ── max-size guard ────────────────────────────────────────────────────
        const MAX_COUNCIL_SIZE: usize = 5;
        if blockchain.council_members.len() >= MAX_COUNCIL_SIZE {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                format!("Council is at maximum capacity ({} members)", MAX_COUNCIL_SIZE),
            ));
        }

        // ── post-genesis registration (not yet implemented) ───────────────────
        // Adding members after genesis requires cryptographic multisig verification
        // (council_threshold-of-N Dilithium signatures).  The current request body
        // carries DID strings in `council_signatures`, not actual signature bytes,
        // so accepting them would be a security bypass.  This path is disabled
        // until proper signature verification is wired in.
        Ok(create_error_response(
            ZhtpStatus::Forbidden,
            format!(
                "Post-genesis council registration requires cryptographic multisig verification \
                 ({}-of-{} council signatures), which is not yet implemented.",
                blockchain.council_threshold,
                blockchain.council_members.len(),
            ),
        ))
    }

    // =========================================================================
    // Emergency state handlers (dao-2)
    // =========================================================================

    /// POST /api/v1/dao/emergency/activate
    ///
    /// Emergency state activation requires cryptographic multisig verification
    /// (council_threshold-of-N Dilithium signatures). The current request body
    /// carries DID strings in `council_signatures`, not actual signature bytes,
    /// so accepting them over a public API would allow anyone who knows council
    /// member DIDs to activate emergency state without authorization.
    /// This endpoint is disabled until proper signature verification is implemented.
    async fn handle_emergency_activate(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: EmergencyActivateRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let _ = &req; // parsed but not used until crypto verification is available
        Ok(create_error_response(
            ZhtpStatus::Forbidden,
            format!(
                "Emergency activation requires cryptographic multisig verification \
                 ({}-of-{} council signatures), which is not yet implemented.",
                blockchain.council_threshold,
                blockchain.council_members.len(),
            ),
        ))
    }

    /// GET /api/v1/dao/emergency/status
    async fn handle_emergency_status(&self) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        create_json_response(json!({
            "status": "success",
            "emergency_state": blockchain.emergency_state,
            "activated_at": blockchain.emergency_activated_at,
            "activated_by": blockchain.emergency_activated_by,
            "expires_at": blockchain.emergency_expires_at,
            "current_height": blockchain.height,
        }))
    }

    /// POST /api/v1/dao/voting/delegate — set or revoke a vote delegation.
    ///
    /// Body: `{ "delegate_did": "did:zhtp:HEX" }` to delegate,
    ///       `{ "delegate_did": "" }` to revoke an existing delegation.
    ///
    /// Rejects: invalid DID format, non-existent delegate, self-delegation,
    /// circular delegation chains.
    async fn handle_vote_delegate(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let session_token = match request.headers.get("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string())) {
            Some(token) => token,
            None => return Ok(create_error_response(ZhtpStatus::Unauthorized,
                "Missing or invalid Authorization header".to_string())),
        };

        let client_ip = extract_client_ip(request);
        let user_agent = extract_user_agent(request);
        let session = self.session_manager
            .validate_session(&session_token, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Session validation failed: {}", e))?;

        #[derive(serde::Deserialize)]
        struct DelegateRequest {
            delegate_did: String,
        }
        let req: DelegateRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        // Delegator key is the 64-char hex of the raw identity bytes.
        let delegator_hex = hex::encode(session.identity_id.as_bytes());

        let blockchain_arc = self.get_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;

        // ── revocation ────────────────────────────────────────────────────────
        if req.delegate_did.is_empty() {
            let removed = blockchain.vote_delegations.remove(&delegator_hex).is_some();
            return create_json_response(json!({
                "status": if removed { "revoked" } else { "no_delegation_found" },
                "delegator": delegator_hex,
            }));
        }

        // ── DID format validation ─────────────────────────────────────────────
        let delegate_hex = match req.delegate_did.strip_prefix("did:zhtp:") {
            Some(hex_part) if !hex_part.is_empty() => hex_part.to_string(),
            _ => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Invalid delegate_did format; expected did:zhtp:HEXVALUE".to_string(),
            )),
        };

        // Validate the hex part is a valid 32-byte ID.
        if hex::decode(&delegate_hex).map(|b| b.len()).unwrap_or(0) != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "delegate_did hex part must decode to exactly 32 bytes".to_string(),
            ));
        }

        // ── self-delegation check ─────────────────────────────────────────────
        if delegate_hex == delegator_hex {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Cannot delegate voting power to yourself".to_string(),
            ));
        }

        // ── delegate existence check ──────────────────────────────────────────
        if !blockchain.identity_registry.contains_key(&req.delegate_did) {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Delegate identity '{}' not found in identity registry", req.delegate_did),
            ));
        }

        // ── cycle detection ───────────────────────────────────────────────────
        // Walk the existing delegation graph forward from the proposed delegate.
        // If we reach the delegator, this edge would close a cycle — reject it.
        const MAX_DEPTH: usize = 64;
        let mut current = delegate_hex.clone();
        for _ in 0..MAX_DEPTH {
            match blockchain.vote_delegations.get(&current) {
                Some(next) if next == &delegator_hex => {
                    return Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Delegation would create a cycle in the delegation graph".to_string(),
                    ));
                }
                Some(next) => current = next.clone(),
                None => break,
            }
        }

        // ── store (delegator_id_hex → delegate_id_hex) ────────────────────────
        blockchain.vote_delegations.insert(delegator_hex.clone(), delegate_hex.clone());

        create_json_response(json!({
            "status": "success",
            "delegator": delegator_hex,
            "delegate": delegate_hex,
        }))
    }

    // ── Phase Transition endpoints (dao-3) ────────────────────────────────────

    /// GET /api/v1/dao/governance/phase
    async fn handle_get_governance_phase(&self) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let phase_str = match blockchain.governance_phase {
            lib_blockchain::dao::GovernancePhase::Bootstrap => "bootstrap",
            lib_blockchain::dao::GovernancePhase::Hybrid    => "hybrid",
            lib_blockchain::dao::GovernancePhase::FullDao   => "full_dao",
        };

        create_json_response(json!({
            "status": "success",
            "governance_phase": phase_str,
            "council_threshold": blockchain.council_threshold,
            "governance_cycles_with_quorum": blockchain.governance_cycles_with_quorum,
            "last_governance_cycle_height": blockchain.last_governance_cycle_height,
            "current_height": blockchain.height,
        }))
    }

    /// GET /api/v1/dao/governance/transition-status
    async fn handle_get_transition_status(&self) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let snap = blockchain.compute_decentralization_snapshot();
        let can_advance = match blockchain.governance_phase {
            lib_blockchain::dao::GovernancePhase::Bootstrap => blockchain.check_phase0_to_phase1(),
            lib_blockchain::dao::GovernancePhase::Hybrid    => blockchain.check_phase1_to_phase2(),
            lib_blockchain::dao::GovernancePhase::FullDao   => false,
        };

        create_json_response(json!({
            "status": "success",
            "snapshot": {
                "verified_citizen_count": snap.verified_citizen_count,
                "max_wallet_pct_bps": snap.max_wallet_pct_bps,
                "snapshot_height": snap.snapshot_height,
            },
            "can_advance_phase": can_advance,
            "phase_transition_config": {
                "min_citizens_for_phase1": blockchain.phase_transition_config.min_citizens_for_phase1,
                "max_wallet_pct_bps_for_phase1": blockchain.phase_transition_config.max_wallet_pct_bps_for_phase1,
                "min_citizens_for_phase2": blockchain.phase_transition_config.min_citizens_for_phase2,
                "max_wallet_pct_bps_for_phase2": blockchain.phase_transition_config.max_wallet_pct_bps_for_phase2,
                "phase2_quorum_consecutive_cycles": blockchain.phase_transition_config.phase2_quorum_consecutive_cycles,
            },
        }))
    }

    /// POST /api/v1/dao/governance/trigger-transition
    async fn handle_trigger_transition(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct TriggerRequest {
            council_signatures: Vec<String>,
        }
        let req: TriggerRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        let blockchain_arc = self.get_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;

        let threshold = blockchain.council_threshold as usize;
        let valid = req.council_signatures.iter()
            .filter(|did| blockchain.is_council_member(did.as_str()))
            .count();
        if valid < threshold {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                format!("Requires {} council signatures, got {}", threshold, valid),
            ));
        }

        let phase_before = blockchain.governance_phase.clone();
        blockchain.try_advance_governance_phase();
        let phase_after = blockchain.governance_phase.clone();
        let advanced = phase_before != phase_after;

        create_json_response(json!({
            "status": "success",
            "advanced": advanced,
            "new_phase": format!("{:?}", phase_after),
        }))
    }

    async fn submit_dao_registry_execution(
        &self,
        request: &ZhtpRequest,
        token_id: [u8; 32],
        class: DAOType,
        metadata_hash: [u8; 32],
        governance_config_hash: Option<[u8; 32]>,
        execution_type: &'static str,
        memo: &'static [u8],
        success_message: &'static str,
    ) -> Result<ZhtpResponse> {
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

        let identity_manager = self.identity_manager.read().await;
        let identity = identity_manager
            .get_identity(&session.identity_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Authenticated identity not found"))?;
        drop(identity_manager);

        // Always use the authenticated identity's public key as the treasury key.
        // The optional `treasury_key_id` field in the request is accepted but ignored:
        // since it must always equal the identity's key_id, accepting arbitrary values
        // would only produce confusing Forbidden errors with no additional security benefit.
        let treasury_key_id = identity.public_key.key_id;

        let token_addr = Self::public_key_from_key_id(token_id);
        let treasury = Self::public_key_from_key_id(treasury_key_id);
        let dao_id = derive_dao_id(&token_addr, class, &treasury);

        let event = if execution_type == Self::DAO_FACTORY_CREATE_EXEC {
            serde_json::to_value(DaoFactoryCreateEventV1 {
                schema_version: Self::DAO_FACTORY_CREATE_SCHEMA_V1,
                token_id: hex::encode(token_id),
                class: class.as_str().to_string(),
                metadata_hash: hex::encode(metadata_hash),
                treasury_key_id: hex::encode(treasury_key_id),
                dao_id: hex::encode(dao_id),
                governance_config_hash: governance_config_hash.map(hex::encode),
            })?
        } else {
            json!({
                "token_id": hex::encode(token_id),
                "class": class.as_str(),
                "metadata_hash": hex::encode(metadata_hash),
                "treasury_key_id": hex::encode(treasury_key_id),
            })
        };
        let event_bytes = serde_json::to_vec(&event)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("System time error: {}", e))?
            .as_secs();
        let blockchain_arc = self.get_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;
        let token_contract = blockchain.get_token_contract(&token_id).ok_or_else(|| {
            anyhow::anyhow!("token_id does not match a deployed token contract")
        })?;
        if !Self::is_registry_registration_authorized(
            &token_contract,
            &identity.did,
            &identity.public_key.key_id,
        ) {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Only the token creator can register DAO metadata".to_string(),
            ));
        }
        let existing_registry = Self::rebuild_dao_registry(&blockchain)?;
        if existing_registry.get_dao_by_id(dao_id).is_ok() {
            return Ok(create_error_response(
                ZhtpStatus::Conflict,
                "DAO already registered for this token/class/treasury tuple".to_string(),
            ));
        }
        let height = blockchain.get_height();

        let execution_data = DaoExecutionData {
            proposal_id: BcHash::from_slice(&lib_crypto::hash_blake3(&[
                execution_type.as_bytes(),
                session.identity_id.as_bytes(),
                &now.to_le_bytes(),
                &token_id,
            ].concat())),
            executor: identity.did.clone(),
            execution_type: execution_type.to_string(),
            recipient: Some(hex::encode(dao_id)),
            amount: None,
            executed_at: now,
            executed_at_height: height,
            // NOTE: DaoExecutionData.multisig_signatures is documented as
            // "Multi-sig signatures from approving validators". For DAO registry
            // executions this field carries the serialized event payload (JSON)
            // instead of actual validator signatures. If DaoExecutionData is
            // extended with a dedicated execution/event data field in the future,
            // this should be migrated accordingly.
            multisig_signatures: vec![event_bytes],
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
            memo.to_vec(),
        );

        if let Some(private_key) = identity.private_key.clone() {
            let keypair = lib_crypto::KeyPair {
                public_key: identity.public_key.clone(),
                private_key,
            };
            let sig = lib_crypto::sign_message(&keypair, tx.signing_hash().as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to sign dao transaction: {}", e))?;
            tx.signature.signature = sig.signature;
        } else {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Identity private key unavailable on node".to_string(),
            ));
        }

        blockchain
            .add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("Failed to submit dao transaction: {}", e))?;

        create_json_response(json!({
            "status": "success",
            "dao_id": hex::encode(dao_id),
            "token_id": hex::encode(token_id),
            "class": class.as_str(),
            "execution_type": execution_type,
            "message": success_message
        }))
    }

    /// Handle POST /api/v1/dao/registry/register
    async fn handle_register_dao(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: RegisterDaoRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;
        let _legacy_treasury_hint = req.treasury_key_id.as_deref();

        let token_id = Self::parse_hex_32(&req.token_id, "token_id")?;
        if token_id == [0u8; 32] {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "token_id must be non-zero".to_string(),
            ));
        }
        let class = Self::parse_dao_class(&req.class)?;
        let metadata_hash = Self::parse_hex_32(&req.metadata_hash, "metadata_hash")?;
        if metadata_hash.iter().all(|&b| b == 0) {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "metadata_hash must be non-zero".to_string(),
            ));
        }

        self.submit_dao_registry_execution(
            request,
            token_id,
            class,
            metadata_hash,
            None,
            Self::DAO_REGISTRY_REGISTER_EXEC,
            b"dao:registry:register",
            "DAO registry registration submitted to mempool",
        ).await
    }

    /// Handle POST /api/v1/dao/factory/create
    async fn handle_factory_create_dao(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: DaoFactoryCreateRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;
        let _legacy_treasury_hint = req.treasury_key_id.as_deref();

        let token_id = Self::parse_hex_32(&req.token_id, "token_id")?;
        if token_id == [0u8; 32] {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "token_id must be non-zero".to_string(),
            ));
        }
        let class = Self::parse_dao_class(&req.class)?;
        let metadata_hash = Self::parse_hex_32(&req.metadata_hash, "metadata_hash")?;
        if metadata_hash.iter().all(|&b| b == 0) {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "metadata_hash must be non-zero".to_string(),
            ));
        }
        let governance_config_hash = Self::parse_optional_hex_32(
            req.governance_config_hash.as_deref(),
            "governance_config_hash",
        )?;
        if governance_config_hash
            .as_ref()
            .is_some_and(|v| v.iter().all(|&b| b == 0))
        {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "governance_config_hash must be non-zero when provided".to_string(),
            ));
        }

        self.submit_dao_registry_execution(
            request,
            token_id,
            class,
            metadata_hash,
            governance_config_hash,
            Self::DAO_FACTORY_CREATE_EXEC,
            b"dao:factory:create",
            "DAO factory create transaction submitted to mempool",
        ).await
    }

    /// Handle GET /api/v1/dao/registry/list
    async fn handle_list_registered_daos(&self) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let registry = Self::rebuild_dao_registry(&blockchain)?;
        let entries = registry
            .list_daos_with_ids()
            .map_err(|e| anyhow::anyhow!("Failed to list DAO registry entries: {}", e))?;

        let daos: Vec<_> = entries
            .into_iter()
            .map(|(entry, dao_id)| dao_entry_json(entry, dao_id))
            .collect();

        create_json_response(json!({
            "status": "success",
            "count": daos.len(),
            "daos": daos
        }))
    }

    /// Handle GET /api/v1/dao/registry/{dao_id}
    async fn handle_get_registered_dao(&self, dao_id_hex: &str) -> Result<ZhtpResponse> {
        let dao_id = Self::parse_hex_32(dao_id_hex, "dao_id")?;
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let registry = Self::rebuild_dao_registry(&blockchain)?;
        let entry = registry
            .get_dao_by_id(dao_id)
            .map_err(|_| anyhow::anyhow!("DAO not found"))?;

        create_json_response(json!({
            "status": "success",
            "dao": dao_entry_json(entry, dao_id)
        }))
    }
}

fn dao_entry_json(entry: DAOEntry, dao_id: [u8; 32]) -> serde_json::Value {
    json!({
        "dao_id": hex::encode(dao_id),
        "token_key_id": hex::encode(entry.token_addr.key_id),
        "class": entry.class.as_str(),
        "treasury_key_id": hex::encode(entry.treasury.key_id),
        "owner_key_id": hex::encode(entry.owner.key_id),
        "metadata_hash": hex::encode(entry.metadata_hash),
        "created_at": entry.created_at,
    })
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
            (ZhtpMethod::Post, ["api", "v1", "dao", "registry", "register"]) => {
                self.handle_register_dao(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Post, ["api", "v1", "dao", "factory", "create"]) => {
                self.handle_factory_create_dao(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "registry", "list"]) => {
                self.handle_list_registered_daos().await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "registry", dao_id]) => {
                self.handle_get_registered_dao(dao_id).await.map_err(anyhow::Error::from)
            },

            // Administrative endpoints
            (ZhtpMethod::Post, ["api", "v1", "dao", "admin", "process-expired"]) => {
                self.handle_process_expired(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "admin", "stats"]) => {
                self.handle_dao_stats().await.map_err(anyhow::Error::from)
            },

            // Bootstrap Council endpoints (dao-1)
            (ZhtpMethod::Get, ["api", "v1", "dao", "council", "members"]) => {
                self.handle_get_council_members().await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Post, ["api", "v1", "dao", "council", "register"]) => {
                self.handle_register_council_member(&request).await.map_err(anyhow::Error::from)
            },

            // Emergency state endpoints (dao-2)
            (ZhtpMethod::Post, ["api", "v1", "dao", "emergency", "activate"]) => {
                self.handle_emergency_activate(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "emergency", "status"]) => {
                self.handle_emergency_status().await.map_err(anyhow::Error::from)
            },

            // Voting power delegation (dao-5)
            (ZhtpMethod::Post, ["api", "v1", "dao", "voting", "delegate"]) => {
                self.handle_vote_delegate(&request).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Delete, ["api", "v1", "dao", "voting", "delegate"]) => {
                // Revoke delegation: treat as delegate to empty string.
                let body = b"{\"delegate_did\":\"\"}";
                let mut revoke_req = request.clone();
                revoke_req.body = body.to_vec();
                self.handle_vote_delegate(&revoke_req).await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "voting-power", identity_id]) => {
                self.handle_get_voting_power(identity_id).await.map_err(anyhow::Error::from)
            },
            // Governance phase endpoints (dao-3)
            (ZhtpMethod::Get, ["api", "v1", "dao", "governance", "phase"]) => {
                self.handle_get_governance_phase().await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Get, ["api", "v1", "dao", "governance", "transition-status"]) => {
                self.handle_get_transition_status().await.map_err(anyhow::Error::from)
            },
            (ZhtpMethod::Post, ["api", "v1", "dao", "governance", "trigger-transition"]) => {
                self.handle_trigger_transition(&request).await.map_err(anyhow::Error::from)
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

#[cfg(test)]
mod tests {
    use super::{CastVoteRequest, CreateProposalRequest, DaoHandler, DAOType};
    use lib_blockchain::contracts::{derive_dao_id, DAORegistry, TokenContract};
    use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
    use lib_blockchain::transaction::{DaoExecutionData, Transaction};
    use lib_blockchain::types::Hash as BcHash;
    use serde_json::json;

    fn test_public_key(seed: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![seed; 32],
            kyber_pk: vec![seed.wrapping_add(1); 32],
            key_id: [seed; 32],
        }
    }

    fn dao_registry_tx(event: serde_json::Value, execution_type: &str, signer_seed: u8) -> Transaction {
        let now = 42_u64;
        let execution_data = DaoExecutionData {
            proposal_id: BcHash::from_slice(&lib_crypto::hash_blake3(
                format!("registry:{execution_type}:{signer_seed}:{now}").as_bytes(),
            )),
            executor: "did:zhtp:test".to_string(),
            execution_type: execution_type.to_string(),
            recipient: None,
            amount: None,
            executed_at: now,
            executed_at_height: 99,
            multisig_signatures: vec![serde_json::to_vec(&event).expect("event json")],
        };

        Transaction::new_dao_execution(
            execution_data,
            Vec::new(),
            Vec::new(),
            0,
            Signature {
                signature: Vec::new(),
                public_key: test_public_key(signer_seed),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: now,
            },
            b"test:dao:registry".to_vec(),
        )
    }

    #[test]
    fn create_proposal_accepts_legacy_cli_shape() {
        let body = r#"{
            "title":"Legacy title",
            "description":"Legacy description",
            "orchestrated":true
        }"#;

        let parsed: CreateProposalRequest = serde_json::from_str(body).expect("legacy propose payload should parse");
        assert_eq!(parsed.title, "Legacy title");
        assert!(parsed.proposer_identity_id.is_none());
        assert!(parsed.proposal_type.is_none());
        assert!(parsed.voting_period_days.is_none());
    }

    #[test]
    fn create_proposal_accepts_canonical_shape() {
        let body = r#"{
            "proposer_identity_id":"abc",
            "title":"Canonical title",
            "description":"Canonical description",
            "proposal_type":"treasury_allocation",
            "voting_period_days":7
        }"#;

        let parsed: CreateProposalRequest = serde_json::from_str(body).expect("canonical propose payload should parse");
        assert_eq!(parsed.proposal_type.as_deref(), Some("treasury_allocation"));
        assert_eq!(parsed.voting_period_days, Some(7));
    }

    #[test]
    fn cast_vote_accepts_legacy_and_canonical_fields() {
        let legacy_body = r#"{
            "proposal_id":"deadbeef",
            "choice":" yes ",
            "orchestrated":true
        }"#;
        let canonical_body = r#"{
            "voter_identity_id":"abc",
            "proposal_id":"deadbeef",
            "vote_choice":"no"
        }"#;

        let legacy: CastVoteRequest = serde_json::from_str(legacy_body).expect("legacy vote payload should parse");
        let canonical: CastVoteRequest = serde_json::from_str(canonical_body).expect("canonical vote payload should parse");

        assert_eq!(legacy.choice.as_deref(), Some(" yes "));
        assert_eq!(legacy.vote_choice, None);
        assert_eq!(canonical.vote_choice.as_deref(), Some("no"));
        assert_eq!(canonical.choice, None);
    }

    #[test]
    fn dao_registry_parse_hex_32_validates_length_and_prefix() {
        let parsed = DaoHandler::parse_hex_32(&format!("0x{}", "ab".repeat(32)), "token_id")
            .expect("prefixed hex should parse");
        assert_eq!(parsed, [0xab; 32]);

        let err = DaoHandler::parse_hex_32("01", "token_id").expect_err("short hex must fail");
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn dao_registry_authorization_accepts_creator_key_or_creator_did() {
        let creator = test_public_key(7);
        let mut token = TokenContract::new(
            [1; 32],
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            false,
            0,
            creator.clone(),
        );

        assert!(DaoHandler::is_registry_registration_authorized(
            &token,
            "did:zhtp:alice",
            &creator.key_id,
        ));
        assert!(!DaoHandler::is_registry_registration_authorized(
            &token,
            "did:zhtp:alice",
            &[9; 32],
        ));

        token.creator_did = Some("did:zhtp:alice".to_string());
        assert!(DaoHandler::is_registry_registration_authorized(
            &token,
            "did:zhtp:alice",
            &[9; 32],
        ));
    }

    #[test]
    fn dao_registry_replay_applies_only_valid_registration_events() {
        let mut registry = DAORegistry::new();
        let factory_expected_dao_id = derive_dao_id(
            &DaoHandler::public_key_from_key_id([10u8; 32]),
            DAOType::FP,
            &DaoHandler::public_key_from_key_id([12u8; 32]),
        );
        let valid = dao_registry_tx(
            json!({
                "token_id": hex::encode([1u8; 32]),
                "class": "np",
                "metadata_hash": hex::encode([2u8; 32]),
                "treasury_key_id": hex::encode([3u8; 32]),
            }),
            "dao_registry_register_v1",
            9,
        );
        let invalid_class = dao_registry_tx(
            json!({
                "token_id": hex::encode([4u8; 32]),
                "class": "unknown",
                "metadata_hash": hex::encode([5u8; 32]),
                "treasury_key_id": hex::encode([6u8; 32]),
            }),
            "dao_registry_register_v1",
            8,
        );
        let wrong_exec = dao_registry_tx(
            json!({
                "token_id": hex::encode([7u8; 32]),
                "class": "np",
                "metadata_hash": hex::encode([8u8; 32]),
                "treasury_key_id": hex::encode([9u8; 32]),
            }),
            "dao_delegate_register_v1",
            7,
        );
        let factory_valid = dao_registry_tx(
            json!({
                "schema_version": 1,
                "token_id": hex::encode([10u8; 32]),
                "class": "fp",
                "metadata_hash": hex::encode([11u8; 32]),
                "treasury_key_id": hex::encode([12u8; 32]),
                "dao_id": hex::encode(factory_expected_dao_id),
                "governance_config_hash": hex::encode([13u8; 32]),
            }),
            "dao_factory_create_v1",
            6,
        );
        let factory_bad_dao_id = dao_registry_tx(
            json!({
                "schema_version": 1,
                "token_id": hex::encode([14u8; 32]),
                "class": "np",
                "metadata_hash": hex::encode([15u8; 32]),
                "treasury_key_id": hex::encode([16u8; 32]),
                "dao_id": hex::encode([99u8; 32]),
                "governance_config_hash": hex::encode([17u8; 32]),
            }),
            "dao_factory_create_v1",
            5,
        );

        DaoHandler::apply_registry_registration_from_tx(&mut registry, &valid, 120);
        DaoHandler::apply_registry_registration_from_tx(&mut registry, &invalid_class, 121);
        DaoHandler::apply_registry_registration_from_tx(&mut registry, &wrong_exec, 122);
        DaoHandler::apply_registry_registration_from_tx(&mut registry, &factory_valid, 123);
        DaoHandler::apply_registry_registration_from_tx(&mut registry, &factory_bad_dao_id, 124);

        let entries = registry
            .list_daos_with_ids()
            .expect("registry should list entries");
        assert_eq!(entries.len(), 2);
        let (entry_legacy, dao_id_legacy) = entries[0].clone();
        let expected_legacy = derive_dao_id(
            &DaoHandler::public_key_from_key_id([1u8; 32]),
            DAOType::NP,
            &DaoHandler::public_key_from_key_id([3u8; 32]),
        );
        assert_eq!(dao_id_legacy, expected_legacy);
        assert_eq!(entry_legacy.owner.key_id, [9u8; 32]);
        assert_eq!(entry_legacy.created_at, 120);

        let (entry_factory, dao_id_factory) = entries[1].clone();
        assert_eq!(dao_id_factory, factory_expected_dao_id);
        assert_eq!(entry_factory.class, DAOType::FP);
        assert_eq!(entry_factory.owner.key_id, [6u8; 32]);
        assert_eq!(entry_factory.created_at, 123);
    }
}
