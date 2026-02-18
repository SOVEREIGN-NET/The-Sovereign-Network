//! Blockchain Handler Module
//!
//! Clean, minimal blockchain operations using lib-blockchain patterns

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
// Removed unused serde_json::json import

// ZHTP protocol imports
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

// Blockchain imports
use lib_blockchain::types::Hash;
use lib_blockchain::Blockchain;
use lib_blockchain::transaction::Transaction;
use lib_blockchain::types::transaction_type::TransactionType;

/// Clean blockchain handler implementation
///
/// NOTE: This handler does NOT store a blockchain reference.
/// Instead, it fetches the current shared blockchain on every request
/// to ensure it always sees the latest state (including transactions
/// added via mesh protocol).
pub struct BlockchainHandler {
}

impl BlockchainHandler {
    pub fn new(_blockchain: Arc<RwLock<Blockchain>>) -> Self {
        // We ignore the passed blockchain reference and always fetch from global provider
        Self {}
    }

    /// Get the current shared blockchain instance
    /// This ensures we always see the latest state
    async fn get_blockchain(&self) -> anyhow::Result<Arc<RwLock<Blockchain>>> {
        crate::runtime::blockchain_provider::get_global_blockchain().await
    }

    fn parse_query_params(uri: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        let query = match uri.split_once('?') {
            Some((_, q)) => q,
            None => return params,
        };

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut iter = pair.splitn(2, '=');
            let key = iter.next().unwrap_or("").trim();
            let value = iter.next().unwrap_or("").trim();
            if key.is_empty() {
                continue;
            }
            let decoded_key = urlencoding::decode(key).unwrap_or_else(|_| key.into()).to_string();
            let decoded_value = urlencoding::decode(value).unwrap_or_else(|_| value.into()).to_string();
            params.insert(decoded_key, decoded_value);
        }

        params
    }

    fn parse_pagination(params: &HashMap<String, String>) -> (usize, usize) {
        let page = params
            .get("page")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let limit = params
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(20)
            .max(1)
            .min(100);
        (page, limit)
    }

    fn is_hex_64(value: &str) -> bool {
        value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn strip_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
        value
            .strip_prefix(&format!("{}_", prefix))
            .or_else(|| value.strip_prefix(&format!("{}:", prefix)))
    }

    fn tx_to_info(tx: &lib_blockchain::transaction::Transaction) -> TransactionInfo {
        TransactionInfo {
            hash: tx.hash().to_string(),
            from: tx
                .inputs
                .first()
                .map(|i| i.previous_output.to_string())
                .unwrap_or_else(|| "genesis".to_string()),
            to: tx
                .outputs
                .first()
                .map(|o| format!("{:02x?}", &o.recipient.key_id[..8]))
                .unwrap_or_else(|| "unknown".to_string()),
            amount: 0, // Amount is hidden in commitment for privacy
            fee: tx.fee,
            transaction_type: format!("{:?}", tx.transaction_type),
            timestamp: tx.signature.timestamp,
            size: tx.size(),
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for BlockchainHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("Blockchain handler: {} {}", request.method, request.uri);

        let uri_path = request.uri.split('?').next().unwrap_or(request.uri.as_str());
        let response = match (request.method, uri_path) {
            (ZhtpMethod::Get, "/api/v1/blockchain/blocks") => {
                self.handle_list_blocks(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/transactions") => {
                self.handle_list_transactions(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/stats") => {
                self.handle_get_stats(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/search") => {
                self.handle_search(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/status") => {
                self.handle_blockchain_status(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/latest") => {
                self.handle_latest_block(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/transaction") => {
                self.handle_submit_transaction(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/block/hash/") => {
                self.handle_get_block_by_hash(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/block/") => {
                self.handle_get_block(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/validators") => {
                self.handle_get_validators(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/balance/") => {
                self.handle_get_balance(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/mempool") => {
                self.handle_get_mempool_status(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/transactions/pending") => {
                self.handle_get_pending_transactions(request).await
            }
            (ZhtpMethod::Get, path)
                if path.starts_with("/api/v1/blockchain/transaction/")
                    && path.ends_with("/receipt") =>
            {
                self.handle_get_transaction_receipt(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/transaction/") => {
                self.handle_get_transaction_by_hash(request).await
            }
            // Blockchain sync endpoints
            (ZhtpMethod::Get, "/api/v1/blockchain/export") => {
                self.handle_export_chain(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/import") => {
                self.handle_import_chain(request).await
            }
            // New incremental sync endpoints
            (ZhtpMethod::Get, "/api/v1/blockchain/tip") => self.handle_get_chain_tip(request).await,
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/blocks/") => {
                self.handle_get_block_range(request).await
            }
            // Edge node stats endpoint
            (ZhtpMethod::Get, "/api/v1/blockchain/edge-stats") => {
                self.handle_edge_stats(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/fee-config") => {
                self.handle_get_fee_config(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/transaction/estimate-fee") => {
                self.handle_estimate_transaction_fee(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/transaction/quote-fee") => {
                self.handle_quote_transaction_fee(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/transaction/broadcast") => {
                self.handle_broadcast_transaction(request).await
            }
            // Identity and Wallet Query endpoints (Phase 4)
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/identities/") => {
                self.handle_get_identity(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/wallets") => {
                self.handle_list_wallets(request).await
            }
            // Smart Contract endpoints
            (ZhtpMethod::Post, "/api/v1/blockchain/contracts/deploy") => {
                self.handle_deploy_contract(request).await
            }
            (ZhtpMethod::Post, path)
                if path.starts_with("/api/v1/blockchain/contracts/") && path.ends_with("/call") =>
            {
                self.handle_call_contract(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/contracts") => {
                self.handle_list_contracts(request).await
            }
            (ZhtpMethod::Get, path)
                if path.starts_with("/api/v1/blockchain/contracts/") && path.contains("/state") =>
            {
                self.handle_get_contract_state(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/contracts/") => {
                self.handle_get_contract_info(request).await
            }
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "Blockchain endpoint not found".to_string(),
            )),
        };

        match response {
            Ok(mut resp) => {
                resp.headers.set("X-Handler", "Blockchain".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());
                Ok(resp)
            }
            Err(e) => {
                tracing::error!("Blockchain handler error: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Blockchain error: {}", e),
                ))
            }
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/blockchain/")
    }

    fn priority(&self) -> u32 {
        90
    }
}

// Response structures
#[derive(Serialize)]
struct BlockchainStatusResponse {
    status: String,
    height: u64,
    latest_block_hash: String,
    total_transactions: u64,
    pending_transactions: usize,
    network_hash_rate: String,
    difficulty: u64,
}

#[derive(Serialize)]
struct BlockResponse {
    status: String,
    height: u64,
    hash: String,
    previous_hash: String,
    timestamp: u64,
    transaction_count: usize,
    merkle_root: String,
    nonce: u64,
}

#[derive(Serialize)]
struct BlockSummary {
    height: u64,
    hash: String,
    previous_hash: String,
    timestamp: u64,
    transaction_count: usize,
    merkle_root: String,
    nonce: u64,
}

#[derive(Serialize)]
struct PaginatedBlocksResponse {
    status: String,
    page: usize,
    limit: usize,
    total: usize,
    total_pages: usize,
    blocks: Vec<BlockSummary>,
}

#[derive(Serialize)]
struct TransactionSubmissionResponse {
    status: String,
    transaction_hash: String,
    message: String,
}

#[derive(Deserialize)]
struct SubmitTransactionRequest {
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    signature: String,
}

#[derive(Serialize)]
struct ValidatorsResponse {
    status: String,
    total_validators: usize,
    active_validators: usize,
    validators: Vec<ValidatorInfo>,
}

#[derive(Serialize)]
struct ValidatorInfo {
    address: String,
    stake: u64,
    is_active: bool,
    blocks_produced: u64,
    uptime_percentage: f64,
}

#[derive(Serialize)]
struct BalanceResponse {
    status: String,
    address: String,
    balance: u64,
    pending_balance: u64,
    transaction_count: u64,
    note: Option<String>,
}

#[derive(Serialize)]
struct MempoolStatusResponse {
    status: String,
    transaction_count: usize,
    total_fees: u64,
    total_size: usize,
    average_fee_rate: f64,
    min_fee_rate: u64,
    max_size: usize,
}

#[derive(Serialize)]
struct PendingTransactionsResponse {
    status: String,
    transaction_count: usize,
    transactions: Vec<TransactionInfo>,
}

#[derive(Serialize)]
struct TransactionInfo {
    hash: String,
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    transaction_type: String,
    timestamp: u64,
    size: usize,
}

#[derive(Serialize)]
struct PaginatedTransactionsResponse {
    status: String,
    page: usize,
    limit: usize,
    total: usize,
    total_pages: usize,
    transactions: Vec<TransactionInfo>,
}

#[derive(Serialize)]
struct ExplorerStatsResponse {
    status: String,
    latest_height: u64,
    latest_block_time: Option<u64>,
    total_transactions: u64,
    avg_block_time_secs: Option<u64>,
    total_supply: u64,
    total_ubi_distributed: u64,
    active_validators: usize,
    mempool_size: usize,
}

#[derive(Serialize)]
struct SearchResponse {
    status: String,
    query: String,
    result_type: Option<String>,
    result: Option<serde_json::Value>,
    message: Option<String>,
}

#[derive(Serialize)]
struct TransactionResponse {
    status: String,
    transaction: Option<TransactionInfo>,
    block_height: Option<u64>,
    confirmations: Option<u64>,
    in_mempool: bool,
}

#[derive(Serialize)]
struct FeeEstimateResponse {
    status: String,
    estimated_fee: u64,
    base_fee: u64,
    dao_fee: u64,
    total_fee: u64,
    transaction_size: usize,
    fee_rate: f64,
}

#[derive(Serialize)]
struct FeeConfigResponse {
    status: String,
    base_fee: u64,
    bytes_per_sov: u64,
    witness_cap: u32,
    updated_at_height: u64,
    chain_height: u64,
}

#[derive(Deserialize)]
struct FeeQuoteRequest {
    /// Hex-encoded bincode transaction (may be unsigned)
    transaction_hex: Option<String>,
    /// Optional direct size override
    transaction_size: Option<usize>,
}

#[derive(Serialize)]
struct FeeQuoteResponse {
    status: String,
    estimated_fee: u64,
    base_fee: u64,
    bytes_per_sov: u64,
    witness_cap: u32,
    transaction_size: usize,
}

#[derive(Serialize)]
struct BroadcastResponse {
    status: String,
    transaction_hash: String,
    message: String,
    accepted_to_mempool: bool,
}

#[derive(Serialize)]
struct TransactionReceiptResponse {
    status: String,
    transaction_hash: String,
    block_height: Option<u64>,
    block_hash: Option<String>,
    transaction_index: Option<usize>,
    confirmations: u64,
    timestamp: Option<u64>,
    gas_used: Option<u64>,
    success: bool,
    logs: Vec<String>,
}

#[derive(Serialize)]
struct ContractListItem {
    contract_id: String,
    contract_kind: String,
    block_height: Option<u64>,
}

#[derive(Serialize)]
struct ContractsListResponse {
    status: String,
    page: usize,
    limit: usize,
    total: usize,
    total_pages: usize,
    contracts: Vec<ContractListItem>,
}

#[derive(Serialize)]
struct ContractInfoResponse {
    status: String,
    contract_id: String,
    contract_kind: String,
    block_height: Option<u64>,
    metadata: serde_json::Value,
}

#[derive(Serialize)]
struct ContractStateResponse {
    status: String,
    contract_id: String,
    contract_kind: String,
    block_height: Option<u64>,
    state: serde_json::Value,
}

#[derive(Deserialize)]
struct FeeEstimateRequest {
    transaction_size: Option<usize>,
    amount: u64,
    priority: Option<String>, // "low", "medium", "high"
    is_system_transaction: Option<bool>,
}

#[derive(Deserialize)]
struct BroadcastTransactionRequest {
    transaction_data: String, // Hex-encoded transaction
}

#[derive(Deserialize)]
struct ContractTransactionRequest {
    transaction_data: String, // Hex-encoded canonical transaction
}

#[derive(Serialize)]
struct ContractSubmissionResponse {
    status: String,
    transaction_hash: String,
    message: String,
}

fn estimate_signed_tx_size(raw_tx: &[u8]) -> usize {
    match bincode::deserialize::<lib_blockchain::transaction::Transaction>(raw_tx) {
        Ok(mut tx) => {
            let sig_len = tx.signature.signature.len();
            let pk_len = tx.signature.public_key.dilithium_pk.len();
            if sig_len == 0 || pk_len == 0 {
                // Fill signature/public key with expected sizes for fee estimation.
                let (expected_sig, expected_pk) = match tx.signature.algorithm {
                    lib_crypto::types::SignatureAlgorithm::Dilithium5 => (4627usize, 2592usize),
                    _ => (2420usize, 1312usize), // Default to Dilithium2
                };
                tx.signature.signature = vec![0u8; expected_sig];
                tx.signature.public_key.dilithium_pk = vec![0u8; expected_pk];
            }
            bincode::serialize(&tx).map(|b| b.len()).unwrap_or(raw_tx.len())
        }
        Err(_) => raw_tx.len(),
    }
}

impl BlockchainHandler {
    fn decode_transaction_hex(hex_data: &str) -> Result<Transaction> {
        let tx_bytes = hex::decode(hex_data)
            .map_err(|_| anyhow::anyhow!("Invalid hex transaction data"))?;

        if let Ok(tx) = serde_json::from_slice::<Transaction>(&tx_bytes) {
            return Ok(tx);
        }

        bincode::deserialize::<Transaction>(&tx_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid transaction encoding (expected JSON or bincode)"))
    }

    async fn submit_canonical_contract_transaction(
        &self,
        request: ZhtpRequest,
        expected_type: TransactionType,
        success_message: &str,
    ) -> Result<ZhtpResponse> {
        let req_data: ContractTransactionRequest = serde_json::from_slice(&request.body)
            .map_err(|_| anyhow::anyhow!(
                "Invalid request body. Expected JSON: {{\"transaction_data\":\"<hex>\"}}"
            ))?;

        let transaction = Self::decode_transaction_hex(&req_data.transaction_data)?;

        if transaction.transaction_type != expected_type {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!(
                    "Expected {:?} transaction, got {:?}",
                    expected_type, transaction.transaction_type
                ),
            ));
        }

        let tx_hash = transaction.hash();
        let blockchain_arc = self.get_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;

        match blockchain.add_pending_transaction(transaction) {
            Ok(()) => {
                tracing::info!(
                    "Contract transaction accepted to mempool: {} ({:?})",
                    tx_hash,
                    expected_type
                );
                let response_data = ContractSubmissionResponse {
                    status: "accepted".to_string(),
                    transaction_hash: tx_hash.to_string(),
                    message: success_message.to_string(),
                };
                let json_response = serde_json::to_vec(&response_data)?;
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                tracing::warn!(
                    "Contract transaction rejected: {} ({:?}) error={}",
                    tx_hash,
                    expected_type,
                    e
                );
                Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Contract transaction {} rejected: {}", tx_hash, e),
                ))
            }
        }
    }

    fn parse_contract_id_hex(contract_id_hex: &str) -> Result<[u8; 32]> {
        let bytes = hex::decode(contract_id_hex)
            .map_err(|_| anyhow::anyhow!("Contract ID must be valid hex"))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Contract ID must be 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            ));
        }
        let mut contract_id = [0u8; 32];
        contract_id.copy_from_slice(&bytes);
        Ok(contract_id)
    }

    /// Handle blockchain status request
    async fn handle_blockchain_status(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let response_data = BlockchainStatusResponse {
            status: "active".to_string(),
            height: blockchain.get_height(),
            latest_block_hash: blockchain
                .latest_block()
                .map(|b| b.header.block_hash.to_string())
                .unwrap_or_else(|| "none".to_string()),
            total_transactions: blockchain
                .blocks
                .iter()
                .map(|block| block.transactions.len() as u64)
                .sum(),
            pending_transactions: blockchain.pending_transactions.len(),
            network_hash_rate: {
                // Calculate network hash rate from difficulty and work
                let work = blockchain.difficulty.work();
                let target_block_time = 600; // 10 minutes in seconds
                let hash_rate = work / target_block_time as u128;
                if hash_rate > 1_000_000_000_000 {
                    // TH/s
                    format!("{:.1} TH/s", hash_rate as f64 / 1_000_000_000_000.0)
                } else if hash_rate > 1_000_000_000 {
                    // GH/s
                    format!("{:.1} GH/s", hash_rate as f64 / 1_000_000_000.0)
                } else if hash_rate > 1_000_000 {
                    // MH/s
                    format!("{:.1} MH/s", hash_rate as f64 / 1_000_000.0)
                } else {
                    // H/s
                    format!("{} H/s", hash_rate)
                }
            },
            difficulty: blockchain.difficulty.bits() as u64,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle latest block request
    async fn handle_latest_block(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let latest_block = blockchain.latest_block();

        let response_data = if let Some(block) = latest_block {
            BlockResponse {
                status: "block_found".to_string(),
                height: block.header.height,
                hash: block.header.block_hash.to_string(),
                previous_hash: block.header.previous_block_hash.to_string(),
                timestamp: block.header.timestamp,
                transaction_count: block.transactions.len(),
                merkle_root: block.header.merkle_root.to_string(),
                nonce: block.header.nonce,
            }
        } else {
            BlockResponse {
                status: "no_blocks".to_string(),
                height: 0,
                hash: "none".to_string(),
                previous_hash: "none".to_string(),
                timestamp: 0,
                transaction_count: 0,
                merkle_root: "none".to_string(),
                nonce: 0,
            }
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle paginated block listing
    async fn handle_list_blocks(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let params = Self::parse_query_params(&request.uri);
        let (page, limit) = Self::parse_pagination(&params);

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let total = blockchain.blocks.len();

        let total_pages = if total == 0 {
            0
        } else {
            (total + limit - 1) / limit
        };

        let offset = (page - 1).saturating_mul(limit);
        let blocks = if offset >= total {
            Vec::new()
        } else {
            blockchain
                .blocks
                .iter()
                .rev()
                .skip(offset)
                .take(limit)
                .map(|block| BlockSummary {
                    height: block.header.height,
                    hash: block.header.block_hash.to_string(),
                    previous_hash: block.header.previous_block_hash.to_string(),
                    timestamp: block.header.timestamp,
                    transaction_count: block.transactions.len(),
                    merkle_root: block.header.merkle_root.to_string(),
                    nonce: block.header.nonce,
                })
                .collect()
        };

        let response_data = PaginatedBlocksResponse {
            status: "success".to_string(),
            page,
            limit,
            total,
            total_pages,
            blocks,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle paginated transaction listing (latest first, confirmed only)
    async fn handle_list_transactions(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let params = Self::parse_query_params(&request.uri);
        let (page, limit) = Self::parse_pagination(&params);

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let total: usize = blockchain.blocks.iter().map(|b| b.transactions.len()).sum();
        let total_pages = if total == 0 {
            0
        } else {
            (total + limit - 1) / limit
        };

        let offset = (page - 1).saturating_mul(limit);
        let mut skipped = 0usize;
        let mut transactions = Vec::new();

        for block in blockchain.blocks.iter().rev() {
            for tx in block.transactions.iter().rev() {
                if skipped < offset {
                    skipped += 1;
                    continue;
                }
                if transactions.len() >= limit {
                    break;
                }
                transactions.push(Self::tx_to_info(tx));
            }
            if transactions.len() >= limit {
                break;
            }
        }

        let response_data = PaginatedTransactionsResponse {
            status: "success".to_string(),
            page,
            limit,
            total,
            total_pages,
            transactions,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle explorer stats endpoint
    async fn handle_get_stats(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let total_transactions: u64 = blockchain
            .blocks
            .iter()
            .map(|b| b.transactions.len() as u64)
            .sum();

        let latest_height = blockchain.blocks.last().map(|b| b.header.height).unwrap_or(0);
        let latest_block_time = blockchain.blocks.last().map(|b| b.header.timestamp);

        let avg_block_time_secs = if blockchain.blocks.len() >= 2 {
            let mut total_delta = 0u64;
            for window in blockchain.blocks.windows(2) {
                let a = window[0].header.timestamp;
                let b = window[1].header.timestamp;
                total_delta = total_delta.saturating_add(b.saturating_sub(a));
            }
            Some(total_delta / (blockchain.blocks.len() as u64 - 1))
        } else {
            None
        };

        let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();
        let total_supply = blockchain
            .token_contracts
            .get(&sov_token_id)
            .map(|token| token.total_supply)
            .unwrap_or(0);

        let total_ubi_distributed: u64 = blockchain
            .ubi_registry
            .values()
            .map(|entry| entry.total_received)
            .sum();

        let active_validators = blockchain.get_active_validators().len();
        let mempool_size = blockchain.get_pending_transactions().len();

        let response_data = ExplorerStatsResponse {
            status: "success".to_string(),
            latest_height,
            latest_block_time,
            total_transactions,
            avg_block_time_secs,
            total_supply,
            total_ubi_distributed,
            active_validators,
            mempool_size,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle unified search endpoint with strict resolution order
    async fn handle_search(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let params = Self::parse_query_params(&request.uri);
        let query = params.get("q").cloned().unwrap_or_default();
        if query.trim().is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Search query (q) is required".to_string(),
            ));
        }

        let explicit_type = params.get("type").map(|s| s.to_lowercase());

        let mut search_type: Option<String> = None;
        let mut value = query.trim().to_string();

        if let Some(stripped) = Self::strip_prefix(&value, "tx") {
            search_type = Some("tx".to_string());
            value = stripped.to_string();
        } else if let Some(stripped) = Self::strip_prefix(&value, "blk") {
            search_type = Some("block".to_string());
            value = stripped.to_string();
        } else if let Some(stripped) = Self::strip_prefix(&value, "wal") {
            search_type = Some("wallet".to_string());
            value = stripped.to_string();
        } else if let Some(stripped) = Self::strip_prefix(&value, "did") {
            search_type = Some("did".to_string());
            value = stripped.to_string();
        }

        if let Some(explicit) = explicit_type {
            search_type = Some(explicit);
        }

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let latest_height = blockchain.blocks.last().map(|b| b.header.height).unwrap_or(0);

        let mut result_type: Option<String> = None;
        let mut result: Option<serde_json::Value> = None;
        let mut message: Option<String> = None;

        let resolve_tx = |tx_hash: &str| -> Option<serde_json::Value> {
            let tx_hash = Hash::from_hex(tx_hash).ok()?;
            let pending_txs = blockchain.get_pending_transactions();
            if let Some(pending_tx) = pending_txs.iter().find(|tx| tx.hash() == tx_hash) {
                return Some(serde_json::json!({
                    "transaction": Self::tx_to_info(pending_tx),
                    "in_mempool": true
                }));
            }

            for block in blockchain.blocks.iter().rev() {
                if let Some(tx) = block.transactions.iter().find(|tx| tx.hash() == tx_hash) {
                    let confirmations = latest_height.saturating_sub(block.header.height) + 1;
                    return Some(serde_json::json!({
                        "transaction": Self::tx_to_info(tx),
                        "block_height": block.header.height,
                        "confirmations": confirmations,
                        "in_mempool": false
                    }));
                }
            }
            None
        };

        let resolve_block = |block_hash: &str| -> Option<serde_json::Value> {
            let block = blockchain
                .blocks
                .iter()
                .find(|b| b.header.block_hash.to_string() == block_hash)?;
            Some(serde_json::json!({
                "height": block.header.height,
                "hash": block.header.block_hash.to_string(),
                "previous_hash": block.header.previous_block_hash.to_string(),
                "timestamp": block.header.timestamp,
                "transaction_count": block.transactions.len(),
                "merkle_root": block.header.merkle_root.to_string(),
                "nonce": block.header.nonce,
            }))
        };

        let resolve_wallet = |wallet_id: &str| -> Option<serde_json::Value> {
            let wallet = blockchain.wallet_registry.get(wallet_id)?;
            Some(serde_json::json!({
                "wallet_id": wallet_id,
                "wallet_name": wallet.wallet_name,
                "wallet_type": wallet.wallet_type,
                "alias": wallet.alias,
                "owner_identity_id": wallet.owner_identity_id,
                "capabilities": wallet.capabilities,
                "created_at": wallet.created_at,
            }))
        };

        let resolve_identity = |did: &str| -> Option<serde_json::Value> {
            let identity = blockchain.identity_registry.get(&did.to_string())?;
            Some(serde_json::json!({
                "did": identity.did,
                "display_name": identity.display_name,
                "identity_type": identity.identity_type,
                "registration_fee": identity.registration_fee,
                "created_at": identity.created_at,
                "controlled_nodes": identity.controlled_nodes,
                "owned_wallets": identity.owned_wallets,
            }))
        };

        if let Some(kind) = search_type.as_deref() {
            match kind {
                "tx" => {
                    result = resolve_tx(&value);
                    if result.is_some() {
                        result_type = Some("tx".to_string());
                    }
                }
                "block" => {
                    result = resolve_block(&value);
                    if result.is_some() {
                        result_type = Some("block".to_string());
                    }
                }
                "wallet" => {
                    result = resolve_wallet(&value);
                    if result.is_some() {
                        result_type = Some("wallet".to_string());
                    }
                }
                "did" => {
                    result = resolve_identity(&value);
                    if result.is_some() {
                        result_type = Some("did".to_string());
                    }
                }
                _ => {
                    message = Some("Unsupported search type. Use tx, block, wallet, did.".to_string());
                }
            }
        } else if Self::is_hex_64(&value) {
            result = if let Some(found) = resolve_tx(&value) {
                result_type = Some("tx".to_string());
                Some(found)
            } else if let Some(found) = resolve_block(&value) {
                result_type = Some("block".to_string());
                Some(found)
            } else {
                let wallet = resolve_wallet(&value);
                if wallet.is_some() {
                    result_type = Some("wallet".to_string());
                }
                wallet
            };
        } else {
            message = Some(
                "Ambiguous identifier. Specify type: tx, block, wallet, did".to_string(),
            );
        }

        if result.is_none() && message.is_none() {
            message = Some("No results found".to_string());
        }

        let response_data = SearchResponse {
            status: "success".to_string(),
            query,
            result_type,
            result,
            message,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle get block by hash (explicit)
    async fn handle_get_block_by_hash(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let block_hash = path_parts
            .get(6)
            .ok_or_else(|| anyhow::anyhow!("Block hash required"))?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let block = blockchain
            .blocks
            .iter()
            .find(|b| b.header.block_hash.to_string() == *block_hash);

        match block {
            Some(block) => {
                let response_data = BlockResponse {
                    status: "block_found".to_string(),
                    height: block.header.height,
                    hash: block.header.block_hash.to_string(),
                    previous_hash: block.header.previous_block_hash.to_string(),
                    timestamp: block.header.timestamp,
                    transaction_count: block.transactions.len(),
                    merkle_root: block.header.merkle_root.to_string(),
                    nonce: block.header.nonce,
                };

                let json_response = serde_json::to_vec(&response_data)?;
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            None => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Block {} not found", block_hash),
            )),
        }
    }

    /// Handle get specific block
    async fn handle_get_block(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract block identifier from path: /api/v1/blockchain/block/{id}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let block_id = path_parts
            .get(5)
            .ok_or_else(|| anyhow::anyhow!("Block ID required"))?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Try to parse as height first, then as hash
        let block = if let Ok(height) = block_id.parse::<u64>() {
            blockchain.get_block(height)
        } else {
            // For hash lookup, we'll need to search through blocks manually
            blockchain
                .blocks
                .iter()
                .find(|b| b.header.block_hash.to_string() == *block_id)
        };

        match block {
            Some(block) => {
                let response_data = BlockResponse {
                    status: "block_found".to_string(),
                    height: block.header.height,
                    hash: block.header.block_hash.to_string(),
                    previous_hash: block.header.previous_block_hash.to_string(),
                    timestamp: block.header.timestamp,
                    transaction_count: block.transactions.len(),
                    merkle_root: block.header.merkle_root.to_string(),
                    nonce: block.header.nonce,
                };

                let json_response = serde_json::to_vec(&response_data)?;
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            None => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Block {} not found", block_id),
            )),
        }
    }

    /// Handle transaction submission (P2P transfers with UTXO consumption)
    async fn handle_submit_transaction(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: SubmitTransactionRequest = serde_json::from_slice(&request.body)?;

        // Basic validation using all fields
        if req_data.amount == 0 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Transaction amount must be greater than zero".to_string(),
            ));
        }

        if req_data.from.is_empty() || req_data.to.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "From and to addresses must not be empty".to_string(),
            ));
        }

        if req_data.fee == 0 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Transaction fee must be greater than zero".to_string(),
            ));
        }

        if req_data.signature.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Transaction signature is required".to_string(),
            ));
        }

        // Create actual transaction using the provided fields
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        // Get current blockchain height for validation
        let current_height = blockchain.blocks.len();

        // Validate transaction isn't too old (should reference recent blocks)
        if current_height == 0 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Blockchain not initialized".to_string(),
            ));
        }

        tracing::info!(
            "Processing P2P transfer at blockchain height: {}",
            current_height
        );
        drop(blockchain); // Release read lock before creating transaction

        // Parse sender and recipient pubkeys
        let sender_pubkey = req_data.from.as_bytes().to_vec();
        let recipient_pubkey = req_data.to.as_bytes().to_vec();

        // Parse the provided signature (hex string)
        let signature_bytes = hex::decode(&req_data.signature)
            .context("Invalid signature hex")?;

        // Create transaction input (simplified - consuming from sender's wallet)
        let input = lib_blockchain::TransactionInput {
            previous_output: lib_blockchain::Hash::from_slice(&sender_pubkey),
            output_index: 0,
            nullifier: lib_blockchain::Hash::from_slice(&[0u8; 32]),
            zk_proof: lib_blockchain::integration::zk_integration::ZkTransactionProof::default(),
        };

        // Create transaction output (sending to recipient)
        let output = lib_blockchain::TransactionOutput {
            commitment: lib_blockchain::Hash::from_slice(&req_data.amount.to_le_bytes()),
            note: lib_blockchain::Hash::from_slice(&recipient_pubkey),
            recipient: lib_blockchain::integration::crypto_integration::PublicKey::new(
                recipient_pubkey.clone(),
            ),
        };

        // Use the provided signature (client must sign with their private key)
        let signature = lib_crypto::Signature {
            signature: signature_bytes, //  Use actual provided signature
            public_key: lib_crypto::PublicKey {
                dilithium_pk: sender_pubkey.clone(),
                kyber_pk: Vec::new(),
                key_id: [0u8; 32],
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Create transaction
        let transaction = lib_blockchain::transaction::Transaction::new(
            vec![input],
            vec![output],
            req_data.fee,
            signature,
            format!(
                "P2P Transfer {} SOV from {} to {}",
                req_data.amount, req_data.from, req_data.to
            )
            .as_bytes()
            .to_vec(),
        );

        // Generate transaction hash
        let tx_hash = transaction.hash();

        // Submit transaction to blockchain mempool
        let blockchain_arc = self
            .get_blockchain()
            .await
            .context("Failed to get blockchain")?;
        let mut blockchain_write = blockchain_arc.write().await;
        match blockchain_write.add_pending_transaction(transaction) {
            Ok(()) => {
                tracing::info!(
                    " P2P Transfer transaction {} added to mempool (amount: {} SOV)",
                    tx_hash,
                    req_data.amount
                );

                let response_data = TransactionSubmissionResponse {
                    status: "transaction_submitted".to_string(),
                    transaction_hash: tx_hash.to_string(),
                    message: format!(
                        "P2P transfer of {} SOV from {} to {} submitted to mempool",
                        req_data.amount, req_data.from, req_data.to
                    ),
                };

                let json_response = serde_json::to_vec(&response_data)?;
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                tracing::error!(
                    " Failed to add P2P transfer transaction to mempool: {}",
                    e
                );
                Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("P2P transfer transaction validation failed: {}", e),
                ))
            }
        }
    }

    /// Handle getting validators information from consensus system
    async fn handle_get_validators(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Get validators directly from blockchain validator_registry
        let all_validators = blockchain.get_all_validators();
        
        // Map validator info to API format
        let validators: Vec<ValidatorInfo> = all_validators
            .iter()
            .map(|(identity_id, v)| ValidatorInfo {
                address: identity_id.clone(), // DID or hex identity
                stake: v.stake,
                is_active: v.status == "active",
                blocks_produced: v.blocks_validated,
                uptime_percentage: {
                    // Calculate uptime as percentage (100% if active, 0% if not)
                    if v.status == "active" { 100.0 } else { 0.0 }
                },
            })
            .collect();

        let validators_info = ValidatorsResponse {
            status: "validators_found".to_string(),
            total_validators: validators.len(),
            active_validators: validators.iter().filter(|v| v.is_active).count(),
            validators,
        };

        let json_response = serde_json::to_vec(&validators_info)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle getting balance for an address
    async fn handle_get_balance(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract address from path: /api/v1/blockchain/balance/{address}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let address_str = path_parts
            .get(4)
            .ok_or_else(|| anyhow::anyhow!("Address required"))?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Try to parse address as hash for wallet balance lookup
        let balance_info = if let Ok(address_hash) = lib_crypto::Hash::from_hex(address_str) {
            let address_bytes = address_hash.as_bytes();

            // Convert slice to fixed-size array for get_wallet_balance
            let balance = if address_bytes.len() == 32 {
                let mut fixed_array = [0u8; 32];
                fixed_array.copy_from_slice(address_bytes);
                blockchain.get_wallet_balance(&fixed_array).unwrap_or(0)
            } else {
                0 // Invalid address length
            };

            // Get transaction count for this address
            let transactions = blockchain.get_transactions_for_address(address_str);

            // Pending balance is set to 0 due to privacy-preserving commitments
            // We cannot estimate pending balances when amounts are hidden via Pedersen commitments
            let pending_balance = 0u64;

            BalanceResponse {
                status: "balance_found".to_string(),
                address: address_str.to_string(),
                balance,
                pending_balance,
                transaction_count: transactions.len() as u64,
                note: Some("Pending balance unavailable due to privacy-preserving commitments".to_string()),
            }
        } else {
            BalanceResponse {
                status: "invalid_address_format".to_string(),
                address: address_str.to_string(),
                balance: 0,
                pending_balance: 0,
                transaction_count: 0,
                note: None,
            }
        };

        let json_response = serde_json::to_vec(&balance_info)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle mempool status request
    async fn handle_get_mempool_status(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Get pending transactions and calculate stats
        let pending_txs = blockchain.get_pending_transactions();
        let transaction_count = pending_txs.len();

        tracing::info!(
            "Mempool API: {} pending transactions in blockchain",
            transaction_count
        );

        // Calculate mempool statistics
        let total_fees: u64 = pending_txs.iter().map(|tx| tx.fee).sum();
        let total_size: usize = pending_txs.iter().map(|tx| tx.size()).sum();
        let average_fee_rate = if total_size > 0 {
            total_fees as f64 / total_size as f64
        } else {
            0.0
        };

        let response_data = MempoolStatusResponse {
            status: "success".to_string(),
            transaction_count,
            total_fees,
            total_size,
            average_fee_rate,
            min_fee_rate: 1, // Default minimum fee rate
            max_size: 10000, // Default max size
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle pending transactions request
    async fn handle_get_pending_transactions(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Get pending transactions from blockchain
        let pending_txs = blockchain.get_pending_transactions();

        // Convert to response format
        let transactions: Vec<TransactionInfo> = pending_txs
            .iter()
            .map(|tx| TransactionInfo {
                hash: tx.hash().to_string(),
                from: tx
                    .inputs
                    .first()
                    .map(|i| i.previous_output.to_string())
                    .unwrap_or_else(|| "genesis".to_string()),
                to: tx
                    .outputs
                    .first()
                    .map(|o| format!("{:02x?}", &o.recipient.key_id[..8]))
                    .unwrap_or_else(|| "unknown".to_string()),
                amount: 0, // Amount is hidden in commitment for privacy
                fee: tx.fee,
                transaction_type: format!("{:?}", tx.transaction_type),
                timestamp: tx.signature.timestamp,
                size: tx.size(),
            })
            .collect();

        let response_data = PendingTransactionsResponse {
            status: "success".to_string(),
            transaction_count: transactions.len(),
            transactions,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle get transaction by hash request
    async fn handle_get_transaction_by_hash(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract transaction hash from path: /api/v1/blockchain/transaction/{hash}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let tx_hash_str = path_parts
            .get(5)
            .ok_or_else(|| anyhow::anyhow!("Transaction hash required"))?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Try to parse the hash
        let tx_hash = match Hash::from_hex(tx_hash_str) {
            Ok(hash) => hash,
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid transaction hash format: {}", tx_hash_str),
                ));
            }
        };

        // First check pending transactions (mempool)
        let pending_txs = blockchain.get_pending_transactions();
        if let Some(pending_tx) = pending_txs.iter().find(|tx| tx.hash() == tx_hash) {
            let transaction_info = TransactionInfo {
                hash: pending_tx.hash().to_string(),
                from: pending_tx
                    .inputs
                    .first()
                    .map(|i| i.previous_output.to_string())
                    .unwrap_or_else(|| "genesis".to_string()),
                to: pending_tx
                    .outputs
                    .first()
                    .map(|o| format!("{:02x?}", &o.recipient.key_id[..8]))
                    .unwrap_or_else(|| "unknown".to_string()),
                amount: 0, // Amount is hidden in commitment for privacy
                fee: pending_tx.fee,
                transaction_type: format!("{:?}", pending_tx.transaction_type),
                timestamp: pending_tx.signature.timestamp,
                size: pending_tx.size(),
            };

            let response_data = TransactionResponse {
                status: "transaction_found".to_string(),
                transaction: Some(transaction_info),
                block_height: None,
                confirmations: None,
                in_mempool: true,
            };

            let json_response = serde_json::to_vec(&response_data)?;
            return Ok(ZhtpResponse::success_with_content_type(
                json_response,
                "application/json".to_string(),
                None,
            ));
        }

        // Search through all blocks for the transaction
        for (_block_index, block) in blockchain.blocks.iter().enumerate() {
            if let Some(confirmed_tx) = block.transactions.iter().find(|tx| tx.hash() == tx_hash) {
                let transaction_info = TransactionInfo {
                    hash: confirmed_tx.hash().to_string(),
                    from: confirmed_tx
                        .inputs
                        .first()
                        .map(|i| i.previous_output.to_string())
                        .unwrap_or_else(|| "genesis".to_string()),
                    to: confirmed_tx
                        .outputs
                        .first()
                        .map(|o| format!("{:02x?}", &o.recipient.key_id[..8]))
                        .unwrap_or_else(|| "unknown".to_string()),
                    amount: 0, // Amount is hidden in commitment for privacy
                    fee: confirmed_tx.fee,
                    transaction_type: format!("{:?}", confirmed_tx.transaction_type),
                    timestamp: confirmed_tx.signature.timestamp,
                    size: confirmed_tx.size(),
                };

                let block_height = block.header.height;
                let confirmations = blockchain.get_height().saturating_sub(block_height);

                let response_data = TransactionResponse {
                    status: "transaction_found".to_string(),
                    transaction: Some(transaction_info),
                    block_height: Some(block_height),
                    confirmations: Some(confirmations),
                    in_mempool: false,
                };

                let json_response = serde_json::to_vec(&response_data)?;
                return Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ));
            }
        }

        // Transaction not found
        let response_data = TransactionResponse {
            status: "transaction_not_found".to_string(),
            transaction: None,
            block_height: None,
            confirmations: None,
            in_mempool: false,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle transaction fee estimation request
    async fn handle_estimate_transaction_fee(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: FeeEstimateRequest = serde_json::from_slice(&request.body)?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Use provided transaction size or estimate a typical size
        let tx_size = req_data.transaction_size.unwrap_or(250); // Typical transaction size

        let is_system = req_data.is_system_transaction.unwrap_or(false);

        // Calculate fees using the canonical chain fee model
        let fee_config = blockchain.get_tx_fee_config();
        let min_fee = lib_blockchain::transaction::creation::utils::calculate_minimum_fee_with_config(
            tx_size,
            fee_config,
        );
        let base_fee = min_fee;
        let dao_fee = 0;
        let total_fee = if is_system { 0 } else { min_fee };

        // Calculate fee rate (fee per byte)
        let fee_rate = if tx_size > 0 {
            total_fee as f64 / tx_size as f64
        } else {
            0.0
        };

        let response_data = FeeEstimateResponse {
            status: "success".to_string(),
            estimated_fee: total_fee,
            base_fee,
            dao_fee,
            total_fee,
            transaction_size: tx_size,
            fee_rate,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle fee configuration fetch
    async fn handle_get_fee_config(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let fee_config = blockchain.get_tx_fee_config();

        let response_data = FeeConfigResponse {
            status: "success".to_string(),
            base_fee: fee_config.base_fee,
            bytes_per_sov: fee_config.bytes_per_sov,
            witness_cap: fee_config.witness_cap,
            updated_at_height: blockchain.tx_fee_config_updated_at_height,
            chain_height: blockchain.get_height(),
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle fee quote request using canonical chain fee config
    async fn handle_quote_transaction_fee(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: FeeQuoteRequest = serde_json::from_slice(&request.body)?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;
        let fee_config = blockchain.get_tx_fee_config();

        let tx_size = if let Some(hex_tx) = req_data.transaction_hex.as_ref() {
            match hex::decode(hex_tx) {
                Ok(bytes) => estimate_signed_tx_size(&bytes),
                Err(_) => req_data.transaction_size.unwrap_or(250),
            }
        } else {
            req_data.transaction_size.unwrap_or(250)
        };

        let min_fee = lib_blockchain::transaction::creation::utils::calculate_minimum_fee_with_config(
            tx_size,
            fee_config,
        );

        let response_data = FeeQuoteResponse {
            status: "success".to_string(),
            estimated_fee: min_fee,
            base_fee: fee_config.base_fee,
            bytes_per_sov: fee_config.bytes_per_sov,
            witness_cap: fee_config.witness_cap,
            transaction_size: tx_size,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle transaction broadcast request
    async fn handle_broadcast_transaction(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: BroadcastTransactionRequest = serde_json::from_slice(&request.body)?;

        // For now, we'll create a simple transaction from the hex data
        // In a implementation, you'd deserialize the hex data into a Transaction
        let blockchain_arc = self
            .get_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get blockchain: {}", e))?;
        let mut blockchain = blockchain_arc.write().await;

        // Parse the hex transaction data into a Transaction
        let transaction = match hex::decode(&req_data.transaction_data) {
            Ok(tx_bytes) => {
                match serde_json::from_slice::<lib_blockchain::transaction::Transaction>(&tx_bytes)
                {
                    Ok(tx) => tx,
                    Err(_) => {
                        // If JSON parsing fails, try bincode deserialization
                        match bincode::deserialize::<lib_blockchain::transaction::Transaction>(
                            &tx_bytes,
                        ) {
                            Ok(tx) => tx,
                            Err(_) => {
                                // If both fail, return error
                                return Ok(ZhtpResponse::error(
                                    lib_protocols::ZhtpStatus::BadRequest,
                                    "Invalid transaction data format".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Invalid hex data
                return Ok(ZhtpResponse::error(
                    lib_protocols::ZhtpStatus::BadRequest,
                    "Invalid hex data".to_string(),
                ));
            }
        };

        let tx_hash = transaction.hash();

        // Try to add transaction to pending pool
        let accepted = match blockchain.add_pending_transaction(transaction) {
            Ok(()) => {
                tracing::info!("Transaction {} accepted to mempool", tx_hash);
                true
            }
            Err(e) => {
                tracing::warn!("Transaction {} rejected: {}", tx_hash, e);
                false
            }
        };

        let response_data = BroadcastResponse {
            status: if accepted { "success" } else { "rejected" }.to_string(),
            transaction_hash: tx_hash.to_string(),
            message: if accepted {
                "Transaction successfully broadcast to network".to_string()
            } else {
                "Transaction validation failed".to_string()
            },
            accepted_to_mempool: accepted,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle transaction receipt request
    async fn handle_get_transaction_receipt(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract transaction hash from path: /api/v1/blockchain/transaction/{hash}/receipt
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let tx_hash_str = path_parts
            .get(5)
            .ok_or_else(|| anyhow::anyhow!("Transaction hash required"))?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Try to parse the hash
        let tx_hash = match Hash::from_hex(tx_hash_str) {
            Ok(hash) => hash,
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid transaction hash format: {}", tx_hash_str),
                ));
            }
        };

        // First, try to get the receipt from the receipt storage (if available)
        if let Some(receipt) = blockchain.get_receipt(&tx_hash) {
            let response_data = serde_json::json!({
                "status": "receipt_found",
                "transaction_hash": hex::encode(receipt.tx_hash.as_bytes()),
                "block_height": receipt.block_height,
                "block_hash": hex::encode(receipt.block_hash.as_bytes()),
                "transaction_index": receipt.tx_index,
                "fee_paid": receipt.fee_paid,
                "confirmations": receipt.confirmations,
                "timestamp": receipt.timestamp,
                "status_text": format!("{}", receipt.status),
                "is_finalized": receipt.is_finalized(),
                "logs": receipt.logs,
            });

            let json_response = serde_json::to_vec(&response_data)?;
            return Ok(ZhtpResponse::success_with_content_type(
                json_response,
                "application/json".to_string(),
                None,
            ));
        }

        // Fallback: Search through all blocks for the transaction (for backward compatibility)
        for (_block_index, block) in blockchain.blocks.iter().enumerate() {
            if let Some((tx_index, confirmed_tx)) = block
                .transactions
                .iter()
                .enumerate()
                .find(|(_, tx)| tx.hash() == tx_hash)
            {
                let block_height = block.header.height;
                let current_height = blockchain.get_height();
                let confirmations = current_height.saturating_sub(block_height);

                let response_data = TransactionReceiptResponse {
                    status: "receipt_found".to_string(),
                    transaction_hash: tx_hash.to_string(),
                    block_height: Some(block_height),
                    block_hash: Some(block.header.block_hash.to_string()),
                    transaction_index: Some(tx_index),
                    confirmations,
                    timestamp: Some(block.header.timestamp),
                    gas_used: Some(confirmed_tx.fee), // Using fee as gas_used equivalent
                    success: true,                    // Assume success if in block
                    logs: vec![
                        format!("Transaction confirmed in block {}", block_height),
                        format!("Fee paid: {} SOV", confirmed_tx.fee),
                        format!("Transaction type: {:?}", confirmed_tx.transaction_type),
                    ],
                };

                let json_response = serde_json::to_vec(&response_data)?;
                return Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ));
            }
        }

        // Check if transaction is in mempool (pending)
        let pending_txs = blockchain.get_pending_transactions();
        if pending_txs.iter().any(|tx| tx.hash() == tx_hash) {
            let response_data = TransactionReceiptResponse {
                status: "pending".to_string(),
                transaction_hash: tx_hash.to_string(),
                block_height: None,
                block_hash: None,
                transaction_index: None,
                confirmations: 0,
                timestamp: None,
                gas_used: None,
                success: false, // Not yet confirmed
                logs: vec![
                    "Transaction is pending in mempool".to_string(),
                    "Waiting for block confirmation".to_string(),
                ],
            };

            let json_response = serde_json::to_vec(&response_data)?;
            return Ok(ZhtpResponse::success_with_content_type(
                json_response,
                "application/json".to_string(),
                None,
            ));
        }

        // Transaction not found
        let response_data = TransactionReceiptResponse {
            status: "receipt_not_found".to_string(),
            transaction_hash: tx_hash.to_string(),
            block_height: None,
            block_hash: None,
            transaction_index: None,
            confirmations: 0,
            timestamp: None,
            gas_used: None,
            success: false,
            logs: vec!["Transaction not found in blockchain or mempool".to_string()],
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
}

// REMOVED: calculate_pending_balance_for_address function
// This function used arbitrary multipliers to estimate pending balances, which:
// 1. Had no cryptographic foundation
// 2. Defeated privacy-preserving commitments by revealing estimates
// 3. Provided misleading information to users
// 4. Created a potential social engineering vector
//
// Pending balances are now properly set to 0 with a clear note about
// privacy-preserving commitments, rather than using fake estimates.

// ============================================================================
// SMART CONTRACT HANDLERS
// ============================================================================

impl BlockchainHandler {
    /// Deploy a new smart contract
    async fn handle_deploy_contract(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        self.submit_canonical_contract_transaction(
            request,
            TransactionType::ContractDeployment,
            "Contract deployment transaction accepted to mempool",
        ).await
    }

    /// Call a smart contract function
    async fn handle_call_contract(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        self.submit_canonical_contract_transaction(
            request,
            TransactionType::ContractExecution,
            "Contract execution transaction accepted to mempool",
        ).await
    }

    /// List all deployed contracts
    async fn handle_list_contracts(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let params = Self::parse_query_params(&request.uri);
        let (page, limit) = Self::parse_pagination(&params);
        let contract_filter = params
            .get("type")
            .map(|v| v.to_ascii_lowercase())
            .unwrap_or_else(|| "all".to_string());

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let mut contracts = Vec::new();
        if contract_filter == "all" || contract_filter == "token" {
            contracts.extend(blockchain.token_contracts.keys().map(|id| ContractListItem {
                contract_id: hex::encode(id),
                contract_kind: "token".to_string(),
                block_height: blockchain.contract_blocks.get(id).copied(),
            }));
        }
        if contract_filter == "all" || contract_filter == "web4" {
            contracts.extend(blockchain.web4_contracts.keys().map(|id| ContractListItem {
                contract_id: hex::encode(id),
                contract_kind: "web4".to_string(),
                block_height: blockchain.contract_blocks.get(id).copied(),
            }));
        }

        contracts.sort_by(|a, b| {
            a.contract_kind
                .cmp(&b.contract_kind)
                .then_with(|| a.contract_id.cmp(&b.contract_id))
        });

        let total = contracts.len();
        let total_pages = if total == 0 {
            0
        } else {
            (total + limit - 1) / limit
        };
        let offset = (page - 1).saturating_mul(limit);
        let contracts = if offset >= total {
            Vec::new()
        } else {
            contracts.into_iter().skip(offset).take(limit).collect()
        };

        let response_data = ContractsListResponse {
            status: "success".to_string(),
            page,
            limit,
            total,
            total_pages,
            contracts,
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Get contract state
    async fn handle_get_contract_state(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path = request.uri.split('?').next().unwrap_or(&request.uri);
        let path_parts: Vec<&str> = path.split('/').collect();
        let contract_id_hex = match path_parts.get(5) {
            Some(v) if !v.is_empty() => *v,
            _ => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Contract ID is required in /api/v1/blockchain/contracts/{id}/state".to_string(),
                ))
            }
        };

        let contract_id = match Self::parse_contract_id_hex(contract_id_hex) {
            Ok(id) => id,
            Err(e) => return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, e.to_string())),
        };

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let block_height = blockchain.contract_blocks.get(&contract_id).copied();
        let (contract_kind, state_json) = if let Some(token) = blockchain.token_contracts.get(&contract_id)
        {
            let raw_state = blockchain
                .get_contract_state(&contract_id)
                .map(hex::encode)
                .unwrap_or_default();
            (
                "token".to_string(),
                serde_json::json!({
                    "name": token.name,
                    "symbol": token.symbol,
                    "decimals": token.decimals,
                    "total_supply": token.total_supply,
                    "max_supply": token.max_supply,
                    "holder_count": token.balances.len(),
                    "raw_state_hex": raw_state,
                }),
            )
        } else if let Some(web4) = blockchain.web4_contracts.get(&contract_id) {
            let raw_state = blockchain
                .get_contract_state(&contract_id)
                .map(hex::encode)
                .unwrap_or_default();
            (
                "web4".to_string(),
                serde_json::json!({
                    "domain": web4.domain,
                    "owner": web4.owner,
                    "route_count": web4.routes.len(),
                    "created_at": web4.created_at,
                    "updated_at": web4.updated_at,
                    "raw_state_hex": raw_state,
                }),
            )
        } else {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Contract {} not found", contract_id_hex),
            ));
        };

        let response_data = ContractStateResponse {
            status: "success".to_string(),
            contract_id: contract_id_hex.to_string(),
            contract_kind,
            block_height,
            state: state_json,
        };
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Get contract information
    async fn handle_get_contract_info(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path = request.uri.split('?').next().unwrap_or(&request.uri);
        let path_parts: Vec<&str> = path.split('/').collect();
        let contract_id_hex = match path_parts.get(5) {
            Some(v) if !v.is_empty() => *v,
            _ => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Contract ID is required in /api/v1/blockchain/contracts/{id}".to_string(),
                ))
            }
        };

        let contract_id = match Self::parse_contract_id_hex(contract_id_hex) {
            Ok(id) => id,
            Err(e) => return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, e.to_string())),
        };

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        let block_height = blockchain.contract_blocks.get(&contract_id).copied();
        let (contract_kind, metadata) = if let Some(token) = blockchain.token_contracts.get(&contract_id) {
            (
                "token".to_string(),
                serde_json::json!({
                    "token_id": hex::encode(token.token_id),
                    "name": token.name,
                    "symbol": token.symbol,
                    "decimals": token.decimals,
                    "max_supply": token.max_supply,
                    "is_deflationary": token.is_deflationary,
                    "kernel_only_mode": token.kernel_only_mode,
                }),
            )
        } else if let Some(web4) = blockchain.web4_contracts.get(&contract_id) {
            (
                "web4".to_string(),
                serde_json::json!({
                    "contract_id": web4.contract_id,
                    "domain": web4.domain,
                    "owner": web4.owner,
                    "route_count": web4.routes.len(),
                    "created_at": web4.created_at,
                    "updated_at": web4.updated_at,
                }),
            )
        } else {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Contract {} not found", contract_id_hex),
            ));
        };

        let response_data = ContractInfoResponse {
            status: "success".to_string(),
            contract_id: contract_id_hex.to_string(),
            contract_kind,
            block_height,
            metadata,
        };
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Export entire blockchain for sync
    async fn handle_export_chain(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let blockchain_arc = self
            .get_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get blockchain: {}", e))?;
        let blockchain = blockchain_arc.read().await;
        let exported_data = blockchain
            .export_chain()
            .map_err(|e| anyhow::anyhow!("Failed to export blockchain: {}", e))?;

        tracing::info!(" Exported blockchain: {} bytes", exported_data.len());

        Ok(ZhtpResponse::success_with_content_type(
            exported_data,
            "application/octet-stream".to_string(),
            None,
        ))
    }

    /// Import blockchain from another node
    async fn handle_import_chain(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Validate that body is not empty
        if request.body.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Import requires blockchain data from /api/v1/blockchain/export endpoint".to_string(),
            ));
        }

        let blockchain_arc = self
            .get_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get blockchain: {}", e))?;
        let mut blockchain = blockchain_arc.write().await;

        // Try to import - if deserialization fails, return 400 not 500
        match blockchain.evaluate_and_merge_chain(request.body).await {
            Ok(_) => {},
            Err(e) => {
                let err_msg = e.to_string();
                // Deserialization errors are client errors (400), not server errors (500)
                if err_msg.contains("deserialize") || err_msg.contains("io error") {
                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::BadRequest,
                        format!("Invalid blockchain data format: {}", err_msg),
                    ));
                }
                return Err(anyhow::anyhow!("Failed to import blockchain: {}", e));
            }
        }

        #[derive(Serialize)]
        struct ImportResponse {
            status: String,
            message: String,
            block_height: usize,
        }

        let response_data = ImportResponse {
            status: "success".to_string(),
            message: "Blockchain imported successfully".to_string(),
            block_height: blockchain.blocks.len(),
        };

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Get chain tip info (height and head hash) for incremental sync
    async fn handle_get_chain_tip(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let blockchain_arc = self
            .get_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get blockchain: {}", e))?;
        let blockchain = blockchain_arc.read().await;

        #[derive(Serialize)]
        struct ChainTipInfo {
            height: u64,
            head_hash: String,
            total_work: String,
            validator_count: usize,
            identity_count: usize,
            genesis_hash: String,
        }

        let head_hash = blockchain
            .blocks
            .last()
            .map(|b| hex::encode(b.header.block_hash.as_bytes()))
            .unwrap_or_else(|| "none".to_string());

        let genesis_hash = blockchain
            .blocks
            .first()
            .map(|b| hex::encode(b.header.merkle_root.as_bytes()))
            .unwrap_or_else(|| "none".to_string());

        let tip_info = ChainTipInfo {
            height: blockchain.height,
            head_hash,
            total_work: blockchain.total_work.to_string(),
            validator_count: blockchain.validator_registry.len(),
            identity_count: blockchain.identity_registry.len(),
            genesis_hash,
        };

        let json_response = serde_json::to_vec(&tip_info)?;
        tracing::info!(
            " Served chain tip: height={}, identities={}, validators={}",
            tip_info.height,
            tip_info.identity_count,
            tip_info.validator_count
        );

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Get block range for incremental sync (e.g., /blocks/10/20 returns blocks 10-20)
    async fn handle_get_block_range(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Parse start/end from URI: /api/v1/blockchain/blocks/{start}/{end}
        let parts: Vec<&str> = request.uri.split('/').collect();
        if parts.len() < 7 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid block range format. Use: /api/v1/blockchain/blocks/{start}/{end}"
                    .to_string(),
            ));
        }

        let start: u64 = parts[5]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid start block number"))?;
        let end: u64 = parts[6]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid end block number"))?;

        if end < start {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "End block must be >= start block".to_string(),
            ));
        }

        if end - start > 1000 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Block range too large (max 1000 blocks per request)".to_string(),
            ));
        }

        let blockchain_arc = self
            .get_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get blockchain: {}", e))?;
        let blockchain = blockchain_arc.read().await;

        // Validate range is within chain
        if start as usize >= blockchain.blocks.len() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!(
                    "Start block {} beyond chain height {}",
                    start, blockchain.height
                ),
            ));
        }

        let actual_end = std::cmp::min(end as usize, blockchain.blocks.len() - 1);
        let blocks_slice = &blockchain.blocks[start as usize..=actual_end];

        // Serialize blocks
        let serialized_blocks = bincode::serialize(blocks_slice)
            .map_err(|e| anyhow::anyhow!("Failed to serialize blocks: {}", e))?;

        tracing::info!(
            " Serving blocks {}-{} ({} blocks, {} bytes)",
            start,
            actual_end,
            blocks_slice.len(),
            serialized_blocks.len()
        );

        Ok(ZhtpResponse::success_with_content_type(
            serialized_blocks,
            "application/octet-stream".to_string(),
            None,
        ))
    }

    /// Get edge node statistics and sync status
    async fn handle_edge_stats(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let blockchain_arc = self
            .get_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get blockchain: {}", e))?;
        let blockchain = blockchain_arc.read().await;

        #[derive(Serialize)]
        struct EdgeNodeStats {
            mode: String,
            current_height: u64,
            headers_stored: usize,
            storage_bytes: usize,
            utxos_tracked: usize,
            network_height: u64,
            sync_complete: bool,
            last_sync: u64,
            sync_method: String,
        }

        // Calculate statistics
        let current_height = blockchain.get_height();
        let headers_count = blockchain.blocks.len();

        // Estimate storage: ~200 bytes per header
        let storage_bytes = headers_count * 200;

        // Count UTXOs
        let utxos_tracked = blockchain.utxo_set.len();

        // Network height is same as current height in this context
        // In a full implementation, this would query other peers
        let network_height = current_height;

        // Sync is complete if we have blocks
        let sync_complete = headers_count > 0;

        // Last sync timestamp (use latest block timestamp if available)
        let last_sync = blockchain
            .blocks
            .last()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);

        let stats = EdgeNodeStats {
            mode: "edge".to_string(),
            current_height,
            headers_stored: headers_count,
            storage_bytes,
            utxos_tracked,
            network_height,
            sync_complete,
            last_sync,
            sync_method: "ble".to_string(),
        };

        tracing::info!(
            " Edge node stats: height={}, headers={}, storage={}KB, utxos={}",
            stats.current_height,
            stats.headers_stored,
            stats.storage_bytes / 1024,
            stats.utxos_tracked
        );

        let json_response = serde_json::to_vec(&stats)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Get identity by DID
    async fn handle_get_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract DID from path: /api/v1/blockchain/identities/{did}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let did = path_parts
            .get(5)
            .ok_or_else(|| anyhow::anyhow!("DID required"))?;

        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Query identity from registry
        if let Some(identity) = blockchain.identity_registry.get(&did.to_string()) {
            let response_data = serde_json::json!({
                "status": "identity_found",
                "did": identity.did,
                "display_name": identity.display_name,
                "identity_type": identity.identity_type,
                "registration_fee": identity.registration_fee,
                "created_at": identity.created_at,
                "controlled_nodes": identity.controlled_nodes,
                "owned_wallets": identity.owned_wallets,
            });

            let json_response = serde_json::to_vec(&response_data)?;
            return Ok(ZhtpResponse::success_with_content_type(
                json_response,
                "application/json".to_string(),
                None,
            ));
        }

        // Identity not found
        let response_data = serde_json::json!({
            "status": "identity_not_found",
            "did": did,
            "message": format!("Identity not found for DID: {}", did),
        });

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// List wallets, optionally filtered by owner identity
    async fn handle_list_wallets(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain_arc = self.get_blockchain().await?;
        let blockchain = blockchain_arc.read().await;

        // Try to parse owner filter from query parameters if present
        let owner_filter = if let Some(query_pos) = request.uri.find('?') {
            let query_part = &request.uri[query_pos + 1..];
            if query_part.starts_with("owner_identity=") {
                let owner_str = &query_part[15..];
                Some(owner_str.to_string())
            } else {
                None
            }
        } else {
            None
        };

        // Collect wallets, optionally filtering by owner_identity_id
        let wallets: Vec<serde_json::Value> = blockchain
            .wallet_registry
            .iter()
            .filter(|(_, wallet)| {
                if let Some(ref owner_id) = owner_filter {
                    if let Some(wallet_owner) = &wallet.owner_identity_id {
                        wallet_owner.to_string() == *owner_id
                    } else {
                        false
                    }
                } else {
                    true
                }
            })
            .map(|(wallet_id, wallet)| {
                serde_json::json!({
                    "wallet_id": wallet_id,
                    "wallet_name": wallet.wallet_name,
                    "wallet_type": wallet.wallet_type,
                    "alias": wallet.alias,
                    "owner_identity_id": wallet.owner_identity_id,
                    "capabilities": wallet.capabilities,
                    "created_at": wallet.created_at,
                })
            })
            .collect();

        let response_data = serde_json::json!({
            "status": "success",
            "wallet_count": wallets.len(),
            "owner_filter": owner_filter,
            "wallets": wallets,
        });

        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
}
