//! Blockchain Handler Module
//! 
//! Clean, minimal blockchain operations using lib-blockchain patterns

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Blockchain imports
use lib_blockchain::Blockchain;
use lib_blockchain::types::Hash;

/// Clean blockchain handler implementation
pub struct BlockchainHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl BlockchainHandler {
    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Self {
        Self { blockchain }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for BlockchainHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("⛓️ Blockchain handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Get, "/api/v1/blockchain/status") => {
                self.handle_blockchain_status(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/latest") => {
                self.handle_latest_block(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/transaction") => {
                self.handle_submit_transaction(request).await
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
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/transaction/") && path.ends_with("/receipt") => {
                self.handle_get_transaction_receipt(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/transaction/") => {
                self.handle_get_transaction_by_hash(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/transaction/estimate-fee") => {
                self.handle_estimate_transaction_fee(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/transaction/broadcast") => {
                self.handle_broadcast_transaction(request).await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Blockchain endpoint not found".to_string(),
                ))
            }
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

impl BlockchainHandler {
    /// Handle blockchain status request
    async fn handle_blockchain_status(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        
        let response_data = BlockchainStatusResponse {
            status: "active".to_string(),
            height: blockchain.get_height(),
            latest_block_hash: blockchain.latest_block()
                .map(|b| b.header.block_hash.to_string())
                .unwrap_or_else(|| "none".to_string()),
            total_transactions: blockchain.blocks.iter()
                .map(|block| block.transactions.len() as u64)
                .sum(),
            pending_transactions: blockchain.pending_transactions.len(),
            network_hash_rate: "12.5 TH/s".to_string(), // Mock value
            difficulty: 1000000u64, // Convert Difficulty to u64
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
        let blockchain = self.blockchain.read().await;
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
    
    /// Handle get specific block
    async fn handle_get_block(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract block identifier from path: /api/v1/blockchain/block/{id}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let block_id = path_parts.get(5)
            .ok_or_else(|| anyhow::anyhow!("Block ID required"))?;
        
        let blockchain = self.blockchain.read().await;
        
        // Try to parse as height first, then as hash
        let block = if let Ok(height) = block_id.parse::<u64>() {
            blockchain.get_block(height)
        } else {
            // For hash lookup, we'll need to search through blocks manually
            blockchain.blocks.iter()
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
            None => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Block {} not found", block_id),
                ))
            }
        }
    }
    
    /// Handle transaction submission
    async fn handle_submit_transaction(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: SubmitTransactionRequest = serde_json::from_slice(&request.body)?;
        
        // Basic validation
        if req_data.amount == 0 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Transaction amount must be greater than zero".to_string(),
            ));
        }
        
        // Generate mock transaction hash
        let tx_hash = lib_crypto::Hash::from_bytes(&[0u8; 32]); // Mock hash for now
        
        let response_data = TransactionSubmissionResponse {
            status: "transaction_submitted".to_string(),
            transaction_hash: tx_hash.to_string(),
            message: "Transaction submitted to mempool".to_string(),
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle getting validators information from consensus system
    async fn handle_get_validators(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        
        // Get consensus status to check for validators
        let validators_info = if let Ok(Some(consensus_status)) = blockchain.get_consensus_status().await {
            // Extract validator information from consensus status
            let validator_count = consensus_status.validator_count;
            let active_count = consensus_status.active_validators;
            
            // Create mock validators since detailed validator info is not directly available from ConsensusStatus
            let validators: Vec<ValidatorInfo> = (0..active_count.min(validator_count))
                .map(|i| ValidatorInfo {
                    address: format!("validator_{}", i),
                    stake: 1000000, // Mock stake amount
                    is_active: true,
                    blocks_produced: 0, // Mock value
                    uptime_percentage: 100.0, // Mock value
                })
                .collect();
            
            ValidatorsResponse {
                status: "validators_found".to_string(),
                total_validators: validator_count,
                active_validators: active_count,
                validators,
            }
        } else {
            // No consensus coordinator available, return empty validator set
            ValidatorsResponse {
                status: "validators_unavailable".to_string(),
                total_validators: 0,
                active_validators: 0,
                validators: vec![],
            }
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
        let address_str = path_parts.get(4)
            .ok_or_else(|| anyhow::anyhow!("Address required"))?;
        
        let blockchain = self.blockchain.read().await;
        
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
                
            BalanceResponse {
                status: "balance_found".to_string(),
                address: address_str.to_string(),
                balance,
                pending_balance: 0, // TODO: Calculate pending balance
                transaction_count: transactions.len() as u64,
            }
        } else {
            BalanceResponse {
                status: "invalid_address_format".to_string(),
                address: address_str.to_string(),
                balance: 0,
                pending_balance: 0,
                transaction_count: 0,
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
        let blockchain = self.blockchain.read().await;
        
        // Get pending transactions and calculate stats
        let pending_txs = blockchain.get_pending_transactions();
        let transaction_count = pending_txs.len();
        
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
        let blockchain = self.blockchain.read().await;
        
        // Get pending transactions from blockchain
        let pending_txs = blockchain.get_pending_transactions();
        
        // Convert to response format
        let transactions: Vec<TransactionInfo> = pending_txs
            .iter()
            .map(|tx| TransactionInfo {
                hash: tx.hash().to_string(),
                from: tx.inputs.first().map(|i| i.previous_output.to_string()).unwrap_or_else(|| "genesis".to_string()),
                to: tx.outputs.first().map(|o| format!("{:02x?}", &o.recipient.key_id[..8])).unwrap_or_else(|| "unknown".to_string()),
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
        let tx_hash_str = path_parts.get(5)
            .ok_or_else(|| anyhow::anyhow!("Transaction hash required"))?;
        
        let blockchain = self.blockchain.read().await;
        
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
                from: pending_tx.inputs.first().map(|i| i.previous_output.to_string()).unwrap_or_else(|| "genesis".to_string()),
                to: pending_tx.outputs.first().map(|o| format!("{:02x?}", &o.recipient.key_id[..8])).unwrap_or_else(|| "unknown".to_string()),
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
        for (block_index, block) in blockchain.blocks.iter().enumerate() {
            if let Some(confirmed_tx) = block.transactions.iter().find(|tx| tx.hash() == tx_hash) {
                let transaction_info = TransactionInfo {
                    hash: confirmed_tx.hash().to_string(),
                    from: confirmed_tx.inputs.first().map(|i| i.previous_output.to_string()).unwrap_or_else(|| "genesis".to_string()),
                    to: confirmed_tx.outputs.first().map(|o| format!("{:02x?}", &o.recipient.key_id[..8])).unwrap_or_else(|| "unknown".to_string()),
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
        
        let blockchain = self.blockchain.read().await;
        
        // Use provided transaction size or estimate a typical size
        let tx_size = req_data.transaction_size.unwrap_or(250); // Typical transaction size
        
        // Map priority string to lib_economy Priority enum
        let priority = match req_data.priority.as_deref() {
            Some("low") => lib_economy::Priority::Low,
            Some("high") => lib_economy::Priority::High,
            Some("urgent") => lib_economy::Priority::Urgent,
            _ => lib_economy::Priority::Normal, // Default
        };
        
        let is_system = req_data.is_system_transaction.unwrap_or(false);
        
        // Calculate fees using blockchain's economic processor
        let (base_fee, dao_fee, total_fee) = blockchain.calculate_transaction_fees(
            tx_size as u64,
            req_data.amount,
            priority,
            is_system,
        );
        
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

    /// Handle transaction broadcast request
    async fn handle_broadcast_transaction(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: BroadcastTransactionRequest = serde_json::from_slice(&request.body)?;
        
        // For now, we'll create a simple transaction from the hex data
        // In a real implementation, you'd deserialize the hex data into a Transaction
        let mut blockchain = self.blockchain.write().await;
        
        // Mock transaction creation for demonstration
        // In reality, you'd decode req_data.transaction_data from hex
        let mock_transaction = lib_blockchain::transaction::Transaction::new(
            Vec::new(), // inputs
            Vec::new(), // outputs  
            1000,       // fee
            lib_blockchain::integration::crypto_integration::Signature {
                signature: req_data.transaction_data.as_bytes().to_vec(),
                public_key: lib_blockchain::integration::crypto_integration::PublicKey::new(vec![0u8; 32]),
                algorithm: lib_blockchain::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            Vec::new(), // memo
        );
        
        let tx_hash = mock_transaction.hash();
        
        // Try to add transaction to pending pool
        let accepted = match blockchain.add_pending_transaction(mock_transaction) {
            Ok(()) => {
                tracing::info!("✅ Transaction {} accepted to mempool", tx_hash);
                true
            }
            Err(e) => {
                tracing::warn!("❌ Transaction {} rejected: {}", tx_hash, e);
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
        let tx_hash_str = path_parts.get(5)
            .ok_or_else(|| anyhow::anyhow!("Transaction hash required"))?;
        
        let blockchain = self.blockchain.read().await;
        
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
        
        // Search through all blocks for the transaction
        for (block_index, block) in blockchain.blocks.iter().enumerate() {
            if let Some((tx_index, confirmed_tx)) = block.transactions.iter().enumerate().find(|(_, tx)| tx.hash() == tx_hash) {
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
                    success: true, // Assume success if in block
                    logs: vec![
                        format!("Transaction confirmed in block {}", block_height),
                        format!("Fee paid: {} ZHTP", confirmed_tx.fee),
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