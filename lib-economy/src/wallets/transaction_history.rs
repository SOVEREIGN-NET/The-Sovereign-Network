//! Comprehensive transaction history and analytics system
//! 
//! Provides detailed transaction tracking, analytics, and audit capabilities
//! using blockchain data from lib-blockchain and lib-network integrations.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, BTreeMap};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{Datelike, Timelike};

use crate::transactions::Transaction;
use crate::types::{TransactionType, Priority};
use crate::wasm::logging::info;

// integrations (avoiding blockchain circular dependency)
use crate::network_types::{get_mesh_status, get_network_statistics};

// Local transaction type to avoid blockchain dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainTransaction {
    pub id: String,
    pub timestamp: u64,
    pub amount: u64,
    pub from: String,
    pub to: String,
    pub fee: u64,
}

/// Transaction status with blockchain validation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction pending in mempool
    Pending,
    /// Transaction confirmed with number of confirmations
    Confirmed { confirmations: u32 },
    /// Transaction failed with error reason
    Failed { reason: String },
    /// Transaction dropped from mempool
    Dropped,
    /// Transaction finalized (irreversible)
    Finalized,
}

/// Transaction category for analytics
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionCategory {
    /// Regular payment transactions
    Payment,
    /// Reward distributions
    Reward,
    /// Staking operations
    Staking,
    /// Governance voting
    Governance,
    /// Smart contract interactions
    SmartContract,
    /// Cross-wallet transfers
    CrossWallet,
    /// Infrastructure payments
    Infrastructure,
    ///  service fees
    IspBypass,
    /// Mesh discovery rewards
    MeshDiscovery,
    /// UBI distributions
    UbiDistribution,
    /// Bridge operations
    Bridge,
    /// Other/unknown
    Other,
}

impl TransactionCategory {
    /// Get category from transaction type
    pub fn from_transaction_type(tx_type: &TransactionType) -> Self {
        match tx_type {
            TransactionType::Payment => Self::Payment,
            TransactionType::Reward => Self::Reward,
            TransactionType::Stake | TransactionType::Unstake => Self::Staking,
            TransactionType::ProposalVote | TransactionType::ProposalExecution => Self::Governance,
            TransactionType::NetworkFee | TransactionType::DaoFee => Self::Infrastructure,
            TransactionType::UbiDistribution => Self::UbiDistribution,
            _ => Self::Other,
        }
    }
}

/// Comprehensive transaction record with blockchain integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Blockchain transaction hash
    pub blockchain_tx_hash: [u8; 32],
    /// Internal transaction reference
    pub internal_tx_id: String,
    /// Transaction type and category
    pub transaction_type: TransactionType,
    pub category: TransactionCategory,
    /// Transaction participants
    pub from_address: Option<[u8; 32]>,
    pub to_address: Option<[u8; 32]>,
    /// Amount details
    pub amount: u64,
    pub fees: u64,
    pub gas_used: Option<u64>,
    /// Blockchain context
    pub block_height: Option<u64>,
    pub block_hash: Option<[u8; 32]>,
    pub transaction_index: Option<u32>,
    /// Status and confirmations
    pub status: TransactionStatus,
    pub priority: Priority,
    /// Timing information
    pub timestamp: u64,
    pub confirmed_at: Option<u64>,
    pub finalized_at: Option<u64>,
    /// Network context
    pub network_conditions: NetworkConditions,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Related transactions
    pub related_transactions: Vec<[u8; 32]>,
}

/// Network conditions at transaction time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConditions {
    /// Network latency in milliseconds
    pub network_latency_ms: u64,
    /// Number of active peers
    pub peer_count: u32,
    /// Network throughput in transactions per second
    pub network_tps: f64,
    /// Mempool size at transaction time
    pub mempool_size: u32,
    /// Average fee rate
    pub average_fee_rate: u64,
    /// Network congestion level (0-100)
    pub congestion_level: u8,
}

/// Transaction analytics and insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAnalytics {
    /// Total transaction count by category
    pub transaction_counts: HashMap<TransactionCategory, u64>,
    /// Total volume by category
    pub volume_by_category: HashMap<TransactionCategory, u64>,
    /// Total fees paid by category
    pub fees_by_category: HashMap<TransactionCategory, u64>,
    /// Average transaction size by category
    pub average_amount_by_category: HashMap<TransactionCategory, f64>,
    /// Success rates by category
    pub success_rates: HashMap<TransactionCategory, f64>,
    /// Monthly transaction trends
    pub monthly_trends: BTreeMap<String, MonthlyTransactionData>,
    /// Daily activity patterns
    pub daily_patterns: HashMap<u8, DailyActivityData>, // Hour of day -> activity
    /// Performance metrics
    pub performance_metrics: TransactionPerformanceMetrics,
}

/// Monthly transaction data for trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthlyTransactionData {
    /// Month identifier (YYYY-MM)
    pub month: String,
    /// Total transactions in month
    pub total_transactions: u64,
    /// Total volume in month
    pub total_volume: u64,
    /// Total fees paid in month
    pub total_fees: u64,
    /// Average confirmation time in seconds
    pub average_confirmation_time: f64,
    /// Transaction breakdown by category
    pub category_breakdown: HashMap<TransactionCategory, u64>,
}

/// Daily activity patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyActivityData {
    /// Hour of day (0-23)
    pub hour: u8,
    /// Transaction count for this hour
    pub transaction_count: u64,
    /// Total volume for this hour
    pub total_volume: u64,
    /// Average confirmation time for this hour
    pub average_confirmation_time: f64,
}

/// Transaction performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPerformanceMetrics {
    /// Average confirmation time in seconds
    pub average_confirmation_time: f64,
    /// Average finalization time in seconds
    pub average_finalization_time: f64,
    /// Transaction throughput (transactions per second)
    pub throughput_tps: f64,
    /// Success rate percentage
    pub success_rate: f64,
    /// Failed transaction analysis
    pub failure_analysis: HashMap<String, u64>,
    /// Network efficiency metrics
    pub network_efficiency: f64,
}

/// Transaction history filter options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionFilter {
    /// Filter by date range
    pub start_date: Option<u64>,
    pub end_date: Option<u64>,
    /// Filter by transaction categories
    pub categories: Option<Vec<TransactionCategory>>,
    /// Filter by transaction status
    pub statuses: Option<Vec<TransactionStatus>>,
    /// Filter by amount range
    pub min_amount: Option<u64>,
    pub max_amount: Option<u64>,
    /// Filter by address (from or to)
    pub address_filter: Option<[u8; 32]>,
    /// Filter by priority
    pub priorities: Option<Vec<Priority>>,
    /// Limit number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Comprehensive transaction history manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryManager {
    /// Node ID this history belongs to
    pub node_id: [u8; 32],
    /// All transaction records
    pub transactions: Vec<TransactionRecord>,
    /// Transaction lookup by hash
    pub hash_index: HashMap<[u8; 32], usize>,
    /// Transaction lookup by internal ID
    pub internal_id_index: HashMap<String, usize>,
    /// Analytics cache
    pub analytics_cache: Option<TransactionAnalytics>,
    /// Last analytics update
    pub analytics_last_updated: u64,
    /// Configuration settings
    pub settings: HistorySettings,
}

/// History management settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySettings {
    /// Maximum number of transactions to keep
    pub max_transactions: usize,
    /// Analytics cache refresh interval in seconds
    pub analytics_refresh_interval: u64,
    /// Enable real-time blockchain validation
    pub enable_blockchain_validation: bool,
    /// Enable network condition tracking
    pub enable_network_tracking: bool,
    /// Auto-archive old transactions
    pub auto_archive_enabled: bool,
    /// Archive transactions older than this (seconds)
    pub archive_age_threshold: u64,
}

impl TransactionHistoryManager {
    /// Create new transaction history manager
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            transactions: Vec::new(),
            hash_index: HashMap::new(),
            internal_id_index: HashMap::new(),
            analytics_cache: None,
            analytics_last_updated: 0,
            settings: HistorySettings::default(),
        }
    }

    /// Add transaction to history
    pub async fn add_transaction(&mut self, transaction: Transaction) -> Result<()> {
        // Get network conditions if enabled
        let network_conditions = if self.settings.enable_network_tracking {
            self.capture_network_conditions().await?
        } else {
            NetworkConditions::default()
        };

        // Create transaction record
        let record = TransactionRecord {
            blockchain_tx_hash: transaction.tx_id,
            internal_tx_id: hex::encode(transaction.tx_id),
            transaction_type: transaction.tx_type.clone(),
            category: TransactionCategory::from_transaction_type(&transaction.tx_type),
            from_address: Some(transaction.from),
            to_address: Some(transaction.to),
            amount: transaction.amount,
            fees: transaction.total_fee,
            gas_used: None, // Could be added if smart contracts involved
            block_height: Some(0), // Block height not available in this context
            block_hash: None, // Will be updated when confirmed
            transaction_index: None,
            status: TransactionStatus::Pending,
            priority: Priority::Normal, // Default priority
            timestamp: transaction.timestamp,
            confirmed_at: None,
            finalized_at: None,
            network_conditions,
            metadata: std::collections::HashMap::new(), // Empty metadata map
            related_transactions: Vec::new(),
        };

        // Add to collections
        let index = self.transactions.len();
        self.transactions.push(record);
        self.hash_index.insert(transaction.tx_id, index);
        self.internal_id_index.insert(hex::encode(transaction.tx_id), index);

        // Validate with blockchain if enabled
        if self.settings.enable_blockchain_validation {
            self.validate_transaction_on_blockchain(&transaction.tx_id).await?;
        }

        // Maintain size limits
        self.enforce_size_limits().await?;

        // Invalidate analytics cache
        self.analytics_cache = None;

        info!(
            "Added transaction {} to history (total: {})",
            hex::encode(transaction.tx_id), self.transactions.len()
        );

        Ok(())
    }

    /// Update transaction status from blockchain
    pub async fn update_transaction_status(&mut self, tx_hash: [u8; 32]) -> Result<()> {
        if let Some(&index) = self.hash_index.get(&tx_hash) {
            // Get blockchain transaction data
            match self.get_blockchain_transaction_by_hash(&tx_hash).await {
                Ok(Some(blockchain_tx)) => {
                    let record = &mut self.transactions[index];
                    
                    // Update from blockchain data
                    record.block_height = Some(blockchain_tx.block_height);
                    record.block_hash = Some([0u8; 32]); // Default since blockchain transaction doesn't have this field
                    record.transaction_index = Some(0); // Default since blockchain transaction doesn't have this field
                    record.confirmed_at = Some(blockchain_tx.timestamp);
                    
                    // Default to finalized status since we don't have blockchain height context
                    record.status = TransactionStatus::Finalized;
                    record.finalized_at = Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
                    
                    info!(
                        "Updated transaction {} status: {:?}",
                        hex::encode(tx_hash), record.status
                    );
                },
                Ok(None) => {
                    // Transaction not found on blockchain, might be failed or dropped
                    let record = &mut self.transactions[index];
                    if matches!(record.status, TransactionStatus::Pending) {
                        // Check if transaction is too old
                        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        if current_time - record.timestamp > 3600 { // 1 hour
                            record.status = TransactionStatus::Dropped;
                            info!("Transaction {} marked as dropped", hex::encode(tx_hash));
                        }
                    }
                },
                Err(_) => {
                    // Transaction not found on blockchain, might be failed or dropped
                    let record = &mut self.transactions[index];
                    if matches!(record.status, TransactionStatus::Pending) {
                        // Check if transaction is too old
                        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        if current_time - record.timestamp > 3600 { // 1 hour
                            record.status = TransactionStatus::Dropped;
                            info!("Transaction {} marked as dropped", hex::encode(tx_hash));
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Get filtered transaction history
    pub fn get_filtered_transactions(&self, filter: &TransactionFilter) -> Vec<&TransactionRecord> {
        let mut results: Vec<&TransactionRecord> = self.transactions.iter().collect();

        // Apply filters
        if let Some(start_date) = filter.start_date {
            results.retain(|tx| tx.timestamp >= start_date);
        }

        if let Some(end_date) = filter.end_date {
            results.retain(|tx| tx.timestamp <= end_date);
        }

        if let Some(categories) = &filter.categories {
            results.retain(|tx| categories.contains(&tx.category));
        }

        if let Some(statuses) = &filter.statuses {
            results.retain(|tx| statuses.contains(&tx.status));
        }

        if let Some(min_amount) = filter.min_amount {
            results.retain(|tx| tx.amount >= min_amount);
        }

        if let Some(max_amount) = filter.max_amount {
            results.retain(|tx| tx.amount <= max_amount);
        }

        if let Some(address) = filter.address_filter {
            results.retain(|tx| {
                tx.from_address == Some(address) || tx.to_address == Some(address)
            });
        }

        if let Some(priorities) = &filter.priorities {
            results.retain(|tx| priorities.contains(&tx.priority));
        }

        // Sort by timestamp (newest first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply pagination
        if let Some(offset) = filter.offset {
            if offset < results.len() {
                results = results[offset..].to_vec();
            } else {
                results.clear();
            }
        }

        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        results
    }

    /// Generate comprehensive transaction analytics
    pub async fn generate_analytics(&mut self) -> Result<&TransactionAnalytics> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Check if analytics cache is valid
        let should_refresh = if let Some(_) = &self.analytics_cache {
            current_time - self.analytics_last_updated >= self.settings.analytics_refresh_interval
        } else {
            true
        };

        if should_refresh {
            // Generate fresh analytics
            let analytics = self.compute_analytics().await?;
            self.analytics_cache = Some(analytics);
            self.analytics_last_updated = current_time;
        }

        Ok(self.analytics_cache.as_ref().unwrap())
    }

    /// Get transaction by hash
    pub fn get_transaction_by_hash(&self, tx_hash: [u8; 32]) -> Option<&TransactionRecord> {
        self.hash_index.get(&tx_hash).and_then(|&index| self.transactions.get(index))
    }

    /// Get transaction by internal ID
    pub fn get_transaction_by_internal_id(&self, internal_id: &str) -> Option<&TransactionRecord> {
        self.internal_id_index.get(internal_id).and_then(|&index| self.transactions.get(index))
    }

    /// Get transaction statistics for a time period
    pub fn get_period_statistics(&self, start_time: u64, end_time: u64) -> Result<serde_json::Value> {
        let period_transactions: Vec<&TransactionRecord> = self.transactions.iter()
            .filter(|tx| tx.timestamp >= start_time && tx.timestamp <= end_time)
            .collect();

        let total_count = period_transactions.len();
        let total_volume: u64 = period_transactions.iter().map(|tx| tx.amount).sum();
        let total_fees: u64 = period_transactions.iter().map(|tx| tx.fees).sum();

        // Category breakdown
        let mut category_counts = HashMap::new();
        let mut category_volumes = HashMap::new();
        
        for tx in &period_transactions {
            *category_counts.entry(tx.category.clone()).or_insert(0) += 1;
            *category_volumes.entry(tx.category.clone()).or_insert(0u64) += tx.amount;
        }

        // Success rates
        let successful_count = period_transactions.iter()
            .filter(|tx| matches!(tx.status, TransactionStatus::Confirmed { .. } | TransactionStatus::Finalized))
            .count();
        let success_rate = if total_count > 0 {
            (successful_count as f64 / total_count as f64) * 100.0
        } else {
            0.0
        };

        // Average confirmation time
        let confirmed_transactions: Vec<&TransactionRecord> = period_transactions.iter()
            .filter(|tx| tx.confirmed_at.is_some())
            .cloned()
            .collect();
        
        let average_confirmation_time = if !confirmed_transactions.is_empty() {
            let total_confirmation_time: u64 = confirmed_transactions.iter()
                .map(|tx| tx.confirmed_at.unwrap() - tx.timestamp)
                .sum();
            total_confirmation_time as f64 / confirmed_transactions.len() as f64
        } else {
            0.0
        };

        Ok(serde_json::json!({
            "period": {
                "start_time": start_time,
                "end_time": end_time,
                "duration_seconds": end_time - start_time
            },
            "totals": {
                "transaction_count": total_count,
                "total_volume": total_volume,
                "total_fees": total_fees,
                "average_transaction_size": if total_count > 0 { total_volume / total_count as u64 } else { 0 }
            },
            "performance": {
                "success_rate": success_rate,
                "average_confirmation_time_seconds": average_confirmation_time,
                "transactions_per_hour": if end_time > start_time { 
                    total_count as f64 / ((end_time - start_time) as f64 / 3600.0) 
                } else { 0.0 }
            },
            "category_breakdown": {
                "counts": category_counts,
                "volumes": category_volumes
            }
        }))
    }

    /// Archive old transactions to optimize performance
    pub async fn archive_old_transactions(&mut self) -> Result<usize> {
        if !self.settings.auto_archive_enabled {
            return Ok(0);
        }

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let archive_threshold = current_time - self.settings.archive_age_threshold;

        let initial_count = self.transactions.len();
        
        // Keep only transactions newer than threshold
        self.transactions.retain(|tx| tx.timestamp > archive_threshold);
        
        // Rebuild indices
        self.rebuild_indices();
        
        // Invalidate analytics cache
        self.analytics_cache = None;
        
        let archived_count = initial_count - self.transactions.len();
        
        if archived_count > 0 {
            info!("🗂️ Archived {} old transactions", archived_count);
        }
        
        Ok(archived_count)
    }

    /// Get transaction by hash (local lookup)
    pub async fn get_blockchain_transaction_by_hash(&self, tx_hash: &[u8; 32]) -> Result<Option<Transaction>> {
        // First check local cache
        if let Some(index) = self.hash_index.get(tx_hash) {
            if let Some(tx) = self.transactions.get(*index) {
                // Convert TransactionRecord back to Transaction
                let transaction = Transaction {
                    tx_id: tx.blockchain_tx_hash,
                    from: tx.from_address.unwrap_or([0u8; 32]),
                    to: tx.to_address.unwrap_or([0u8; 32]),
                    amount: tx.amount,
                    base_fee: tx.fees,
                    dao_fee: 0, // Default DAO fee
                    total_fee: tx.fees,
                    tx_type: tx.transaction_type.clone(),
                    timestamp: tx.timestamp,
                    block_height: tx.block_height.unwrap_or(0),
                    dao_fee_proof: None,
                };
                return Ok(Some(transaction));
            }
        }
        
        // Return None if not found locally
        // In a implementation, this would query the blockchain
        Ok(None)
    }

    /// Export transaction history to JSON
    pub fn export_to_json(&self, filter: Option<&TransactionFilter>) -> Result<String> {
        let transactions = if let Some(filter) = filter {
            self.get_filtered_transactions(filter)
        } else {
            self.transactions.iter().collect()
        };

        let export_data = serde_json::json!({
            "export_metadata": {
                "node_id": hex::encode(self.node_id),
                "export_timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                "total_transactions": transactions.len(),
                "filter_applied": filter.is_some()
            },
            "transactions": transactions
        });

        serde_json::to_string_pretty(&export_data).map_err(|e| anyhow::anyhow!("Export error: {}", e))
    }

    // Private helper methods

    async fn capture_network_conditions(&self) -> Result<NetworkConditions> {
        let network_stats = get_network_statistics().await.map_err(|e| anyhow::anyhow!("Network stats error: {}", e))?;
        let mesh_status = get_mesh_status().await.map_err(|e| anyhow::anyhow!("Mesh status error: {}", e))?;

        Ok(NetworkConditions {
            network_latency_ms: network_stats.average_latency_ms,
            peer_count: mesh_status.connected_peers as u32,
            network_tps: network_stats.transactions_per_second,
            mempool_size: network_stats.mempool_size,
            average_fee_rate: network_stats.average_fee_rate,
            congestion_level: network_stats.congestion_level,
        })
    }

    async fn validate_transaction_on_blockchain(&self, tx_hash: &[u8; 32]) -> Result<()> {
        // In production, this would validate the transaction exists on blockchain
        // For now, just log the validation
        info!("Validating transaction {} on blockchain", hex::encode(tx_hash));
        Ok(())
    }

    async fn enforce_size_limits(&mut self) -> Result<()> {
        if self.transactions.len() > self.settings.max_transactions {
            let excess = self.transactions.len() - self.settings.max_transactions;
            
            // Remove oldest transactions
            self.transactions.drain(0..excess);
            
            // Rebuild indices
            self.rebuild_indices();
            
            info!("Removed {} old transactions to maintain size limit", excess);
        }
        
        Ok(())
    }

    fn rebuild_indices(&mut self) {
        self.hash_index.clear();
        self.internal_id_index.clear();
        
        for (index, tx) in self.transactions.iter().enumerate() {
            self.hash_index.insert(tx.blockchain_tx_hash, index);
            self.internal_id_index.insert(tx.internal_tx_id.clone(), index);
        }
    }

    async fn compute_analytics(&self) -> Result<TransactionAnalytics> {
        let mut transaction_counts = HashMap::new();
        let mut volume_by_category = HashMap::new();
        let mut fees_by_category = HashMap::new();
        let mut monthly_trends = BTreeMap::new();
        let mut daily_patterns = HashMap::new();
        let mut failure_analysis = HashMap::new();

        // Process all transactions
        for tx in &self.transactions {
            // Category counts and volumes
            *transaction_counts.entry(tx.category.clone()).or_insert(0) += 1;
            *volume_by_category.entry(tx.category.clone()).or_insert(0u64) += tx.amount;
            *fees_by_category.entry(tx.category.clone()).or_insert(0u64) += tx.fees;

            // Monthly trends
            let month_key = format!("{}-{:02}", 
                chrono::DateTime::from_timestamp(tx.timestamp as i64, 0).unwrap().year(),
                chrono::DateTime::from_timestamp(tx.timestamp as i64, 0).unwrap().month()
            );
            
            let monthly_data = monthly_trends.entry(month_key.clone()).or_insert(MonthlyTransactionData {
                month: month_key,
                total_transactions: 0,
                total_volume: 0,
                total_fees: 0,
                average_confirmation_time: 0.0,
                category_breakdown: HashMap::new(),
            });
            
            monthly_data.total_transactions += 1;
            monthly_data.total_volume += tx.amount;
            monthly_data.total_fees += tx.fees;
            *monthly_data.category_breakdown.entry(tx.category.clone()).or_insert(0) += 1;

            // Daily patterns
            let hour = chrono::DateTime::from_timestamp(tx.timestamp as i64, 0).unwrap().hour() as u8;
            let daily_data = daily_patterns.entry(hour).or_insert(DailyActivityData {
                hour,
                transaction_count: 0,
                total_volume: 0,
                average_confirmation_time: 0.0,
            });
            
            daily_data.transaction_count += 1;
            daily_data.total_volume += tx.amount;

            // Failure analysis
            if let TransactionStatus::Failed { reason } = &tx.status {
                *failure_analysis.entry(reason.clone()).or_insert(0) += 1;
            }
        }

        // Calculate averages
        let mut average_amount_by_category = HashMap::new();
        for (category, total_volume) in &volume_by_category {
            let count = transaction_counts.get(category).unwrap_or(&0);
            if *count > 0 {
                average_amount_by_category.insert(category.clone(), *total_volume as f64 / *count as f64);
            }
        }

        // Calculate success rates
        let mut success_rates = HashMap::new();
        for category in transaction_counts.keys() {
            let total = transaction_counts.get(category).unwrap_or(&0);
            let successful = self.transactions.iter()
                .filter(|tx| tx.category == *category)
                .filter(|tx| matches!(tx.status, TransactionStatus::Confirmed { .. } | TransactionStatus::Finalized))
                .count();
            
            if *total > 0 {
                success_rates.insert(category.clone(), (successful as f64 / *total as f64) * 100.0);
            }
        }

        // Calculate performance metrics
        let confirmed_transactions: Vec<&TransactionRecord> = self.transactions.iter()
            .filter(|tx| tx.confirmed_at.is_some())
            .collect();
        
        let average_confirmation_time = if !confirmed_transactions.is_empty() {
            let total_confirmation_time: u64 = confirmed_transactions.iter()
                .map(|tx| tx.confirmed_at.unwrap() - tx.timestamp)
                .sum();
            total_confirmation_time as f64 / confirmed_transactions.len() as f64
        } else {
            0.0
        };

        let finalized_transactions: Vec<&TransactionRecord> = self.transactions.iter()
            .filter(|tx| tx.finalized_at.is_some())
            .collect();
        
        let average_finalization_time = if !finalized_transactions.is_empty() {
            let total_finalization_time: u64 = finalized_transactions.iter()
                .map(|tx| tx.finalized_at.unwrap() - tx.timestamp)
                .sum();
            total_finalization_time as f64 / finalized_transactions.len() as f64
        } else {
            0.0
        };

        let successful_count = self.transactions.iter()
            .filter(|tx| matches!(tx.status, TransactionStatus::Confirmed { .. } | TransactionStatus::Finalized))
            .count();
        
        let success_rate = if !self.transactions.is_empty() {
            (successful_count as f64 / self.transactions.len() as f64) * 100.0
        } else {
            100.0
        };

        let performance_metrics = TransactionPerformanceMetrics {
            average_confirmation_time,
            average_finalization_time,
            throughput_tps: 0.0, // Would calculate from recent time window
            success_rate,
            failure_analysis: failure_analysis.clone(),
            network_efficiency: success_rate / 100.0, // Simplified efficiency metric
        };

        Ok(TransactionAnalytics {
            transaction_counts,
            volume_by_category,
            fees_by_category,
            average_amount_by_category,
            success_rates,
            monthly_trends,
            daily_patterns,
            performance_metrics,
        })
    }
}

impl Default for HistorySettings {
    fn default() -> Self {
        Self {
            max_transactions: 10_000,
            analytics_refresh_interval: 300, // 5 minutes
            enable_blockchain_validation: true,
            enable_network_tracking: true,
            auto_archive_enabled: true,
            archive_age_threshold: 86400 * 30, // 30 days
        }
    }
}

impl Default for NetworkConditions {
    fn default() -> Self {
        Self {
            network_latency_ms: 0,
            peer_count: 0,
            network_tps: 0.0,
            mempool_size: 0,
            average_fee_rate: 0,
            congestion_level: 0,
        }
    }
}

/// Create transaction history manager for a node
pub fn create_transaction_history_manager(node_id: [u8; 32]) -> TransactionHistoryManager {
    TransactionHistoryManager::new(node_id)
}

/// Create transaction history manager with custom settings
pub fn create_custom_transaction_history_manager(
    node_id: [u8; 32],
    settings: HistorySettings,
) -> TransactionHistoryManager {
    let mut manager = TransactionHistoryManager::new(node_id);
    manager.settings = settings;
    manager
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::create_payment_transaction;

    #[tokio::test]
    async fn test_transaction_history_creation() {
        let node_id = [1u8; 32];
        let manager = TransactionHistoryManager::new(node_id);
        
        assert_eq!(manager.node_id, node_id);
        assert_eq!(manager.transactions.len(), 0);
        assert!(manager.analytics_cache.is_none());
    }

    #[tokio::test]
    async fn test_add_transaction() {
        let node_id = [1u8; 32];
        let mut manager = TransactionHistoryManager::new(node_id);
        
        let tx = create_payment_transaction(
            [1u8; 32],
            [2u8; 32],
            1000,
            Priority::Normal,
        ).unwrap();
        
        manager.add_transaction(tx).await.unwrap();
        
        assert_eq!(manager.transactions.len(), 1);
        assert_eq!(manager.hash_index.len(), 1);
        assert_eq!(manager.internal_id_index.len(), 1);
    }

    #[tokio::test]
    async fn test_transaction_filtering() {
        let node_id = [1u8; 32];
        let mut manager = TransactionHistoryManager::new(node_id);
        
        // Add multiple transactions with different categories
        for i in 0..5 {
            let tx = create_payment_transaction(
                [i; 32],
                [i + 1; 32],
                1000 * (i as u64 + 1),
                Priority::Normal,
            ).unwrap();
            
            manager.add_transaction(tx).await.unwrap();
        }
        
        // Test amount filtering
        let filter = TransactionFilter {
            min_amount: Some(3000),
            max_amount: Some(5000),
            ..Default::default()
        };
        
        let filtered = manager.get_filtered_transactions(&filter);
        assert_eq!(filtered.len(), 3); // 3000, 4000, and 5000
    }

    #[tokio::test]
    async fn test_analytics_generation() {
        let node_id = [1u8; 32];
        let mut manager = TransactionHistoryManager::new(node_id);
        
        // Add some test transactions
        for i in 0..3 {
            let tx = create_payment_transaction(
                [i; 32],
                [i + 1; 32],
                1000,
                Priority::Normal,
            ).unwrap();
            
            manager.add_transaction(tx).await.unwrap();
        }
        
        let analytics = manager.generate_analytics().await.unwrap();
        
        assert_eq!(analytics.transaction_counts.get(&TransactionCategory::Payment), Some(&3));
        assert_eq!(analytics.volume_by_category.get(&TransactionCategory::Payment), Some(&3000));
    }
}

impl Default for TransactionFilter {
    fn default() -> Self {
        Self {
            start_date: None,
            end_date: None,
            categories: None,
            statuses: None,
            min_amount: None,
            max_amount: None,
            address_filter: None,
            priorities: None,
            limit: None,
            offset: None,
        }
    }
}
