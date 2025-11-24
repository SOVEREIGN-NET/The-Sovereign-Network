//! Reward management system for ZHTP network participants
//! 
//! Manages calculation, accumulation, and distribution of rewards for network services
//! including bandwidth sharing, data storage, mesh routing, and  activities.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{TokenReward, EconomicModel};
use crate::types::{WorkMetrics, IspBypassWork, NetworkStats, TransactionType};
use crate::wallets::WalletBalance;
use crate::wasm::logging::info;

/// Comprehensive reward manager for all network activities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardManager {
    /// Current accumulated work metrics
    pub current_work: WorkMetrics,
    ///  specific work metrics
    pub isp_bypass_work: IspBypassWork,
    /// Pending rewards waiting to be claimed
    pub pending_rewards: Vec<TokenReward>,
    /// Total lifetime rewards earned
    pub lifetime_rewards: u64,
    /// Last reward calculation timestamp
    pub last_calculation: u64,
    /// Node identity for reward attribution
    pub node_id: [u8; 32],
    /// Reward calculation intervals in seconds
    pub calculation_interval: u64,
    /// Quality score history for trend analysis
    pub quality_history: Vec<f64>,
    /// Uptime tracking for bonus calculations
    pub uptime_tracker: UptimeTracker,
}

/// Tracks node uptime for reward bonuses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeTracker {
    /// Session start timestamp
    pub session_start: u64,
    /// Total uptime in hours for current period
    pub current_period_hours: u64,
    /// Historical uptime percentages
    pub uptime_history: Vec<f64>,
    /// Last uptime calculation
    pub last_update: u64,
}

/// Staking system for infrastructure investments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingSystem {
    /// Currently staked amount
    pub staked_amount: u64,
    /// Staking start timestamp
    pub stake_start: u64,
    /// Expected annual yield percentage
    pub annual_yield: u64,
    /// Accumulated staking rewards
    pub accumulated_rewards: u64,
    /// Last reward calculation
    pub last_reward_calc: u64,
    /// Minimum staking period in seconds
    pub min_stake_period: u64,
}

///  specific reward calculator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IspBypassRewards {
    /// Bandwidth sharing metrics
    pub bandwidth_metrics: BandwidthMetrics,
    /// Connection sharing statistics
    pub connection_stats: ConnectionStats,
    /// Cost savings provided to users
    pub cost_savings: u64,
    ///  reward multiplier
    pub bypass_multiplier: f64,
}

/// Bandwidth sharing metrics for 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthMetrics {
    /// Total bandwidth shared in GB
    pub total_shared_gb: u64,
    /// Peak bandwidth capacity
    pub peak_capacity_mbps: u64,
    /// Average utilization percentage
    pub avg_utilization: f64,
    /// Data transfer efficiency
    pub transfer_efficiency: f64,
}

/// Connection sharing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Number of users served
    pub users_served: u32,
    /// Average connection quality
    pub avg_quality: f64,
    /// Total connection hours provided
    pub connection_hours: u64,
    /// Geographic coverage area
    pub coverage_area_km2: f64,
}

/// Mesh discovery and routing rewards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDiscoveryRewards {
    /// Mesh routing metrics
    pub routing_metrics: RoutingMetrics,
    /// Peer discovery statistics
    pub discovery_stats: DiscoveryStats,
    /// Network contribution score
    pub contribution_score: f64,
}

/// Mesh routing performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingMetrics {
    /// Packets successfully routed
    pub packets_routed: u64,
    /// Average routing latency in ms
    pub avg_latency_ms: u64,
    /// Routing success rate
    pub success_rate: f64,
    /// Number of active routes maintained
    pub active_routes: u32,
}

/// Peer discovery contribution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryStats {
    /// New peers discovered
    pub peers_discovered: u32,
    /// Discovery requests handled
    pub discovery_requests: u64,
    /// Network topology contributions
    pub topology_updates: u32,
    /// Geographic diversity contributed
    pub geo_diversity_score: f64,
}

/// Multi-wallet support for different reward types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiWallet {
    /// Main ZHTP wallet
    pub primary_wallet: WalletBalance,
    /// Specialized wallets for different reward types
    pub reward_wallets: HashMap<String, WalletBalance>,
    /// Cross-wallet transaction capabilities
    pub transfer_capabilities: TransferCapabilities,
}

/// Cross-wallet transfer and management capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCapabilities {
    /// Maximum transfer amount per day
    pub daily_transfer_limit: u64,
    /// Transfer fee percentage
    pub transfer_fee_rate: u64,
    /// Supported wallet types
    pub supported_types: Vec<String>,
    /// Auto-consolidation settings
    pub auto_consolidate: bool,
}

/// Comprehensive transaction history with analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistory {
    /// All transaction records
    pub transactions: Vec<HistoricalTransaction>,
    /// Transaction analytics
    pub analytics: TransactionAnalytics,
    /// Search and filter capabilities
    pub filters: HistoryFilters,
}

/// Extended transaction record with analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalTransaction {
    /// Transaction ID
    pub tx_id: [u8; 32],
    /// Transaction type
    pub tx_type: TransactionType,
    /// Amount transferred
    pub amount: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Source address
    pub from: [u8; 32],
    /// Destination address
    pub to: [u8; 32],
    /// Transaction fees paid
    pub fees: u64,
    /// Block height when confirmed
    pub block_height: u64,
    /// Associated work metrics (for rewards)
    pub work_metrics: Option<WorkMetrics>,
    /// Geographic location (if available)
    pub location: Option<String>,
    /// Quality metrics for the transaction
    pub quality_metrics: Option<QualityMetrics>,
}

/// Quality metrics for transactions and services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    /// Service quality score (0.0-1.0)
    pub quality_score: f64,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Success rate percentage
    pub success_rate: f64,
    /// User satisfaction rating
    pub satisfaction_rating: f64,
}

/// Transaction analytics and insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAnalytics {
    /// Total volume by transaction type
    pub volume_by_type: HashMap<String, u64>,
    /// Average transaction values
    pub avg_values: HashMap<String, f64>,
    /// Reward efficiency metrics
    pub reward_efficiency: f64,
    /// Growth trends
    pub growth_trends: Vec<f64>,
}

/// History filtering and search options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFilters {
    /// Date range filters
    pub date_range: Option<(u64, u64)>,
    /// Transaction type filters
    pub tx_types: Vec<TransactionType>,
    /// Amount range filters
    pub amount_range: Option<(u64, u64)>,
    /// Location filters
    pub locations: Vec<String>,
}

impl RewardManager {
    /// Create new reward manager for a node
    pub fn new(node_id: [u8; 32]) -> Self {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            current_work: WorkMetrics::new(),
            isp_bypass_work: IspBypassWork::new(),
            pending_rewards: Vec::new(),
            lifetime_rewards: 0,
            last_calculation: current_time,
            node_id,
            calculation_interval: 3600, // 1 hour
            quality_history: Vec::new(),
            uptime_tracker: UptimeTracker::new(current_time),
        }
    }

    /// Record network work performed
    pub fn record_work(&mut self, work: WorkMetrics) -> Result<()> {
        self.current_work.add_routing_work(work.routing_work);
        self.current_work.add_storage_work(work.storage_work);
        self.current_work.add_compute_work(work.compute_work);
        
        // Update quality score and track history
        self.current_work.update_quality_score(work.quality_score);
        self.quality_history.push(work.quality_score);
        if self.quality_history.len() > 100 {
            self.quality_history.remove(0); // Keep last 100 entries
        }

        // Update uptime
        self.uptime_tracker.update_uptime(work.uptime_hours);

        Ok(())
    }

    /// Record  activities
    pub fn record_isp_bypass_work(&mut self, work: IspBypassWork) -> Result<()> {
        self.isp_bypass_work.add_bandwidth_shared(work.bandwidth_shared_gb);
        self.isp_bypass_work.add_packets_routed(work.packets_routed_mb);
        self.isp_bypass_work.update_connection_quality(work.connection_quality);
        self.isp_bypass_work.add_users_served(work.users_served);
        self.isp_bypass_work.add_cost_savings(work.cost_savings_provided);
        self.isp_bypass_work.uptime_hours += work.uptime_hours;

        Ok(())
    }

    /// Calculate and queue pending rewards
    pub fn calculate_rewards(&mut self, economic_model: &EconomicModel, network_stats: &NetworkStats) -> Result<TokenReward> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if calculation interval has passed
        if current_time - self.last_calculation < self.calculation_interval {
            return Err(anyhow!("Calculation interval not reached"));
        }

        // Calculate standard network rewards
        let network_reward = TokenReward::calculate(&self.current_work, economic_model)?;

        // Calculate  rewards if applicable
        let mut total_reward = network_reward;
        if self.isp_bypass_work.bandwidth_shared_gb > 0 || self.isp_bypass_work.packets_routed_mb > 0 {
            let bypass_reward = TokenReward::calculate_isp_bypass(&self.isp_bypass_work)?;
            total_reward.combine(&bypass_reward);
        }

        // Apply network utilization adjustments
        let adjustment_multiplier = network_stats.get_reward_adjustment_multiplier();
        if adjustment_multiplier != 100 {
            total_reward.total_reward = (total_reward.total_reward as f64 * adjustment_multiplier as f64 / 100.0) as u64;
        }

        // Queue the reward
        self.pending_rewards.push(total_reward.clone());
        self.last_calculation = current_time;

        // Reset work metrics for next period
        self.current_work = WorkMetrics::new();
        self.isp_bypass_work = IspBypassWork::new();

        Ok(total_reward)
    }

    /// Claim all pending rewards and transfer to wallet
    pub fn claim_rewards(&mut self, wallet: &mut WalletBalance) -> Result<u64> {
        let mut total_claimed = 0;

        for reward in self.pending_rewards.drain(..) {
            wallet.add_reward(&reward)?;
            total_claimed += reward.total_reward;
            self.lifetime_rewards += reward.total_reward;
        }

        Ok(total_claimed)
    }

    /// Get current reward statistics
    pub fn get_reward_stats(&self) -> RewardStats {
        let pending_total: u64 = self.pending_rewards.iter().map(|r| r.total_reward).sum();
        let avg_quality = if self.quality_history.is_empty() {
            0.0
        } else {
            self.quality_history.iter().sum::<f64>() / self.quality_history.len() as f64
        };

        RewardStats {
            pending_rewards: pending_total,
            lifetime_rewards: self.lifetime_rewards,
            current_work_value: self.estimate_current_work_value(),
            avg_quality_score: avg_quality,
            uptime_percentage: self.uptime_tracker.get_uptime_percentage(),
            rewards_per_hour: self.calculate_rewards_per_hour(),
        }
    }

    /// Estimate value of current uncalculated work
    fn estimate_current_work_value(&self) -> u64 {
        // Simple estimation based on work metrics
        let routing_est = (self.current_work.routing_work / 1_000_000) * crate::DEFAULT_ROUTING_RATE;
        let storage_est = (self.current_work.storage_work / 1_000_000_000) * crate::DEFAULT_STORAGE_RATE;
        let compute_est = self.current_work.compute_work * crate::DEFAULT_COMPUTE_RATE;
        
        routing_est + storage_est + compute_est
    }

    /// Calculate average rewards per hour
    fn calculate_rewards_per_hour(&self) -> f64 {
        if self.uptime_tracker.current_period_hours == 0 {
            0.0
        } else {
            self.lifetime_rewards as f64 / self.uptime_tracker.current_period_hours as f64
        }
    }
}

/// Current reward statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardStats {
    pub pending_rewards: u64,
    pub lifetime_rewards: u64,
    pub current_work_value: u64,
    pub avg_quality_score: f64,
    pub uptime_percentage: f64,
    pub rewards_per_hour: f64,
}

impl UptimeTracker {
    pub fn new(start_time: u64) -> Self {
        Self {
            session_start: start_time,
            current_period_hours: 0,
            uptime_history: Vec::new(),
            last_update: start_time,
        }
    }

    pub fn update_uptime(&mut self, additional_hours: u64) {
        self.current_period_hours += additional_hours;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_update = current_time;
    }

    pub fn get_uptime_percentage(&self) -> f64 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let total_hours = (current_time - self.session_start) / 3600;
        
        if total_hours == 0 {
            100.0
        } else {
            (self.current_period_hours as f64 / total_hours as f64 * 100.0).min(100.0)
        }
    }
}

impl StakingSystem {
    pub fn new() -> Self {
        Self {
            staked_amount: 0,
            stake_start: 0,
            annual_yield: 0,
            accumulated_rewards: 0,
            last_reward_calc: 0,
            min_stake_period: 86400 * 30, // 30 days minimum
        }
    }

    pub fn stake_tokens(&mut self, amount: u64) -> Result<()> {
        if self.staked_amount > 0 {
            return Err(anyhow!("Already have active stake"));
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.staked_amount = amount;
        self.stake_start = current_time;
        self.last_reward_calc = current_time;

        // Determine yield based on stake amount
        self.annual_yield = if amount >= crate::LARGE_INFRASTRUCTURE_THRESHOLD {
            crate::LARGE_INFRASTRUCTURE_DAILY_YIELD
        } else {
            crate::SMALL_INFRASTRUCTURE_DAILY_YIELD
        };

        Ok(())
    }

    pub fn calculate_staking_rewards(&mut self) -> Result<u64> {
        if self.staked_amount == 0 {
            return Ok(0);
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let time_diff = current_time - self.last_reward_calc;
        let days_passed = time_diff / 86400;

        if days_passed == 0 {
            return Ok(0);
        }

        // Calculate daily yield
        let daily_reward = self.staked_amount / self.annual_yield;
        let total_reward = daily_reward * days_passed;

        self.accumulated_rewards += total_reward;
        self.last_reward_calc = current_time;

        Ok(total_reward)
    }

    pub fn unstake_tokens(&mut self) -> Result<(u64, u64)> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time - self.stake_start < self.min_stake_period {
            return Err(anyhow!("Minimum staking period not met"));
        }

        // Calculate final rewards including any last-minute accumulation
        let final_rewards = self.calculate_staking_rewards()?;
        
        // Add final calculated rewards to accumulated rewards for complete payout
        let total_rewards = self.accumulated_rewards + final_rewards;
        let staked_amount = self.staked_amount;
        
        info!(
            "Unstaking completed: {} ZHTP staked, {} accumulated + {} final = {} total rewards",
            staked_amount, self.accumulated_rewards, final_rewards, total_rewards
        );

        // Reset staking state
        self.staked_amount = 0;
        self.stake_start = 0;
        self.accumulated_rewards = 0;
        self.annual_yield = 0;

        Ok((staked_amount, total_rewards))
    }
}

impl IspBypassRewards {
    pub fn new() -> Self {
        Self {
            bandwidth_metrics: BandwidthMetrics::new(),
            connection_stats: ConnectionStats::new(),
            cost_savings: 0,
            bypass_multiplier: 1.0,
        }
    }

    pub fn calculate_isp_bypass_rewards(&self) -> Result<TokenReward> {
        let work = IspBypassWork {
            bandwidth_shared_gb: self.bandwidth_metrics.total_shared_gb,
            packets_routed_mb: (self.bandwidth_metrics.total_shared_gb * 1024) as u64, // Estimate from bandwidth
            uptime_hours: self.connection_stats.connection_hours,
            connection_quality: self.connection_stats.avg_quality,
            users_served: self.connection_stats.users_served as u64,
            cost_savings_provided: self.cost_savings,
        };

        let mut reward = TokenReward::calculate_isp_bypass(&work)?;
        
        // Apply bypass multiplier for exceptional service
        if self.bypass_multiplier != 1.0 {
            reward.total_reward = (reward.total_reward as f64 * self.bypass_multiplier) as u64;
        }

        Ok(reward)
    }

    pub fn update_bandwidth_metrics(&mut self, shared_gb: u64, utilization: f64, efficiency: f64) {
        self.bandwidth_metrics.total_shared_gb += shared_gb;
        self.bandwidth_metrics.avg_utilization = 
            (self.bandwidth_metrics.avg_utilization + utilization) / 2.0;
        self.bandwidth_metrics.transfer_efficiency = 
            (self.bandwidth_metrics.transfer_efficiency + efficiency) / 2.0;
    }

    pub fn update_connection_stats(&mut self, users: u32, quality: f64, hours: u64) {
        self.connection_stats.users_served += users;
        self.connection_stats.avg_quality = 
            (self.connection_stats.avg_quality + quality) / 2.0;
        self.connection_stats.connection_hours += hours;
    }
}

impl BandwidthMetrics {
    pub fn new() -> Self {
        Self {
            total_shared_gb: 0,
            peak_capacity_mbps: 0,
            avg_utilization: 0.0,
            transfer_efficiency: 0.0,
        }
    }
}

impl ConnectionStats {
    pub fn new() -> Self {
        Self {
            users_served: 0,
            avg_quality: 0.0,
            connection_hours: 0,
            coverage_area_km2: 0.0,
        }
    }
}

impl MeshDiscoveryRewards {
    pub fn new() -> Self {
        Self {
            routing_metrics: RoutingMetrics::new(),
            discovery_stats: DiscoveryStats::new(),
            contribution_score: 0.0,
        }
    }

    pub fn calculate_mesh_rewards(&self) -> Result<TokenReward> {
        // Calculate rewards based on mesh contribution
        let routing_reward = (self.routing_metrics.packets_routed / 1_000_000) * crate::DEFAULT_ROUTING_RATE;
        
        // Bonus for high-quality routing
        let quality_bonus = if self.routing_metrics.success_rate > 0.95 {
            (routing_reward as f64 * 0.5) as u64
        } else {
            0
        };

        // Discovery contribution bonus
        let discovery_bonus = self.discovery_stats.peers_discovered as u64 * 10; // 10 SOV per peer discovered

        let total_reward = routing_reward + quality_bonus + discovery_bonus;

        Ok(TokenReward {
            routing_reward,
            storage_reward: 0,
            compute_reward: 0,
            quality_bonus,
            uptime_bonus: discovery_bonus,
            total_reward,
            currency: "SOV".to_string(),
        })
    }

    pub fn update_routing_metrics(&mut self, packets: u64, latency: u64, success_rate: f64) {
        self.routing_metrics.packets_routed += packets;
        self.routing_metrics.avg_latency_ms = 
            (self.routing_metrics.avg_latency_ms + latency) / 2;
        self.routing_metrics.success_rate = 
            (self.routing_metrics.success_rate + success_rate) / 2.0;
    }

    pub fn update_discovery_stats(&mut self, peers: u32, requests: u64, geo_score: f64) {
        self.discovery_stats.peers_discovered += peers;
        self.discovery_stats.discovery_requests += requests;
        self.discovery_stats.geo_diversity_score = 
            (self.discovery_stats.geo_diversity_score + geo_score) / 2.0;
        self.discovery_stats.topology_updates += 1;
    }
}

impl RoutingMetrics {
    pub fn new() -> Self {
        Self {
            packets_routed: 0,
            avg_latency_ms: 0,
            success_rate: 0.0,
            active_routes: 0,
        }
    }
}

impl DiscoveryStats {
    pub fn new() -> Self {
        Self {
            peers_discovered: 0,
            discovery_requests: 0,
            topology_updates: 0,
            geo_diversity_score: 0.0,
        }
    }
}

impl MultiWallet {
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            primary_wallet: WalletBalance::new(node_id),
            reward_wallets: HashMap::new(),
            transfer_capabilities: TransferCapabilities::new(),
        }
    }

    pub fn create_reward_wallet(&mut self, wallet_type: String, node_id: [u8; 32]) -> Result<()> {
        if self.reward_wallets.contains_key(&wallet_type) {
            return Err(anyhow!("Wallet type already exists"));
        }

        self.reward_wallets.insert(wallet_type.clone(), WalletBalance::new(node_id));
        self.transfer_capabilities.supported_types.push(wallet_type);

        Ok(())
    }

    pub fn transfer_between_wallets(&mut self, from: &str, to: &str, amount: u64) -> Result<()> {
        if amount > self.transfer_capabilities.daily_transfer_limit {
            return Err(anyhow!("Amount exceeds daily transfer limit"));
        }

        // Calculate transfer fee
        let fee = (amount * self.transfer_capabilities.transfer_fee_rate) / 10000;
        let net_amount = amount - fee;

        // Get source wallet
        let from_wallet = if from == "primary" {
            &mut self.primary_wallet
        } else {
            self.reward_wallets.get_mut(from)
                .ok_or_else(|| anyhow!("Source wallet not found"))?
        };

        if !from_wallet.can_afford(amount) {
            return Err(anyhow!("Insufficient funds"));
        }

        from_wallet.available_balance -= amount;

        // Get destination wallet
        let to_wallet = if to == "primary" {
            &mut self.primary_wallet
        } else {
            self.reward_wallets.get_mut(to)
                .ok_or_else(|| anyhow!("Destination wallet not found"))?
        };

        to_wallet.available_balance += net_amount;

        Ok(())
    }

    pub fn get_total_balance(&self) -> u64 {
        let primary_balance = self.primary_wallet.total_balance();
        let reward_balance: u64 = self.reward_wallets.values()
            .map(|w| w.total_balance())
            .sum();

        primary_balance + reward_balance
    }

    pub fn consolidate_rewards(&mut self) -> Result<u64> {
        if !self.transfer_capabilities.auto_consolidate {
            return Err(anyhow!("Auto-consolidation disabled"));
        }

        let mut total_consolidated = 0;

        for (_, wallet) in self.reward_wallets.iter_mut() {
            let balance = wallet.available_balance;
            if balance > 0 {
                wallet.available_balance = 0;
                self.primary_wallet.available_balance += balance;
                total_consolidated += balance;
            }
        }

        Ok(total_consolidated)
    }
}

impl TransferCapabilities {
    pub fn new() -> Self {
        Self {
            daily_transfer_limit: 1_000_000, // 1M ZHTP
            transfer_fee_rate: 50, // 0.5%
            supported_types: vec!["primary".to_string()],
            auto_consolidate: true,
        }
    }
}

impl TransactionHistory {
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            analytics: TransactionAnalytics::new(),
            filters: HistoryFilters::new(),
        }
    }

    pub fn add_transaction(&mut self, transaction: HistoricalTransaction) {
        self.transactions.push(transaction.clone());
        self.analytics.update_with_transaction(&transaction);
        
        // Keep only last 10,000 transactions
        if self.transactions.len() > 10_000 {
            self.transactions.remove(0);
        }
    }

    pub fn search_transactions(&self, query: &str) -> Vec<&HistoricalTransaction> {
        self.transactions.iter()
            .filter(|tx| {
                // Search in transaction type, location, etc.
                format!("{:?}", tx.tx_type).to_lowercase().contains(&query.to_lowercase()) ||
                tx.location.as_ref().map_or(false, |loc| loc.contains(query))
            })
            .collect()
    }

    pub fn filter_transactions(&self) -> Vec<&HistoricalTransaction> {
        self.transactions.iter()
            .filter(|tx| {
                // Apply date range filter
                if let Some((start, end)) = self.filters.date_range {
                    if tx.timestamp < start || tx.timestamp > end {
                        return false;
                    }
                }

                // Apply transaction type filter
                if !self.filters.tx_types.is_empty() && !self.filters.tx_types.contains(&tx.tx_type) {
                    return false;
                }

                // Apply amount range filter
                if let Some((min, max)) = self.filters.amount_range {
                    if tx.amount < min || tx.amount > max {
                        return false;
                    }
                }

                true
            })
            .collect()
    }

    pub fn get_transaction_summary(&self) -> TransactionSummary {
        let total_count = self.transactions.len();
        let total_value: u64 = self.transactions.iter().map(|tx| tx.amount).sum();
        let avg_value = if total_count > 0 { total_value as f64 / total_count as f64 } else { 0.0 };

        let recent_count = self.transactions.iter()
            .filter(|tx| {
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                current_time - tx.timestamp < 86400 // Last 24 hours
            })
            .count();

        TransactionSummary {
            total_transactions: total_count,
            total_value,
            average_value: avg_value,
            recent_transactions: recent_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub total_transactions: usize,
    pub total_value: u64,
    pub average_value: f64,
    pub recent_transactions: usize,
}

impl TransactionAnalytics {
    pub fn new() -> Self {
        Self {
            volume_by_type: HashMap::new(),
            avg_values: HashMap::new(),
            reward_efficiency: 0.0,
            growth_trends: Vec::new(),
        }
    }

    pub fn update_with_transaction(&mut self, transaction: &HistoricalTransaction) {
        let tx_type_str = format!("{:?}", transaction.tx_type);
        
        // Update volume by type
        *self.volume_by_type.entry(tx_type_str.clone()).or_insert(0) += transaction.amount;
        
        // Update average values
        let current_avg = self.avg_values.get(&tx_type_str).unwrap_or(&0.0);
        let new_avg = (current_avg + transaction.amount as f64) / 2.0;
        self.avg_values.insert(tx_type_str, new_avg);
    }

    pub fn calculate_reward_efficiency(&mut self, total_work: u64, total_rewards: u64) {
        if total_work > 0 {
            self.reward_efficiency = total_rewards as f64 / total_work as f64;
        }
    }
}

impl HistoryFilters {
    pub fn new() -> Self {
        Self {
            date_range: None,
            tx_types: Vec::new(),
            amount_range: None,
            locations: Vec::new(),
        }
    }

    pub fn set_date_range(&mut self, start: u64, end: u64) {
        self.date_range = Some((start, end));
    }

    pub fn add_transaction_type(&mut self, tx_type: TransactionType) {
        if !self.tx_types.contains(&tx_type) {
            self.tx_types.push(tx_type);
        }
    }

    pub fn set_amount_range(&mut self, min: u64, max: u64) {
        self.amount_range = Some((min, max));
    }

    pub fn add_location_filter(&mut self, location: String) {
        if !self.locations.contains(&location) {
            self.locations.push(location);
        }
    }

    pub fn clear_filters(&mut self) {
        self.date_range = None;
        self.tx_types.clear();
        self.amount_range = None;
        self.locations.clear();
    }
}

/// Public API functions for external use
pub fn create_reward_manager(node_id: [u8; 32]) -> RewardManager {
    RewardManager::new(node_id)
}

pub fn create_staking_system() -> StakingSystem {
    StakingSystem::new()
}

pub fn create_isp_bypass_rewards() -> IspBypassRewards {
    IspBypassRewards::new()
}

pub fn create_mesh_discovery_rewards() -> MeshDiscoveryRewards {
    MeshDiscoveryRewards::new()
}

pub fn create_multi_wallet(node_id: [u8; 32]) -> MultiWallet {
    MultiWallet::new(node_id)
}

pub fn create_transaction_history() -> TransactionHistory {
    TransactionHistory::new()
}
