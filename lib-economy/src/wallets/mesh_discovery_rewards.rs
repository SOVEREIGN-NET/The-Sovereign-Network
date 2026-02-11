//! Mesh discovery reward calculation and management
//! 
//! Implements reward systems for nodes that contribute to mesh network discovery,
//! routing optimization, and network topology maintenance using lib-network data.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{TokenReward, EconomicModel};
use crate::types::NetworkStats;
use crate::wallets::WalletBalance;
use crate::wasm::logging::info;

// network integrations
use crate::network_types::{
    get_mesh_status, get_network_statistics, get_discovery_statistics, get_active_peer_count,
    MeshStatus, DiscoveryStatistics
};
use crate::rewards::RewardCalculator;

/// Mesh discovery work metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDiscoveryWork {
    /// Number of new peers discovered
    pub peers_discovered: u32,
    /// Discovery requests successfully handled
    pub discovery_requests_handled: u64,
    /// Routing table updates contributed
    pub routing_updates: u32,
    /// Network topology improvements
    pub topology_improvements: u32,
    /// Geographic diversity contributions
    pub geo_diversity_score: f64,
    /// Discovery quality score (success rate)
    pub discovery_quality: f64,
    /// Uptime during discovery operations
    pub discovery_uptime_hours: u64,
}

impl MeshDiscoveryWork {
    pub fn new() -> Self {
        Self {
            peers_discovered: 0,
            discovery_requests_handled: 0,
            routing_updates: 0,
            topology_improvements: 0,
            geo_diversity_score: 0.0,
            discovery_quality: 0.0,
            discovery_uptime_hours: 0,
        }
    }

    pub fn add_peer_discovery(&mut self, count: u32) {
        self.peers_discovered += count;
    }

    pub fn add_discovery_requests(&mut self, count: u64) {
        self.discovery_requests_handled += count;
    }

    pub fn add_routing_update(&mut self) {
        self.routing_updates += 1;
    }

    pub fn update_geo_diversity(&mut self, score: f64) {
        self.geo_diversity_score = score.max(0.0).min(1.0);
    }

    pub fn update_discovery_quality(&mut self, quality: f64) {
        self.discovery_quality = quality.max(0.0).min(1.0);
    }
}

/// Comprehensive mesh discovery reward manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDiscoveryRewardManager {
    /// Current discovery work being tracked
    pub current_work: MeshDiscoveryWork,
    /// Historical discovery performance
    pub discovery_history: Vec<MeshDiscoveryPerformanceRecord>,
    /// Total peers discovered lifetime
    pub total_peers_discovered: u32,
    /// Total discovery requests handled
    pub total_discovery_requests: u64,
    /// Network topology contribution score
    pub topology_contribution_score: f64,
    /// Geographic coverage contribution
    pub geographic_coverage: GeographicCoverage,
    /// Discovery reliability metrics
    pub reliability_metrics: DiscoveryReliabilityMetrics,
}

/// Historical performance record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDiscoveryPerformanceRecord {
    pub timestamp: u64,
    pub work_performed: MeshDiscoveryWork,
    pub reward_earned: u64,
    pub network_health_contribution: f64,
    pub peer_count_at_time: u32,
}

/// Geographic coverage contribution tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicCoverage {
    pub regions_covered: u32,
    pub coverage_diversity_score: f64,
    pub bridge_connections: u32, // Connections between geographic regions
    pub rural_connectivity_score: f64,
}

/// Discovery reliability metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryReliabilityMetrics {
    pub discovery_success_rate: f64,
    pub average_response_time_ms: f64,
    pub uptime_percentage: f64,
    pub consistency_score: f64, // How consistent discovery results are
}

impl MeshDiscoveryRewardManager {
    /// Create new mesh discovery reward manager
    pub fn new() -> Self {
        Self {
            current_work: MeshDiscoveryWork::new(),
            discovery_history: Vec::new(),
            total_peers_discovered: 0,
            total_discovery_requests: 0,
            topology_contribution_score: 0.0,
            geographic_coverage: GeographicCoverage {
                regions_covered: 0,
                coverage_diversity_score: 0.0,
                bridge_connections: 0,
                rural_connectivity_score: 0.0,
            },
            reliability_metrics: DiscoveryReliabilityMetrics {
                discovery_success_rate: 0.0,
                average_response_time_ms: 0.0,
                uptime_percentage: 0.0,
                consistency_score: 0.0,
            },
        }
    }

    /// Record mesh discovery work using network data
    pub async fn record_discovery_work(&mut self, work: MeshDiscoveryWork) -> Result<()> {
        // Get network discovery statistics for validation
        let discovery_stats = get_discovery_statistics().await?;
        let mesh_status = get_mesh_status().await?;
        let network_stats = get_network_statistics().await?;

        // Validate discovery work against network data and statistics
        self.validate_discovery_work(&work, &discovery_stats, &mesh_status).await?;
        self.validate_discovery_work_against_network_stats(&work, &network_stats).await?;

        // Update current work with validated data
        self.current_work.peers_discovered += work.peers_discovered;
        self.current_work.discovery_requests_handled += work.discovery_requests_handled;
        self.current_work.routing_updates += work.routing_updates;
        self.current_work.topology_improvements += work.topology_improvements;
        
        // Update quality metrics with network validation
        let validated_quality = self.calculate_validated_discovery_quality(&work, &discovery_stats).await?;
        self.current_work.discovery_quality = validated_quality;
        self.current_work.geo_diversity_score = work.geo_diversity_score;
        self.current_work.discovery_uptime_hours += work.discovery_uptime_hours;

        // Update aggregate metrics
        self.total_peers_discovered += work.peers_discovered;
        self.total_discovery_requests += work.discovery_requests_handled;

        // Update topology contribution score based on network impact
        self.update_topology_contribution(&mesh_status, &discovery_stats).await?;

        // Update geographic coverage based on peer distribution
        self.update_geographic_coverage(&discovery_stats).await?;

        // Update reliability metrics with network measurements
        self.update_reliability_metrics(&work, &discovery_stats).await?;

        // Update comprehensive work metrics tracking
        self.update_discovery_work_metrics(&work);

        info!(
            "Mesh discovery work recorded: {} peers discovered, {} requests handled, {:.1}% quality, {} topology improvements",
            work.peers_discovered, work.discovery_requests_handled, validated_quality * 100.0, work.topology_improvements
        );

        Ok(())
    }

    /// Calculate mesh discovery rewards using network consensus
    pub async fn calculate_discovery_rewards(&mut self, economic_model: &EconomicModel, network_stats: &NetworkStats) -> Result<TokenReward> {
        // Get network state for reward calculation
        let mesh_status = get_mesh_status().await?;
        let peer_count = get_active_peer_count().await?;
        let discovery_stats = get_discovery_statistics().await?;
        
        // Use discovery stats to inform reward calculations
        let discovery_effectiveness = if discovery_stats.successful_connections > 0 {
            discovery_stats.successful_connections as f64 / (discovery_stats.successful_connections + discovery_stats.failed_connections) as f64
        } else {
            0.5 // Default effectiveness
        };
        
        // Apply economic model parameters for discovery rewards  
        let economic_multiplier = 1.0 + economic_model.quality_multiplier; // Use quality multiplier
        let network_demand_factor = network_stats.total_nodes as f64 / 100.0; // Scale by network size

        // Calculate base discovery rewards
        let base_discovery_reward = self.calculate_base_discovery_reward().await?;
        
        // Calculate topology improvement bonuses
        let topology_bonus = self.calculate_topology_improvement_bonus(&mesh_status).await?;
        
        // Calculate geographic diversity bonuses
        let diversity_bonus = self.calculate_geographic_diversity_bonus().await?;
        
        // Calculate network health contribution bonuses
        let network_health_bonus = self.calculate_network_health_bonus(&mesh_status, peer_count as usize).await?;
        
        // Calculate reliability bonuses based on consistent performance
        let reliability_bonus = self.calculate_reliability_bonus().await?;

        // Calculate network utilization multiplier using network stats
        let network_utilization = mesh_status.connectivity_percentage / 100.0;
        let bandwidth_utilization = network_stats.utilization; // Use correct field name
        let combined_utilization = (network_utilization + bandwidth_utilization) / 2.0;
        
        let utilization_multiplier = if combined_utilization > 0.8 {
            1.0 + economic_model.uptime_multiplier // High utilization bonus
        } else if combined_utilization > 0.5 {
            1.0 + (economic_model.uptime_multiplier * 0.5) // Medium utilization bonus
        } else {
            1.0 // Standard rate
        };

        // Combine all reward components with economic model adjustments
        let total_base_reward = base_discovery_reward + topology_bonus + diversity_bonus + network_health_bonus + reliability_bonus;
        let economically_adjusted_reward = (total_base_reward as f64 * economic_multiplier * discovery_effectiveness) as u64;
        let demand_adjusted_reward = (economically_adjusted_reward as f64 * (1.0 + network_demand_factor * 0.1)) as u64; // Network demand bonus
        let network_adjusted_reward = (demand_adjusted_reward as f64 * utilization_multiplier) as u64;

        // Apply final consensus adjustments using reward calculator
        let mut reward_calculator = RewardCalculator::new();
        reward_calculator.adjust_base_reward(economic_model.base_routing_rate * 80); // Use routing rate for discovery
        
        let work_bonus = reward_calculator.calculate_work_reward(crate::rewards::types::UsefulWorkType::MeshDiscovery, discovery_stats.peers_discovered);
        let final_reward = network_adjusted_reward + work_bonus;

        // Create comprehensive reward structure
        let comprehensive_reward = TokenReward {
            routing_reward: base_discovery_reward * 60 / 100, // 60% for routing discovery
            storage_reward: 0, // Discovery doesn't involve storage
            compute_reward: base_discovery_reward * 20 / 100, // 20% for computation
            quality_bonus: topology_bonus + diversity_bonus,
            uptime_bonus: reliability_bonus + network_health_bonus,
            total_reward: final_reward,
            currency: "SOV".to_string(),
        };

        // Record performance with network validation
        self.record_discovery_performance(&comprehensive_reward, &mesh_status).await?;

        info!(
            " Mesh discovery rewards calculated: {} SOV (base: {}, topology: {}, diversity: {}, health: {}, reliability: {}, network_util: {:.2}x, demand: {:.2}x)",
            comprehensive_reward.total_reward,
            base_discovery_reward,
            topology_bonus,
            diversity_bonus,
            network_health_bonus,
            reliability_bonus,
            utilization_multiplier,
            network_demand_factor
        );

        Ok(comprehensive_reward)
    }

    /// Distribute discovery rewards to multiple participants
    pub async fn distribute_discovery_rewards(
        participants: &mut HashMap<[u8; 32], (&mut WalletBalance, MeshDiscoveryWork)>,
        total_reward_pool: u64,
    ) -> Result<()> {
        let mut total_contribution_score = 0u64;

        // Calculate contribution scores for each participant
        let mut contribution_scores = HashMap::new();
        for (node_id, (_, work)) in participants.iter() {
            let score = calculate_contribution_score(work).await?;
            contribution_scores.insert(*node_id, score);
            total_contribution_score += score;
        }

        // Distribute rewards proportionally
        let participants_len = participants.len();
        for (node_id, (wallet, _)) in participants.iter_mut() {
            if let Some(score) = contribution_scores.get(node_id) {
                let reward_amount = if total_contribution_score > 0 {
                    (total_reward_pool * score) / total_contribution_score
                } else {
                    total_reward_pool / participants_len as u64
                };

                let reward = TokenReward {
                    routing_reward: reward_amount * 60 / 100,
                    storage_reward: 0,
                    compute_reward: reward_amount * 20 / 100,
                    quality_bonus: reward_amount * 10 / 100,
                    uptime_bonus: reward_amount * 10 / 100,
                    total_reward: reward_amount,
                    currency: "SOV".to_string(),
                };

                wallet.add_reward(&reward)?;

                info!(
                    "Distributed {} SOV discovery reward to node {} (contribution score: {})",
                    reward_amount, hex::encode(node_id), score
                );
            }
        }

        Ok(())
    }

    /// Get comprehensive discovery statistics
    pub async fn get_discovery_statistics(&self) -> Result<serde_json::Value> {
        let mesh_status = get_mesh_status().await?;
        let discovery_stats = get_discovery_statistics().await?;

        Ok(serde_json::json!({
            "current_work": {
                "peers_discovered": self.current_work.peers_discovered,
                "discovery_requests_handled": self.current_work.discovery_requests_handled,
                "routing_updates": self.current_work.routing_updates,
                "topology_improvements": self.current_work.topology_improvements,
                "discovery_quality": self.current_work.discovery_quality,
                "geo_diversity_score": self.current_work.geo_diversity_score,
                "uptime_hours": self.current_work.discovery_uptime_hours
            },
            "lifetime_metrics": {
                "total_peers_discovered": self.total_peers_discovered,
                "total_discovery_requests": self.total_discovery_requests,
                "topology_contribution_score": self.topology_contribution_score,
                "performance_records": self.discovery_history.len()
            },
            "geographic_coverage": {
                "regions_covered": self.geographic_coverage.regions_covered,
                "coverage_diversity_score": self.geographic_coverage.coverage_diversity_score,
                "bridge_connections": self.geographic_coverage.bridge_connections,
                "rural_connectivity_score": self.geographic_coverage.rural_connectivity_score
            },
            "reliability_metrics": {
                "discovery_success_rate": self.reliability_metrics.discovery_success_rate,
                "average_response_time_ms": self.reliability_metrics.average_response_time_ms,
                "uptime_percentage": self.reliability_metrics.uptime_percentage,
                "consistency_score": self.reliability_metrics.consistency_score
            },
            "network_context": {
                "mesh_connectivity": mesh_status.mesh_connectivity,
                "active_peers": mesh_status.active_peers,
                "connectivity_percentage": mesh_status.connectivity_percentage,
                "stability": mesh_status.stability,
                "network_discovery_stats": discovery_stats
            }
        }))
    }

    /// Reset work period for next calculation cycle
    pub async fn reset_discovery_period(&mut self) -> Result<()> {
        self.current_work = MeshDiscoveryWork::new();
        
        info!(" Mesh discovery work period reset for next calculation cycle");
        Ok(())
    }

    // Private helper methods using network data

    async fn validate_discovery_work(
        &self,
        work: &MeshDiscoveryWork,
        discovery_stats: &DiscoveryStatistics,
        mesh_status: &MeshStatus
    ) -> Result<()> {
        // Validate peer discovery claims against network statistics
        if work.peers_discovered > discovery_stats.total_peers_discovered_per_hour {
            return Err(anyhow::anyhow!("Reported peer discoveries exceed network capability"));
        }

        // Validate discovery quality against network measurements
        if work.discovery_quality > discovery_stats.average_discovery_success_rate + 0.1 {
            return Err(anyhow::anyhow!("Reported discovery quality exceeds network measurements"));
        }

        // Validate topology improvements against mesh stability
        let max_topology_improvements = (mesh_status.active_peers / 10).max(1);
        if work.topology_improvements > max_topology_improvements {
            return Err(anyhow::anyhow!("Reported topology improvements exceed network capacity"));
        }

        Ok(())
    }

    /// Validate discovery work against comprehensive network statistics
    async fn validate_discovery_work_against_network_stats(
        &self,
        work: &MeshDiscoveryWork,
        network_stats: &crate::network_types::NetworkStatistics
    ) -> Result<()> {
        // Validate peer discovery capacity against total network active peers
        let max_discoverable_peers = (network_stats.mesh_status.active_peers / 2).max(1); // Can discover up to 50% of network
        if work.peers_discovered > max_discoverable_peers {
            return Err(anyhow::anyhow!("Peer discoveries exceed network size limitations"));
        }

        // Validate discovery quality is within reasonable bounds
        if work.discovery_quality > 1.0 || work.discovery_quality < 0.0 {
            return Err(anyhow::anyhow!("Discovery quality out of valid range: {:.3}", work.discovery_quality));
        }

        // Check network congestion and validate work load
        let high_congestion = network_stats.congestion_level >= 3; // Assume 3+ is high congestion
        
        if high_congestion && work.discovery_requests_handled > 1000 {
            return Err(anyhow::anyhow!("High discovery workload during network congestion is suspicious"));
        }

        // Validate routing updates against network transaction activity
        let max_routing_updates = (network_stats.total_transactions / 1000).max(10); // Max 0.1% of total transactions
        if u64::from(work.routing_updates) > max_routing_updates {
            return Err(anyhow::anyhow!("Routing updates exceed reasonable proportion of network activity"));
        }

        Ok(())
    }

    async fn calculate_validated_discovery_quality(
        &self,
        work: &MeshDiscoveryWork,
        discovery_stats: &DiscoveryStatistics
    ) -> Result<f64> {
        // Blend reported quality with actual network measurements
        let network_quality = discovery_stats.average_discovery_success_rate;
        let reported_quality = work.discovery_quality;
        
        // Weight network measurements higher for validation
        let validated_quality = (network_quality * 0.7 + reported_quality * 0.3).min(1.0).max(0.0);
        
        Ok(validated_quality)
    }

    async fn update_topology_contribution(
        &mut self,
        mesh_status: &MeshStatus,
        discovery_stats: &DiscoveryStatistics
    ) -> Result<()> {
        // Calculate topology contribution based on network improvements
        let stability_contribution = mesh_status.stability * 0.3;
        let redundancy_contribution = mesh_status.redundancy * 0.2;
        let discovery_contribution = (discovery_stats.average_discovery_success_rate * 0.5).min(0.5);
        
        let new_contribution = stability_contribution + redundancy_contribution + discovery_contribution;
        self.topology_contribution_score = (self.topology_contribution_score * 0.8 + new_contribution * 0.2).min(1.0);

        Ok(())
    }

    async fn update_geographic_coverage(
        &mut self,
        discovery_stats: &DiscoveryStatistics
    ) -> Result<()> {
        // Update based on geographic distribution of discovered peers
        self.geographic_coverage.regions_covered = discovery_stats.regions_with_peers;
        self.geographic_coverage.coverage_diversity_score = discovery_stats.geographic_diversity_index;
        
        // Calculate bridge connections (connections between distant regions)
        self.geographic_coverage.bridge_connections = discovery_stats.long_distance_connections;
        
        // Rural connectivity based on low-density peer areas
        self.geographic_coverage.rural_connectivity_score = discovery_stats.rural_connectivity_index;

        Ok(())
    }

    async fn update_reliability_metrics(
        &mut self,
        work: &MeshDiscoveryWork,
        discovery_stats: &DiscoveryStatistics
    ) -> Result<()> {
        // Update with network performance measurements
        self.reliability_metrics.discovery_success_rate = (self.reliability_metrics.discovery_success_rate * 0.8 + work.discovery_quality * 0.2).min(1.0);
        self.reliability_metrics.average_response_time_ms = (self.reliability_metrics.average_response_time_ms * 0.8 + discovery_stats.average_response_time_ms * 0.2).max(0.0);
        
        // Calculate uptime percentage
        let total_hours = 24; // Assume 24-hour periods
        let uptime_percentage = (work.discovery_uptime_hours as f64 / total_hours as f64 * 100.0).min(100.0);
        self.reliability_metrics.uptime_percentage = (self.reliability_metrics.uptime_percentage * 0.8 + uptime_percentage * 0.2).min(100.0);
        
        // Consistency score based on stable discovery patterns
        let consistency = if discovery_stats.discovery_variance < 0.2 { 0.9 } else { 0.7 };
        self.reliability_metrics.consistency_score = (self.reliability_metrics.consistency_score * 0.8 + consistency * 0.2).min(1.0);

        Ok(())
    }

    async fn calculate_base_discovery_reward(&self) -> Result<u64> {
        // Base reward calculation
        let peer_discovery_reward = self.current_work.peers_discovered as u64 * 50; // 50 SOV per peer
        let request_handling_reward = (self.current_work.discovery_requests_handled / 100) * 10; // 10 SOV per 100 requests
        let routing_update_reward = self.current_work.routing_updates as u64 * 25; // 25 SOV per update
        
        Ok(peer_discovery_reward + request_handling_reward + routing_update_reward)
    }

    async fn calculate_topology_improvement_bonus(&self, mesh_status: &MeshStatus) -> Result<u64> {
        // Bonus based on actual network topology improvements
        let stability_bonus = (mesh_status.stability * 100.0) as u64;
        let redundancy_bonus = (mesh_status.redundancy * 50.0) as u64;
        let topology_improvements_bonus = self.current_work.topology_improvements as u64 * 100;
        
        Ok(stability_bonus + redundancy_bonus + topology_improvements_bonus)
    }

    async fn calculate_geographic_diversity_bonus(&self) -> Result<u64> {
        // Bonus for geographic diversity contributions
        let coverage_bonus = (self.geographic_coverage.coverage_diversity_score * 200.0) as u64;
        let bridge_bonus = self.geographic_coverage.bridge_connections as u64 * 150;
        let rural_bonus = (self.geographic_coverage.rural_connectivity_score * 300.0) as u64;
        
        Ok(coverage_bonus + bridge_bonus + rural_bonus)
    }

    async fn calculate_network_health_bonus(&self, mesh_status: &MeshStatus, peer_count: usize) -> Result<u64> {
        // Bonus based on contribution to overall network health
        let connectivity_bonus = (mesh_status.connectivity_percentage * 2.0) as u64;
        let peer_growth_bonus = if peer_count > 10 { 100 } else { 50 };
        let health_contribution = (self.topology_contribution_score * 150.0) as u64;
        
        Ok(connectivity_bonus + peer_growth_bonus + health_contribution)
    }

    async fn calculate_reliability_bonus(&self) -> Result<u64> {
        // Bonus for reliable discovery services
        let success_rate_bonus = (self.reliability_metrics.discovery_success_rate * 100.0) as u64;
        let uptime_bonus = (self.reliability_metrics.uptime_percentage * 2.0) as u64;
        let consistency_bonus = (self.reliability_metrics.consistency_score * 150.0) as u64;
        
        Ok(success_rate_bonus + uptime_bonus + consistency_bonus)
    }

    async fn record_discovery_performance(
        &mut self,
        reward: &TokenReward,
        mesh_status: &MeshStatus
    ) -> Result<()> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let performance_record = MeshDiscoveryPerformanceRecord {
            timestamp: current_time,
            work_performed: self.current_work.clone(),
            reward_earned: reward.total_reward,
            network_health_contribution: self.topology_contribution_score,
            peer_count_at_time: mesh_status.active_peers,
        };

        self.discovery_history.push(performance_record);

        // Keep only last 500 records
        if self.discovery_history.len() > 500 {
            self.discovery_history.remove(0);
        }

        Ok(())
    }

    /// Update comprehensive work metrics from mesh discovery work
    fn update_discovery_work_metrics(&mut self, work: &MeshDiscoveryWork) {
        // Convert mesh discovery work to general work metrics for analytics
        let _discovery_operations = work.peers_discovered as u64 + work.discovery_requests_handled + work.routing_updates as u64;
        
        // Log comprehensive discovery work metrics for external analytics systems
        info!(
            "Mesh discovery work metrics: peers_discovered={}, requests_handled={}, routing_updates={}, topology_improvements={}, quality={:.3}, geo_diversity={:.3}, uptime={}h",
            work.peers_discovered,
            work.discovery_requests_handled,
            work.routing_updates,
            work.topology_improvements,
            work.discovery_quality,
            work.geo_diversity_score,
            work.discovery_uptime_hours
        );

        // In a full implementation, this would update a WorkMetrics struct field
        // and integrate with external monitoring and mesh topology analytics systems
    }
}

/// Calculate contribution score for a discovery work session
async fn calculate_contribution_score(work: &MeshDiscoveryWork) -> Result<u64> {
    let peer_score = work.peers_discovered as u64 * 10;
    let request_score = work.discovery_requests_handled / 50; // 1 point per 50 requests
    let topology_score = work.topology_improvements as u64 * 20;
    let quality_score = (work.discovery_quality * 100.0) as u64;
    let uptime_score = work.discovery_uptime_hours * 5;
    
    Ok(peer_score + request_score + topology_score + quality_score + uptime_score)
}

impl Default for MeshDiscoveryRewardManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a new mesh discovery reward manager
pub fn create_mesh_discovery_reward_manager() -> MeshDiscoveryRewardManager {
    MeshDiscoveryRewardManager::new()
}

/// Calculate mesh discovery rewards for given work
pub async fn calculate_mesh_discovery_rewards(
    work: &MeshDiscoveryWork,
    economic_model: &EconomicModel,
    network_stats: &NetworkStats,
) -> Result<TokenReward> {
    let mut manager = MeshDiscoveryRewardManager::new();
    manager.record_discovery_work(work.clone()).await?;
    manager.calculate_discovery_rewards(economic_model, network_stats).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_discovery_work_creation() {
        let work = MeshDiscoveryWork::new();
        
        assert_eq!(work.peers_discovered, 0);
        assert_eq!(work.discovery_requests_handled, 0);
        assert_eq!(work.routing_updates, 0);
        assert_eq!(work.discovery_quality, 0.0);
    }

    #[test]
    fn test_mesh_discovery_work_operations() {
        let mut work = MeshDiscoveryWork::new();
        
        work.add_peer_discovery(5);
        work.add_discovery_requests(100);
        work.add_routing_update();
        work.update_discovery_quality(0.95);
        work.update_geo_diversity(0.8);
        
        assert_eq!(work.peers_discovered, 5);
        assert_eq!(work.discovery_requests_handled, 100);
        assert_eq!(work.routing_updates, 1);
        assert_eq!(work.discovery_quality, 0.95);
        assert_eq!(work.geo_diversity_score, 0.8);
    }

    #[test]
    fn test_reward_manager_creation() {
        let manager = MeshDiscoveryRewardManager::new();
        
        assert_eq!(manager.total_peers_discovered, 0);
        assert_eq!(manager.total_discovery_requests, 0);
        assert_eq!(manager.topology_contribution_score, 0.0);
        assert_eq!(manager.discovery_history.len(), 0);
    }
}
