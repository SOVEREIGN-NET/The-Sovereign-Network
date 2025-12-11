//! Mesh Router Monitoring
//! 
//! Performance tracking, metrics, and alerting for mesh router
//! 
//! ✅ **Phase 4 Integration**: Now uses lib-network::monitoring::HealthMonitor for network metrics
//! Delegates network-level monitoring to lib-network while maintaining application-specific
//! peer reputation tracking and performance metrics.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{debug, info};
use anyhow::Result;

use super::core::MeshRouter;
use crate::server::monitoring::{
    PeerPerformanceStats, SyncPerformanceMetrics, SyncAlert, 
    AlertLevel, AlertThresholds, MetricsSnapshot
};

// ✅ Phase 4: Import lib-network monitoring components
use lib_network::monitoring::health_monitoring::{HealthMonitor, NetworkHealthSummary};

impl MeshRouter {
    // ==================== Performance Monitoring Getters ====================
    
    /// Get performance metrics
    pub async fn get_performance_metrics(&self) -> SyncPerformanceMetrics {
        self.performance_metrics.read().await.clone()
    }
    
    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<SyncAlert> {
        self.active_alerts.read().await.clone()
    }
    
    /// Acknowledge an alert by ID
    pub async fn acknowledge_alert(&self, alert_id: &str) -> bool {
        let mut alerts = self.active_alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            return true;
        }
        false
    }
    
    /// Clear acknowledged alerts
    pub async fn clear_acknowledged_alerts(&self) {
        let mut alerts = self.active_alerts.write().await;
        alerts.retain(|a| !a.acknowledged);
    }
    
    /// Get alert thresholds
    pub async fn get_alert_thresholds(&self) -> AlertThresholds {
        self.alert_thresholds.read().await.clone()
    }
    
    /// Update alert thresholds
    pub async fn update_alert_thresholds(&self, thresholds: AlertThresholds) {
        *self.alert_thresholds.write().await = thresholds;
    }
    
    /// Get metrics history
    pub async fn get_metrics_history(&self, last_n: Option<usize>) -> Vec<MetricsSnapshot> {
        let history = self.metrics_history.read().await;
        match last_n {
            Some(n) => {
                let start = history.snapshots.len().saturating_sub(n);
                history.snapshots[start..].to_vec()
            }
            None => history.snapshots.clone(),
        }
    }
    
    /// Get peer-specific performance metrics
    pub async fn get_peer_performance(&self, peer_id: &str) -> Option<PeerPerformanceStats> {
        let reputation = self.peer_reputations.read().await.get(peer_id).cloned()?;
        
        Some(PeerPerformanceStats {
            peer_id: peer_id.to_string(),
            reputation_score: reputation.score,
            blocks_accepted: reputation.blocks_accepted,
            blocks_rejected: reputation.blocks_rejected,
            txs_accepted: reputation.txs_accepted,
            txs_rejected: reputation.txs_rejected,
            violations: reputation.violations,
            acceptance_rate: reputation.get_acceptance_rate(),
            first_seen: reputation.first_seen,
            last_seen: reputation.last_seen,
        })
    }
    
    /// List all peers with performance stats
    pub async fn list_peer_performance(&self) -> Vec<PeerPerformanceStats> {
        let reputations = self.peer_reputations.read().await;
        reputations.iter().map(|(peer_id, rep)| {
            PeerPerformanceStats {
                peer_id: peer_id.clone(),
                reputation_score: rep.score,
                blocks_accepted: rep.blocks_accepted,
                blocks_rejected: rep.blocks_rejected,
                txs_accepted: rep.txs_accepted,
                txs_rejected: rep.txs_rejected,
                violations: rep.violations,
                acceptance_rate: rep.get_acceptance_rate(),
                first_seen: rep.first_seen,
                last_seen: rep.last_seen,
            }
        }).collect()
    }

    // ==================== Performance Tracking Methods ====================

    /// Record block propagation latency
    pub async fn track_block_latency(&self, block_timestamp: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if now > block_timestamp {
            let latency_ms = ((now - block_timestamp) * 1000) as u64;
            
            // Add to latency samples for percentile calculation
            let mut samples = self.latency_samples_blocks.write().await;
            samples.push(latency_ms);
            
            // Keep only last 1000 samples to prevent unbounded growth
            if samples.len() > 1000 {
                let excess = samples.len() - 1000;
                samples.drain(0..excess);
            }
            
            // Update metrics
            self.update_performance_metrics().await;
        }
    }

    /// Record transaction propagation latency
    pub async fn track_tx_latency(&self, tx_timestamp: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if now > tx_timestamp {
            let latency_ms = ((now - tx_timestamp) * 1000) as u64;
            
            // Add to latency samples
            let mut samples = self.latency_samples_txs.write().await;
            samples.push(latency_ms);
            
            // Keep only last 1000 samples
            if samples.len() > 1000 {
                let excess = samples.len() - 1000;
                samples.drain(0..excess);
            }
            
            // Update metrics
            self.update_performance_metrics().await;
        }
    }

    /// Record bytes sent to track bandwidth
    pub async fn track_bytes_sent(&self, bytes: u64) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.total_bytes_sent += bytes;
    }

    /// Record bytes received to track bandwidth
    pub async fn track_bytes_received(&self, bytes: u64) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.total_bytes_received += bytes;
    }

    /// Calculate p95 percentile from samples
    fn calculate_p95(samples: &[u64]) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        
        let index = ((sorted.len() as f64) * 0.95).ceil() as usize;
        sorted.get(index.saturating_sub(1)).copied().unwrap_or(0)
    }

    /// Update performance metrics with current data
    pub async fn update_performance_metrics(&self) {
        let mut metrics = self.performance_metrics.write().await;
        let broadcast_metrics = self.broadcast_metrics.read().await;
        
        // Calculate block latency metrics
        let block_samples = self.latency_samples_blocks.read().await;
        if !block_samples.is_empty() {
            let sum: u64 = block_samples.iter().sum();
            metrics.avg_block_propagation_ms = sum as f64 / block_samples.len() as f64;
            metrics.min_block_latency_ms = *block_samples.iter().min().unwrap_or(&0);
            metrics.max_block_latency_ms = *block_samples.iter().max().unwrap_or(&0);
            metrics.p95_block_latency_ms = Self::calculate_p95(&block_samples);
        }
        
        // Calculate tx latency metrics
        let tx_samples = self.latency_samples_txs.read().await;
        if !tx_samples.is_empty() {
            let sum: u64 = tx_samples.iter().sum();
            metrics.avg_tx_propagation_ms = sum as f64 / tx_samples.len() as f64;
            metrics.min_tx_latency_ms = *tx_samples.iter().min().unwrap_or(&0);
            metrics.max_tx_latency_ms = *tx_samples.iter().max().unwrap_or(&0);
            metrics.p95_tx_latency_ms = Self::calculate_p95(&tx_samples);
        }
        
        // Calculate bandwidth metrics
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let duration = now - metrics.measurement_start;
        
        if duration > 0 {
            metrics.bytes_sent_per_sec = metrics.total_bytes_sent as f64 / duration as f64;
            metrics.bytes_received_per_sec = metrics.total_bytes_received as f64 / duration as f64;
            
            let current_bps = (metrics.bytes_sent_per_sec + metrics.bytes_received_per_sec) as u64;
            if current_bps > metrics.peak_bandwidth_usage_bps {
                metrics.peak_bandwidth_usage_bps = current_bps;
            }
        }
        
        // Calculate duplicate ratios
        let total_blocks = broadcast_metrics.blocks_received + broadcast_metrics.blocks_relayed;
        if total_blocks > 0 {
            metrics.duplicate_block_ratio = (broadcast_metrics.blocks_rejected as f64 / total_blocks as f64) * 100.0;
        }
        
        let total_txs = broadcast_metrics.transactions_received + broadcast_metrics.transactions_relayed;
        if total_txs > 0 {
            metrics.duplicate_tx_ratio = (broadcast_metrics.transactions_rejected as f64 / total_txs as f64) * 100.0;
        }
        
        // Calculate validation success rate
        let total_validated = broadcast_metrics.blocks_received + broadcast_metrics.transactions_received;
        let total_rejected = broadcast_metrics.blocks_rejected + broadcast_metrics.transactions_rejected;
        if total_validated > 0 {
            metrics.validation_success_rate = ((total_validated - total_rejected) as f64 / total_validated as f64) * 100.0;
        }
        
        // Calculate relay efficiency
        let total_sent = broadcast_metrics.blocks_sent + broadcast_metrics.transactions_sent;
        if total_sent > 0 {
            metrics.relay_efficiency = ((total_blocks + total_txs) as f64 / total_sent as f64) * 100.0;
        }
        
        metrics.measurement_duration_secs = duration;
    }

    /// Check thresholds and generate alerts
    pub async fn check_and_generate_alerts(&self) {
        let metrics = self.performance_metrics.read().await;
        let thresholds = self.alert_thresholds.read().await;
        let mut alerts = self.active_alerts.write().await;
        
        // Check block latency threshold
        if metrics.avg_block_propagation_ms > thresholds.max_block_latency_ms as f64 {
            let alert = SyncAlert::new(
                AlertLevel::Warning,
                "block_latency".to_string(),
                format!("Block propagation latency ({:.2}ms) exceeds threshold ({}ms)", 
                        metrics.avg_block_propagation_ms, thresholds.max_block_latency_ms)
            ).with_metric(metrics.avg_block_propagation_ms, thresholds.max_block_latency_ms as f64);
            
            if !alerts.iter().any(|a| a.category == "block_latency" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check tx latency threshold
        if metrics.avg_tx_propagation_ms > thresholds.max_tx_latency_ms as f64 {
            let alert = SyncAlert::new(
                AlertLevel::Warning,
                "tx_latency".to_string(),
                format!("Transaction propagation latency ({:.2}ms) exceeds threshold ({}ms)", 
                        metrics.avg_tx_propagation_ms, thresholds.max_tx_latency_ms)
            ).with_metric(metrics.avg_tx_propagation_ms, thresholds.max_tx_latency_ms as f64);
            
            if !alerts.iter().any(|a| a.category == "tx_latency" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check bandwidth threshold
        let bandwidth_mbps = (metrics.bytes_sent_per_sec + metrics.bytes_received_per_sec) / 1_000_000.0;
        if bandwidth_mbps > thresholds.max_bandwidth_mbps {
            let alert = SyncAlert::new(
                AlertLevel::Critical,
                "bandwidth".to_string(),
                format!("Bandwidth usage ({:.2} MB/s) exceeds threshold ({:.2} MB/s)", 
                        bandwidth_mbps, thresholds.max_bandwidth_mbps)
            ).with_metric(bandwidth_mbps, thresholds.max_bandwidth_mbps);
            
            if !alerts.iter().any(|a| a.category == "bandwidth" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check validation success rate
        if metrics.validation_success_rate < thresholds.min_validation_success_rate && metrics.validation_success_rate > 0.0 {
            let alert = SyncAlert::new(
                AlertLevel::Critical,
                "validation_rate".to_string(),
                format!("Validation success rate ({:.1}%) below threshold ({:.1}%)", 
                        metrics.validation_success_rate, thresholds.min_validation_success_rate)
            ).with_metric(metrics.validation_success_rate, thresholds.min_validation_success_rate);
            
            if !alerts.iter().any(|a| a.category == "validation_rate" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check duplicate ratio
        if metrics.duplicate_block_ratio > thresholds.max_duplicate_ratio {
            let alert = SyncAlert::new(
                AlertLevel::Warning,
                "duplicate_blocks".to_string(),
                format!("Duplicate block ratio ({:.1}%) exceeds threshold ({:.1}%)", 
                        metrics.duplicate_block_ratio, thresholds.max_duplicate_ratio)
            ).with_metric(metrics.duplicate_block_ratio, thresholds.max_duplicate_ratio);
            
            if !alerts.iter().any(|a| a.category == "duplicate_blocks" && !a.acknowledged) {
                alerts.push(alert);
            }
        }
        
        // Check peer scores
        let reputations = self.peer_reputations.read().await;
        for (peer_id, rep) in reputations.iter() {
            if rep.score < thresholds.min_peer_score && rep.score < 0 {
                let alert = SyncAlert::new(
                    AlertLevel::Warning,
                    "peer_score".to_string(),
                    format!("Peer {} has low reputation score ({})", 
                            &peer_id[..16.min(peer_id.len())], rep.score)
                ).with_peer(peer_id.clone())
                 .with_metric(rep.score as f64, thresholds.min_peer_score as f64);
                
                if !alerts.iter().any(|a| a.category == "peer_score" && 
                                       a.peer_id.as_ref() == Some(peer_id) && 
                                       !a.acknowledged) {
                    alerts.push(alert);
                }
            }
        }
    }

    /// Create a metrics snapshot for historical tracking
    pub async fn create_metrics_snapshot(&self) -> MetricsSnapshot {
        let broadcast_metrics = self.broadcast_metrics.read().await;
        let performance_metrics = self.performance_metrics.read().await;
        let connections = self.connections.read().await;
        let reputations = self.peer_reputations.read().await;
        
        let banned_count = reputations.values().filter(|r| r.is_banned()).count();
        
        MetricsSnapshot {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            blocks_received: broadcast_metrics.blocks_received,
            txs_received: broadcast_metrics.transactions_received,
            blocks_rejected: broadcast_metrics.blocks_rejected,
            txs_rejected: broadcast_metrics.transactions_rejected,
            avg_latency_ms: (performance_metrics.avg_block_propagation_ms + 
                           performance_metrics.avg_tx_propagation_ms) / 2.0,
            bandwidth_bps: (performance_metrics.bytes_sent_per_sec + 
                          performance_metrics.bytes_received_per_sec) as u64,
            active_peers: connections.all_peers().count() as u32,
            banned_peers: banned_count,
        }
    }

    /// Start background metrics snapshot task
    pub async fn start_metrics_snapshot_task(&self) {
        let metrics_history = self.metrics_history.clone();
        let mesh_router = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Create snapshot
                let snapshot = mesh_router.create_metrics_snapshot().await;
                
                // Add to history
                let mut history = metrics_history.write().await;
                history.add_snapshot(snapshot);
                
                // Check and generate alerts
                mesh_router.check_and_generate_alerts().await;
                
                debug!("📊 Metrics snapshot created ({} total snapshots)", history.snapshots.len());
            }
        });
        
        info!("📊 Started metrics snapshot background task (60s interval)");
    }
    
    // ==================== Phase 4: lib-network Health Monitoring Integration ====================
    
    /// Initialize network health monitoring from lib-network
    /// 
    /// ✅ Phase 4: Delegates network-level monitoring to lib-network::monitoring::HealthMonitor
    pub async fn initialize_network_health_monitoring(&self) -> Result<()> {
        info!("🏥 Initializing network health monitoring (lib-network integration)...");
        
        // Create lib-network HealthMonitor with references to mesh components
        // Ticket #149: Use peer_registry instead of connections
        let peer_registry = Arc::new(RwLock::new(lib_network::peer_registry::PeerRegistry::new()));
        let health_monitor = HealthMonitor::new(
            self.mesh_protocol_stats.clone(),
            peer_registry,
            Arc::new(RwLock::new(HashMap::new())), // long_range_relays (will be populated later)
        );
        
        // Start monitoring
        health_monitor.start_monitoring().await?;
        
        // Store health monitor
        *self.network_health_monitor.write().await = Some(Arc::new(health_monitor));
        
        info!("✅ Network health monitoring initialized (Phase 4 integration)");
        Ok(())
    }
    
    /// Get network health summary from lib-network
    /// 
    /// ✅ Phase 4: Uses lib-network's HealthMonitor for comprehensive network health metrics
    pub async fn get_network_health_summary(&self) -> Result<NetworkHealthSummary> {
        let monitor_guard = self.network_health_monitor.read().await;
        
        if let Some(monitor) = monitor_guard.as_ref() {
            Ok(monitor.get_health_summary().await)
        } else {
            // Fallback if monitoring not initialized
            Ok(NetworkHealthSummary {
                overall_health_score: 0.0,
                connection_health_score: 0.0,
                coverage_score: 0.0,
                bandwidth_utilization: 0.0,
                active_connections: 0,
                total_relays: 0,
                coverage_area_km2: 0.0,
                average_latency_ms: 0,
                data_throughput_mbps: 0.0,
                people_served: 0,
            })
        }
    }
    
    /// Update mesh protocol statistics (for lib-network monitoring)
    /// 
    /// ✅ Phase 4: Updates statistics that lib-network's HealthMonitor uses
    pub async fn update_mesh_protocol_stats(&self) {
        let mut stats = self.mesh_protocol_stats.write().await;
        let connections = self.connections.read().await;
        let metrics = self.broadcast_metrics.read().await;
        
        // Update statistics that lib-network monitors
        stats.active_connections = connections.all_peers().count() as u32;
        stats.total_data_routed = metrics.blocks_sent + metrics.transactions_sent;
        
        // Calculate average latency from our tracking
        let block_latencies = self.latency_samples_blocks.read().await;
        let tx_latencies = self.latency_samples_txs.read().await;
        
        if !block_latencies.is_empty() || !tx_latencies.is_empty() {
            let total_samples = block_latencies.len() + tx_latencies.len();
            let sum: u64 = block_latencies.iter().sum::<u64>() + tx_latencies.iter().sum::<u64>();
            stats.average_latency_ms = (sum / total_samples as u64) as u32;
        }
        
        debug!("📊 Updated mesh protocol stats: {} connections, {} data routed, {}ms avg latency",
               stats.active_connections, stats.total_data_routed, stats.average_latency_ms);
    }
}
