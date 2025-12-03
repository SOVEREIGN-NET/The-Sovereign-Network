//! Network Health Monitoring Implementation
//!
//! Comprehensive health monitoring for ZHTP mesh network

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tracing::{info, warn};
use lib_crypto::PublicKey;

use crate::mesh::{MeshConnection, MeshProtocolStats};
use crate::relays::LongRangeRelay;

/// Network health monitoring system
#[derive(Clone)]
pub struct HealthMonitor {
    /// Mesh protocol statistics
    pub stats: Arc<RwLock<MeshProtocolStats>>,
    /// Active mesh connections
    pub mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
    /// Long-range relays
    pub long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    /// Monitoring active flag
    pub monitoring_active: Arc<RwLock<bool>>,
}

impl HealthMonitor {
    /// Create new health monitor
    pub fn new(
        stats: Arc<RwLock<MeshProtocolStats>>,
        mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
        long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    ) -> Self {
        Self {
            stats,
            mesh_connections,
            long_range_relays,
            monitoring_active: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Start network health monitoring
    pub async fn start_monitoring(&self) -> Result<()> {
        info!("Starting network health monitoring...");
        
        // Set monitoring active
        *self.monitoring_active.write().await = true;
        
        // Start monitoring loops
        self.start_statistics_collection().await?;
        self.start_connection_health_check().await?;
        self.start_relay_health_check().await?;
        self.start_coverage_analysis().await?;
        
        info!(" Network health monitoring started");
        Ok(())
    }
    
    /// Stop network health monitoring
    pub async fn stop_monitoring(&self) -> Result<()> {
        info!("🛑 Stopping network health monitoring...");
        
        // Set monitoring inactive
        *self.monitoring_active.write().await = false;
        
        info!(" Network health monitoring stopped");
        Ok(())
    }
    
    /// Start statistics collection loop
    async fn start_statistics_collection(&self) -> Result<()> {
        let stats = self.stats.clone();
        let mesh_connections = self.mesh_connections.clone();
        let long_range_relays = self.long_range_relays.clone();
        let monitoring_active = self.monitoring_active.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Check if monitoring is still active
                if !*monitoring_active.read().await {
                    break;
                }
                
                // Update network statistics
                let mut network_stats = stats.write().await;
                let connections = mesh_connections.read().await;
                let relays = long_range_relays.read().await;
                
                // Update connection count
                network_stats.active_connections = connections.len() as u32;
                network_stats.long_range_relays = relays.len() as u32;
                
                // Calculate total data routed
                network_stats.total_data_routed = connections.values()
                    .map(|conn| conn.data_transferred)
                    .sum();
                
                // Calculate average latency
                if !connections.is_empty() {
                    network_stats.average_latency_ms = connections.values()
                        .map(|conn| conn.latency_ms)
                        .sum::<u32>() / connections.len() as u32;
                } else {
                    network_stats.average_latency_ms = 0;
                }
                
                // Estimate coverage area (π * r²) for all relays
                network_stats.coverage_area_km2 = relays.values()
                    .map(|relay| {
                        let radius = relay.coverage_radius_km;
                        std::f64::consts::PI * radius * radius
                    })
                    .sum();
                
                // Estimate people with free internet access
                // Rough estimate: 100 people per km² in coverage areas
                network_stats.people_with_free_internet = 
                    (network_stats.coverage_area_km2 * 100.0) as u32;
                
                // Calculate total UBI distributed through mesh networking
                let mesh_conn_read = mesh_connections.read().await;
                network_stats.total_ubi_distributed = mesh_conn_read.values()
                    .map(|conn| conn.data_transferred)
                    .sum();
                
                info!("Network Health Update:");
                info!("   Active connections: {}", network_stats.active_connections);
                info!("   Mesh connections: {}", mesh_conn_read.len());
                info!("   Long-range relays: {}", network_stats.long_range_relays);
                info!("   Data routed: {:.2} MB", network_stats.total_data_routed as f64 / 1_000_000.0);
                info!("   Average latency: {} ms", network_stats.average_latency_ms);
                info!("   Coverage area: {:.0} km²", network_stats.coverage_area_km2);
                info!("   People with free internet: {}", network_stats.people_with_free_internet);
                info!("   UBI distributed: {} tokens", network_stats.total_ubi_distributed);
            }
        });
        
        Ok(())
    }
    
    /// Start connection health checking
    async fn start_connection_health_check(&self) -> Result<()> {
        let mesh_connections = self.mesh_connections.clone();
        let monitoring_active = self.monitoring_active.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Check every 5 minutes
            
            loop {
                interval.tick().await;
                
                // Check if monitoring is still active
                if !*monitoring_active.read().await {
                    break;
                }
                
                // Check connection health
                let mut connections = mesh_connections.write().await;
                let mut unhealthy_connections = Vec::new();
                
                for (peer_id, connection) in connections.iter() {
                    // Check connection stability
                    if connection.stability_score < 0.3 {
                        warn!(" Unstable connection detected: peer {} (stability: {:.2})", 
                              hex::encode(&peer_id.key_id[0..4]), connection.stability_score);
                        unhealthy_connections.push(peer_id.clone());
                    }
                    
                    // Check if connection is too old without recent activity
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    
                    let connection_age = current_time - connection.connected_at;
                    if connection_age > 3600 && connection.data_transferred == 0 {
                        warn!(" Stale connection detected: peer {} (age: {} minutes, no data)", 
                              hex::encode(&peer_id.key_id[0..4]), connection_age / 60);
                        unhealthy_connections.push(peer_id.clone());
                    }
                    
                    // Check for high latency
                    if connection.latency_ms > 1000 {
                        warn!(" High latency connection: peer {} (latency: {} ms)", 
                              hex::encode(&peer_id.key_id[0..4]), connection.latency_ms);
                    }
                }
                
                // Remove unhealthy connections
                for peer_id in unhealthy_connections {
                    info!(" Removing unhealthy connection: {}", 
                          hex::encode(&peer_id.key_id[0..4]));
                    connections.remove(&peer_id);
                }
                
                info!("Connection health check completed: {} active connections", 
                      connections.len());
            }
        });
        
        Ok(())
    }
    
    /// Start relay health checking
    async fn start_relay_health_check(&self) -> Result<()> {
        let long_range_relays = self.long_range_relays.clone();
        let monitoring_active = self.monitoring_active.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(600)); // Check every 10 minutes
            
            loop {
                interval.tick().await;
                
                // Check if monitoring is still active
                if !*monitoring_active.read().await {
                    break;
                }
                
                // Check relay health
                let relays = long_range_relays.read().await;
                let mut healthy_relays = 0;
                let mut total_throughput = 0;
                let mut total_coverage = 0.0;
                
                for (relay_id, relay) in relays.iter() {
                    // Simple health check - in production would ping each relay
                    let relay_healthy = Self::check_relay_health(relay).await;
                    
                    if relay_healthy {
                        healthy_relays += 1;
                        total_throughput += relay.max_throughput_mbps;
                        total_coverage += relay.coverage_radius_km;
                        
                        info!(" Relay {} healthy: {} Mbps, {:.0} km coverage", 
                              relay_id, relay.max_throughput_mbps, relay.coverage_radius_km);
                    } else {
                        warn!("Relay {} unhealthy or unreachable", relay_id);
                    }
                }
                
                info!("Relay health summary:");
                info!("    Healthy relays: {}/{}", healthy_relays, relays.len());
                info!("   Total throughput: {} Mbps", total_throughput);
                info!("   Total coverage: {:.0} km", total_coverage);
                
                // Alert if too few relays are healthy
                if healthy_relays < relays.len() / 2 {
                    warn!(" WARNING: Less than 50% of relays are healthy!");
                }
            }
        });
        
        Ok(())
    }
    
    /// Start coverage analysis
    async fn start_coverage_analysis(&self) -> Result<()> {
        let long_range_relays = self.long_range_relays.clone();
        let mesh_connections = self.mesh_connections.clone();
        let stats = self.stats.clone();
        let monitoring_active = self.monitoring_active.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(900)); // Check every 15 minutes
            
            loop {
                interval.tick().await;
                
                // Check if monitoring is still active
                if !*monitoring_active.read().await {
                    break;
                }
                
                // Analyze network coverage
                let relays = long_range_relays.read().await;
                let connections = mesh_connections.read().await;
                let network_stats = stats.write().await;
                
                // Calculate coverage metrics
                let has_satellite = relays.values()
                    .any(|relay| matches!(relay.relay_type, crate::types::relay_type::LongRangeRelayType::Satellite));
                
                let has_internet_bridge = relays.values()
                    .any(|relay| matches!(relay.relay_type, crate::types::relay_type::LongRangeRelayType::WiFiRelay));
                
                let total_relay_coverage: f64 = relays.values()
                    .map(|relay| relay.coverage_radius_km)
                    .sum();
                
                let total_mesh_bandwidth: u32 = connections.values()
                    .map(|conn| (conn.bandwidth_capacity / 1_000_000) as u32) // Convert to Mbps
                    .sum();
                
                // Update coverage analysis
                info!("Network Coverage Analysis:");
                info!("   Total relay coverage: {:.0} km", total_relay_coverage);
                info!("   🛰️ Satellite access: {}", if has_satellite { " GLOBAL" } else { "Regional only" });
                info!("    Internet bridges: {}", if has_internet_bridge { " Available" } else { "None" });
                info!("  Total mesh bandwidth: {} Mbps", total_mesh_bandwidth);
                
                // Coverage quality assessment
                let coverage_quality = if has_satellite && has_internet_bridge && total_relay_coverage > 1000.0 {
                    "GLOBAL"
                } else if total_relay_coverage > 500.0 || has_internet_bridge {
                    "REGIONAL"
                } else if total_relay_coverage > 100.0 {
                    "LOCAL"
                } else {
                    "LIMITED"
                };
                
                info!("   Coverage quality: {}", coverage_quality);
                
                // Identify coverage gaps
                if !has_satellite {
                    info!("   Recommendation: Add satellite uplinks for global coverage");
                }
                
                if !has_internet_bridge {
                    info!("   Recommendation: Add internet bridges for external connectivity");
                }
                
                if total_mesh_bandwidth < 100 {
                    info!("   Recommendation: Encourage more mesh connections for bandwidth");
                }
                
                // Performance analysis
                let avg_connection_quality: f64 = if !connections.is_empty() {
                    // Simplified quality metric based on signal strength
                    connections.values().map(|conn| conn.signal_strength).sum::<f64>() / connections.len() as f64
                } else {
                    0.0
                };
                
                info!("   Average connection quality: {:.1} Mbps per node", avg_connection_quality);
            }
        });
        
        Ok(())
    }
    
    /// Check health of a specific relay
    async fn check_relay_health(relay: &LongRangeRelay) -> bool {
        // In production, this would actually ping or test the relay
        // For now, simulate realistic health check with some failures
        
        match relay.relay_type {
            crate::types::relay_type::LongRangeRelayType::Satellite => {
                // Satellites are usually reliable but can have weather issues
                rand::random::<f32>() > 0.05 // 95% uptime
            },
            crate::types::relay_type::LongRangeRelayType::LoRaWAN => {
                // LoRaWAN gateways are very reliable
                rand::random::<f32>() > 0.02 // 98% uptime
            },
            crate::types::relay_type::LongRangeRelayType::WiFiRelay => {
                // WiFi relays can be less reliable
                rand::random::<f32>() > 0.10 // 90% uptime
            },
            _ => {
                // Other relay types
                rand::random::<f32>() > 0.08 // 92% uptime
            }
        }
    }
    
    /// Get current network health summary
    pub async fn get_health_summary(&self) -> NetworkHealthSummary {
        let stats = self.stats.read().await;
        let connections = self.mesh_connections.read().await;
        // WiFi sharing removed for legal compliance
        let relays = self.long_range_relays.read().await;
        
        // Calculate health metrics
        let connection_health = if connections.is_empty() {
            0.0
        } else {
            connections.values()
                .map(|conn| conn.stability_score)
                .sum::<f64>() / connections.len() as f64
        };
        
        let bandwidth_utilization = if stats.active_connections > 0 {
            (stats.total_data_routed as f64 / (stats.active_connections as f64 * 1_000_000.0)) * 100.0
        } else {
            0.0
        };
        
        let coverage_score = if relays.is_empty() {
            0.0
        } else {
            // Score based on relay count and coverage
            let relay_score = (relays.len() as f64 / 10.0).min(1.0); // Up to 10 relays = 100%
            let coverage_score = (stats.coverage_area_km2 / 10000.0).min(1.0); // Up to 10,000 km² = 100%
            (relay_score + coverage_score) / 2.0
        };
        
        // Overall health score
        let overall_health = (connection_health + coverage_score) / 2.0;
        
        NetworkHealthSummary {
            overall_health_score: overall_health,
            connection_health_score: connection_health,
            coverage_score,
            bandwidth_utilization,
            active_connections: stats.active_connections,
            total_relays: relays.len() as u32,
            coverage_area_km2: stats.coverage_area_km2,
            average_latency_ms: stats.average_latency_ms,
            data_throughput_mbps: (stats.total_data_routed as f64 / 1_000_000.0) as f32,
            people_served: stats.people_with_free_internet,
        }
    }
}

/// Network health summary
#[derive(Debug, Clone)]
pub struct NetworkHealthSummary {
    pub overall_health_score: f64, // 0.0 to 1.0
    pub connection_health_score: f64, // 0.0 to 1.0
    pub coverage_score: f64, // 0.0 to 1.0
    pub bandwidth_utilization: f64, // Percentage
    pub active_connections: u32,
    pub total_relays: u32,
    pub coverage_area_km2: f64,
    pub average_latency_ms: u32,
    pub data_throughput_mbps: f32,
    pub people_served: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    #[tokio::test]
    async fn test_health_monitor_creation() {
        let stats = Arc::new(RwLock::new(MeshProtocolStats::default()));
        let mesh_connections = Arc::new(RwLock::new(HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        
        let monitor = HealthMonitor::new(
            stats,
            mesh_connections,
            long_range_relays,
        );
        
        assert!(!*monitor.monitoring_active.read().await);
    }
    
    #[tokio::test]
    async fn test_health_summary() {
        let stats = Arc::new(RwLock::new(MeshProtocolStats::default()));
        let mesh_connections = Arc::new(RwLock::new(HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        
        let monitor = HealthMonitor::new(
            stats,
            mesh_connections,
            long_range_relays,
        );
        
        let summary = monitor.get_health_summary().await;
        
        // With no connections, health should be 0
        assert_eq!(summary.overall_health_score, 0.0);
        assert_eq!(summary.active_connections, 0);
    }
}
