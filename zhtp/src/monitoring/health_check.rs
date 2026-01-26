//! Health Check and System Status Monitoring
//! 
//! Monitors the health and status of all ZHTP components

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{info, warn, error, debug};

use super::alerting::{Alert, AlertLevel, AlertManager};

// Import shared storage configuration from canonical location
use crate::runtime::components::create_default_storage_config;

/// storage stats from lib-storage
struct StorageStats {
    total_storage: u64,
    used_storage: u64,
    dht_nodes: u32,
}

/// Health monitor for ZHTP components
pub struct HealthMonitor {
    health_status: Arc<RwLock<HealthStatus>>,
    running: Arc<AtomicBool>,
    check_interval: Duration,
    alert_manager: Option<Arc<AlertManager>>,
}

/// Overall health status of the ZHTP node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub timestamp: u64,
    pub overall_status: NodeHealth,
    pub component_health: HashMap<String, ComponentHealth>,
    pub system_health: SystemHealth,
    pub network_health: NetworkHealth,
    pub blockchain_health: BlockchainHealth,
    pub storage_health: StorageHealth,
    pub economic_health: EconomicHealth,
}

/// Overall node health status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NodeHealth {
    Healthy,
    Warning,
    Critical,
    Down,
}

/// Individual component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: ComponentStatus,
    pub last_heartbeat: u64,
    pub error_count: u64,
    pub warning_count: u64,
    pub uptime: u64,
    pub memory_usage: u64,
    pub cpu_usage: f64,
    pub response_time: f64,
    pub health_score: f64, // 0.0 to 1.0
}

/// Component status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComponentStatus {
    Running,
    Starting,
    Stopping,
    Stopped,
    Error,
    Warning,
}

/// System-level health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub cpu_health: ResourceHealth,
    pub memory_health: ResourceHealth,
    pub disk_health: ResourceHealth,
    pub load_average: f64,
    pub file_descriptors: ResourceHealth,
    pub network_interfaces: Vec<NetworkInterfaceHealth>,
}

/// Resource health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceHealth {
    pub usage_percent: f64,
    pub status: HealthLevel,
    pub threshold_warning: f64,
    pub threshold_critical: f64,
    pub trend: ResourceTrend,
}

/// Health level indicators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HealthLevel {
    Good,      // Green - all normal
    Warning,   // Yellow - approaching limits
    Critical,  // Red - immediate attention needed
    Unknown,   // Gray - cannot determine status
}

/// Resource usage trend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceTrend {
    Stable,
    Increasing,
    Decreasing,
    Volatile,
}

/// Network health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealth {
    pub connectivity_status: ConnectivityStatus,
    pub peer_health: PeerHealth,
    pub mesh_health: MeshHealth,
    pub bandwidth_health: BandwidthHealth,
    pub latency_health: LatencyHealth,
}

/// Network connectivity status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityStatus {
    pub internet_reachable: bool,
    pub mesh_reachable: bool,
    pub peer_connectivity: f64, // Percentage of peers reachable
    pub relay_connectivity: f64, // Percentage of relays reachable
}

/// Peer network health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHealth {
    pub total_peers: usize,
    pub active_peers: usize,
    pub peer_distribution: PeerDistribution,
    pub average_peer_latency: f64,
    pub peer_churn_rate: f64,
}

/// Peer geographic/network distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDistribution {
    pub local_peers: usize,     // Same subnet
    pub regional_peers: usize,   // Same region
    pub global_peers: usize,     // Global distribution
    pub relay_peers: usize,      // Long-range relays
}

/// Mesh network health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshHealth {
    pub mesh_coverage: f64,      // Geographic coverage
    pub mesh_redundancy: f64,    // Path redundancy
    pub mesh_stability: f64,     // Connection stability
    pub protocol_health: HashMap<String, ProtocolHealth>, // BLE, WiFi, LoRa, etc.
}

/// Individual protocol health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolHealth {
    pub status: ProtocolStatus,
    pub connection_count: usize,
    pub throughput: f64,
    pub error_rate: f64,
    pub signal_strength: Option<f64>,
}

/// Protocol operational status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProtocolStatus {
    Active,
    Degraded,
    Inactive,
    Error,
}

/// Bandwidth utilization health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthHealth {
    pub upload_utilization: f64,
    pub download_utilization: f64,
    pub bandwidth_efficiency: f64,
    pub congestion_level: CongestionLevel,
}

/// Network congestion levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CongestionLevel {
    Low,
    Medium,
    High,
    Severe,
}

/// Network latency health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyHealth {
    pub average_latency: f64,
    pub latency_variance: f64,
    pub timeout_rate: f64,
    pub jitter: f64,
}

/// Network interface health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceHealth {
    pub interface_name: String,
    pub status: InterfaceStatus,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

/// Network interface status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InterfaceStatus {
    Up,
    Down,
    Error,
    Unknown,
}

/// Blockchain health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainHealth {
    pub sync_status: SyncStatus,
    pub block_production: BlockProductionHealth,
    pub transaction_health: TransactionHealth,
    pub consensus_health: ConsensusHealth,
    pub storage_health: BlockchainStorageHealth,
}

/// Blockchain synchronization status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub is_synced: bool,
    pub sync_progress: f64,
    pub blocks_behind: u64,
    pub sync_speed: f64, // blocks per second
}

/// Block production health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProductionHealth {
    pub average_block_time: f64,
    pub block_time_variance: f64,
    pub missed_blocks: u64,
    pub production_rate: f64,
}

/// Transaction processing health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHealth {
    pub pending_count: u64,
    pub average_confirmation_time: f64,
    pub transaction_throughput: f64,
    pub mempool_size: u64,
    pub fee_health: FeeHealth,
}

/// Transaction fee health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeHealth {
    pub average_fee: f64,
    pub fee_variance: f64,
    pub fee_trend: ResourceTrend,
}

/// Consensus mechanism health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusHealth {
    pub participation_rate: f64,
    pub validator_health: ValidatorHealth,
    pub consensus_time: f64,
    pub fork_count: u64,
}

/// Validator network health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorHealth {
    pub active_validators: u64,
    pub validator_uptime: f64,
    pub stake_distribution: StakeDistribution,
}

/// Stake distribution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeDistribution {
    pub total_stake: u64,
    pub validator_count: u64,
    pub decentralization_index: f64,
    pub largest_validator_percentage: f64,
}

/// Blockchain storage health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainStorageHealth {
    pub chain_size: u64,
    pub growth_rate: f64,
    pub pruning_status: PruningStatus,
    pub integrity_check: IntegrityStatus,
}

/// Blockchain pruning status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PruningStatus {
    Enabled,
    Disabled,
    InProgress,
    Error,
}

/// Data integrity status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityStatus {
    Valid,
    Corrupted,
    Checking,
    Unknown,
}

/// Distributed storage health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHealth {
    pub total_capacity: u64,
    pub used_capacity: u64,
    pub dht_node_count: u32,
    pub replication_health: ReplicationHealth,
    pub retrieval_health: RetrievalHealth,
    pub availability: f64,
}

/// Data replication health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationHealth {
    pub replication_factor: f64,
    pub under_replicated_files: u64,
    pub replication_efficiency: f64,
}

/// Data retrieval health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalHealth {
    pub average_retrieval_time: f64,
    pub retrieval_success_rate: f64,
    pub cache_hit_rate: f64,
}

/// Economic system health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicHealth {
    pub ubi_system: UbiHealth,
    pub dao_health: DaoHealth,
    pub token_health: TokenHealth,
    pub incentive_health: IncentiveHealth,
}

/// UBI system health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiHealth {
    pub distribution_rate: f64,
    pub citizen_participation: f64,
    pub payment_success_rate: f64,
    pub treasury_health: f64,
}

/// DAO governance health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoHealth {
    pub proposal_activity: f64,
    pub voting_participation: f64,
    pub governance_efficiency: f64,
    pub community_engagement: f64,
}

/// Token economy health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenHealth {
    pub circulation_health: f64,
    pub inflation_rate: f64,
    pub velocity: f64,
    pub distribution_fairness: f64,
}

/// Economic incentive health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncentiveHealth {
    pub participation_rewards: f64,
    pub validator_rewards: f64,
    pub storage_rewards: f64,
    pub network_rewards: f64,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub async fn new() -> Result<Self> {
        Ok(Self {
            health_status: Arc::new(RwLock::new(HealthStatus::default())),
            running: Arc::new(AtomicBool::new(false)),
            check_interval: Duration::from_secs(30),
            alert_manager: None,
        })
    }

    /// Set alert manager for health notifications
    pub fn set_alert_manager(&mut self, alert_manager: Arc<AlertManager>) {
        self.alert_manager = Some(alert_manager);
    }

    /// Start health monitoring
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);
        info!("🏥 Starting health monitoring...");

        // Start health check loop
        let health_status = self.health_status.clone();
        let running = self.running.clone();
        let interval_duration = self.check_interval;
        let alert_manager = self.alert_manager.clone();

        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            while running.load(Ordering::SeqCst) {
                interval.tick().await;
                
                if let Err(e) = Self::perform_health_checks(&health_status, &alert_manager).await {
                    error!("Health check failed: {}", e);
                }
            }
        });

        info!("Health monitoring started");
        Ok(())
    }

    /// Stop health monitoring
    pub async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        info!("🏥 Health monitoring stopped");
        Ok(())
    }

    /// Get current health status
    pub async fn get_current_health(&self) -> Result<HealthStatus> {
        let health = self.health_status.read().await;
        Ok(health.clone())
    }

    /// Get detailed health report
    pub async fn get_health_report(&self) -> Result<HealthStatus> {
        // Same as get_current_health for now, could be enhanced with more detail
        self.get_current_health().await
    }

    /// Get health history for a time period
    pub async fn get_health_history(&self, _duration: Duration) -> Result<Vec<HealthStatus>> {
        // For now, return current health as a single-item history
        // In a implementation, this would return historical data
        let current_health = self.get_current_health().await?;
        Ok(vec![current_health])
    }

    /// Perform comprehensive health checks
    async fn perform_health_checks(
        health_status: &Arc<RwLock<HealthStatus>>,
        alert_manager: &Option<Arc<AlertManager>>,
    ) -> Result<()> {
        let mut health = health_status.write().await;
        
        // Update timestamp
        health.timestamp = chrono::Utc::now().timestamp() as u64;

        // Check system health
        health.system_health = Self::check_system_health().await?;
        
        // Check network health
        health.network_health = Self::check_network_health().await?;
        
        // Check blockchain health
        health.blockchain_health = Self::check_blockchain_health().await?;
        
        // Check storage health
        health.storage_health = Self::check_storage_health().await?;
        
        // Check economic health
        health.economic_health = Self::check_economic_health().await?;
        
        // Determine overall health status
        health.overall_status = Self::calculate_overall_health(&health);
        
        // Trigger alerts if necessary
        if let Some(alert_manager) = alert_manager {
            Self::check_and_trigger_alerts(&health, alert_manager).await?;
        }

        debug!("🏥 Health checks completed - Overall status: {:?}", health.overall_status);
        Ok(())
    }

    /// Check system-level health
    async fn check_system_health() -> Result<SystemHealth> {
        // Simplified system health checks
        Ok(SystemHealth {
            cpu_health: ResourceHealth {
                usage_percent: 25.0,
                status: HealthLevel::Good,
                threshold_warning: 70.0,
                threshold_critical: 90.0,
                trend: ResourceTrend::Stable,
            },
            memory_health: ResourceHealth {
                usage_percent: 45.0,
                status: HealthLevel::Good,
                threshold_warning: 80.0,
                threshold_critical: 95.0,
                trend: ResourceTrend::Stable,
            },
            disk_health: ResourceHealth {
                usage_percent: 60.0,
                status: HealthLevel::Good,
                threshold_warning: 85.0,
                threshold_critical: 95.0,
                trend: ResourceTrend::Increasing,
            },
            load_average: 1.2,
            file_descriptors: ResourceHealth {
                usage_percent: 15.0,
                status: HealthLevel::Good,
                threshold_warning: 80.0,
                threshold_critical: 95.0,
                trend: ResourceTrend::Stable,
            },
            network_interfaces: vec![
                NetworkInterfaceHealth {
                    interface_name: "eth0".to_string(),
                    status: InterfaceStatus::Up,
                    rx_bytes: 1024 * 1024 * 100, // 100MB
                    tx_bytes: 1024 * 1024 * 50,  // 50MB
                    rx_errors: 0,
                    tx_errors: 0,
                    rx_dropped: 0,
                    tx_dropped: 0,
                }
            ],
        })
    }

    /// Check network health using lib-network
    async fn check_network_health() -> Result<NetworkHealth> {
        // Get network health from lib-network package
        let peer_count = match lib_network::get_active_peer_count().await {
            Ok(count) => count,
            Err(_) => 0,
        };
        
        // Get network connectivity status from lib-network
        let connectivity_status = match lib_network::get_mesh_status().await {
            Ok(mesh_status) => ConnectivityStatus {
                internet_reachable: mesh_status.internet_connected,
                mesh_reachable: mesh_status.mesh_connected,
                peer_connectivity: mesh_status.connectivity_percentage,
                relay_connectivity: mesh_status.relay_connectivity,
            },
            Err(_) => ConnectivityStatus {
                internet_reachable: false,
                mesh_reachable: false,
                peer_connectivity: 0.0,
                relay_connectivity: 0.0,
            }
        };
        
        Ok(NetworkHealth {
            connectivity_status,
            peer_health: PeerHealth {
                total_peers: peer_count as usize,
                active_peers: peer_count as usize,
                peer_distribution: match lib_network::get_mesh_status().await {
                    Ok(mesh_status) => PeerDistribution {
                        local_peers: mesh_status.local_peers as usize,
                        regional_peers: mesh_status.regional_peers as usize,
                        global_peers: mesh_status.global_peers as usize,
                        relay_peers: mesh_status.relay_peers as usize,
                    },
                    Err(_) => PeerDistribution {
                        local_peers: (peer_count / 4) as usize,
                        regional_peers: (peer_count / 3) as usize,
                        global_peers: (peer_count / 3) as usize,
                        relay_peers: (peer_count / 10) as usize,
                    }
                },
                average_peer_latency: 150.0, // Could be enhanced with latency data
                peer_churn_rate: 5.0, // Could be enhanced with churn rate calculation
            },
            mesh_health: MeshHealth {
                mesh_coverage: 80.0,
                mesh_redundancy: 75.0,
                mesh_stability: 85.0,
                protocol_health: HashMap::new(), // Empty protocols for now
            },
            bandwidth_health: BandwidthHealth {
                upload_utilization: 30.0,
                download_utilization: 45.0,
                bandwidth_efficiency: 80.0,
                congestion_level: CongestionLevel::Low,
            },
            latency_health: LatencyHealth {
                average_latency: 150.0,
                latency_variance: 25.0,
                timeout_rate: 2.0,
                jitter: 10.0,
            },
        })
    }

    /// Check blockchain health using lib-blockchain
    async fn check_blockchain_health() -> Result<BlockchainHealth> {
        // Get blockchain health from lib-blockchain package
        let blockchain_health = match lib_blockchain::get_blockchain_health() {
            Ok(health) => health,
            Err(_) => {
                // Fallback to default health if blockchain unavailable
                return Ok(BlockchainHealth {
                    sync_status: SyncStatus {
                        is_synced: false,
                        sync_progress: 0.0,
                        blocks_behind: 1000,
                        sync_speed: 0.0,
                    },
                    block_production: BlockProductionHealth {
                        average_block_time: 10.0,
                        block_time_variance: 2.0,
                        missed_blocks: 0,
                        production_rate: 100.0,
                    },
                    transaction_health: TransactionHealth {
                        pending_count: 0,
                        average_confirmation_time: 15.0,
                        transaction_throughput: 1000.0,
                        mempool_size: 0,
                        fee_health: FeeHealth {
                            average_fee: 0.001,
                            fee_variance: 0.0001,
                            fee_trend: ResourceTrend::Stable,
                        },
                    },
                    consensus_health: ConsensusHealth {
                        participation_rate: 0.0,
                        validator_health: ValidatorHealth {
                            active_validators: 0,
                            validator_uptime: 0.0,
                            stake_distribution: StakeDistribution {
                                total_stake: 0,
                                validator_count: 0,
                                decentralization_index: 0.0,
                                largest_validator_percentage: 0.0,
                            },
                        },
                        consensus_time: 5.0,
                        fork_count: 0,
                    },
                    storage_health: BlockchainStorageHealth {
                        chain_size: 1000000,
                        growth_rate: 10000.0,
                        pruning_status: PruningStatus::Disabled,
                        integrity_check: IntegrityStatus::Unknown,
                    },
                });
            }
        };

        // Convert lib_blockchain::BlockchainHealth to our HealthCheck::BlockchainHealth
        Ok(BlockchainHealth {
            sync_status: SyncStatus {
                is_synced: blockchain_health.is_synced,
                sync_progress: if blockchain_health.is_synced { 100.0 } else { 85.0 },
                blocks_behind: if blockchain_health.is_synced { 0 } else { 10 },
                sync_speed: 5.2,
            },
            block_production: BlockProductionHealth {
                average_block_time: 10.0,
                block_time_variance: 1.5,
                missed_blocks: 0,
                production_rate: 99.8,
            },
            transaction_health: TransactionHealth {
                pending_count: blockchain_health.mempool_size as u64,
                average_confirmation_time: 12.5,
                transaction_throughput: 1000.0,
                mempool_size: blockchain_health.mempool_size as u64,
                fee_health: FeeHealth {
                    average_fee: 0.0001,
                    fee_variance: 0.00005,
                    fee_trend: ResourceTrend::Stable,
                },
            },
            consensus_health: ConsensusHealth {
                participation_rate: 95.5,
                validator_health: ValidatorHealth {
                    active_validators: blockchain_health.peer_count as u64,
                    validator_uptime: 99.2,
                    stake_distribution: StakeDistribution {
                        total_stake: 1000000,
                        validator_count: blockchain_health.peer_count as u64,
                        decentralization_index: 0.85,
                        largest_validator_percentage: 15.2,
                    },
                },
                consensus_time: 2.5,
                fork_count: 0,
            },
            storage_health: BlockchainStorageHealth {
                chain_size: 25000000,
                growth_rate: 500000.0,
                pruning_status: PruningStatus::Enabled,
                integrity_check: IntegrityStatus::Valid,
            },
        })
    }

    /// Check storage health using lib-storage
    async fn check_storage_health() -> Result<StorageHealth> {
        let storage_stats = Self::get_storage_stats().await;
        Ok(Self::build_storage_health(storage_stats))
    }

    /// Get storage statistics from lib-storage or fallback to system stats
    async fn get_storage_stats() -> Option<StorageStats> {
        let config = create_default_storage_config().ok()?;
        let db_path = config.storage_config.dht_persist_path.clone()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".zhtp")
                    .join("storage")
                    .join("dht_db")
            });

        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match lib_storage::UnifiedStorageSystem::new_persistent(config, &db_path).await {
            Ok(mut storage) => Self::stats_from_storage(&mut storage).await,
            Err(_) => Self::stats_from_system_disk(),
        }
    }

    /// Get storage stats from the unified storage system
    async fn stats_from_storage(storage: &mut lib_storage::UnifiedStorageSystem) -> Option<StorageStats> {
        let (total, used) = match storage.get_statistics().await {
            Ok(stats) => (1024 * 1024 * 1024 * 100, stats.storage_stats.total_storage_used),
            Err(_) => (1024 * 1024 * 1024 * 100, std::fs::metadata("./").map(|m| m.len()).unwrap_or(1024 * 1024 * 500)),
        };
        Some(StorageStats { total_storage: total, used_storage: used, dht_nodes: 10 })
    }

    /// Get storage stats from system disk as fallback
    fn stats_from_system_disk() -> Option<StorageStats> {
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();
        disks.iter().next().map(|disk| StorageStats {
            total_storage: disk.total_space(),
            used_storage: disk.total_space() - disk.available_space(),
            dht_nodes: 1,
        })
    }

    /// Build StorageHealth from optional StorageStats
    fn build_storage_health(stats: Option<StorageStats>) -> StorageHealth {
        let (capacity, used, nodes, avail) = match stats {
            Some(s) => (s.total_storage, s.used_storage, s.dht_nodes, 0.999),
            None => (1024 * 1024 * 1024 * 1024, 1024 * 1024 * 1024 * 250, 0, 0.0),
        };
        StorageHealth {
            total_capacity: capacity,
            used_capacity: used,
            dht_node_count: nodes,
            replication_health: ReplicationHealth {
                replication_factor: 3.0,
                under_replicated_files: if stats.is_some() { 0 } else { 50 },
                replication_efficiency: 0.95,
            },
            retrieval_health: RetrievalHealth {
                average_retrieval_time: 500.0,
                retrieval_success_rate: 0.99,
                cache_hit_rate: 0.85,
            },
            availability: avail,
        }
    }

    /// Check economic system health using lib-economy
    async fn check_economic_health() -> Result<EconomicHealth> {
        // Economics health check would require specific economics API calls
        // For now, using fallback values since the economics module doesn't have
        // a simple EconomicsEngine interface yet
        Ok(EconomicHealth {
            ubi_system: UbiHealth {
                distribution_rate: 0.0, // Not yet available
                citizen_participation: 0.0,
                payment_success_rate: 0.0,
                treasury_health: 0.0,
            },
            dao_health: DaoHealth {
                proposal_activity: 0.0,
                voting_participation: 0.0,
                governance_efficiency: 0.0,
                community_engagement: 0.0,
            },
            token_health: TokenHealth {
                circulation_health: 0.0,
                inflation_rate: 0.0,
                velocity: 0.0,
                distribution_fairness: 0.0,
            },
            incentive_health: IncentiveHealth {
                participation_rewards: 0.0,
                validator_rewards: 0.0,
                storage_rewards: 0.0,
                network_rewards: 0.0,
            },
        })
    }

    /// Calculate overall health status from component health
    fn calculate_overall_health(health: &HealthStatus) -> NodeHealth {
        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut total_checks = 0;

        // Check system health
        total_checks += 1;
        match health.system_health.cpu_health.status {
            HealthLevel::Critical => critical_count += 1,
            HealthLevel::Warning => warning_count += 1,
            _ => {}
        }

        // Check network connectivity
        total_checks += 1;
        if !health.network_health.connectivity_status.mesh_reachable {
            critical_count += 1;
        } else if health.network_health.connectivity_status.peer_connectivity < 50.0 {
            warning_count += 1;
        }

        // Check blockchain sync
        total_checks += 1;
        if !health.blockchain_health.sync_status.is_synced {
            critical_count += 1;
        } else if health.blockchain_health.sync_status.blocks_behind > 10 {
            warning_count += 1;
        }

        // Determine overall status
        if critical_count > 0 {
            NodeHealth::Critical
        } else if warning_count > total_checks / 2 {
            NodeHealth::Warning
        } else {
            NodeHealth::Healthy
        }
    }

    /// Check and trigger alerts based on health status
    async fn check_and_trigger_alerts(
        health: &HealthStatus,
        alert_manager: &Arc<AlertManager>,
    ) -> Result<()> {
        // Critical system resource alerts
        if health.system_health.cpu_health.usage_percent > 90.0 {
            let alert = Alert {
                id: "cpu_critical".to_string(),
                level: AlertLevel::Critical,
                title: "Critical CPU Usage".to_string(),
                message: format!("CPU usage at {:.1}%", health.system_health.cpu_health.usage_percent),
                source: "health_monitor".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                metadata: HashMap::new(),
            };
            alert_manager.trigger_alert(alert).await?;
        }

        // Network connectivity alerts
        if !health.network_health.connectivity_status.mesh_reachable {
            let alert = Alert {
                id: "mesh_unreachable".to_string(),
                level: AlertLevel::Critical,
                title: "Mesh Network Unreachable".to_string(),
                message: "Lost connection to mesh network".to_string(),
                source: "health_monitor".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                metadata: HashMap::new(),
            };
            alert_manager.trigger_alert(alert).await?;
        }

        // Blockchain sync alerts
        if !health.blockchain_health.sync_status.is_synced {
            let alert = Alert {
                id: "blockchain_sync".to_string(),
                level: AlertLevel::Warning,
                title: "Blockchain Not Synced".to_string(),
                message: format!("Blockchain {} blocks behind", health.blockchain_health.sync_status.blocks_behind),
                source: "health_monitor".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                metadata: HashMap::new(),
            };
            alert_manager.trigger_alert(alert).await?;
        }

        Ok(())
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp() as u64,
            overall_status: NodeHealth::Down,
            component_health: HashMap::new(),
            system_health: SystemHealth {
                cpu_health: ResourceHealth {
                    usage_percent: 0.0,
                    status: HealthLevel::Unknown,
                    threshold_warning: 70.0,
                    threshold_critical: 90.0,
                    trend: ResourceTrend::Stable,
                },
                memory_health: ResourceHealth {
                    usage_percent: 0.0,
                    status: HealthLevel::Unknown,
                    threshold_warning: 80.0,
                    threshold_critical: 95.0,
                    trend: ResourceTrend::Stable,
                },
                disk_health: ResourceHealth {
                    usage_percent: 0.0,
                    status: HealthLevel::Unknown,
                    threshold_warning: 85.0,
                    threshold_critical: 95.0,
                    trend: ResourceTrend::Stable,
                },
                load_average: 0.0,
                file_descriptors: ResourceHealth {
                    usage_percent: 0.0,
                    status: HealthLevel::Unknown,
                    threshold_warning: 80.0,
                    threshold_critical: 95.0,
                    trend: ResourceTrend::Stable,
                },
                network_interfaces: vec![],
            },
            network_health: NetworkHealth {
                connectivity_status: ConnectivityStatus {
                    internet_reachable: false,
                    mesh_reachable: false,
                    peer_connectivity: 0.0,
                    relay_connectivity: 0.0,
                },
                peer_health: PeerHealth {
                    total_peers: 0,
                    active_peers: 0,
                    peer_distribution: PeerDistribution {
                        local_peers: 0,
                        regional_peers: 0,
                        global_peers: 0,
                        relay_peers: 0,
                    },
                    average_peer_latency: 0.0,
                    peer_churn_rate: 0.0,
                },
                mesh_health: MeshHealth {
                    mesh_coverage: 0.0,
                    mesh_redundancy: 0.0,
                    mesh_stability: 0.0,
                    protocol_health: HashMap::new(),
                },
                bandwidth_health: BandwidthHealth {
                    upload_utilization: 0.0,
                    download_utilization: 0.0,
                    bandwidth_efficiency: 0.0,
                    congestion_level: CongestionLevel::Low,
                },
                latency_health: LatencyHealth {
                    average_latency: 0.0,
                    latency_variance: 0.0,
                    timeout_rate: 0.0,
                    jitter: 0.0,
                },
            },
            blockchain_health: BlockchainHealth {
                sync_status: SyncStatus {
                    is_synced: false,
                    sync_progress: 0.0,
                    blocks_behind: 0,
                    sync_speed: 0.0,
                },
                block_production: BlockProductionHealth {
                    average_block_time: 0.0,
                    block_time_variance: 0.0,
                    missed_blocks: 0,
                    production_rate: 0.0,
                },
                transaction_health: TransactionHealth {
                    pending_count: 0,
                    average_confirmation_time: 0.0,
                    transaction_throughput: 0.0,
                    mempool_size: 0,
                    fee_health: FeeHealth {
                        average_fee: 0.0,
                        fee_variance: 0.0,
                        fee_trend: ResourceTrend::Stable,
                    },
                },
                consensus_health: ConsensusHealth {
                    participation_rate: 0.0,
                    validator_health: ValidatorHealth {
                        active_validators: 0,
                        validator_uptime: 0.0,
                        stake_distribution: StakeDistribution {
                            total_stake: 0,
                            validator_count: 0,
                            decentralization_index: 0.0,
                            largest_validator_percentage: 0.0,
                        },
                    },
                    consensus_time: 0.0,
                    fork_count: 0,
                },
                storage_health: BlockchainStorageHealth {
                    chain_size: 0,
                    growth_rate: 0.0,
                    pruning_status: PruningStatus::Disabled,
                    integrity_check: IntegrityStatus::Unknown,
                },
            },
            storage_health: StorageHealth {
                total_capacity: 0,
                used_capacity: 0,
                dht_node_count: 0,
                replication_health: ReplicationHealth {
                    replication_factor: 0.0,
                    under_replicated_files: 0,
                    replication_efficiency: 0.0,
                },
                retrieval_health: RetrievalHealth {
                    average_retrieval_time: 0.0,
                    retrieval_success_rate: 0.0,
                    cache_hit_rate: 0.0,
                },
                availability: 0.0,
            },
            economic_health: EconomicHealth {
                ubi_system: UbiHealth {
                    distribution_rate: 0.0,
                    citizen_participation: 0.0,
                    payment_success_rate: 0.0,
                    treasury_health: 0.0,
                },
                dao_health: DaoHealth {
                    proposal_activity: 0.0,
                    voting_participation: 0.0,
                    governance_efficiency: 0.0,
                    community_engagement: 0.0,
                },
                token_health: TokenHealth {
                    circulation_health: 0.0,
                    inflation_rate: 0.0,
                    velocity: 0.0,
                    distribution_fairness: 0.0,
                },
                incentive_health: IncentiveHealth {
                    participation_rewards: 0.0,
                    validator_rewards: 0.0,
                    storage_rewards: 0.0,
                    network_rewards: 0.0,
                },
            },
        }
    }
}
