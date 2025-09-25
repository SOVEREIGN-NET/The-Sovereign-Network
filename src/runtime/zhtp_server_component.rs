//! ZHTP Server Component for the Orchestrator
//! 
//! This component runs the ZHTP server directly in the orchestrator
//! using the well-designed handlers from the zhtp API module.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, error, debug};

use super::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};

// Import ZHTP server from lib-protocols
use lib_protocols::{ZhtpServer, ServerConfig};
use lib_protocols::zhtp::ZhtpRequestHandler;

// Import our well-designed handlers
use crate::api::handlers::{IdentityHandler, BlockchainHandler, StorageHandler, ProtocolHandler};

// Import the components we need for handler initialization
use lib_identity::IdentityManager;
use lib_blockchain::Blockchain;
use lib_storage::UnifiedStorageSystem;

/// ZHTP Server component that uses our well-designed API handlers
#[derive(Debug)]
pub struct ZhtpServerComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    zhtp_server: Arc<RwLock<Option<ZhtpServer>>>,
    server_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl ZhtpServerComponent {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            zhtp_server: Arc::new(RwLock::new(None)),
            server_task: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Component for ZhtpServerComponent {
    fn id(&self) -> ComponentId {
        ComponentId::ZhtpServer // We'd need to add this to the enum
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("🌐 Starting ZHTP server component with comprehensive API handlers...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Create ZHTP server configuration
        let server_config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 9333,
            ..Default::default()
        };
        
        let mut zhtp_server = ZhtpServer::new(server_config);
        
        // Initialize the backend components needed for handlers
        info!("🔧 Initializing backend components for API handlers...");
        
        // Get shared blockchain instance
        let blockchain = match lib_blockchain::get_shared_blockchain().await {
            Ok(shared_blockchain) => {
                let blockchain_guard = shared_blockchain.read().await;
                Arc::new(RwLock::new(blockchain_guard.clone()))
            }
            Err(_) => {
                // Fallback to new blockchain
                Arc::new(RwLock::new(Blockchain::new()?))
            }
        };
        
        // Initialize identity manager
        let identity_manager = Arc::new(RwLock::new(
            lib_identity::initialize_identity_system().await?
        ));
        
        // Initialize storage (simplified for demo)
        let storage_config = lib_storage::UnifiedStorageConfig {
            node_id: lib_storage::types::NodeId::from(lib_crypto::Hash::from_bytes(b"zhtp_server")),
            addresses: vec!["127.0.0.1:8000".to_string()],
            economic_config: lib_storage::EconomicManagerConfig::default(),
            storage_config: lib_storage::StorageConfig {
                max_storage_size: 1024 * 1024 * 1024, // 1GB
                default_tier: lib_storage::StorageTier::Hot,
                enable_compression: true,
                enable_encryption: true,
            },
            erasure_config: lib_storage::ErasureConfig {
                data_shards: 4,
                parity_shards: 2,
            },
        };
        
        let storage = Arc::new(RwLock::new(
            UnifiedStorageSystem::new(storage_config).await?
        ));
        
        // Create and register our comprehensive handlers
        info!("📋 Registering comprehensive API handlers...");
        
        // Blockchain handler with real blockchain integration
        let blockchain_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            BlockchainHandler::new(blockchain.clone())
        );
        zhtp_server.add_handler(blockchain_handler);
        
        // Identity handler with real identity management
        let identity_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            IdentityHandler::new(identity_manager.clone())
        );
        zhtp_server.add_handler(identity_handler);
        
        // Storage handler with real storage system
        let storage_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            StorageHandler::new(storage.clone())
        );
        zhtp_server.add_handler(storage_handler);
        
        // Protocol handler
        let protocol_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            ProtocolHandler::new()
        );
        zhtp_server.add_handler(protocol_handler);
        
        info!("✅ Registered comprehensive API handlers:");
        info!("   - BlockchainHandler: /api/v1/blockchain/*");
        info!("   - IdentityHandler: /api/v1/identity/*");
        info!("   - StorageHandler: /api/v1/storage/*");
        info!("   - ProtocolHandler: /api/v1/protocol/*");
        
        // Start the server in a background task
        let server_task = tokio::spawn(async move {
            if let Err(e) = zhtp_server.start().await {
                error!("❌ ZHTP server error: {}", e);
            }
        });
        
        *self.server_task.write().await = Some(server_task);
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("✅ ZHTP server component started on http://localhost:9333");
        info!("🚀 Comprehensive API endpoints now available!");
        
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("🛑 Stopping ZHTP server component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        // Stop the server task
        if let Some(task) = self.server_task.write().await.take() {
            task.abort();
            info!("🌐 ZHTP server task terminated");
        }
        
        *self.zhtp_server.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        
        info!("✅ ZHTP server component stopped");
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::HealthCheck => {
                debug!("🌐 ZHTP server component health check");
                Ok(())
            }
            _ => {
                debug!("🌐 ZHTP server component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), 
            if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        // Add API-specific metrics
        metrics.insert("handlers_registered".to_string(), 4.0); // blockchain, identity, storage, protocol
        metrics.insert("server_port".to_string(), 9333.0);
        
        Ok(metrics)
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}