use anyhow::{Result, anyhow};
use lib_blockchain::Blockchain;
use lib_storage::PersistentStorageSystem;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

/// Service for bootstrapping blockchain from network peers
pub struct BootstrapService;

impl BootstrapService {
    /// Try to bootstrap blockchain from network discovery
    pub async fn try_bootstrap_blockchain(
        _blockchain: &Arc<RwLock<Blockchain>>,
        _storage: &Arc<RwLock<PersistentStorageSystem>>,
        _api_port: u16,
        environment: &crate::config::environment::Environment,
    ) -> Result<Blockchain> {
        let _ = environment;
        warn!("Bootstrap via network is disabled in the stub build");
        Err(anyhow!("No network bootstrap available"))
    }

    /// Try to sync blockchain from a specific peer address using incremental protocol
    pub async fn try_bootstrap_blockchain_from_peer(
        _blockchain: &Arc<RwLock<Blockchain>>,
        _storage: &Arc<RwLock<PersistentStorageSystem>>,
        _peer_addr: &str,
    ) -> Result<Blockchain> {
        warn!("Bootstrap over HTTP/TCP is disabled; use QUIC bootstrap sync paths");
        Err(anyhow!("Legacy HTTP/TCP bootstrap sync is not supported"))
    }
}
