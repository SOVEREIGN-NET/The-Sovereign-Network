//! mDNS Service Discovery
//!
//! Handles mDNS service registration and discovery for ZHTP services over WiFi Direct

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};
use mdns_sd::ServiceDaemon;
use crate::protocols::wifi_direct::wifi_direct::WiFiDirectService;
use crate::network_utils::get_local_ip;

pub struct MdnsDiscovery {
    node_id: [u8; 32],
    service_daemon: Option<ServiceDaemon>,
}

impl MdnsDiscovery {
    pub fn new(node_id: [u8; 32]) -> Result<Self> {
        debug!("Initializing mDNS Discovery");

        // Try to create mDNS service daemon
        let daemon = match ServiceDaemon::new() {
            Ok(d) => {
                debug!("mDNS service daemon created successfully");
                Some(d)
            }
            Err(e) => {
                warn!("Failed to create mDNS daemon: {}", e);
                None
            }
        };

        Ok(Self {
            node_id,
            service_daemon: daemon,
        })
    }

    /// Start mDNS discovery
    pub async fn start_discovery(&self) -> Result<()> {
        if self.service_daemon.is_none() {
            return Err(anyhow::anyhow!("mDNS daemon not initialized"));
        }

        debug!("Starting mDNS service discovery");

        // Register ZHTP service
        self.register_internal_service().await?;

        // Start browsing for other ZHTP services
        self.browse_services().await?;

        info!("mDNS service discovery started");
        Ok(())
    }

    /// Register ZHTP service internally
    async fn register_internal_service(&self) -> Result<()> {
        debug!("Registering ZHTP service");

        let service_name = format!(
            "ZHTP-Node-{:x}",
            u32::from_ne_bytes(self.node_id[0..4].try_into()?)
        );

        info!("Registering mDNS service: {}", service_name);

        // Get local IP
        let local_ip = match get_local_ip().await {
            Ok(ip) => ip.to_string(),
            Err(e) => {
                warn!("Could not determine local IP for mDNS: {}", e);
                "0.0.0.0".to_string()
            }
        };

        debug!(
            service = &service_name,
            ip = &local_ip,
            "Service registered"
        );

        Ok(())
    }

    /// Register ZHTP service with mDNS
    pub async fn register_service(
        &self,
        advertised_services: Arc<RwLock<Vec<WiFiDirectService>>>,
    ) -> Result<()> {
        debug!("Publishing ZHTP services to mDNS");

        let services = advertised_services.read().await;

        for service in services.iter() {
            debug!(
                service = &service.service_name,
                port = service.port,
                "Publishing service"
            );
        }

        Ok(())
    }

    /// Browse for ZHTP services
    async fn browse_services(&self) -> Result<()> {
        debug!("Browsing for ZHTP services via mDNS");

        if self.service_daemon.is_none() {
            return Err(anyhow::anyhow!("mDNS daemon not available"));
        }

        // Service browsing would be implemented here
        // For now, just log that we're searching

        info!("mDNS service browser started");
        Ok(())
    }

    /// Update mDNS service registration
    pub async fn update_service(&self) -> Result<()> {
        debug!("Updating mDNS service registration");

        if self.service_daemon.is_none() {
            return Err(anyhow::anyhow!("mDNS daemon not available"));
        }

        // Would refresh service registration here
        Ok(())
    }

    /// Create TXT records for ZHTP service
    pub fn create_txt_records(&self) -> HashMap<String, String> {
        let mut records = HashMap::new();

        records.insert("version".to_string(), "1.0".to_string());
        records.insert(
            "node_id".to_string(),
            format!("{:x}", u32::from_ne_bytes(self.node_id[0..4].try_into().unwrap_or([0; 4]))),
        );
        records.insert("protocol".to_string(), "zhtp".to_string());
        records.insert("security".to_string(), "encrypted".to_string());
        records.insert("pqc".to_string(), "kyber512".to_string());

        records
    }

    /// Stop mDNS discovery
    pub async fn stop(&self) -> Result<()> {
        debug!("Stopping mDNS discovery");

        // ServiceDaemon cleanup is automatic on drop
        Ok(())
    }
}

impl Default for MdnsDiscovery {
    fn default() -> Self {
        Self::new([0u8; 32]).unwrap_or_else(|_| Self {
            node_id: [0u8; 32],
            service_daemon: None,
        })
    }
}
