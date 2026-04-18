//! Gateway backend discovery.
//!
//! Seeds a PeerRegistry from bootstrap addresses and wires it into the
//! BackendPool so dynamic backend candidates can be discovered.

use crate::backend_pool::BackendPool;
use crate::config::GatewayConfig;
use anyhow::Result;
use lib_identity::ZhtpIdentity;
use lib_network::peer_registry::new_shared_registry;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Initialize gateway discovery and return the shared peer registry.
///
/// If `gateway.static_backends` is non-empty, they are used as bootstrap
/// addresses to seed the PeerRegistry. The registry is then handed to the
/// BackendPool so its background dynamic-discovery task can scan it for
/// backend candidates.
pub async fn start_gateway_discovery(
    cfg: &GatewayConfig,
    identity: ZhtpIdentity,
    backend_pool: Arc<BackendPool>,
) -> Result<lib_network::SharedPeerRegistry> {
    let registry = new_shared_registry();

    // Seed the registry via bootstrap discovery using static backends.
    if !cfg.static_backends.is_empty() {
        info!(
            count = cfg.static_backends.len(),
            "Seeding PeerRegistry from static backend bootstrap addresses"
        );

        match lib_network::bootstrap::discover_bootstrap_peers(
            &cfg.static_backends,
            &identity,
            registry.clone(),
        )
        .await
        {
            Ok(count) => {
                info!(discovered = count, "Bootstrap peer discovery completed");
            }
            Err(e) => {
                warn!(error = %e, "Bootstrap peer discovery failed; continuing with static backends only");
            }
        }

        // Give bootstrap entries a moment to settle in the registry.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Wire the registry into the backend pool.
    backend_pool.start_background_tasks(Some(registry.clone()));

    Ok(registry)
}
