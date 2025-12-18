//! Data-only DHT integration events/dispatcher.
//!
//! Goal: relocate DHT bootstrap/transport wiring out of mesh/core. This dispatcher
//! carries intent to an integration handler without pulling lib-storage into mesh.

use std::path::PathBuf;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tracing::{info, warn};
use std::fs;

/// DHT integration intents emitted from mesh/core.
#[derive(Debug, Clone)]
pub enum DhtIntegrationEvent {
    /// Request to bootstrap DHT storage with local node id and persistence path.
    InitStorage {
        local_node_id: lib_identity::NodeId,
        persist_path: PathBuf,
        max_bytes: u64,
    },
}

/// Simple dispatcher that fans events out to a receiver for the integration layer.
#[derive(Clone)]
pub struct DhtIntegrationDispatcher {
    sender: UnboundedSender<DhtIntegrationEvent>,
}

impl DhtIntegrationDispatcher {
    pub fn new(sender: UnboundedSender<DhtIntegrationEvent>) -> Self {
        Self { sender }
    }

    pub fn dispatch(&self, evt: DhtIntegrationEvent) {
        let _ = self.sender.send(evt);
    }
}

/// Build an event channel for DHT integration.
pub fn dht_integration_channel() -> (DhtIntegrationDispatcher, UnboundedReceiver<DhtIntegrationEvent>) {
    let (tx, rx) = unbounded_channel();
    (DhtIntegrationDispatcher::new(tx), rx)
}

pub async fn drain_dht_events(mut rx: UnboundedReceiver<DhtIntegrationEvent>) {
    while let Some(evt) = rx.recv().await {
        match evt {
            DhtIntegrationEvent::InitStorage { local_node_id, persist_path, max_bytes } => {
                // Ensure parent dir exists so callers can safely persist.
                if let Some(parent) = persist_path.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        warn!("Failed to create DHT storage dir {:?}: {}", parent, e);
                    }
                }
                info!(
                    "DHT integration init: node_id={}, path={:?}, max_bytes={}",
                    hex::encode(local_node_id.as_bytes()),
                    persist_path,
                    max_bytes
                );
            }
        }
    }
}
