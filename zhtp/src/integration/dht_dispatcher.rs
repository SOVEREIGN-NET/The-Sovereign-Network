//! Data-only DHT integration events/dispatcher.
//!
//! Goal: relocate DHT bootstrap/transport wiring out of mesh/core. This dispatcher
//! carries intent to an integration handler without pulling lib-storage into mesh.

use std::path::PathBuf;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tracing::{info, warn};
use lib_types::NodeId;
use std::sync::{Arc, Mutex, OnceLock};
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
    /// Register a payload sender for message handlers (data-only wiring).
    RegisterPayloadSender {
        sender: UnboundedSender<(Vec<u8>, NodeId)>,
    },
}

static LATEST_DHT_SENDER: OnceLock<Arc<Mutex<Option<UnboundedSender<(Vec<u8>, NodeId)>>>>>
    = OnceLock::new();

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
            DhtIntegrationEvent::RegisterPayloadSender { sender } => {
                info!("DHT integration payload sender registered (data-only stub)");
                let store = LATEST_DHT_SENDER.get_or_init(|| Arc::new(Mutex::new(None)));
                if let Ok(mut guard) = store.lock() {
                    *guard = Some(sender);
                }
            }
        }
    }
}

/// Retrieve the most recently registered DHT payload sender (if any).
pub fn latest_dht_payload_sender() -> Option<UnboundedSender<(Vec<u8>, NodeId)>> {
    let store = LATEST_DHT_SENDER.get_or_init(|| Arc::new(Mutex::new(None)));
    store.lock().ok().and_then(|guard| guard.clone())
}
