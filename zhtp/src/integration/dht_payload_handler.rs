//! Integration-level DHT payload handling.
//!
//! Consumes payload sender registrations from the dispatcher and exposes a data-only drain hook
//! so mesh/core no longer needs to own lib-storage wiring.

use anyhow::Result;
use tracing::{info, warn, debug};

use crate::integration::dht_dispatcher::latest_dht_payload_sender;
use crate::integration::dht_integration::DhtStorageHandle;

/// Attach a message handler to the latest registered DHT payload sender.
pub async fn wire_message_handler(
    handler: &mut lib_network::messaging::MeshMessageHandler,
) {
    if let Some(sender) = latest_dht_payload_sender() {
        handler.set_dht_payload_sender(sender);
        info!("DHT payload sender wired to message handler via integration layer");
    }
}

/// Drain incoming DHT data and hand it to a consumer (data-only, no lib-storage dependency).
pub async fn drain_dht_payloads<F>(mut receiver: tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, lib_storage::dht::transport::PeerId)>, mut consume: F)
where
    F: FnMut(Vec<u8>, lib_storage::dht::transport::PeerId) + Send + 'static,
{
    while let Some((data, peer)) = receiver.recv().await {
        consume(data, peer);
    }
}

/// Store a DHT value through the integration-held storage handle.
pub async fn store_dht_value(
    dht_storage: &DhtStorageHandle,
    key: &[u8],
    value: &[u8],
) -> bool {
    let key_str = hex::encode(key);
    match dht_storage.lock().await.store(key_str.clone(), value.to_vec(), None).await {
        Ok(()) => {
            debug!("✅ DHT value stored via integration: key={}", &key_str[0..key_str.len().min(16)]);
            true
        }
        Err(e) => {
            warn!("⚠️ DHT store failed via integration: {}", e);
            false
        }
    }
}

/// Fetch a DHT value through the integration-held storage handle.
pub async fn fetch_dht_value(
    dht_storage: &DhtStorageHandle,
    key: &[u8],
) -> Result<(bool, Option<Vec<u8>>)> {
    let key_str = hex::encode(key);
    match dht_storage.lock().await.get(&key_str).await {
        Ok(Some(dht_value)) => {
            debug!("✅ DHT value found via integration: key={}", &key_str[0..key_str.len().min(16)]);
            Ok((true, Some(dht_value)))
        }
        Ok(None) => {
            debug!("⚠️ DHT value not found locally via integration");
            Ok((false, None))
        }
        Err(e) => {
            warn!("DHT get failed via integration: {}", e);
            Ok((false, None))
        }
    }
}
