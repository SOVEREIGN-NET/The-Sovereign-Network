//! Integration-level DHT payload handling.
//!
//! Consumes payload sender registrations from the dispatcher and exposes a data-only drain hook
//! so mesh/core no longer needs to own lib-storage wiring.

use anyhow::Result;
use tracing::{debug, info, warn};

use crate::compression::{compress_for_wire, decompress_from_wire, DataCategory};
use crate::integration::dht_dispatcher::latest_dht_payload_sender;
use crate::integration::dht_integration::DhtStorageHandle;

/// Attach a message handler to the latest registered DHT payload sender.
pub async fn wire_message_handler(handler: &mut lib_network::messaging::MeshMessageHandler) {
    if let Some(sender) = latest_dht_payload_sender() {
        handler.set_dht_payload_sender(sender);
        info!("DHT payload sender wired to message handler via integration layer");
    }
}

/// Drain incoming DHT data and hand it to a consumer (data-only, no lib-storage dependency).
pub async fn drain_dht_payloads<F>(
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<(
        Vec<u8>,
        lib_storage::dht::transport::PeerId,
    )>,
    mut consume: F,
) where
    F: FnMut(Vec<u8>, lib_storage::dht::transport::PeerId) + Send + 'static,
{
    while let Some((data, peer)) = receiver.recv().await {
        consume(data, peer);
    }
}

/// Store a DHT value through the integration-held storage handle.
/// SovereignCodec compression — Neural Mesh compresses ALL DHT content.
pub async fn store_dht_value(dht_storage: &DhtStorageHandle, key: &[u8], value: &[u8]) -> bool {
    let key_str = hex::encode(key);
    // Compress DHT values with SovereignCodec before storing
    let compressed_value = compress_for_wire(value, DataCategory::Dht);
    let raw_len = value.len();
    let comp_len = compressed_value.len();
    if comp_len < raw_len {
        debug!("📦 DHT compressed: {} → {} bytes ({:.1}x) key={}",
            raw_len, comp_len, raw_len as f64 / comp_len as f64,
            &key_str[0..key_str.len().min(16)]);
    }
    match dht_storage
        .lock()
        .await
        .store(key_str.clone(), compressed_value, None)
        .await
    {
        Ok(()) => {
            debug!(
                "✅ DHT value stored via integration: key={}",
                &key_str[0..key_str.len().min(16)]
            );
            true
        }
        Err(e) => {
            warn!("⚠️ DHT store failed via integration: {}", e);
            false
        }
    }
}

/// Fetch a DHT value through the integration-held storage handle.
/// Transparently decompresses SovereignCodec-compressed values.
pub async fn fetch_dht_value(
    dht_storage: &DhtStorageHandle,
    key: &[u8],
) -> Result<(bool, Option<Vec<u8>>)> {
    let key_str = hex::encode(key);
    match dht_storage.lock().await.get(&key_str).await {
        Ok(Some(dht_value)) => {
            // Decompress SFC-compressed DHT values transparently
            let decompressed = decompress_from_wire(&dht_value)
                .unwrap_or(dht_value);
            debug!(
                "✅ DHT value found via integration: key={}",
                &key_str[0..key_str.len().min(16)]
            );
            Ok((true, Some(decompressed)))
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
