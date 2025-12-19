//! Integration-level DHT payload handling.
//!
//! Consumes payload sender registrations from the dispatcher and exposes a data-only drain hook
//! so mesh/core no longer needs to own lib-storage wiring.

use tracing::info;

use crate::integration::dht_dispatcher::latest_dht_payload_sender;

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
