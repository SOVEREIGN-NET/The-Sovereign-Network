use std::time::Duration;
use crate::storage_network_integration::{
    channel_handler,
    spawn_network_output_processor,
    NetworkOutputHandler,
};
use lib_network::NetworkOutput;
use lib_crypto::PublicKey;
use lib_network::types::mesh_message::BlockchainRequestType;
use lib_network::protocols::bluetooth::gatt::EdgeSyncMessage;
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{info, warn};

/// Application-level handler mapping NetworkOutput to storage/blockchain actions.
pub struct AppNetworkOutputHandler;

#[async_trait]
impl NetworkOutputHandler for AppNetworkOutputHandler {
    async fn handle_blockchain_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        request: BlockchainRequestType,
    ) {
        info!(
            "Dispatching BlockchainRequest {:?} req_id={} from {:?} (stub)",
            request,
            request_id,
            requester.key_id
        );
        // TODO: Call blockchain API / storage integration as appropriate.
    }

    async fn handle_bootstrap_proof_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        current_height: u64,
    ) {
        info!(
            "Dispatching BootstrapProofRequest req_id={} current_height={} from {:?} (stub)",
            request_id,
            current_height,
            requester.key_id
        );
        // TODO: Fetch/generate proof and headers via blockchain provider.
    }

    async fn handle_edge_sync_request(
        &self,
        peer: String,
        message: EdgeSyncMessage,
    ) {
        warn!("Dispatching EdgeSyncRequest from {} message {:?} (stub)", peer, message);
        // TODO: Forward to edge sync subsystem.
    }
}

/// Spawn background processor using the app handler.
pub fn spawn_app_network_output_processor() {
    // drain every 500ms; adjust as needed
    spawn_network_output_processor(AppNetworkOutputHandler, Duration::from_millis(500));
}

/// Example of using channel-based fan-out for outputs.
pub fn channel_dispatcher() -> UnboundedReceiver<NetworkOutput> {
    let (handler, rx) = channel_handler();
    // Start processor with channel handler
    spawn_network_output_processor(handler, Duration::from_millis(500));
    rx
}
