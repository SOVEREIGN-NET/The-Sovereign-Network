//! NetworkOutput consumer/dispatcher for lib-storage integration.
//! Enabled via the `network-integration` feature.

use async_trait::async_trait;
use lib_network::{NetworkOutput, global_output_queue};
use tracing::warn;

/// Drain all pending NetworkOutputs.
pub async fn drain_network_outputs() -> Vec<NetworkOutput> {
    global_output_queue().drain().await
}

/// Handler interface for consumers of NetworkOutput.
#[async_trait]
pub trait NetworkOutputHandler: Send + Sync {
    async fn handle_blockchain_request(
        &self,
        requester: lib_network::PublicKey,
        request_id: u64,
        request: lib_network::types::mesh_message::BlockchainRequestType,
    );

    async fn handle_bootstrap_proof_request(
        &self,
        requester: lib_network::PublicKey,
        request_id: u64,
        current_height: u64,
    );

    async fn handle_edge_sync_request(
        &self,
        peer: String,
        message: lib_network::protocols::bluetooth::gatt::EdgeSyncMessage,
    );
}

/// No-op handler for testing/default wiring.
pub struct NoopNetworkOutputHandler;

#[async_trait]
impl NetworkOutputHandler for NoopNetworkOutputHandler {
    async fn handle_blockchain_request(
        &self,
        requester: lib_network::PublicKey,
        request_id: u64,
        request: lib_network::types::mesh_message::BlockchainRequestType,
    ) {
        warn!(
            "NetworkOutput BlockchainRequest {:?} req_id={} from {:?} (noop handler)",
            request,
            request_id,
            requester.key_id
        );
    }

    async fn handle_bootstrap_proof_request(
        &self,
        requester: lib_network::PublicKey,
        request_id: u64,
        current_height: u64,
    ) {
        warn!(
            "NetworkOutput BootstrapProofRequest req_id={} current_height={} from {:?} (noop handler)",
            request_id,
            current_height,
            requester.key_id
        );
    }

    async fn handle_edge_sync_request(
        &self,
        peer: String,
        message: lib_network::protocols::bluetooth::gatt::EdgeSyncMessage,
    ) {
        warn!(
            "NetworkOutput EdgeSyncRequest from {} message {:?} (noop handler)",
            peer,
            message
        );
    }
}

/// Drain and dispatch outputs to the provided handler.
pub async fn process_network_outputs_with(handler: &impl NetworkOutputHandler) {
    let outputs = drain_network_outputs().await;
    for output in outputs {
        match output {
            NetworkOutput::BlockchainRequest { requester, request_id, request } => {
                handler
                    .handle_blockchain_request(requester, request_id, request)
                    .await;
            }
            NetworkOutput::BootstrapProofRequest { requester, request_id, current_height } => {
                handler
                    .handle_bootstrap_proof_request(requester, request_id, current_height)
                    .await;
            }
            NetworkOutput::EdgeSyncRequest { peer, message } => {
                handler.handle_edge_sync_request(peer, message).await;
            }
        }
    }
}

/// Drain and log outputs with a noop handler.
pub async fn process_network_outputs() {
    process_network_outputs_with(&NoopNetworkOutputHandler).await;
}
