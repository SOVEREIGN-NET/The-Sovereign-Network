//! NetworkOutput consumer/dispatcher for lib-storage integration.
//! Enabled via the `network-integration` feature.

use async_trait::async_trait;
use lib_crypto::PublicKey;
use lib_network::{NetworkOutput, global_output_queue};
use tokio::task::JoinHandle;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
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
        requester: PublicKey,
        request_id: u64,
        request: lib_network::types::mesh_message::BlockchainRequestType,
    );

    async fn handle_bootstrap_proof_request(
        &self,
        requester: PublicKey,
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
        requester: PublicKey,
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
        requester: PublicKey,
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

#[cfg(test)]
mod tests {
    use super::*;
    use lib_network::types::mesh_message::BlockchainRequestType;
    use lib_network::protocols::bluetooth::gatt::EdgeSyncMessage;
    use lib_crypto::PublicKey;

    #[tokio::test]
    async fn channel_handler_receives_outputs() {
        let (handler, mut rx) = channel_handler();

        // enqueue outputs
        let pk = PublicKey::new(vec![0u8; 32]);
        let queue = lib_network::global_output_queue();
        queue.push(NetworkOutput::BlockchainRequest {
            requester: pk.clone(),
            request_id: 1,
            request: BlockchainRequestType::FullChain,
        }).await;
        queue.push(NetworkOutput::BootstrapProofRequest {
            requester: pk.clone(),
            request_id: 2,
            current_height: 10,
        }).await;
        queue.push(NetworkOutput::EdgeSyncRequest {
            peer: "peer-1".to_string(),
            message: EdgeSyncMessage::HeadersRequest { request_id: 3, start_height: 0, count: 1 },
        }).await;

        process_network_outputs_with(&handler).await;

        // Ensure outputs were forwarded
        let mut received = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            received.push(msg);
        }
        assert_eq!(received.len(), 3);
    }
}

/// Handler that forwards outputs into an unbounded channel for external consumption.
#[derive(Clone)]
pub struct ChannelNetworkOutputHandler {
    sender: mpsc::UnboundedSender<NetworkOutput>,
}

impl ChannelNetworkOutputHandler {
    pub fn new(sender: mpsc::UnboundedSender<NetworkOutput>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl NetworkOutputHandler for ChannelNetworkOutputHandler {
    async fn handle_blockchain_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        request: lib_network::types::mesh_message::BlockchainRequestType,
    ) {
        let _ = self.sender.send(NetworkOutput::BlockchainRequest { requester, request_id, request });
    }

    async fn handle_bootstrap_proof_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        current_height: u64,
    ) {
        let _ = self.sender.send(NetworkOutput::BootstrapProofRequest { requester, request_id, current_height });
    }

    async fn handle_edge_sync_request(
        &self,
        peer: String,
        message: lib_network::protocols::bluetooth::gatt::EdgeSyncMessage,
    ) {
        let _ = self.sender.send(NetworkOutput::EdgeSyncRequest { peer, message });
    }
}

/// Convenience helper to create a channel-backed handler.
pub fn channel_handler() -> (ChannelNetworkOutputHandler, mpsc::UnboundedReceiver<NetworkOutput>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (ChannelNetworkOutputHandler::new(tx), rx)
}

/// Spawn a background task that drains outputs and dispatches to a handler.
pub fn spawn_network_output_processor(
    handler: impl NetworkOutputHandler + 'static,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            process_network_outputs_with(&handler).await;
            sleep(interval).await;
        }
    })
}
