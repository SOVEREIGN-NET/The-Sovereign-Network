//! NetworkOutput consumer/dispatcher for storage integration.

use async_trait::async_trait;
use lib_crypto::PublicKey;
use lib_network::{NetworkOutput, global_output_queue};
use lib_storage::PersistentStorageSystem;
use std::sync::Arc;
use tokio::sync::RwLock;
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
        let _ = self
            .sender
            .send(NetworkOutput::BlockchainRequest { requester, request_id, request });
    }

    async fn handle_bootstrap_proof_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        current_height: u64,
    ) {
        let _ = self.sender.send(NetworkOutput::BootstrapProofRequest {
            requester,
            request_id,
            current_height,
        });
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

/// Spawn a background task to poll outputs.
pub fn spawn_network_output_processor(
    handler: impl NetworkOutputHandler + 'static,
    interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            process_network_outputs_with(&handler).await;
            sleep(interval).await;
        }
    });
}

/// Wrapper type for Arc<RwLock<PersistentStorageSystem>> to implement the UnifiedStorage trait.
/// Kept here to avoid lib-storage depending on lib-network.
pub struct UnifiedStorageWrapper(pub Arc<RwLock<PersistentStorageSystem>>);

#[async_trait]
impl lib_network::storage_stub::UnifiedStorage for UnifiedStorageWrapper {
    async fn store_domain_record(&self, domain: &str, data: Vec<u8>) -> anyhow::Result<()> {
        let mut sys = self.0.write().await;
        sys.store_domain_record(domain, &data).await
    }

    async fn load_domain_record(&self, domain: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let mut sys = self.0.write().await;
        sys.get_domain_record(domain).await
    }

    async fn delete_domain_record(&self, domain: &str) -> anyhow::Result<()> {
        let mut sys = self.0.write().await;
        sys.delete_domain_record(domain).await
    }

    async fn list_domain_records(&self) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        let mut sys = self.0.write().await;
        sys.list_domain_records().await
    }

    async fn store_manifest(&self, domain: &str, manifest_data: Vec<u8>) -> anyhow::Result<()> {
        let mut sys = self.0.write().await;
        let manifest_key = format!("manifest:{}", domain);
        sys.store_domain_record(&manifest_key, &manifest_data).await
    }

    async fn load_manifest(&self, domain: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let mut sys = self.0.write().await;
        let manifest_key = format!("manifest:{}", domain);
        sys.get_domain_record(&manifest_key).await
    }

    fn is_stub(&self) -> bool {
        false
    }
}
