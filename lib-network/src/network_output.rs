//! Data-only outputs emitted by lib-network for upper-layer handling.
//! TODO (relocation pass): replace protocol stubs with real dispatchers.

use std::collections::VecDeque;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

use crate::types::mesh_message::BlockchainRequestType;
use crate::protocols::bluetooth::gatt::EdgeSyncMessage;
use lib_crypto::PublicKey;

#[derive(Clone, Debug)]
pub enum NetworkOutput {
    BlockchainRequest {
        requester: PublicKey,
        request_id: u64,
        request: BlockchainRequestType,
    },
    BootstrapProofRequest {
        requester: PublicKey,
        request_id: u64,
        current_height: u64,
    },
    EdgeSyncRequest {
        peer: String,
        message: EdgeSyncMessage,
    },
}

#[derive(Clone, Default)]
pub struct OutputQueue {
    inner: Arc<Mutex<VecDeque<NetworkOutput>>>,
}

impl OutputQueue {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub async fn push(&self, output: NetworkOutput) {
        self.inner.lock().await.push_back(output);
    }

    pub async fn drain(&self) -> Vec<NetworkOutput> {
        let mut guard = self.inner.lock().await;
        guard.drain(..).collect()
    }
}

static OUTPUTS: OnceLock<OutputQueue> = OnceLock::new();

pub fn global_output_queue() -> &'static OutputQueue {
    OUTPUTS.get_or_init(OutputQueue::new)
}
