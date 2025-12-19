//! DHT integration wiring for mesh/core.
//!
//! Moves bootstrap logic out of mesh/core while keeping the interface data-only.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;

use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

use lib_crypto::{self, PostQuantumSignature};
use lib_network::routing::message_routing::MeshMessageRouter;
use lib_storage::dht::DhtStorage;
use lib_storage::types::dht_types::{DhtNode, DhtPeerIdentity};
use lib_types::NodeId;

use crate::integration::dht_dispatcher::{DhtIntegrationDispatcher, DhtIntegrationEvent};
use crate::web4_stub::MeshDhtTransport;

const DHT_STORAGE_BYTES: u64 = 10_000_000_000;

pub type DhtStorageHandle = Arc<Mutex<DhtStorage>>;
pub type DhtPayloadSender = Arc<mpsc::UnboundedSender<(Vec<u8>, NodeId)>>;

pub struct DhtIntegrationHandles {
    pub dht_storage: DhtStorageHandle,
    pub dht_payload_sender: DhtPayloadSender,
}

/// Wire a DHT payload sender into a lib-network message handler.
pub fn wire_dht_payload_sender(
    handler: &mut lib_network::messaging::MeshMessageHandler,
    sender: &DhtPayloadSender,
) {
    let sender_clone = sender.as_ref().clone();
    handler.set_dht_payload_sender(sender_clone);
}

/// Build DHT storage + mesh transport wiring. Emits an integration event so upper layers
/// can observe the bootstrap without owning lib-storage inside mesh/core.
pub fn setup_mesh_dht_integration(
    server_id: Uuid,
    mesh_message_router: Arc<RwLock<MeshMessageRouter>>,
    dispatcher: &DhtIntegrationDispatcher,
) -> DhtIntegrationHandles {
    let local_node_id = derive_local_node_id(server_id);
    let dht_storage = create_persistent_storage(local_node_id.clone(), dispatcher);

    let dht_keypair = Arc::new(
        lib_crypto::KeyPair::generate().expect("Failed to generate DHT keypair"),
    );

    let (mesh_dht_transport, dht_payload_sender_raw) =
        MeshDhtTransport::new(mesh_message_router, dht_keypair);
    let mesh_dht_transport = Arc::new(mesh_dht_transport);

    // Map NodeId to PeerId for the lib-storage transport.
    let (mapped_tx, mut mapped_rx) =
        mpsc::unbounded_channel::<(Vec<u8>, NodeId)>();
    tokio::spawn(async move {
        while let Some((data, node_id)) = mapped_rx.recv().await {
            let peer_id = lib_storage::dht::transport::PeerId::Mesh(node_id.0.to_vec());
            let _ = dht_payload_sender_raw.send((data, peer_id));
        }
    });

    // Spawn network-enabled DHT storage with mesh routing.
    {
        let dht_storage_task = dht_storage.clone();
        let local_node_for_task = build_local_node(local_node_id);
        tokio::spawn(async move {
            match DhtStorage::new_with_transport(
                local_node_for_task,
                mesh_dht_transport,
                DHT_STORAGE_BYTES,
            ) {
                Ok(mut network_storage) => {
                    let _ = network_storage.start_network_processing().await;
                    let mut storage = dht_storage_task.lock().await;
                    *storage = network_storage;
                    debug!("DHT network storage initialized with mesh routing (Ticket #154)");
                }
                Err(e) => {
                    debug!(
                        "DHT network initialization failed (using local-only mode): {}",
                        e
                    );
                }
            }
        });
    }

    DhtIntegrationHandles {
        dht_storage,
        dht_payload_sender: Arc::new(mapped_tx),
    }
}

/// Compatibility shim for older callers; builds persistent DHT storage and emits InitStorage.
/// Prefer `setup_mesh_dht_integration` for full transport wiring.
pub fn create_dht_storage_placeholder(
    local_node_id: lib_identity::NodeId,
    dispatcher: &DhtIntegrationDispatcher,
) -> DhtStorageHandle {
    create_persistent_storage(local_node_id, dispatcher)
}

fn create_persistent_storage(
    local_node_id: lib_identity::NodeId,
    dispatcher: &DhtIntegrationDispatcher,
) -> DhtStorageHandle {
    let zhtp_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zhtp")
        .join("storage");

    if let Err(e) = std::fs::create_dir_all(&zhtp_dir) {
        warn!("Failed to create DHT storage directory {:?}: {}", zhtp_dir, e);
    }

    let dht_persist_path = zhtp_dir.join("dht_storage.bin");
    info!("MeshRouter DHT persistence path: {:?}", dht_persist_path);

    dispatcher.dispatch(DhtIntegrationEvent::InitStorage {
        local_node_id: local_node_id.clone(),
        persist_path: dht_persist_path.clone(),
        max_bytes: DHT_STORAGE_BYTES,
    });

    Arc::new(Mutex::new(DhtStorage::new_with_persistence(
        local_node_id,
        DHT_STORAGE_BYTES,
        dht_persist_path,
    )))
}

fn derive_local_node_id(server_id: Uuid) -> lib_identity::NodeId {
    let hash_bytes = lib_crypto::hash_blake3(server_id.as_bytes());
    lib_identity::NodeId::from_bytes(hash_bytes)
}

fn build_local_node(local_node_id: lib_identity::NodeId) -> DhtNode {
    DhtNode {
        peer: DhtPeerIdentity {
            node_id: local_node_id.clone(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            did: format!("did:zhtp:{}", hex::encode(local_node_id.as_bytes())),
            device_id: "mesh-node".to_string(),
        },
        addresses: vec!["0.0.0.0:0".to_string()],
        public_key: PostQuantumSignature::default(),
        last_seen: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        reputation: 1000,
        storage_info: None,
    }
}
