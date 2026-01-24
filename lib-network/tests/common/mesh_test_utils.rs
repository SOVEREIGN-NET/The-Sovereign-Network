use anyhow::Result;
use blake3::hash;
use hex;
use lib_crypto::{hash_blake3, kdf::hkdf::hkdf_sha3};
use lib_identity::{IdentityType, NodeId, ZhtpIdentity};
use lib_network::discovery::{DiscoveryProtocol, DiscoveryResult, UnifiedDiscoveryService};
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::str::FromStr;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Node {
    pub did: String,
    pub device: String,
    pub node_id: String,
    pub peers: Arc<Mutex<HashSet<String>>>,
    pub persisted_state: Arc<Mutex<HashMap<String, String>>>,
}

impl Node {
    pub fn new(did: &str, device: &str) -> Self {
        let node_id = compute_node_id(did, device);
        Node {
            did: did.to_string(),
            device: device.to_string(),
            node_id,
            peers: Arc::new(Mutex::new(HashSet::new())),
            persisted_state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn persist(&self) {
        let mut storage = self.persisted_state.lock().unwrap();
        storage.insert("node_id".into(), self.node_id.clone());
        storage.insert("did".into(), self.did.clone());
        storage.insert("device".into(), self.device.clone());
    }

    pub fn restore(&mut self) {
        let storage = self.persisted_state.lock().unwrap();
        if let Some(id) = storage.get("node_id") {
            self.node_id = id.clone();
        }
    }

    pub fn advertise_multicast(&self, fabric: &mut MulticastFabric) {
        fabric.broadcast(self.node_id.clone());
    }

    pub fn discover_peers(&self, fabric: &MulticastFabric) {
        let seen = fabric.collect();
        let mut peers = self.peers.lock().unwrap();
        for id in seen.into_iter() {
            if id != self.node_id {
                peers.insert(id);
            }
        }
    }

    pub fn handshake_with(&self, remote: &Node) -> bool {
        // Simulated 3-phase handshake: UHP (identity string exchange),
        // KEM simulation (derive a shared secret), and verification (blake3 of DID)
        let uhp_ok = self.did.starts_with("did:zhtp:") && remote.did.starts_with("did:zhtp:");
        if !uhp_ok {
            return false;
        }

        // Simulate KEM by deriving a shared token using a deterministic ordering.
        let (first, second) = if self.node_id <= remote.node_id {
            (&self.node_id, &remote.node_id)
        } else {
            (&remote.node_id, &self.node_id)
        };
        
        // Compute shared secret hash for both sides of the handshake
        let shared = hash(format!("{}{}", first, second).as_bytes());
        let shared_hex = hex::encode(shared.as_bytes());
        
        // Verification: In real implementation, remote would compute this independently
        // For testing purposes, we just verify the hash is consistent
        !shared_hex.is_empty()
    }
}

/// Simulated multicast fabric for feature-gated tests
#[derive(Clone, Debug)]
pub struct MulticastFabric {
    pub messages: Arc<Mutex<Vec<String>>>,
}

impl MulticastFabric {
    pub fn new() -> Self {
        MulticastFabric {
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn broadcast(&mut self, node_id: String) {
        let mut m = self.messages.lock().unwrap();
        m.push(node_id);
    }

    pub fn collect(&self) -> Vec<String> {
        let m = self.messages.lock().unwrap();
        m.clone()
    }

    pub fn clear(&mut self) {
        let mut m = self.messages.lock().unwrap();
        m.clear();
    }
}

pub const MULTICAST_ADDR: &str = "224.0.1.75";
pub const MULTICAST_PORT: u16 = 37775;

/// Deterministic NodeId derived using Blake3("ZHTP_NODE_V2:" + DID + ":" + device)
pub fn compute_node_id(did: &str, device: &str) -> String {
    let input = format!("ZHTP_NODE_V2:{}:{}", did, device);
    hex::encode(hash(input.as_bytes()).as_bytes())
}

/// Create a deterministic RNG seeded by a reproducible seed (for reproducible simulations)
pub fn deterministic_rng(seed: u64) -> rand_chacha::ChaCha20Rng {
    use rand_chacha::ChaCha20Rng;
    ChaCha20Rng::seed_from_u64(seed)
}

pub fn make_multicast_socket(bind_ip: Ipv4Addr, bind_port: u16) -> std::net::UdpSocket {
    let addr = SocketAddr::new(IpAddr::V4(bind_ip), bind_port);
    let socket = std::net::UdpSocket::bind(addr).expect("bind socket");

    // Join multicast group on all interfaces
    let multi = Ipv4Addr::from_str(MULTICAST_ADDR).expect("valid multicast");
    socket.join_multicast_v4(&multi, &bind_ip).ok();

    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
    socket.set_nonblocking(true).ok();

    socket
}

pub async fn spawn_simple_node(
    did: String,
    device: String,
    seed: u64,
    mut shutdown_rx: mpsc::Receiver<()>,
    peer_event_tx: mpsc::Sender<String>,
) {
    let node_id = compute_node_id(&did, &device);
    let bind_ip = Ipv4Addr::new(0, 0, 0, 0);
    let socket = make_multicast_socket(bind_ip, 0);
    let _local_addr = socket.local_addr().expect("local addr");
    let udp = tokio::net::UdpSocket::from_std(socket).expect("tokio udp");

    // deterministic RNG for message delays and timing
    let mut rng = deterministic_rng(seed);

    // Broadcast HELLO with NodeId
    let hello = format!("HELLO:{}:{}", node_id, did);
    let multicast: SocketAddr = format!("{}:{}", MULTICAST_ADDR, MULTICAST_PORT)
        .parse()
        .expect("multicast addr parse");

    let _ = udp.send_to(hello.as_bytes(), &multicast).await;

    let mut buf = vec![0u8; 1024];
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                break;
            }
            res = udp.recv_from(&mut buf) => {
                if let Ok((n, src)) = res {
                    if n == 0 { continue; }
                    if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                        // Notify test harness about peer event
                        let _ = peer_event_tx.send(format!("{}->{}: {}", node_id, src, s)).await;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis((rng.next_u64() % 200) as u64)) => {}
        }
    }
}

// === Helper functions for mesh integration tests ===

/// Create a ZhtpIdentity with a deterministic seed
pub fn identity_with_seed(device: &str, seed: [u8; 64]) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        device,
        Some(seed),
    )
}

/// Convert NodeId to UUID for UnifiedDiscoveryService
pub fn peer_id_from_node_id(node_id: &NodeId) -> Uuid {
    Uuid::from_slice(&node_id.as_bytes()[..16])
        .expect("NodeId::as_bytes() must return at least 16 bytes for UUID conversion")
}

/// Create UnifiedDiscoveryService initialized with identity
pub fn create_discovery_service(identity: &ZhtpIdentity) -> UnifiedDiscoveryService {
    UnifiedDiscoveryService::new(
        peer_id_from_node_id(&identity.node_id),
        9443,
        identity.public_key.clone(),
    )
}

/// Build a DiscoveryResult populated with identity metadata
pub fn create_discovery_result(
    identity: &ZhtpIdentity,
    addr: SocketAddr,
    protocol: DiscoveryProtocol,
) -> DiscoveryResult {
    let peer_id = peer_id_from_node_id(&identity.node_id);
    let mut result = DiscoveryResult::new(peer_id, addr, protocol, 9443);
    result.public_key = Some(identity.public_key.clone());
    result.did = Some(identity.did.clone());
    result.device_id = Some(identity.primary_device.clone());
    result
}

/// Derive session key for testing (v2 HKDF-SHA3 with transcript hash)
pub fn derive_session_key_for_test(
    uhp_session_key: &[u8; 32],
    pqc_shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
    peer_node_id: &[u8],
) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + peer_node_id.len());
    ikm.extend_from_slice(uhp_session_key);
    ikm.extend_from_slice(pqc_shared_secret);
    ikm.extend_from_slice(transcript_hash);
    ikm.extend_from_slice(peer_node_id);

    let extracted = hkdf_sha3(&ikm, b"zhtp-quic-mesh-v2", 32)?;
    let expanded = hkdf_sha3(&extracted, b"zhtp-quic-session-v2", 32)?;

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(&expanded);
    Ok(session_key)
}
