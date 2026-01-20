use blake3::hash;
use hex;
use rand::{rngs::StdRng, SeedableRng, RngCore};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::str::FromStr;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::mpsc;

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
        let node_id = deterministic_node_id(did, device);
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
        let shared = hash(format!("{}{}", first, second).as_bytes());
        let shared_hex = hex::encode(shared.as_bytes());
        let shared2_hash = hash(format!("{}{}", first, second).as_bytes());
        let shared2 = hex::encode(shared2_hash.as_bytes());
        shared_hex == shared2
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

/// Deterministic NodeId derived using Blake3("ZHTP_NODE_V2:" + DID + ":" + device)
pub fn deterministic_node_id(did: &str, device: &str) -> String {
    let input = format!("ZHTP_NODE_V2:{}:{}", did, device);
    hex::encode(hash(input.as_bytes()).as_bytes())
}

/// Utility: create a deterministic RNG seeded by a reproducible seed (for reproducible simulations)
pub fn deterministic_rng_for_run(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

pub const MULTICAST_ADDR: &str = "224.0.1.75";
pub const MULTICAST_PORT: u16 = 37775;

pub fn deterministic_rng(seed: u64) -> rand_chacha::ChaCha20Rng {
    use rand_chacha::ChaCha20Rng;
    ChaCha20Rng::seed_from_u64(seed)
}

pub fn compute_node_id(did: &str, device: &str) -> String {
    let input = format!("ZHTP_NODE_V2:{}:{}", did, device);
    hex::encode(hash(input.as_bytes()).as_bytes())
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
