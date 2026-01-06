use blake3;
use hex;
use rand::{rngs::StdRng, SeedableRng, RngCore};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

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

        // Simulate KEM by deriving an ephemeral shared token using blake3 over both node ids
        let mut ctx = blake3::Hasher::new();
        ctx.update(self.node_id.as_bytes());
        ctx.update(remote.node_id.as_bytes());
        let shared = ctx.finalize();
        // Convert to hex and verify both sides produce same value (deterministic)
        let shared_hex = hex::encode(shared.as_bytes());
        let mut ctx2 = blake3::Hasher::new();
        ctx2.update(remote.node_id.as_bytes());
        ctx2.update(self.node_id.as_bytes());
        let shared2 = hex::encode(ctx2.finalize().as_bytes());
        shared_hex == shared2
    }
}

/// Very small in-memory multicast fabric for deterministic tests
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
    let mut ctx = blake3::Hasher::new();
    ctx.update(b"ZHTP_NODE_V2:");
    ctx.update(did.as_bytes());
    ctx.update(b":");
    ctx.update(device.as_bytes());
    hex::encode(ctx.finalize().as_bytes())
}

/// Utility: create a deterministic RNG seeded by a reproducible seed (for reproducible simulations)
pub fn deterministic_rng_for_run(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}
use blake3;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::sync::mpsc;

pub const MULTICAST_ADDR: &str = "224.0.1.75";
pub const MULTICAST_PORT: u16 = 37775;

pub fn deterministic_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

pub fn compute_node_id(did: &str, device: &str) -> String {
    let input = format!("ZHTP_NODE_V2:{}:{}", did, device);
    let hash = blake3::hash(input.as_bytes());
    hex::encode(hash.as_bytes())
}

pub fn make_multicast_socket(bind_ip: Ipv4Addr, bind_port: u16) -> std::net::UdpSocket {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("create socket");
    socket.set_reuse_address(true).ok();
    #[cfg(target_family = "unix")]
    socket.set_reuse_port(true).ok();

    let addr = SockAddr::from(SocketAddr::new(IpAddr::V4(bind_ip), bind_port));
    socket.bind(&addr).expect("bind socket");

    // Join multicast group on all interfaces
    let multi = Ipv4Addr::from_str(MULTICAST_ADDR).expect("valid multicast" );
    socket.join_multicast_v4(&multi, &bind_ip).ok();

    socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
    socket.set_nonblocking(true).ok();

    socket.into_udp_socket()
}

use std::str::FromStr;

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
    let local_addr = socket.local_addr().expect("local addr");
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
