use anyhow::Result;
use bincode;
use log::{error, info};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};
use crate::{
    zhtp::consensus_engine::ZkNetworkMetrics,
    storage::ContentMetadata,
};

use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
    time::Duration,
};


pub mod contracts;
pub mod crypto;
pub mod dao;
pub mod dapp_launchpad;
pub mod monitoring;
pub mod dns;
pub mod economics;
pub mod routing;
pub mod consensus_engine;
pub mod zk_proofs;
pub mod zk_transactions;
pub mod p2p_network;
pub mod ceremony_participants;
pub mod ceremony_coordinator;


mod routing_proof_serde {
    use serde::{Serialize, Deserialize, Serializer, Deserializer};
    use super::zk_proofs::ByteRoutingProof;

    pub fn serialize<S>(proof: &ByteRoutingProof, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialize::serialize(proof, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ByteRoutingProof, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer)
    }
}


pub use ceremony_participants::{
    CeremonyParticipantManager, ParticipantType, CeremonyParticipant, 
    ParticipationStatus, CeremonyState, CeremonyPhase, CeremonyStats
};
pub use ceremony_coordinator::{
    ZhtpCeremonyCoordinator, TrustedSetupResult, CeremonyAttestation,
    run_zhtp_trusted_setup_ceremony
};
pub use contracts::WasmRuntime;
pub use crypto::{Keypair, Signature, KeyPackage, KeyStatus};
pub use dns::{ZhtpDNS, DomainRecord, SubdomainRecord, CertificateRecord, OwnershipProof};
pub use routing::{NodeInfo, RoutingTable};
pub use consensus_engine::{ZhtpConsensusEngine, ConsensusStatus, ZkValidator, ZkBlock, ZkConsensusParams, ValidatorStatus};
pub use zk_proofs::{RoutingProof, ByteRoutingProof};
pub use zk_transactions::{ZkTransaction, ZkTransactionPool, ZkBalance};


#[derive(Clone, Serialize, Deserialize)]
pub struct ZhtpPacket {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
    pub key_package: Option<KeyPackage>,
    #[serde(with = "routing_proof_serde")]
    pub routing_proof: ByteRoutingProof,
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PacketHeader {
    pub id: [u8; 32],
    pub source_addr: Option<SocketAddr>,
    pub destination_commitment: [u8; 32],
    pub ttl: u8,
    pub routing_metadata: Vec<u8>,
}

#[derive(Clone)]
pub struct SharedNode(Arc<Mutex<ZhtpNode>>);

impl SharedNode {
    pub fn new(node: ZhtpNode) -> Self {
        SharedNode(Arc::new(Mutex::new(node)))
    }

    pub async fn start_listening(&self) -> Result<()> {
        let socket = {
            let node = self.0.lock().await;
            node.socket.clone()
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(ZhtpPacket, SocketAddr)>(32);
        let packet_tx = tx.clone();
        let _node = self.0.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, src)) => {
                        if let Ok(packet) = bincode::deserialize(&buf[..size]) {
                            if packet_tx.send((packet, src)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Socket receive error: {}", e);
                        break;
                    }
                }
            }
        });

        while let Some((packet, src)) = rx.recv().await {
            let mut node = self.0.lock().await;
            if let Err(e) = node.process_packet(packet).await {
                error!("Failed to process packet from {}: {}", src, e);
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct ZhtpNode {
    pub(crate) socket: Arc<UdpSocket>,
    keypair: Keypair,
    addr: SocketAddr,
    routing_table: RoutingTable,
    message_handler: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    content_store: Arc<RwLock<HashMap<String, (Vec<u8>, ContentMetadata)>>>,
    runtime: Arc<Mutex<WasmRuntime>>,
}

impl ZhtpPacket {
    pub fn with_routing_proof(mut self, proof: RoutingProof) -> Self {
        self.routing_proof = ByteRoutingProof::from(proof);
        self
    }

    pub fn get_routing_proof(&self) -> Result<RoutingProof, ark_serialize::SerializationError> {
        RoutingProof::try_from(self.routing_proof.clone())
    }
}

impl ZhtpNode {
    pub async fn new(addr: SocketAddr, keypair: Keypair) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        socket.set_broadcast(true)?;
        
        Ok(Self {
            socket: Arc::new(socket),
            keypair,
            addr,
            routing_table: RoutingTable::new(),
            message_handler: None,
            content_store: Arc::new(RwLock::new(HashMap::new())),
            runtime: Arc::new(Mutex::new(WasmRuntime::new())),
        })
    }

    pub async fn new_shared(addr: SocketAddr, keypair: Keypair) -> Result<Arc<Mutex<Self>>> {
        let node = Self::new(addr, keypair).await?;
        Ok(Arc::new(Mutex::new(node)))
    }

    fn commit_destination(&self, addr: SocketAddr) -> [u8; 32] {
        let mut result = [0u8; 32];
        let port_bytes = addr.port().to_be_bytes();
        let ip_bytes = match addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        
        result[0..2].copy_from_slice(&port_bytes);
        let copy_len = std::cmp::min(ip_bytes.len(), 6);
        result[2..2 + copy_len].copy_from_slice(&ip_bytes[..copy_len]);
        
        result
    }

    pub fn get_routing_metrics(&self) -> ZkNetworkMetrics {
        let metrics = self.routing_table.get_all_metrics();
        let mut network_metrics = ZkNetworkMetrics::new(0.9);
        
        for m in metrics.iter() {
            if m.reliability > 0.0 {
                network_metrics.delivery_success += 1.0;
            } else {
                network_metrics.delivery_failures += 1;
            }
            network_metrics.packets_routed += (m.successful_forwards + m.failed_forwards) as u64;
            network_metrics.avg_latency += m.avg_latency;
            network_metrics.reputation_score += m.reputation;
        }
        
        let len = metrics.len() as f64;
        if len > 0.0 {
            network_metrics.avg_latency /= len;
            network_metrics.reputation_score /= len;
        }
        
        network_metrics
    }

    pub async fn process_packet(&mut self, packet: ZhtpPacket) -> Result<Vec<u8>> {
        if packet.header.destination_commitment == self.commit_destination(self.addr) {
            info!("Received packet for this node");
            
            // Handle handshake packets
            if packet.payload == "ZHTP_HANDSHAKE".as_bytes() {
                if let Some(source_addr) = packet.header.source_addr {
                    info!("Received handshake from {}, sending response", source_addr);
                    
                    // Add the source node to our routing table with a direct connection
                    let mut connections = HashSet::new();
                    connections.insert(source_addr);
                    self.routing_table.update_node(self.addr, Some(connections))?;
                    
                    // Create and send response
                    let response = "ZHTP_ACK".as_bytes().to_vec();
                    let response_packet = self.create_packet(source_addr, response).await?;
                    self.send_packet(response_packet, source_addr).await?;
                    
                    info!("Sent handshake response to {}", source_addr);
                } else {
                    error!("Received handshake without source address");
                }
            } else if packet.payload == "ZHTP_ACK".as_bytes() {
                if let Some(source_addr) = packet.header.source_addr {
                    info!("Received handshake acknowledgement from {}", source_addr);
                    
                    // Add the node to our routing table
                    let mut connections = HashSet::new();
                    connections.insert(source_addr);
                    self.routing_table.update_node(self.addr, Some(connections))?;
                } else {
                    error!("Received handshake ACK without source address");
                }
            }
            
            Ok(packet.payload)
        } else {
            info!("Forwarding packet to next hop");
            Ok(vec![])
        }
    }
    

    pub async fn create_packet(&self, destination: SocketAddr, payload: Vec<u8>) -> Result<ZhtpPacket> {
        let header = PacketHeader {
            id: rand::random(),
            source_addr: Some(self.addr),
            destination_commitment: self.commit_destination(destination),
            ttl: 32,
            routing_metadata: vec![],
        };
        
        let header_bytes = bincode::serialize(&header)?;
        let signature = self.keypair.sign(&header_bytes)?;

        Ok(ZhtpPacket {
            header,
            payload,
            key_package: None,
            routing_proof: ByteRoutingProof {
                commitments: vec![],
                elements: vec![],
                inputs: vec![],
            },
            signature,
        })
    }

    pub async fn send_packet(&self, packet: ZhtpPacket, addr: SocketAddr) -> Result<()> {
        let data = bincode::serialize(&packet)?;
        self.socket.send_to(&data, addr).await?;
        Ok(())
    }

    pub async fn connect(&mut self, peer: SocketAddr) -> Result<()> {
        info!("Attempting to connect to {} from {}", peer, self.addr);
        
        let handshake = "ZHTP_HANDSHAKE".as_bytes().to_vec();
        let packet = self.create_packet(peer, handshake).await?;
        
        self.send_packet(packet, peer).await?;
        info!("Handshake sent to {}", peer);

        let mut connections = HashSet::new();
        connections.insert(peer);
        self.routing_table.update_node(self.addr, Some(connections))?;

        let mut buf = vec![0u8; 65535];
        let timeout_duration = Duration::from_secs(5);
        info!("Waiting for handshake response with timeout of {} seconds", timeout_duration.as_secs());
        
        match tokio::time::timeout(
            timeout_duration,
            self.socket.recv_from(&mut buf)
        ).await {
            Ok(Ok((_, src))) if src == peer => {
                info!("Successfully connected to peer at {}", peer);
                Ok(())
            }
            Ok(Ok((_, src))) => {
                error!("Received response from wrong peer: {}", src);
                Err(anyhow::anyhow!("Received response from wrong peer"))
            }
            Ok(Err(e)) => {
                error!("Error receiving response: {}", e);
                Err(anyhow::anyhow!("Error receiving response: {}", e))
            }
            Err(_) => {
                error!("Connection timeout waiting for peer {}", peer);
                Err(anyhow::anyhow!("Connection timeout"))
            }
        }
    }

    pub fn get_key_status(&self) -> KeyStatus {
        self.keypair.get_status()
    }

    pub fn get_keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn get_address(&self) -> SocketAddr {
        self.addr
    }

    pub fn rotate_keys(&mut self) -> Result<()> {
        if self.keypair.get_status().needs_rotation {
            self.keypair = Keypair::rotate();
            info!("Rotated keys for node {}", self.addr);
        }
        Ok(())
    }

    pub fn force_immediate_rotation(&mut self) -> bool {
        self.keypair.needs_immediate_rotation();
        true
    }

    pub fn set_message_handler(&mut self, handler: tokio::sync::mpsc::Sender<Vec<u8>>) {
        self.message_handler = Some(handler);
    }

    pub async fn check_ready(&self) -> bool {
        if let Ok(addr) = self.socket.local_addr() {
            // Try sending a small test packet to ourselves
            let test_data = vec![0u8; 1];
            let mut buf = vec![0u8; 1];
            if let Ok(_) = self.socket.send_to(&test_data, addr).await {
                // Use a very short timeout for recv
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    self.socket.recv_from(&mut buf)
                ).await {
                    Ok(Ok(_)) => true,
                    _ => false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    pub async fn get_content(&self, id: &str) -> Result<(Vec<u8>, ContentMetadata)> {
        let store = self.content_store.read().await;
        store.get(id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Content not found"))
    }

    pub async fn store_content(&mut self, content: Vec<u8>, metadata: ContentMetadata) -> Result<String> {
        let id = format!("{:x}", Sha256::digest(&content));
        let mut store = self.content_store.write().await;
        store.insert(id.clone(), (content, metadata));
        Ok(id)
    }

    pub async fn search_content(&self, query: &str) -> Result<Vec<(String, ContentMetadata)>> {
        let store = self.content_store.read().await;
        let results: Vec<_> = store
            .iter()
            .filter(|(_, (_, metadata))| {
                metadata.content_type.contains(query) ||
                metadata.tags.iter().any(|tag| tag.contains(query))
            })
            .map(|(id, (_, metadata))| (id.clone(), metadata.clone()))
            .collect();
        Ok(results)
    }

    pub async fn deploy_contract(&mut self, bytecode: Vec<u8>, _interface: String) -> Result<Vec<u8>> {
        let mut runtime = self.runtime.lock().await;
        runtime.deploy(&bytecode)?;
        Ok(vec![1])
    }

    pub async fn call_contract(&mut self, _id: &str, method: &str, params: Vec<Vec<u8>>) -> Result<Vec<u8>> {
        let mut runtime = self.runtime.lock().await;
        let wasm_params: Vec<wasmi::Value> = params.iter()
            .filter_map(|p| {
                if p.len() >= 4 {
                    Some(wasmi::Value::I32(i32::from_le_bytes(p[..4].try_into().unwrap_or([0; 4]))))
                } else {
                    None
                }
            })
            .collect();
        runtime.call_function(method, &wasm_params)
    }

    pub async fn init_key_rotation(node: Arc<Mutex<Self>>) {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Check every 5 minutes
        loop {
            interval.tick().await;
            match node.lock().await.rotate_keys() {
                Ok(_) => info!("Key rotation check completed"),
                Err(e) => error!("Key rotation failed: {}", e),
            }
        }
    }

    pub async fn start_listening_shared(node: Arc<Mutex<Self>>) -> Result<()> {
        let socket = node.lock().await.socket.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(ZhtpPacket, SocketAddr)>(32);
        let packet_tx = tx.clone();
        let node_clone = node.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, src)) => {
                        if let Ok(packet) = bincode::deserialize(&buf[..size]) {
                            if packet_tx.send((packet, src)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Socket receive error: {}", e);
                        break;
                    }
                }
            }
        });

        while let Some((packet, src)) = rx.recv().await {
            let mut node = node_clone.lock().await;
            if let Err(e) = node.process_packet(packet).await {
                error!("Failed to process packet from {}: {}", src, e);
            }
        }

        Ok(())
    }
}

// Public re-exports for easy access
pub use dao::{ZhtpDao, GovernanceProposal, UbiSystem, ZkIdentity};
pub use dapp_launchpad::{DAppLaunchpad, DeployedDApp, TokenInfo, DAppStore};
pub use monitoring::{ZhtpMonitor, SystemMetrics};
pub use economics::ZhtpEconomics;
pub use p2p_network::{ZhtpP2PNetwork, ZhtpPeer, NetworkStats};
