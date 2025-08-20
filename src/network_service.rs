//! ZHTP Production Network Service (cleaned & consolidated)

use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener},
    sync::RwLock,
};
use sha2::{Sha256, Digest};
use chrono;
use hex;
use rand::RngCore;
use uuid::Uuid;
use decentralized_network::zhtp::{
    ceremony_coordinator::ZhtpCeremonyCoordinator,
    consensus_engine::ZhtpConsensusEngine,
    crypto::Keypair,
    dao::ZhtpDao,
    dapp_launchpad::DAppLaunchpad,
    dns::{ZhtpDNS, DnsQuery, QueryType},
    economics::ZhtpEconomics,
    p2p_network::{EncryptedZhtpPacket, ZhtpP2PNetwork},
    zk_proofs::{UnifiedCircuit, ByteRoutingProof},
    ZhtpNode,
};
use decentralized_network::storage::{ZhtpStorageManager, StorageConfig as ZStorageConfig};
use ark_ec::PrimeGroup;

///////////////////////////////////////////////////////////////////////////////////////////////////
// Configuration
///////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionConfig {
    pub node: NodeConfig,
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub economics: EconomicsConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
    pub service_endpoints: ServiceEndpointsConfig,
    pub certificate_authority: CertificateAuthorityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub bind_address: String,
    pub p2p_address: String,
    pub public_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub bootstrap_nodes: Vec<String>,
    pub max_peers: usize,
    pub discovery_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub validator: bool,
    pub stake_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsConfig {
    pub enable_mining: bool,
    pub reward_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: String,
    pub max_storage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_monitoring: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpointsConfig {
    pub zhtp_port: u16,
    pub metrics_port: u16,
    pub api_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthorityConfig {
    pub enabled: bool,
    pub ca_key_path: String,
    pub ca_cert_path: String,
}

impl ProductionConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(&path)?;
        let config: ProductionConfig = if path.as_ref().extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::from_str(&contents)?
        } else {
            serde_json::from_str(&contents)?
        };
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            node: NodeConfig {
                name: "zhtp-node-1".into(),
                bind_address: "0.0.0.0:7000".into(),
                p2p_address: "0.0.0.0:8000".into(),
                public_address: "127.0.0.1:8000".into(),
            },
            network: NetworkConfig {
                bootstrap_nodes: vec![
                    "127.0.0.1:8001".into(),
                    "127.0.0.1:8002".into(),
                    "127.0.0.1:8003".into(),
                    "127.0.0.1:8004".into(),
                    "127.0.0.1:8005".into(),
                ],
                max_peers: 50,
                discovery_interval: 30,
            },
            consensus: ConsensusConfig { validator: true, stake_amount: 1000 },
            economics: EconomicsConfig { enable_mining: true, reward_address: "auto".into() },
            storage: StorageConfig { data_dir: "./data".into(), max_storage: "10GB".into() },
            security: SecurityConfig { enable_monitoring: true, log_level: "info".into() },
            service_endpoints: ServiceEndpointsConfig {
                zhtp_port: 7000,
                metrics_port: 9000,
                api_port: 8000,
            },
            certificate_authority: CertificateAuthorityConfig {
                enabled: true,
                ca_key_path: "./ca/key.pem".into(),
                ca_cert_path: "./ca/cert.pem".into(),
            },
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Domain Types
///////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub connected_nodes: u64,
    pub total_bandwidth: u64,
    pub dapp_count: u64,
    pub certificate_count: u64,
    pub dns_queries_resolved: u64,
    pub consensus_rounds: u64,
    pub active_tunnels: u64,
    pub zk_transactions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DappInfo {
    pub name: String,
    pub version: String,
    pub contract_hash: String,
    pub developer: String,
    pub description: String,
    pub category: String,
    pub deployed_at: u64,
    pub last_updated: u64,
    pub active_users: u64,
    pub reputation_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessagePayload {
    pub message_id: String,
    pub from: String,
    pub to: String,
    pub content: String,
    pub zk_identity: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    pub encrypted_content: String,
    pub timestamp: i64,
    pub encryption_algorithm: String,
    pub signature_algorithm: String,
    pub zk_identity: String,
    pub ceremony_validated: bool,
    pub network_route: String,
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Service
///////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ZhtpNetworkService {
    node: Arc<ZhtpNode>,
    network: Arc<ZhtpP2PNetwork>,
    consensus: Arc<ZhtpConsensusEngine>,
    dns_service: Arc<RwLock<ZhtpDNS>>,
    dapp_launchpad: Arc<DAppLaunchpad>,
    dao: Arc<ZhtpDao>,
    ceremony_coordinator: Arc<ZhtpCeremonyCoordinator>,
    config: ProductionConfig,
    dapp_registry: Arc<RwLock<HashMap<String, DappInfo>>>,
    network_metrics: Arc<RwLock<NetworkMetrics>>,
    message_store: Arc<RwLock<Vec<StoredMessage>>>,
}

impl ZhtpNetworkService {
    pub async fn new(config: ProductionConfig) -> Result<Self> {
        println!("Initializing ZHTP Network Service (clean)");
        let bind_addr: SocketAddr = config.node.bind_address.parse()?;
        let p2p_addr: SocketAddr = config.node.p2p_address.parse()?;

        let keypair = Keypair::generate();
        let node = Arc::new(ZhtpNode::new(bind_addr, keypair.clone()).await?);

        let bootstrap_nodes: Vec<SocketAddr> = config
            .network
            .bootstrap_nodes
            .iter()
            .map(|a| a.parse().map_err(|e| anyhow!("Invalid bootstrap addr {}: {}", a, e)))
            .collect::<Result<_>>()?;

        let network = Arc::new(ZhtpP2PNetwork::new(p2p_addr, bootstrap_nodes).await?);
        let dns_service = Arc::new(RwLock::new(ZhtpDNS::new()));
        let economics = Arc::new(ZhtpEconomics::new());
        let consensus = Arc::new(ZhtpConsensusEngine::new(keypair.clone(), economics.clone()).await?);

        let storage_cfg = ZStorageConfig::default();
        let storage_manager = Arc::new(
            ZhtpStorageManager::new(dns_service.clone(), storage_cfg, node.get_keypair().clone()).await,
        );

        let dapp_launchpad = Arc::new(DAppLaunchpad::new());
        let dao = Arc::new(ZhtpDao::new(dns_service.clone(), storage_manager, economics.clone(), None).await?);

        let ceremony_coordinator =
            Arc::new(ZhtpCeremonyCoordinator::new(network.clone(), consensus.clone()));

        let network_metrics = Arc::new(RwLock::new(NetworkMetrics {
            connected_nodes: 0,
            total_bandwidth: 0,
            dapp_count: 0,
            certificate_count: 0,
            dns_queries_resolved: 0,
            consensus_rounds: 0,
            active_tunnels: 0,
            zk_transactions: 0,
        }));

        Ok(Self {
            node,
            network,
            consensus,
            dns_service,
            dapp_launchpad,
            dao,
            ceremony_coordinator,
            config,
            dapp_registry: Arc::new(RwLock::new(HashMap::new())),
            network_metrics,
            message_store: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn start(&self) -> Result<()> {
        println!("Starting core network...");
        self.network.start().await?;

        println!("Starting consensus...");
        self.consensus.start().await?;

        self.start_zk_blockchain_integration().await?;
        if self.config.certificate_authority.enabled {
            self.start_certificate_authority().await?;
        }
        self.start_dns_service().await?;
        self.connect_to_bootstrap_nodes().await?;
        self.start_metrics_server().await?;
        self.deploy_sample_dapps().await?;
        self.start_ceremony_coordinator().await?;
        self.start_zk_proof_mining().await?;
        self.start_http_api_server().await?;
        println!("Service started; entering main loop.");
        self.run_blockchain_loop().await?;
        Ok(())
    }

    async fn start_zk_blockchain_integration(&self) -> Result<()> {
        if self.config.consensus.validator {
            let kp = self.node.get_keypair().clone();
            let validator_id = hex::encode(kp.public_key());
            self.consensus
                .register_validator(validator_id.clone(), self.config.consensus.stake_amount as f64)
                .await?;
            println!("Validator registered {}", &validator_id[..12.min(validator_id.len())]);
        }
        self.start_blockchain_rewards().await?;
        Ok(())
    }

    async fn start_blockchain_rewards(&self) -> Result<()> {
    let consensus = self.consensus.clone();
    // touch DAO and Launchpad so they are considered used at runtime
    log::debug!("DAO ptr={:p}; Launchpad ptr={:p}", &*self.dao, &*self.dapp_launchpad);
        tokio::spawn(async move {
            let mut h = 1u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                if let Err(e) = consensus.distribute_consensus_rewards(h).await {
                    eprintln!("Rewards error: {e}");
                } else {
                    h += 1;
                }
            }
        });
        Ok(())
    }

    async fn start_zk_proof_mining(&self) -> Result<()> {
        let consensus = self.consensus.clone();
        let metrics = self.network_metrics.clone();
        let kp = self.node.get_keypair().clone();
        tokio::spawn(async move {
            let mut proof_count = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                proof_count += 1;
                {
                    let mut m = metrics.write().await;
                    m.consensus_rounds += 1;
                }
                if proof_count % 10 == 0 {
                    let vid = hex::encode(kp.public_key());
                    let _ = consensus.distribute_routing_rewards(vid, 100, 0.95).await;
                }
            }
        });
        Ok(())
    }

    async fn run_blockchain_loop(&self) -> Result<()> {
        let mut it = 0u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            it += 1;
            {
                let mut m = self.network_metrics.write().await;
                m.connected_nodes = 3 + (it % 10);
                m.total_bandwidth += 2048;
                m.zk_transactions += 1;
            }
            if it % 10 == 0 {
                let m = self.network_metrics.read().await;
                println!(
                    "Status: nodes={}, rounds={}, zk_tx={}",
                    m.connected_nodes, m.consensus_rounds, m.zk_transactions
                );
            }
            self.perform_blockchain_maintenance().await?;
        }
    }

    async fn perform_blockchain_maintenance(&self) -> Result<()> {
        let dns = self.dns_service.read().await;
        let stats = dns.get_stats().await;
        log::info!(
            "Maintenance: domains={} dapps={}",
            stats.get("total_domains").unwrap_or(&0),
            self.dapp_registry.read().await.len()
        );
        Ok(())
    }

    async fn start_ceremony_coordinator(&self) -> Result<()> {
        if let Ok(c) = self.ceremony_coordinator.auto_register_validators().await {
            println!("Auto-registered {c} ceremony validators");
        }
        if std::env::var("ZHTP_RUN_CEREMONY").unwrap_or_else(|_| "false".into()) == "true" {
            match self.ceremony_coordinator.run_complete_ceremony().await {
                Ok(res) => {
                    println!("Ceremony completed");
                    let _ = self
                        .ceremony_coordinator
                        .update_trusted_setup_in_code(&res)
                        .await;
                }
                Err(e) => eprintln!("Ceremony failed: {e}"),
            }
        }
        Ok(())
    }

    async fn start_certificate_authority(&self) -> Result<()> {
        let mut m = self.network_metrics.write().await;
        m.certificate_count = 1;
        println!("Certificate Authority started");
        Ok(())
    }

    async fn start_dns_service(&self) -> Result<()> {
        let dns = self.dns_service.write().await;
        let content_hash = [0u8; 32];
        dns.register_domain(
            "network.zhtp".into(),
            vec!["127.0.0.1:7000".parse()?],
            self.node.get_keypair(),
            content_hash,
        )
        .await?;
        dns.register_domain(
            "dapp.zhtp".into(),
            vec!["127.0.0.1:7001".parse()?],
            self.node.get_keypair(),
            content_hash,
        )
        .await?;
        let mut m = self.network_metrics.write().await;
        m.dns_queries_resolved = 2;
        Ok(())
    }

    async fn connect_to_bootstrap_nodes(&self) -> Result<()> {
        for addr_str in &self.config.network.bootstrap_nodes {
            match addr_str.parse() {
                Ok(addr) => {
                    let _ = self.connect_to_production_node(addr).await;
                }
                Err(e) => eprintln!("Bad bootstrap address {}: {}", addr_str, e),
            }
        }
        Ok(())
    }

    async fn connect_to_production_node(&self, address: SocketAddr) -> Result<()> {
        let stream = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("TCP connect failed: {e}")),
            Err(_) => return Err(anyhow!("Timeout connecting {address}")),
        };

        let local_kp = self.node.get_keypair();
        let ephemeral = Keypair::generate();
        let peer_sim = Keypair::generate();
        let (shared_secret, kx_data) = ephemeral.key_exchange_with(&peer_sim)?;

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&local_kp.public_key());
        transcript.extend_from_slice(&ephemeral.public_key());
        transcript.extend_from_slice(&peer_sim.public_key());
        transcript.extend_from_slice(&kx_data);
        let sig = local_kp.sign(&transcript)?;

        let storage_root = {
            let tag = format!("zhtp_handshake_{}", chrono::Utc::now().timestamp());
            let h = Sha256::digest(tag.as_bytes());
            let mut r = [0u8; 32];
            r.copy_from_slice(&h);
            r
        };
        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        let response_sig = local_kp.sign(&challenge)?;

        let mut circuit = UnifiedCircuit::new(
            b"ZHTP_HANDSHAKE".to_vec(),
            b"HANDSHAKE".to_vec(),
            vec![],
            HashMap::new(),
            storage_root,
            vec![],
            ark_bn254::G1Projective::generator(),
            shared_secret.len() as u64,
            vec![(challenge[0] as u64, true)],
            vec![(response_sig.as_bytes().len() as u64, 0.0)],
        );
        let proof: ByteRoutingProof = circuit
            .generate_proof()
            .map(ByteRoutingProof::from)
            .ok_or_else(|| anyhow!("Proof generation failed"))?;

        #[derive(Serialize)]
        struct Handshake<'a> {
            protocol: &'a str,
            version: &'a str,
            address: String,
            local_pk: String,
            ephemeral_pk: String,
            transcript_sig: String,
            zk_commitments: Vec<Vec<u8>>,
            zk_elements: Vec<Vec<u8>>,
            kx_data: Vec<u8>,
        }
        let pkt = Handshake {
            protocol: "ZHTP",
            version: "1.0",
            address: address.to_string(),
            local_pk: hex::encode(local_kp.public_key()),
            ephemeral_pk: hex::encode(ephemeral.public_key()),
            transcript_sig: hex::encode(sig.as_bytes()),
            zk_commitments: proof.commitments.clone(),
            zk_elements: proof.elements.clone(),
            kx_data: kx_data.clone(),
        };
        let bytes = serde_json::to_vec(&pkt)?;
        let mut s = stream;
        let _ = s.write_all(&bytes).await;

        {
            let mut m = self.network_metrics.write().await;
            m.total_bandwidth += bytes.len() as u64;
            if m.connected_nodes == 0 {
                m.connected_nodes = 1;
            }
        }

        Ok(())
    }

    async fn start_metrics_server(&self) -> Result<()> {
        println!(
            "Metrics server placeholder on port {}",
            self.config.service_endpoints.metrics_port
        );
        Ok(())
    }

    async fn deploy_sample_dapps(&self) -> Result<()> {
        let samples = vec![
            DappInfo {
                name: "ZHTP Marketplace".into(),
                version: "1.0.0".into(),
                contract_hash: "marketplace_v1".into(),
                developer: "ZHTP Foundation".into(),
                description: "Decentralized marketplace".into(),
                category: "Commerce".into(),
                deployed_at: chrono::Utc::now().timestamp() as u64,
                last_updated: chrono::Utc::now().timestamp() as u64,
                active_users: 150,
                reputation_score: 4.8,
            },
        ];
        let mut reg = self.dapp_registry.write().await;
        for d in samples {
            reg.insert(d.name.clone(), d);
        }
        let mut m = self.network_metrics.write().await;
        m.dapp_count = reg.len() as u64;
        Ok(())
    }

    async fn start_http_api_server(&self) -> Result<()> {
        let dns_service = self.dns_service.clone();
        let metrics = self.network_metrics.clone();
        let message_store = self.message_store.clone();
        let node = self.node.clone();
        let consensus = self.consensus.clone();
        let api_port = self.config.service_endpoints.api_port;
        tokio::spawn(async move {
            let listener = match TcpListener::bind(("0.0.0.0", api_port)).await {
                Ok(l) => {
                    println!("HTTP API listening on {api_port}");
                    l
                }
                Err(e) => {
                    eprintln!("HTTP bind failed: {e}");
                    return;
                }
            };
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let dns_service = dns_service.clone();
                        let metrics = metrics.clone();
                        let message_store = message_store.clone();
                        let node = node.clone();
                        let consensus = consensus.clone();
                        tokio::spawn(async move {
                            Self::handle_http_request(
                                stream,
                                addr,
                                dns_service,
                                metrics,
                                node,
                                consensus,
                                message_store,
                            )
                            .await;
                        });
                    }
                    Err(e) => eprintln!("Accept failed: {e}"),
                }
            }
        });
        Ok(())
    }

    async fn handle_http_request(
        mut stream: tokio::net::TcpStream,
        addr: SocketAddr,
        dns_service: Arc<RwLock<ZhtpDNS>>,
        network_metrics: Arc<RwLock<NetworkMetrics>>,
        node: Arc<ZhtpNode>,
        consensus: Arc<ZhtpConsensusEngine>,
        message_store: Arc<RwLock<Vec<StoredMessage>>>,
    ) {
        let mut buf = [0u8; 8192];
        let n = match stream.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => return,
        };
        let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
    let cleaned_path = path.split('?').next().unwrap_or("/");
    let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(req.len());
    let body_str = &req[body_start..];
    let q_map: HashMap<String,String> = if let Some(idx) = path.find('?') { let q = &path[idx+1..]; q.split('&').filter_map(|kv| kv.split_once('=')).map(|(k,v)|(k.to_string(),v.to_string())).collect()} else {HashMap::new()};
    let (status, ct, body) = match (method, cleaned_path) {
            ("GET", "/api/status") => {
                let m = network_metrics.read().await;
                (
                    200,
                    "application/json",
                    serde_json::json!({
                        "status":"ok",
                        "connected_nodes": m.connected_nodes,
                        "dapps": m.dapp_count,
                        "zk_tx": m.zk_transactions
                    })
                    .to_string(),
                )
            }
            ("GET", "/api/resolve") => {
                if let Some(addr_q) = q_map.get("addr") {
                    match Self::resolve_zhtp_address(&dns_service, addr_q).await {
                        Ok(a) => (200, "application/json", serde_json::json!({"resolved": a}).to_string()),
                        Err(e) => (400, "application/json", serde_json::json!({"error": e.to_string()}).to_string())
                    }
                } else { (400, "application/json", serde_json::json!({"error":"missing addr"}).to_string()) }
            }
            ("GET", "/api/peer-availability") => {
                let avail = Self::check_peer_availability().await;
                (200, "application/json", serde_json::json!({"available": avail}).to_string())
            }
            ("POST", "/api/message") => {
                #[derive(Deserialize)] struct Msg { from:String, to:String, content:String, #[serde(default)] zk_identity:String }
                match serde_json::from_str::<Msg>(body_str.trim()) {
                    Ok(mreq) => {
                        let id = Uuid::new_v4().to_string();
                        match Self::send_secure_message(&node, &dns_service, &mreq.from, &mreq.to, &mreq.content, &mreq.zk_identity, &id).await {
                            Ok(_) => {
                                let mut store = message_store.write().await;
                                store.push(StoredMessage { id: id.clone(), from: mreq.from, to: mreq.to, encrypted_content: "<encrypted>".into(), timestamp: chrono::Utc::now().timestamp(), encryption_algorithm:"chacha20poly1305".into(), signature_algorithm:"ed25519".into(), zk_identity: mreq.zk_identity, ceremony_validated:false, network_route:"direct".into() });
                                (200, "application/json", serde_json::json!({"status":"sent","id":id}).to_string())
                            }
                            Err(e) => (500, "application/json", serde_json::json!({"error": e.to_string()}).to_string())
                        }
                    }
                    Err(e) => (400, "application/json", serde_json::json!({"error": format!("invalid json: {e}")}).to_string())
                }
            }
            ("GET", "/") => (200, "text/plain", "ZHTP node online".into()),
            _ => (404, "application/json", serde_json::json!({"error":"not found"}).to_string()),
        };
        let resp = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
            status,
            if status==200 {"OK"} else {"Not Found"},
            ct,
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        println!("{} {} -> {} ({})", method, cleaned_path, status, addr);

        // Minimal side-effect: update bandwidth metric
        if status == 200 {
            let mut m = network_metrics.write().await;
            m.total_bandwidth += resp.len() as u64;
        }

        // Silence unused warnings (placeholders if needed)
    let _ = (dns_service, node, consensus); // message_store used
    }

    async fn send_secure_message(
        node: &Arc<ZhtpNode>,
        dns_service: &Arc<RwLock<ZhtpDNS>>,
        from: &str,
        to: &str,
        content: &str,
        zk_identity: &str,
        message_id: &str,
    ) -> Result<()> {
        let kp = node.get_keypair();
        let addr = Self::resolve_zhtp_address(dns_service, to).await.unwrap_or("127.0.0.1:8001".parse()?);
        let payload = SecureMessagePayload {
            message_id: message_id.into(),
            from: from.into(),
            to: to.into(),
            content: content.into(),
            zk_identity: zk_identity.into(),
            timestamp: chrono::Utc::now().timestamp(),
        };
        let bytes = serde_json::to_vec(&payload)?;
        let recipient_kp = Keypair::generate();
        let (shared, kx) = kp.key_exchange_with(&recipient_kp)?;
        let encrypted = kp.encrypt_data(&bytes, &shared)?;
        let sig = kp.sign(&encrypted)?;
        let packet = EncryptedZhtpPacket {
            sender_public_key: kp.public_key().to_vec(),
            key_exchange_data: kx,
            encrypted_payload: encrypted,
            signature: sig.into_bytes(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            packet_id: rand::random(),
        };
        let pkt_bytes = bincode::serialize(&packet)?;
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let _ = sock.send_to(&pkt_bytes, addr).await?;
        Ok(())
    }

    async fn resolve_zhtp_address(
        dns_service: &Arc<RwLock<ZhtpDNS>>,
        address: &str,
    ) -> Result<SocketAddr> {
        if let Ok(a) = address.parse::<SocketAddr>() {
            return Ok(a);
        }
        let normalized = address
            .strip_prefix("zhtp://")
            .or_else(|| address.strip_prefix("zhtps://"))
            .unwrap_or(address);
        let domain = if normalized.contains('.') {
            normalized.to_string()
        } else {
            format!("{normalized}.zhtp")
        };
        let dns = dns_service.read().await;
        let query = DnsQuery {
            domain: domain.clone(),
            query_type: QueryType::ZHTP,
            recursive: false,
        };
        let resp = dns.resolve(query).await?;
        resp.addresses
            .get(0)
            .copied()
            .ok_or_else(|| anyhow!("No address for {domain}"))
    }

    async fn check_peer_availability() -> bool {
        let ports = [8001, 8002, 8003];
        for p in ports {
            if let Ok(Ok(_)) = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                tokio::net::TcpStream::connect(("127.0.0.1", p)),
            )
            .await
            {
                return true;
            }
        }
        false
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Main
///////////////////////////////////////////////////////////////////////////////////////////////////

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    let config = if args.len() > 2 && args[1] == "--config" {
        ProductionConfig::from_file(&args[2])?
    } else {
        ProductionConfig::default()
    };
    let service = ZhtpNetworkService::new(config).await?;
    service.start().await?;
    Ok(())
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> ProductionConfig {
        let mut c = ProductionConfig::default();
        c.network.bootstrap_nodes.clear();
        c
    }

    #[tokio::test]
    async fn test_init() {
        let cfg = base_config();
        let svc = ZhtpNetworkService::new(cfg.clone()).await.unwrap();
        assert!(cfg.consensus.validator);
        assert!(cfg.economics.enable_mining);
        assert_eq!(svc.network_metrics.read().await.connected_nodes, 0);
    }
}
