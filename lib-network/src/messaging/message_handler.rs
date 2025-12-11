//! Mesh Message Handler Implementation
//! 
//! Central message routing and handling for ZHTP mesh protocol

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use lib_crypto::PublicKey;

use crate::types::mesh_message::ZhtpMeshMessage;
use crate::protocols::NetworkProtocol;
use crate::mesh::connection::MeshConnection;
use crate::identity::unified_peer::UnifiedPeerId;

use crate::relays::LongRangeRelay;

/// Central mesh message handler
///
/// **MIGRATION (Ticket #149):** Now uses unified PeerRegistry instead of separate mesh_connections
#[derive(Clone)]
pub struct MeshMessageHandler {
    /// Unified peer registry (Ticket #149: replaces mesh_connections)
    pub peer_registry: crate::peer_registry::SharedPeerRegistry,
    /// Long-range relays
    pub long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
    /// Revenue pools
    pub revenue_pools: Arc<RwLock<HashMap<String, u64>>>,
    /// Message router for sending responses (Phase 2)
    pub message_router: Option<Arc<RwLock<crate::routing::message_routing::MeshMessageRouter>>>,
    /// Node ID for this handler (Phase 2)
    pub node_id: Option<PublicKey>,
    /// Blockchain sync manager for chunk reassembly (full nodes)
    pub sync_manager: Arc<crate::blockchain_sync::BlockchainSyncManager>,
    /// Edge node sync manager (optional - only for constrained devices)
    pub edge_sync_manager: Option<Arc<crate::blockchain_sync::EdgeNodeSyncManager>>,
    /// Blockchain provider for accessing chain data (injected by application layer)
    pub blockchain_provider: Arc<dyn crate::blockchain_sync::BlockchainProvider>,
}

impl MeshMessageHandler {
    /// Create a new MeshMessageHandler
    ///
    /// **MIGRATION (Ticket #149):** Now accepts SharedPeerRegistry instead of mesh_connections
    pub fn new(
        peer_registry: crate::peer_registry::SharedPeerRegistry,
        long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,
        revenue_pools: Arc<RwLock<HashMap<String, u64>>>,
    ) -> Self {
        Self {
            peer_registry,
            long_range_relays,
            revenue_pools,
            message_router: None,
            node_id: None,
            sync_manager: Arc::new(crate::blockchain_sync::BlockchainSyncManager::new()),
            edge_sync_manager: None, // Only set for edge nodes
            blockchain_provider: Arc::new(crate::blockchain_sync::NullBlockchainProvider),
        }
    }
    
    /// Set message router for sending responses (Phase 2)
    pub fn set_message_router(&mut self, router: Arc<RwLock<crate::routing::message_routing::MeshMessageRouter>>) {
        self.message_router = Some(router);
    }
    
    /// Set node ID (Phase 2)
    pub fn set_node_id(&mut self, node_id: PublicKey) {
        self.node_id = Some(node_id);
    }
    
    /// Set edge node sync manager (for constrained devices)
    pub fn set_edge_sync_manager(&mut self, edge_sync: Arc<crate::blockchain_sync::EdgeNodeSyncManager>) {
        self.edge_sync_manager = Some(edge_sync);
    }
    
    /// Set blockchain provider (injected by application layer)
    pub fn set_blockchain_provider(&mut self, provider: Arc<dyn crate::blockchain_sync::BlockchainProvider>) {
        self.blockchain_provider = provider;
    }
    
    /// Handle incoming mesh message
    pub async fn handle_mesh_message(&self, message: ZhtpMeshMessage, sender: PublicKey) -> Result<()> {
        match message {
            ZhtpMeshMessage::PeerDiscovery { capabilities, location, shared_resources } => {
                self.handle_peer_discovery(sender, capabilities, location, shared_resources).await?;
            },
            ZhtpMeshMessage::PeerAnnouncement { sender: announced_sender, timestamp, signature } => {
                // PeerAnnouncement is handled in unified_server.rs (UDP mesh layer)
                // This is just a pass-through or logging placeholder
                tracing::debug!("PeerAnnouncement from {:?} at timestamp {} (signature: {} bytes)", 
                    hex::encode(&announced_sender.key_id[0..8.min(announced_sender.key_id.len())]),
                    timestamp,
                    signature.len()
                );
            },
            ZhtpMeshMessage::ConnectivityRequest { requester, bandwidth_needed_kbps, duration_minutes, payment_tokens } => {
                self.handle_connectivity_request(requester, bandwidth_needed_kbps, duration_minutes, payment_tokens).await?;
            },
            ZhtpMeshMessage::ConnectivityResponse { provider, accepted, available_bandwidth_kbps, cost_tokens_per_mb, connection_details } => {
                self.handle_connectivity_response(provider, accepted, available_bandwidth_kbps, cost_tokens_per_mb, connection_details).await?;
            },
            ZhtpMeshMessage::LongRangeRoute { destination, relay_chain, payload, max_hops } => {
                self.handle_long_range_route(destination, relay_chain, payload, max_hops).await?;
            },
            ZhtpMeshMessage::UbiDistribution { recipient, amount_tokens, distribution_round, proof } => {
                self.handle_ubi_distribution(recipient, amount_tokens, distribution_round, proof).await?;
            },
            ZhtpMeshMessage::HealthReport { reporter, network_quality, available_bandwidth, connected_peers, uptime_hours } => {
                self.handle_health_report(reporter, network_quality, available_bandwidth, connected_peers, uptime_hours).await?;
            },
            ZhtpMeshMessage::ZhtpRequest(request) => {
                let mut headers_map = HashMap::new();
                for (k, v) in &request.headers.custom {
                    headers_map.insert(k.clone(), v.clone());
                }
                if let Some(ct) = &request.headers.content_type { headers_map.insert("Content-Type".to_string(), ct.clone()); }
                
                self.handle_lib_request(sender, request.method.to_string(), request.uri, headers_map, request.body, request.timestamp).await?;
            },
            ZhtpMeshMessage::ZhtpResponse(response) => {
                let mut headers_map = HashMap::new();
                for (k, v) in &response.headers.custom {
                    headers_map.insert(k.clone(), v.clone());
                }
                let request_id = response.headers.custom.get("Request-ID")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                    
                self.handle_lib_response(request_id, response.status.code(), response.status_message, headers_map, response.body, response.timestamp).await?;
            },
            ZhtpMeshMessage::BlockchainRequest { requester, request_id, request_type } => {
                self.handle_blockchain_request(requester, request_id, request_type).await?;
            },
            ZhtpMeshMessage::BlockchainData { sender, request_id, chunk_index, total_chunks, data, complete_data_hash } => {
                self.handle_blockchain_data(&sender, request_id, chunk_index, total_chunks, data, complete_data_hash).await?;
            },
            ZhtpMeshMessage::NewBlock { block, sender, height, timestamp } => {
                self.handle_new_block(block, sender, height, timestamp).await?;
            },
            ZhtpMeshMessage::NewTransaction { transaction, sender, tx_hash, fee } => {
                self.handle_new_transaction(transaction, sender, tx_hash, fee).await?;
            },
            ZhtpMeshMessage::RouteProbe { probe_id, target } => {
                // TODO: Implement route probe handling
                tracing::info!("Received route probe {} for target {:?}", probe_id, target);
            },
            ZhtpMeshMessage::RouteResponse { probe_id, route_quality, latency_ms } => {
                // TODO: Implement route response handling
                tracing::info!("Received route response for probe {} with quality {} and latency {}ms", 
                    probe_id, route_quality, latency_ms);
            },
            ZhtpMeshMessage::BootstrapProofRequest { requester, request_id, current_height } => {
                self.handle_bootstrap_proof_request(requester, request_id, current_height).await?;
            },
            ZhtpMeshMessage::BootstrapProofResponse { request_id, proof_data, proof_height, headers } => {
                self.handle_bootstrap_proof_response(request_id, proof_data, proof_height, headers).await?;
            },
            ZhtpMeshMessage::HeadersRequest { requester, request_id, start_height, count } => {
                self.handle_headers_request(requester, request_id, start_height, count).await?;
            },
            ZhtpMeshMessage::HeadersResponse { request_id, headers, start_height } => {
                self.handle_headers_response(request_id, headers, start_height).await?;
            },
            ZhtpMeshMessage::DhtStore { requester, request_id, key, value, ttl, signature } => {
                self.handle_dht_store(requester, request_id, key, value, ttl, signature).await?;
            },
            ZhtpMeshMessage::DhtStoreAck { request_id, success, stored_count } => {
                self.handle_dht_store_ack(request_id, success, stored_count).await?;
            },
            ZhtpMeshMessage::DhtFindValue { requester, request_id, key, max_hops } => {
                self.handle_dht_find_value(requester, request_id, key, max_hops).await?;
            },
            ZhtpMeshMessage::DhtFindValueResponse { request_id, found, value, closer_nodes } => {
                self.handle_dht_find_value_response(request_id, found, value, closer_nodes).await?;
            },
            ZhtpMeshMessage::DhtFindNode { requester, request_id, target_id, max_hops } => {
                self.handle_dht_find_node(requester, request_id, target_id, max_hops).await?;
            },
            ZhtpMeshMessage::DhtFindNodeResponse { request_id, closer_nodes } => {
                self.handle_dht_find_node_response(request_id, closer_nodes).await?;
            },
            ZhtpMeshMessage::DhtPing { requester, request_id, timestamp } => {
                self.handle_dht_ping(requester, request_id, timestamp).await?;
            },
            ZhtpMeshMessage::DhtPong { request_id, timestamp } => {
                self.handle_dht_pong(request_id, timestamp).await?;
            },
        }
        Ok(())
    }
    
    /// Handle peer discovery message
    pub async fn handle_peer_discovery(
        &self, 
        peer: PublicKey, 
        capabilities: Vec<crate::types::mesh_capability::MeshCapability>, 
        _location: Option<crate::types::geographic::GeographicLocation>,
        shared_resources: crate::types::mesh_capability::SharedResources
    ) -> Result<()> {
        info!("Discovered peer {:?} with {} capabilities", 
              hex::encode(&peer.key_id[0..8]), capabilities.len());
        
        // Process peer capabilities for legitimate mesh services
        for capability in &capabilities {
            if let crate::types::mesh_capability::MeshCapability::MeshRelay { capacity_mbps } = capability {
                info!("Peer offers mesh relay service: {} Mbps capacity", capacity_mbps);
            }
        }
        
        // Establish mesh connection (Ticket #149: using peer_registry)
        // MIGRATION (Ticket #146): Convert PublicKey to UnifiedPeerId
        let unified_peer = UnifiedPeerId::from_public_key_legacy(peer.clone());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create PeerEntry from connection info using constructor
        let peer_entry = crate::peer_registry::PeerEntry::new(
            unified_peer.clone(),
            vec![crate::peer_registry::PeerEndpoint {
                address: String::new(), // Address not available in PeerDiscovery
                protocol: crate::protocols::NetworkProtocol::BluetoothLE,
                signal_strength: 0.8,
                latency_ms: 50,
            }],
            vec![crate::protocols::NetworkProtocol::BluetoothLE],
            crate::peer_registry::ConnectionMetrics {
                signal_strength: 0.8,
                bandwidth_capacity: shared_resources.relay_bandwidth_kbps as u64 * 1024,
                latency_ms: 50,
                stability_score: shared_resources.reliability_score,
                connected_at: now,
            },
            false, // authenticated
            true,  // quantum_secure
            None,  // next_hop
            1,     // hop_count
            0.8,   // route_quality
            crate::peer_registry::NodeCapabilities {
                protocols: vec![crate::protocols::NetworkProtocol::BluetoothLE],
                max_bandwidth: shared_resources.relay_bandwidth_kbps as u64 * 1024,
                available_bandwidth: shared_resources.relay_bandwidth_kbps as u64 * 1024,
                routing_capacity: 100,
                energy_level: None,
                availability_percent: 95.0,
            },
            None, // location
            shared_resources.reliability_score,
            None, // dht_info
            crate::peer_registry::DiscoveryMethod::MeshScan,
            now,  // first_seen
            now,  // last_seen
            crate::peer_registry::PeerTier::Tier3, // Standard participating nodes
            0.5,  // trust_score
        );
        
        let mut registry = self.peer_registry.write().await;
        registry.upsert(peer_entry)?;
        
        Ok(())
    }
    
    /// Handle connectivity request - legitimate P2P mesh routing
    async fn handle_connectivity_request(
        &self, 
        _requester: PublicKey, 
        bandwidth_needed_kbps: u32, 
        duration_minutes: u32, 
        _payment_tokens: u64
    ) -> Result<()> {
        info!("📞 P2P mesh routing request: {} kbps for {} minutes", 
              bandwidth_needed_kbps, duration_minutes);
        
        // ZHTP provides direct peer-to-peer mesh routing without 
        let relays = self.long_range_relays.read().await;
        if !relays.is_empty() {
            info!("Mesh relay capacity available for P2P routing");
            info!(" Sending connectivity acceptance via legitimate mesh routing");
        } else {
            warn!("No mesh relay nodes available for routing");
            info!(" Sending connectivity rejection - no relay capacity");
        }
        
        Ok(())
    }
    
    /// Handle connectivity response
    async fn handle_connectivity_response(
        &self, 
        provider: PublicKey, 
        accepted: bool, 
        available_bandwidth_kbps: u32, 
        cost_tokens_per_mb: u64, 
        connection_details: Option<crate::types::connection_details::ConnectionDetails>
    ) -> Result<()> {
        if accepted {
            info!("Connectivity accepted from provider {:?}: {} kbps at {} tokens/MB", 
                  hex::encode(&provider.key_id[0..8]), available_bandwidth_kbps, cost_tokens_per_mb);
            
            // TODO: Use connection_details to establish actual mesh connection
            if let Some(_details) = connection_details {
                info!(" Connection details received - TODO: establish connection");
            }
        } else {
            info!("Connectivity request denied by provider {:?}", hex::encode(&provider.key_id[0..8]));
        }
        Ok(())
    }
    
    /// Handle long-range routing - GLOBAL reach through multi-hop mesh!
    async fn handle_long_range_route(
        &self, 
        destination: PublicKey, 
        relay_chain: Vec<String>, 
        payload: Vec<u8>, 
        max_hops: u8
    ) -> Result<()> {
        info!("GLOBAL long-range route: {} bytes to destination {:?} via {} relays", 
              payload.len(), hex::encode(&destination.key_id[0..8]), relay_chain.len());
        
        // ZHTP supports unlimited global routing through mesh relays
        if max_hops > 0 {
            let relays = self.long_range_relays.read().await;
            let mut total_distance_km = 0.0;
            let mut routing_path = Vec::new();
            
            for relay_id in &relay_chain {
                if let Some(relay) = relays.get(relay_id) {
                    total_distance_km += relay.coverage_radius_km;
                    routing_path.push(format!("{} ({}km)", relay_id, relay.coverage_radius_km));
                    
                    match relay.relay_type {
                        crate::types::relay_type::LongRangeRelayType::Satellite => {
                            info!("🛰️ GLOBAL satellite relay: {} - WORLDWIDE coverage", relay_id);
                        }
                        crate::types::relay_type::LongRangeRelayType::LoRaWAN => {
                            info!("LoRa relay: {} - {}km regional coverage", relay_id, relay.coverage_radius_km);
                        }
                        crate::types::relay_type::LongRangeRelayType::WiFiRelay => {
                            info!("Internet bridge: {} - GLOBAL internet access", relay_id);
                        }
                        _ => {
                            info!("Long-range relay: {} - {}km coverage", relay_id, relay.coverage_radius_km);
                        }
                    }
                }
            }
            
            info!("TOTAL GLOBAL REACH: {:.0}km via path: {:?}", 
                  total_distance_km, routing_path);
            
            // With satellite + internet bridges, ZHTP reaches ANYWHERE on Earth!
            if total_distance_km > 10000.0 {
                info!(" INTERCONTINENTAL ZHTP routing active - Planet-wide mesh network!");
            }
        }
        
        Ok(())
    }
    
    /// Handle UBI distribution message
    pub async fn handle_ubi_distribution(
        &self,
        recipient: PublicKey,
        amount_tokens: u64,
        distribution_round: u64,
        proof: Vec<u8>
    ) -> Result<()> {
        info!("UBI distribution: {} tokens to recipient (round {})", 
              amount_tokens, distribution_round);
        
        // Verify ZK proof using lib-proofs
        if proof.is_empty() {
            warn!(" Empty ZK proof for UBI distribution - rejecting");
            return Err(anyhow::anyhow!("UBI distribution requires valid ZK proof"));
        }
        
        // Deserialize and verify the proof
        // The proof format depends on the UBI distribution circuit implementation
        let verification_result = match bincode::deserialize::<lib_proofs::ZkProof>(&proof) {
            Ok(zk_proof) => {
                // Use the recursive verifier for chain proofs (UBI is a chain operation)
                let verifier = lib_proofs::verifiers::RecursiveProofAggregator::new()?;
                
                // For UBI distribution, we need to verify:
                // 1. The recipient is eligible (identity proof)
                // 2. The amount matches the current round distribution
                // 3. The distribution round hasn't been claimed before (replay protection)
                
                // Note: The actual proof structure depends on the circuit implementation
                // For now, we perform basic verification
                match bincode::deserialize::<lib_proofs::ChainRecursiveProof>(&proof) {
                    Ok(chain_proof) => {
                        match verifier.verify_recursive_chain_proof(&chain_proof) {
                            Ok(result) => result,
                            Err(e) => {
                                warn!("ZK proof verification error: {}", e);
                                false
                            }
                        }
                    },
                    Err(_) => {
                        // Try identity proof verification as fallback
                        let identity_verifier = lib_proofs::verifiers::IdentityVerifier::new();
                        match bincode::deserialize::<lib_proofs::ZkIdentityProof>(&proof) {
                            Ok(identity_proof) => {
                                match identity_verifier.verify_identity(&identity_proof) {
                                    Ok(result) => result.is_valid(),
                                    Err(e) => {
                                        warn!("Identity proof verification error: {}", e);
                                        false
                                    }
                                }
                            },
                            Err(e) => {
                                warn!("Failed to deserialize proof: {}", e);
                                false
                            }
                        }
                    }
                }
            },
            Err(e) => {
                warn!("Failed to deserialize ZK proof: {}", e);
                false
            }
        };
        
        if !verification_result {
            warn!("Invalid ZK proof for UBI distribution - rejecting");
            return Err(anyhow::anyhow!("Invalid ZK proof for UBI distribution"));
        }
        
        info!(" ZK proof verified successfully for UBI distribution");
        
        // Validate distribution round to prevent replay attacks
        let mut pools = self.revenue_pools.write().await;
        let last_round_key = format!("ubi_last_round_{}", hex::encode(&recipient.key_id[0..8]));
        let last_round = pools.get(&last_round_key).unwrap_or(&0);
        
        if distribution_round <= *last_round {
            warn!("UBI distribution round {} already processed for recipient", distribution_round);
            return Err(anyhow::anyhow!("UBI distribution round already processed"));
        }
        
        // Update recipient's UBI balance and track distribution
        *pools.entry("ubi_total".to_string()).or_insert(0) += amount_tokens;
        *pools.entry(last_round_key).or_insert(0) = distribution_round;
        
        let recipient_balance_key = format!("ubi_balance_{}", hex::encode(&recipient.key_id[0..8]));
        *pools.entry(recipient_balance_key).or_insert(0) += amount_tokens;
        
        info!("UBI distribution completed: {} tokens distributed (round {})", 
              amount_tokens, distribution_round);
        
        Ok(())
    }
    
    /// Handle network health report
    pub async fn handle_health_report(
        &self,
        reporter: PublicKey,
        network_quality: f64,
        available_bandwidth: u64,
        connected_peers: u32,
        uptime_hours: u32
    ) -> Result<()> {
        info!("Health report: quality={:.2}, bandwidth={} MB/s, peers={}, uptime={}h",
              network_quality, available_bandwidth / 1_000_000, connected_peers, uptime_hours);

        // Update connection statistics (Ticket #149: using peer_registry)
        //
        // NOTE: TOCTOU race condition accepted here. The read-clone-drop-write pattern
        // means the peer could be removed between the read and write locks. This is
        // acceptable for health reports because:
        // 1. Health updates are best-effort (missing one update is not critical)
        // 2. upsert() will re-add the peer if it was removed, which is safe
        // 3. Using a single write lock for the entire operation would increase contention
        let registry = self.peer_registry.read().await;
        if let Some(mut peer_entry) = registry.find_by_public_key(&reporter).cloned() {
            peer_entry.connection_metrics.stability_score = network_quality;
            peer_entry.connection_metrics.bandwidth_capacity = available_bandwidth;
            drop(registry);
            let mut registry_write = self.peer_registry.write().await;
            registry_write.upsert(peer_entry)?;
        }

        Ok(())
    }
    
    /// Handle native ZHTP protocol request from browser/API clients (UPDATED - Phase 3)
    pub async fn handle_lib_request(
        &self,
        requester: PublicKey,
        method: String,
        uri: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timestamp: u64,
    ) -> Result<()> {
        info!("📥 Native ZHTP Request: {} {} from {:?}", method, uri, hex::encode(&requester.key_id[0..8]));
        
        // Validate timestamp (replay protection)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if now.abs_diff(timestamp) > 300 {  // 5 minute window
            warn!(" Request timestamp too old/future: {} vs {}", timestamp, now);
            return self.send_error_response(requester, 400, "Request timestamp invalid".to_string()).await;
        }
        
        info!(" Timestamp valid, headers: {}, body: {} bytes", headers.len(), body.len());
        
        // For Phase 3, we'll create a simplified ZHTP response
        // In production, this would forward to lib-protocols ZHTP server
        // For now, we'll handle basic requests directly
        
        let (status, status_message, response_body) = match method.as_str() {
            "GET" => {
                info!("Processing GET request for {}", uri);
                // Simulate content retrieval
                if uri == "/health" {
                    (200, "OK".to_string(), b"Mesh node healthy".to_vec())
                } else if uri.starts_with("/content/") {
                    (200, "OK".to_string(), format!("Content for {}", uri).into_bytes())
                } else {
                    (404, "Not Found".to_string(), b"Resource not found".to_vec())
                }
            }
            "POST" => {
                info!("Processing POST request for {}", uri);
                (200, "OK".to_string(), b"Data received".to_vec())
            }
            _ => {
                (405, "Method Not Allowed".to_string(), b"Method not supported".to_vec())
            }
        };
        
        // Generate request ID for tracking
        let request_id = self.generate_request_id().await;
        
        // Create response message
        let mut response = lib_protocols::types::ZhtpResponse::success(response_body, None);
        response.status = lib_protocols::types::ZhtpStatus::from_code(status).unwrap_or(lib_protocols::types::ZhtpStatus::InternalServerError);
        response.status_message = status_message.clone();
        
        // Add custom headers
        response.headers.custom.insert("X-Mesh-Node".to_string(), "ZHTP/1.0".to_string());
        response.headers.custom.insert("Request-ID".to_string(), request_id.to_string());
        response.headers.content_type = Some("text/plain".to_string());
        
        let response_message = ZhtpMeshMessage::ZhtpResponse(response);
        
        // Send response back to requester via mesh
        info!("📤 Sending response {} {} back to requester", status, status_message);
        self.send_response_to_requester(requester, response_message).await?;
        
        info!(" ZHTP Request processed: {} {}", method, uri);
        
        Ok(())
    }
    
    /// Send response back through mesh network (NEW - Phase 3)
    async fn send_response_to_requester(
        &self,
        requester: PublicKey,
        response: ZhtpMeshMessage,
    ) -> Result<()> {
        if let Some(router) = &self.message_router {
            if let Some(my_id) = &self.node_id {
                let router_guard = router.read().await;
                router_guard.route_message_with_forwarding(
                    requester.clone(),
                    response,
                    my_id.clone()
                ).await?;
                info!(" Response routed back to requester");
            } else {
                warn!(" Node ID not set, cannot send response");
            }
        } else {
            warn!(" Message router not available, cannot send response");
        }
        Ok(())
    }
    
    /// Send error response (NEW - Phase 3)
    async fn send_error_response(
        &self,
        requester: PublicKey,
        status: u16,
        message: String,
    ) -> Result<()> {
        let request_id = self.generate_request_id().await;
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/plain".to_string());
        
        let mut response = lib_protocols::types::ZhtpResponse::error(
            lib_protocols::types::ZhtpStatus::from_code(status).unwrap_or(lib_protocols::types::ZhtpStatus::InternalServerError),
            message.clone()
        );
        
        for (k, v) in headers {
            response.headers.custom.insert(k, v);
        }
        response.headers.custom.insert("Request-ID".to_string(), request_id.to_string());
        
        let error_message = ZhtpMeshMessage::ZhtpResponse(response);
        
        self.send_response_to_requester(requester, error_message).await
    }
    
    /// Generate unique request ID (NEW - Phase 3)
    async fn generate_request_id(&self) -> u64 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        
        // Combine timestamp with random bits for uniqueness
        timestamp ^ (rand::random::<u64>() >> 16)
    }
    
    /// Handle native ZHTP protocol response
    pub async fn handle_lib_response(
        &self,
        request_id: u64,
        status: u16,
        status_message: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        timestamp: u64,
    ) -> Result<()> {
        info!("ZHTP Response received: {} {} (request_id: {})", status, status_message, request_id);
        
        // TODO: Implement full ZHTP response handling
        // - Parse response headers
        // - Process response body
        // - Validate timestamp
        // - Match with pending request and fulfill promise
        info!(" Headers: {} present, Body: {} bytes, Timestamp: {}", 
              headers.len(), body.len(), timestamp);
        
        Ok(())
    }

    /// Handle blockchain request from peer (implements bootstrap sync)
    /// This allows new nodes to download blockchain data before creating their identity
    pub async fn handle_blockchain_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        request_type: crate::types::mesh_message::BlockchainRequestType,
    ) -> Result<()> {
        info!(" Blockchain request from peer {:?} (request_id: {}, type: {:?})", 
              hex::encode(&requester.key_id[0..8]), request_id, request_type);
        
        // Use the blockchain provider to get blockchain data
        match request_type {
            crate::types::mesh_message::BlockchainRequestType::FullChain => {
                info!("   Sending full blockchain to peer");
                
                // Get full blockchain data from provider
                match self.blockchain_provider.get_full_blockchain().await {
                    Ok(blockchain_data) => {
                        info!("   Retrieved blockchain data: {} bytes", blockchain_data.len());
                        
                        // Get protocol for chunking
                        let protocol = self.get_protocol_for_peer(&requester).await
                            .unwrap_or(NetworkProtocol::QUIC); // Default to QUIC
                        
                        // Chunk the data based on protocol
                        let chunks = self.chunk_blockchain_data(
                            self.node_id.clone().unwrap_or_else(|| PublicKey::new(vec![0; 32])),
                            request_id,
                            blockchain_data,
                            &protocol,
                        )?;
                        
                        info!("   Sending {} chunks to peer", chunks.len());
                        
                        // Send chunks via message router
                        if let Some(router) = &self.message_router {
                            if let Some(node_id) = &self.node_id {
                                for chunk in chunks {
                                    if let Err(e) = router.write().await.route_message(chunk, requester.clone(), node_id.clone()).await {
                                        warn!("Failed to send blockchain chunk: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get blockchain data: {}", e);
                    }
                }
            }
            crate::types::mesh_message::BlockchainRequestType::HeadersOnly { start_height, count } => {
                info!("   Sending headers from height {} (count: {})", start_height, count);
                
                // Get headers from provider (convert u32 to u64)
                match self.blockchain_provider.get_headers(start_height, count as u64).await {
                    Ok(headers) => {
                        info!("   Retrieved {} headers", headers.len());
                        
                        // Serialize headers to Vec<Vec<u8>>
                        let serialized_headers: Vec<Vec<u8>> = headers
                            .iter()
                            .map(|h| bincode::serialize(h).unwrap_or_default())
                            .collect();
                        
                        // Send headers response
                        let response = ZhtpMeshMessage::HeadersResponse {
                            request_id,
                            headers: serialized_headers,
                            start_height,
                        };
                        
                        if let Some(router) = &self.message_router {
                            if let Some(node_id) = &self.node_id {
                                if let Err(e) = router.write().await.route_message(response, requester, node_id.clone()).await {
                                    warn!("Failed to send headers response: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get headers: {}", e);
                    }
                }
            }
            // Other request types not yet implemented
            _ => {
                warn!("Unsupported blockchain request type: {:?}", request_type);
            }
        }
        
        Ok(())
    }
    
    /// Get protocol being used for peer (NEW - Phase 3)
    /// TODO (Ticket #149): Migrated to peer_registry
    async fn get_protocol_for_peer(&self, peer_id: &PublicKey) -> Result<NetworkProtocol> {
        let registry = self.peer_registry.read().await;
        // Find connection by PublicKey
        if let Some(peer_entry) = registry.find_by_public_key(peer_id) {
            if let Some(endpoint) = peer_entry.endpoints.first() {
                return Ok(endpoint.protocol.clone());
            }
        }
        Err(anyhow!("No connection to peer"))
    }
    
    /// Chunk blockchain data for protocol (NEW - Phase 3)
    fn chunk_blockchain_data(
        &self,
        sender: PublicKey,
        request_id: u64,
        data: Vec<u8>,
        protocol: &NetworkProtocol,
    ) -> Result<Vec<ZhtpMeshMessage>> {
        // Calculate chunk size based on protocol
        let chunk_size = match protocol {
            NetworkProtocol::BluetoothLE => 200,        // BLE 5.0 conservative
            NetworkProtocol::BluetoothClassic => 800,   // Bluetooth Classic larger MTU
            NetworkProtocol::WiFiDirect => 1400,        // WiFi Direct near-ethernet
            NetworkProtocol::LoRaWAN => 50,             // LoRa very small packets
            _ => 512,                                    // Default safe size
        };
        
        // Calculate complete data hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let complete_data_hash: [u8; 32] = hasher.finalize().into();
        
        // Split into chunks
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let total_chunks = chunks.len() as u32;
        
        info!(" Chunking {} bytes into {} chunks of ~{} bytes", data.len(), total_chunks, chunk_size);
        
        // Create ZhtpMeshMessage for each chunk
        let messages: Vec<ZhtpMeshMessage> = chunks.into_iter().enumerate().map(|(i, chunk)| {
            ZhtpMeshMessage::BlockchainData {
                sender: sender.clone(),
                request_id,
                chunk_index: i as u32,
                total_chunks,
                data: chunk.to_vec(),
                complete_data_hash,
            }
        }).collect();
        
        Ok(messages)
    }

    /// Handle incoming blockchain data chunks
    pub async fn handle_blockchain_data(
        &self,
        _sender: &PublicKey,
        request_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        complete_data_hash: [u8; 32],
    ) -> Result<()> {
        info!(" Blockchain data chunk {}/{} received ({} bytes, request_id: {})", 
              chunk_index + 1, total_chunks, data.len(), request_id);
        
        // Add chunk to sync manager for reassembly
        match self.sync_manager.add_chunk(request_id, chunk_index, total_chunks, data, complete_data_hash).await {
            Ok(Some(complete_data)) => {
                info!(" All blockchain chunks received and verified! Total: {} bytes", complete_data.len());
                info!("   Hash: {}", hex::encode(complete_data_hash));
                
                // TODO: Forward complete blockchain data to application layer for import
                // This requires lib-blockchain which would create a circular dependency
                // The unified_server handles this properly in handle_udp_mesh()
                info!(" Blockchain chunks reassembled successfully");
                info!("   Application layer should import this data via blockchain.evaluate_and_merge_chain()");
            }
            Ok(None) => {
                debug!("Chunk {}/{} buffered, waiting for more chunks", chunk_index + 1, total_chunks);
            }
            Err(e) => {
                warn!("Failed to process blockchain chunk: {}", e);
                return Err(e);
            }
        }
        
        Ok(())
    }
    
    /// Handle new block announcement (NEW - Phase 3)
    /// TODO: This requires lib-blockchain which would create a circular dependency
    pub async fn handle_new_block(
        &self,
        block: Vec<u8>,
        sender: PublicKey,
        height: u64,
        timestamp: u64,
    ) -> Result<()> {
        info!(" New block announcement: height {} from {:?} ({} bytes)", 
              height, hex::encode(&sender.key_id[0..4]), block.len());
        
        // TODO: Implement blockchain integration at application layer
        warn!(" Blockchain integration not yet implemented (circular dependency issue)");
        
        Ok(())
    }
    
    /// Handle new transaction announcement (NEW - Phase 3)
    /// TODO: This requires lib-blockchain which would create a circular dependency
    pub async fn handle_new_transaction(
        &self,
        transaction: Vec<u8>,
        sender: PublicKey,
        tx_hash: [u8; 32],
        fee: u64,
    ) -> Result<()> {
        info!(" New transaction from {:?}: hash={}, fee={}", 
              hex::encode(&sender.key_id[0..4]), 
              hex::encode(&tx_hash[0..8]),
              fee);
        
        // TODO: Implement blockchain integration at application layer
        warn!(" Blockchain integration not yet implemented (circular dependency issue)");
        
        Ok(())
    }

    /// Handle bootstrap proof request from edge node
    /// 
    /// This is called on a FULL VALIDATOR NODE when an edge node requests
    /// a chain bootstrap proof. The validator generates a ChainRecursiveProof
    /// that proves the entire blockchain state up to the current height.
    /// 
    /// Edge nodes are computationally constrained (BLE phones, IoT devices)
    /// and cannot generate proofs themselves - they only verify proofs.
    pub async fn handle_bootstrap_proof_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        current_height: u64,
    ) -> Result<()> {
        info!(" Bootstrap proof request from edge node {:?} at height {}", 
              hex::encode(&requester.key_id[0..4]), 
              current_height);
        
        // Check if blockchain is available
        if !self.blockchain_provider.is_available().await {
            warn!(" Blockchain not available - cannot generate bootstrap proof");
            return Err(anyhow!("Blockchain not available"));
        }
        
        // Get current blockchain height
        let chain_tip_height = self.blockchain_provider.get_current_height().await?;
        info!(" Current chain height: {}, edge node at: {}", chain_tip_height, current_height);
        
        // Get the recursive chain proof (cached or generated)
        let chain_proof = self.blockchain_provider.get_chain_proof(chain_tip_height).await?;
        info!(" Got chain proof for height {}", chain_proof.chain_tip_height);
        
        // Get recent headers for edge node (last 500 blocks or less)
        let headers_count = std::cmp::min(500, chain_tip_height.saturating_sub(current_height));
        let start_height = chain_tip_height.saturating_sub(headers_count) + 1;
        
        let headers = self.blockchain_provider.get_headers(start_height, headers_count).await?;
        info!(" Fetched {} headers starting from height {}", headers.len(), start_height);
        
        // Serialize headers
        let serialized_headers: Vec<Vec<u8>> = headers.iter()
            .map(|h| bincode::serialize(h))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("Failed to serialize headers: {}", e))?;
        
        // Serialize FULL ChainRecursiveProof (not just recursive_proof)
        // CRITICAL: Edge nodes expect the complete ChainRecursiveProof structure
        let proof_data = bincode::serialize(&chain_proof)
            .map_err(|e| anyhow!("Failed to serialize proof: {}", e))?;
        
        // Send response
        let response_message = ZhtpMeshMessage::BootstrapProofResponse {
            request_id,
            proof_data,
            proof_height: chain_proof.chain_tip_height,
            headers: serialized_headers,
        };
        
        // Send via message router if available
        if let Some(router) = &self.message_router {
            let router_lock = router.read().await;
            if let Some(sender_node_id) = &self.node_id {
                router_lock.route_message(response_message, requester, sender_node_id.clone()).await?;
                info!(" Bootstrap proof response sent to edge node");
            } else {
                warn!(" Node ID not set - cannot send response");
            }
        } else {
            warn!(" Message router not available - cannot send response");
        }
        
        Ok(())
    }

    /// Handle bootstrap proof response
    /// 
    /// This is called on an EDGE NODE when it receives a ChainRecursiveProof
    /// from a validator. The edge node performs lightweight verification
    /// (O(1) time regardless of chain length!) and then stores headers.
    /// 
    /// Edge nodes have limited computation/storage, so they:
    /// 1. Verify the recursive proof (fast!)
    /// 2. Store rolling window of headers (100-500 blocks)
    /// 3. Track UTXOs for their addresses
    pub async fn handle_bootstrap_proof_response(
        &self,
        request_id: u64,
        proof_data: Vec<u8>,
        proof_height: u64,
        headers: Vec<Vec<u8>>,
    ) -> Result<()> {
        info!(" Bootstrap proof response: {} headers at height {}", 
              headers.len(), 
              proof_height);
        
        // Check if we have an edge node sync manager
        let edge_sync = match &self.edge_sync_manager {
            Some(sync) => sync,
            None => {
                warn!(" Edge sync manager not configured - ignoring bootstrap proof");
                return Ok(());
            }
        };
        
        // Deserialize the chain proof
        use lib_proofs::{RecursiveProofAggregator, ChainRecursiveProof};
        let chain_proof: ChainRecursiveProof = bincode::deserialize(&proof_data)
            .map_err(|e| anyhow!("Failed to deserialize chain proof: {}", e))?;
        
        info!(" Chain proof: tip={}, genesis={}, txs={}", 
              chain_proof.chain_tip_height, 
              chain_proof.genesis_height,
              chain_proof.total_transaction_count);
        
        // Verify the recursive proof (O(1) verification!)
        let aggregator = RecursiveProofAggregator::new()?;
        let is_valid = aggregator.verify_recursive_chain_proof(&chain_proof)?;
        
        if !is_valid {
            return Err(anyhow!(" Invalid bootstrap proof from validator!"));
        }
        
        info!(" Bootstrap proof VALID! Chain proven up to height {}", chain_proof.chain_tip_height);
        
        // Deserialize headers
        let block_headers: Vec<lib_blockchain::block::BlockHeader> = headers.iter()
            .map(|h| bincode::deserialize(h))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("Failed to deserialize headers: {}", e))?;
        
        // Process headers through edge node sync manager
        edge_sync.process_bootstrap_proof(proof_data, proof_height, block_headers).await?;
        
        info!(" Edge node bootstrapped to height {} with {} headers", 
              proof_height, 
              headers.len());
        
        // Log storage usage
        let storage_bytes = edge_sync.estimated_storage_bytes().await;
        info!("💾 Edge node storage: ~{} KB", storage_bytes / 1024);
        
        Ok(())
    }

    /// Handle headers request from edge node
    /// 
    /// Edge nodes request specific block headers when they're close to the
    /// chain tip (<500 blocks behind) and don't need a full bootstrap proof.
    /// This is more efficient for incremental sync.
    pub async fn handle_headers_request(
        &self,
        requester: PublicKey,
        request_id: u64,
        start_height: u64,
        count: u32,
    ) -> Result<()> {
        info!(" Headers request from {:?}: start={}, count={}", 
              hex::encode(&requester.key_id[0..4]), 
              start_height, 
              count);
        
        // Check if blockchain is available
        if !self.blockchain_provider.is_available().await {
            warn!(" Blockchain not available - cannot fetch headers");
            return Err(anyhow!("Blockchain not available"));
        }
        
        // Limit count to prevent abuse (max 1000 headers per request)
        let safe_count = std::cmp::min(count as u64, 1000);
        
        // Fetch headers from blockchain
        let headers = self.blockchain_provider.get_headers(start_height, safe_count).await?;
        info!(" Fetched {} headers starting at height {}", headers.len(), start_height);
        
        // Serialize headers
        let serialized_headers: Vec<Vec<u8>> = headers.iter()
            .map(|h| bincode::serialize(h))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("Failed to serialize headers: {}", e))?;
        
        // Send response
        let response_message = ZhtpMeshMessage::HeadersResponse {
            request_id,
            headers: serialized_headers,
            start_height,
        };
        
        // Send via message router if available
        if let Some(router) = &self.message_router {
            let router_lock = router.read().await;
            if let Some(sender_node_id) = &self.node_id {
                router_lock.route_message(response_message, requester, sender_node_id.clone()).await?;
                info!("📤 Sent {} headers to edge node", headers.len());
            } else {
                warn!(" Node ID not set - cannot send response");
            }
        } else {
            warn!(" Message router not available - cannot send response");
        }
        
        Ok(())
    }

    /// Handle headers response
    /// 
    /// Edge node receives block headers from validator for incremental sync.
    /// Headers are stored in a rolling window (100-500 blocks) and used to:
    /// 1. Verify merkle proofs for transactions
    /// 2. Track UTXO states for owned addresses
    /// 3. Validate incoming payments instantly
    pub async fn handle_headers_response(
        &self,
        request_id: u64,
        headers: Vec<Vec<u8>>,
        start_height: u64,
    ) -> Result<()> {
        info!(" Headers response: {} headers from height {}", 
              headers.len(), 
              start_height);
        
        // Check if we have an edge node sync manager
        let edge_sync = match &self.edge_sync_manager {
            Some(sync) => sync,
            None => {
                warn!(" Edge sync manager not configured - ignoring headers");
                return Ok(());
            }
        };
        
        // Deserialize headers
        let block_headers: Vec<lib_blockchain::block::BlockHeader> = headers.iter()
            .map(|h| bincode::deserialize(h))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("Failed to deserialize headers: {}", e))?;
        
        // Process headers through edge node state
        edge_sync.process_headers(block_headers).await?;
        
        let current_height = edge_sync.current_height().await;
        info!(" Edge node synced {} headers, now at height {}", 
              headers.len(), 
              current_height);
        
        // Check if we need more headers (if blockchain provider is available)
        if self.blockchain_provider.is_available().await {
            if let Ok(network_height) = self.blockchain_provider.get_current_height().await {
                if network_height.saturating_sub(current_height) > 100 {
                    info!(" Still {} blocks behind, may need more headers", 
                          network_height - current_height);
                }
            }
        }
        
        Ok(())
    }

    // DHT message handlers
    // Note: These are protocol-level handlers. Actual DHT logic is in lib-storage.
    // The application layer (zhtp) should handle DHT operations through ZkDHTIntegration.
    
    async fn handle_dht_store(&self, requester: PublicKey, request_id: u64, key: Vec<u8>, value: Vec<u8>, ttl: u64, _signature: Vec<u8>) -> Result<()> {
        info!("DHT Store request from {:?}: key={} bytes, value={} bytes, ttl={}", 
              requester, key.len(), value.len(), ttl);
        
        // DHT storage operations should be implemented at the application layer
        // through ZkDHTIntegration. This handler just logs the request.
        // In a full implementation, this would forward to the local DHT node.
        
        warn!("DHT Store: Application layer should implement through ZkDHTIntegration");
        Ok(())
    }
    
    async fn handle_dht_store_ack(&self, request_id: u64, success: bool, stored_count: u32) -> Result<()> {
        info!("DHT Store ACK: request_id={}, success={}, stored_count={}", 
              request_id, success, stored_count);
        
        // This confirms a previous store request completed
        // Application layer should track pending requests
        Ok(())
    }
    
    async fn handle_dht_find_value(&self, requester: PublicKey, request_id: u64, key: Vec<u8>, max_hops: u8) -> Result<()> {
        info!("DHT Find Value from {:?}: key={} bytes, max_hops={}", 
              requester, key.len(), max_hops);
        
        // DHT lookup operations should be implemented at the application layer
        // This would query the local DHT storage and return the value or closer nodes
        
        warn!("DHT Find Value: Application layer should implement through ZkDHTIntegration");
        Ok(())
    }
    
    async fn handle_dht_find_value_response(&self, request_id: u64, found: bool, value: Option<Vec<u8>>, closer_nodes: Vec<PublicKey>) -> Result<()> {
        info!("DHT Find Value Response: request_id={}, found={}, value={} bytes, closer_nodes={}", 
              request_id, found, value.as_ref().map(|v| v.len()).unwrap_or(0), closer_nodes.len());
        
        // This is a response to a previous find_value request
        // Application layer should match this with the pending request
        Ok(())
    }
    
    async fn handle_dht_find_node(&self, requester: PublicKey, request_id: u64, target_id: Vec<u8>, max_hops: u8) -> Result<()> {
        info!("DHT Find Node from {:?}: target_id={} bytes, max_hops={}", 
              requester, target_id.len(), max_hops);
        
        // DHT node discovery operations should be implemented at the application layer
        // This would query the routing table for nodes closer to target_id
        
        warn!("DHT Find Node: Application layer should implement through ZkDHTIntegration");
        Ok(())
    }
    
    async fn handle_dht_find_node_response(&self, request_id: u64, closer_nodes: Vec<(PublicKey, String)>) -> Result<()> {
        info!("DHT Find Node Response: request_id={}, closer_nodes={}", 
              request_id, closer_nodes.len());
        
        // This is a response to a previous find_node request
        // Application layer should use these nodes to continue the search
        Ok(())
    }
    
    async fn handle_dht_ping(&self, requester: PublicKey, request_id: u64, timestamp: u64) -> Result<()> {
        debug!("DHT Ping from {:?}: request_id={}, timestamp={}", 
               requester, request_id, timestamp);
        
        // DHT ping is used to keep nodes alive in the routing table
        // Should respond with a pong message
        
        // In a full implementation, we would send a DhtPong response here
        Ok(())
    }
    
    async fn handle_dht_pong(&self, request_id: u64, timestamp: u64) -> Result<()> {
        debug!("DHT Pong: request_id={}, timestamp={}", request_id, timestamp);
        
        // This confirms the peer is still alive
        // Application layer should update the routing table's last_seen timestamp
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    #[tokio::test]
    async fn test_message_handler_creation() {
        // Ticket #149: Use peer_registry instead of mesh_connections
        let peer_registry = Arc::new(RwLock::new(crate::peer_registry::PeerRegistry::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(HashMap::new()));
        
        let handler = MeshMessageHandler::new(
            peer_registry.clone(),
            long_range_relays,
            revenue_pools,
        );
        
        // Handler should be created successfully
        assert_eq!(peer_registry.read().await.all_peers().count(), 0);
    }
    
    #[tokio::test]
    async fn test_health_report_handling() {
        // Ticket #149: Use peer_registry instead of mesh_connections
        let peer_registry = Arc::new(RwLock::new(crate::peer_registry::PeerRegistry::new()));
        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(HashMap::new()));
        
        let handler = MeshMessageHandler::new(
            peer_registry.clone(),
            long_range_relays,
            revenue_pools,
        );
        
        let reporter = PublicKey::new(vec![1, 2, 3]);
        // Ticket #146: Use UnifiedPeerId for HashMap key
        let unified_peer = crate::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(reporter.clone());

        // Add a peer entry first (Ticket #149)
        {
            let peer_entry = crate::peer_registry::PeerEntry::new(
                unified_peer.clone(),
                vec![crate::peer_registry::PeerEndpoint {
                    address: String::new(),
                    protocol: crate::protocols::NetworkProtocol::BluetoothLE,
                    signal_strength: 0.5,
                    latency_ms: 100,
                }],
                vec![crate::protocols::NetworkProtocol::BluetoothLE],
                crate::peer_registry::ConnectionMetrics {
                    signal_strength: 0.5,
                    bandwidth_capacity: 1000000,
                    latency_ms: 100,
                    stability_score: 0.5,
                    connected_at: 1000000,
                },
                false, // authenticated
                true,  // quantum_secure
                None,  // next_hop
                1,     // hop_count
                0.8,   // route_quality
                crate::peer_registry::NodeCapabilities {
                    protocols: vec![crate::protocols::NetworkProtocol::BluetoothLE],
                    max_bandwidth: 1000000,
                    available_bandwidth: 1000000,
                    routing_capacity: 100,
                    energy_level: None,
                    availability_percent: 95.0,
                },
                None, // location
                0.8,  // reliability_score
                None, // dht_info
                crate::peer_registry::DiscoveryMethod::MeshScan,
                1000000, // first_seen
                1000000, // last_seen
                crate::peer_registry::PeerTier::Tier3, // Standard participating nodes
                0.5,  // trust_score
            );
            let mut registry = peer_registry.write().await;
            let _ = registry.upsert(peer_entry);
        }

        // Handle health report
        let result = handler.handle_health_report(
            reporter.clone(),
            0.9,
            2000000,
            5,
            24,
        ).await;

        assert!(result.is_ok());

        // Check that connection was updated (Ticket #149: using peer_registry)
        let registry = peer_registry.read().await;
        let peer_entry = registry.find_by_public_key(&reporter).unwrap();
        assert_eq!(peer_entry.connection_metrics.stability_score, 0.9);
        assert_eq!(peer_entry.connection_metrics.bandwidth_capacity, 2000000);
    }
}
