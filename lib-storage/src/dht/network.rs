//! DHT Network Operations
//! 
//! Handles UDP-based communication for DHT operations including message sending,
//! receiving, and connection management.

use crate::types::dht_types::{DhtMessage, DhtNode, DhtMessageType, DhtQueryResponse};
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use serde::{Serialize, Deserialize};

/// Network envelope for DHT messages with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEnvelope {
    /// The actual DHT message
    pub message: DhtMessage,
    /// Network-level metadata
    pub metadata: NetworkMetadata,
}

/// Network metadata for message routing and reliability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetadata {
    /// Message sequence number
    pub sequence: u64,
    /// Network protocol version
    pub version: u8,
    /// Hop count for routing
    pub hop_count: u8,
    /// Message priority
    pub priority: MessagePriority,
}

/// Message priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// DHT network manager for UDP communication
#[derive(Debug)]
pub struct DhtNetwork {
    /// Local UDP socket
    socket: UdpSocket,
    /// Local node information
    local_node: DhtNode,
    /// Message timeout duration
    timeout_duration: Duration,
}

impl DhtNetwork {
    /// Create a new DHT network manager
    pub fn new(local_node: DhtNode, bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        
        Ok(Self {
            socket,
            local_node,
            timeout_duration: Duration::from_secs(5),
        })
    }
    
    /// Send a DHT message to a target node
    pub async fn send_message(&self, target: &DhtNode, message: DhtMessage) -> Result<()> {
        // Serialize message
        let message_bytes = bincode::serialize(&message)?;
        
        // Get target address
        let target_addr = target.addresses.first()
            .ok_or_else(|| anyhow!("No address available for target node"))?
            .parse::<SocketAddr>()?;
        
        // Send message
        self.socket.send_to(&message_bytes, target_addr)?;
        
        Ok(())
    }
    
    /// Receive and parse DHT message
    pub async fn receive_message(&self) -> Result<(DhtMessage, SocketAddr)> {
        let mut buffer = vec![0u8; 65536]; // 64KB buffer
        
        let (size, sender_addr) = timeout(self.timeout_duration, async {
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok(result) => return Ok(result),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        continue;
                    }
                    Err(e) => return Err(anyhow!("UDP receive error: {}", e)),
                }
            }
        }).await??;
        
        // Deserialize message
        let message: DhtMessage = bincode::deserialize(&buffer[..size])?;
        
        Ok((message, sender_addr))
    }
    
    /// Send PING message to check node liveness
    pub async fn ping(&self, target: &DhtNode) -> Result<bool> {
        let ping_message = DhtMessage {
            message_id: generate_message_id(),
            message_type: DhtMessageType::Ping,
            sender_id: self.local_node.id.clone(),
            target_id: Some(target.id.clone()),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: None, // In practice, this would be signed
        };
        
        self.send_message(target, ping_message).await?;
        
        // Wait for PONG response
        let start_time = SystemTime::now();
        while start_time.elapsed()? < self.timeout_duration {
            if let Ok((response, _)) = self.receive_message().await {
                if matches!(response.message_type, DhtMessageType::Pong) &&
                   response.sender_id == target.id {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }
    
    /// Send FIND_NODE query
    pub async fn find_node(&self, target: &DhtNode, query_id: NodeId) -> Result<Vec<DhtNode>> {
        let find_node_message = DhtMessage {
            message_id: generate_message_id(),
            message_type: DhtMessageType::FindNode,
            sender_id: self.local_node.id.clone(),
            target_id: Some(query_id),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: None,
        };
        
        self.send_message(target, find_node_message).await?;
        
        // Wait for response
        let start_time = SystemTime::now();
        while start_time.elapsed()? < self.timeout_duration {
            if let Ok((response, _)) = self.receive_message().await {
                if matches!(response.message_type, DhtMessageType::FindNodeResponse) &&
                   response.sender_id == target.id {
                    return Ok(response.nodes.unwrap_or_default());
                }
            }
        }
        
        Err(anyhow!("FIND_NODE query timeout"))
    }
    
    /// Send FIND_VALUE query
    pub async fn find_value(&self, target: &DhtNode, key: String) -> Result<DhtQueryResponse> {
        let find_value_message = DhtMessage {
            message_id: generate_message_id(),
            message_type: DhtMessageType::FindValue,
            sender_id: self.local_node.id.clone(),
            target_id: Some(target.id.clone()),
            key: Some(key.clone()),
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: None,
        };
        
        self.send_message(target, find_value_message).await?;
        
        // Wait for response
        let start_time = SystemTime::now();
        while start_time.elapsed()? < self.timeout_duration {
            if let Ok((response, _)) = self.receive_message().await {
                if matches!(response.message_type, DhtMessageType::FindValueResponse) &&
                   response.sender_id == target.id {
                    if let Some(value) = response.value {
                        return Ok(DhtQueryResponse::Value(value));
                    } else if let Some(nodes) = response.nodes {
                        return Ok(DhtQueryResponse::Nodes(nodes));
                    }
                }
            }
        }
        
        Err(anyhow!("FIND_VALUE query timeout"))
    }
    
    /// Send STORE message
    pub async fn store(&self, target: &DhtNode, key: String, value: Vec<u8>) -> Result<bool> {
        let store_message = DhtMessage {
            message_id: generate_message_id(),
            message_type: DhtMessageType::Store,
            sender_id: self.local_node.id.clone(),
            target_id: Some(target.id.clone()),
            key: Some(key),
            value: Some(value),
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: None,
        };
        
        self.send_message(target, store_message).await?;
        
        // Wait for acknowledgment
        let start_time = SystemTime::now();
        while start_time.elapsed()? < self.timeout_duration {
            if let Ok((response, _)) = self.receive_message().await {
                if matches!(response.message_type, DhtMessageType::StoreResponse) &&
                   response.sender_id == target.id {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }
    
    /// Handle incoming message and generate appropriate response
    pub async fn handle_incoming_message(&self, message: DhtMessage, _sender_addr: SocketAddr) -> Result<Option<DhtMessage>> {
        match message.message_type {
            DhtMessageType::Ping => {
                Ok(Some(DhtMessage {
                    message_id: generate_message_id(),
                    message_type: DhtMessageType::Pong,
                    sender_id: self.local_node.id.clone(),
                    target_id: Some(message.sender_id),
                    key: None,
                    value: None,
                    nodes: None,
                    contract_data: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    signature: None,
                }))
            }
            
            DhtMessageType::FindNode => {
                // In a implementation, this would query the routing table
                // For now, return empty node list
                Ok(Some(DhtMessage {
                    message_id: generate_message_id(),
                    message_type: DhtMessageType::FindNodeResponse,
                    sender_id: self.local_node.id.clone(),
                    target_id: Some(message.sender_id),
                    key: None,
                    value: None,
                    nodes: Some(Vec::new()),
                    contract_data: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    signature: None,
                }))
            }
            
            DhtMessageType::FindValue => {
                // In a implementation, this would check local storage
                // For now, return empty node list (value not found)
                Ok(Some(DhtMessage {
                    message_id: generate_message_id(),
                    message_type: DhtMessageType::FindValueResponse,
                    sender_id: self.local_node.id.clone(),
                    target_id: Some(message.sender_id),
                    key: message.key,
                    value: None,
                    nodes: Some(Vec::new()),
                    contract_data: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    signature: None,
                }))
            }
            
            DhtMessageType::Store => {
                // In a implementation, this would store the key-value pair
                Ok(Some(DhtMessage {
                    message_id: generate_message_id(),
                    message_type: DhtMessageType::StoreResponse,
                    sender_id: self.local_node.id.clone(),
                    target_id: Some(message.sender_id),
                    key: None,
                    value: None,
                    nodes: None,
                    contract_data: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    signature: None,
                }))
            }
            
            _ => Ok(None), // Response messages don't need responses
        }
    }
    
    /// Get local socket address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

/// Generate a unique message ID
fn generate_message_id() -> String {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    
    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;
    
    #[test]
    fn test_message_id_generation() {
        let id1 = generate_message_id();
        let id2 = generate_message_id();
        
        assert_ne!(id1, id2);
        assert!(!id1.is_empty());
        assert!(!id2.is_empty());
    }
    
    #[tokio::test]
    async fn test_network_creation() {
        let test_node = DhtNode {
            id: Hash::from_bytes(&[1u8; 32]),
            addresses: vec!["127.0.0.1:33442".to_string()],
            public_key: lib_crypto::PostQuantumSignature {
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    ed25519_pk: vec![],
                    key_id: [0u8; 32],
                },
                timestamp: 0,
            },
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        };
        
        let bind_addr = "127.0.0.1:0".parse().unwrap(); // Use any available port
        let network = DhtNetwork::new(test_node, bind_addr);
        
        assert!(network.is_ok());
        if let Ok(net) = network {
            assert!(net.local_addr().is_ok());
        }
    }
    
    #[tokio::test]
    async fn test_ping_pong_response() {
        let test_node = DhtNode {
            id: Hash::from_bytes(&[1u8; 32]),
            addresses: vec!["127.0.0.1:33443".to_string()],
            public_key: lib_crypto::PostQuantumSignature {
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    ed25519_pk: vec![],
                    key_id: [0u8; 32],
                },
                timestamp: 0,
            },
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        };
        
        let bind_addr = "127.0.0.1:0".parse().unwrap();
        let network = DhtNetwork::new(test_node, bind_addr).unwrap();
        
        // Test PING message handling
        let ping_message = DhtMessage {
            message_id: "test_ping".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: Hash::from_bytes(&[2u8; 32]),
            target_id: Some(Hash::from_bytes(&[1u8; 32])),
            key: None,
            value: None,
            nodes: None,
            timestamp: 12345,
            signature: None,
        };
        
        let sender_addr = "127.0.0.1:12345".parse().unwrap();
        let response = network.handle_incoming_message(ping_message, sender_addr).await.unwrap();
        
        assert!(response.is_some());
        if let Some(pong) = response {
            assert!(matches!(pong.message_type, DhtMessageType::Pong));
        }
    }
}
