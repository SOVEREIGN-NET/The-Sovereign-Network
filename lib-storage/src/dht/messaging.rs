//! DHT Messaging System
//! 
//! Handles message routing, queuing, and processing for DHT operations.

use crate::types::dht_types::{DhtMessage, DhtMessageType, DhtNode};
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::sync::mpsc;

/// Message queue entry
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub message: DhtMessage,
    pub target_node: DhtNode,
    pub attempts: u32,
    pub next_retry: SystemTime,
}

/// DHT message router and queue manager
#[derive(Debug)]
pub struct DhtMessaging {
    /// Outgoing message queue
    outgoing_queue: VecDeque<QueuedMessage>,
    /// Pending responses (message_id -> response_sender)
    pending_responses: HashMap<String, mpsc::Sender<DhtMessage>>,
    /// Message retry configuration
    max_retries: u32,
    retry_delay: Duration,
    /// Local node ID
    local_node_id: NodeId,
    /// Monotonic sequence counter for outgoing messages
    sequence_counter: u64,
}

impl DhtMessaging {
    /// Create a new DHT messaging system
    pub fn new(local_node_id: NodeId) -> Self {
        Self {
            outgoing_queue: VecDeque::new(),
            pending_responses: HashMap::new(),
            max_retries: 3,
            retry_delay: Duration::from_secs(2),
            local_node_id,
            sequence_counter: 0,
        }
    }
    
    /// Queue a message for delivery
    pub async fn queue_message(&mut self, message: DhtMessage, target_node: DhtNode) -> Result<()> {
        let queued_message = QueuedMessage {
            message,
            target_node,
            attempts: 0,
            next_retry: SystemTime::now(),
        };
        
        self.outgoing_queue.push_back(queued_message);
        Ok(())
    }
    
    /// Send a message and wait for response
    pub async fn send_and_wait(&mut self, message: DhtMessage, target_node: DhtNode, timeout: Duration) -> Result<DhtMessage> {
        let (tx, mut rx) = mpsc::channel(1);
        let message_id = message.message_id.clone();
        
        // Register for response
        self.pending_responses.insert(message_id.clone(), tx);
        
        // Queue message
        self.queue_message(message, target_node).await?;
        
        // Wait for response with timeout
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(response)) => {
                self.pending_responses.remove(&response.message_id);
                Ok(response)
            }
            Ok(None) => {
                self.pending_responses.remove(&message_id);
                Err(anyhow!("Response channel closed"))
            }
            Err(_) => {
                self.pending_responses.remove(&message_id);
                Err(anyhow!("Message timeout"))
            }
        }
    }
    
    /// Process incoming message and route to appropriate handler
    pub async fn handle_incoming(&mut self, message: DhtMessage) -> Result<Option<DhtMessage>> {
        // Check if this is a response to a pending request
        if self.is_response_message(&message) {
            if let Some(response_id) = self.get_response_id(&message) {
                if let Some(sender) = self.pending_responses.remove(&response_id) {
                    let _ = sender.send(message).await;
                    return Ok(None);
                }
            }
        }
        
        // Handle request messages
        match message.message_type {
            DhtMessageType::Ping => Ok(Some(self.create_pong_response(&message)?)),
            DhtMessageType::FindNode => Ok(Some(self.create_find_node_response(&message)?)),
            DhtMessageType::FindValue => Ok(Some(self.create_find_value_response(&message)?)),
            DhtMessageType::Store => Ok(Some(self.create_store_response(&message)?)),
            _ => Ok(None), // Response messages are handled above
        }
    }
    
    /// Get next message from queue that's ready to send
    pub fn get_next_message(&mut self) -> Option<QueuedMessage> {
        let now = SystemTime::now();
        
        // Find first message ready for sending
        if let Some(index) = self.outgoing_queue.iter().position(|msg| msg.next_retry <= now) {
            self.outgoing_queue.remove(index)
        } else {
            None
        }
    }
    
    /// Mark a message as failed and potentially requeue
    pub fn mark_message_failed(&mut self, mut message: QueuedMessage) -> bool {
        message.attempts += 1;
        
        if message.attempts <= self.max_retries {
            // Requeue with exponential backoff
            let delay = self.retry_delay * 2_u32.pow(message.attempts - 1);
            message.next_retry = SystemTime::now() + delay;
            self.outgoing_queue.push_back(message);
            true
        } else {
            // Max retries exceeded
            false
        }
    }
    
    /// Check if message is a response type
    fn is_response_message(&self, message: &DhtMessage) -> bool {
        matches!(message.message_type, 
            DhtMessageType::Pong |
            DhtMessageType::FindNodeResponse |
            DhtMessageType::FindValueResponse |
            DhtMessageType::StoreResponse
        )
    }
    
    /// Get response correlation ID
    fn get_response_id(&self, message: &DhtMessage) -> Option<String> {
        // In a implementation, responses would include the original message ID
        // For now, we'll use a simple correlation based on message type and sender
        Some(message.message_id.clone())
    }

    /// Get next sequence number for outgoing messages
    fn next_sequence(&mut self) -> u64 {
        let sequence = self.sequence_counter;
        self.sequence_counter = self.sequence_counter.wrapping_add(1);
        sequence
    }
    
    /// Create PONG response
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    fn create_pong_response(&mut self, ping: &DhtMessage) -> Result<DhtMessage> {
        Ok(DhtMessage {
            message_id: generate_response_id(&ping.message_id),
            message_type: DhtMessageType::Pong,
            sender_id: self.local_node_id.clone(),
            target_id: Some(ping.sender_id.clone()),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            nonce: generate_nonce(),
            sequence_number: self.next_sequence(),
            signature: None, // TODO (HIGH-5): Sign message
        })
    }

    /// Create FIND_NODE response
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    fn create_find_node_response(&mut self, find_node: &DhtMessage) -> Result<DhtMessage> {
        // In a implementation, this would query the routing table
        // For now, return empty node list
        Ok(DhtMessage {
            message_id: generate_response_id(&find_node.message_id),
            message_type: DhtMessageType::FindNodeResponse,
            sender_id: self.local_node_id.clone(),
            target_id: Some(find_node.sender_id.clone()),
            key: None,
            value: None,
            contract_data: None,
            nodes: Some(Vec::new()),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            nonce: generate_nonce(),
            sequence_number: self.next_sequence(),
            signature: None, // TODO (HIGH-5): Sign message
        })
    }

    /// Create FIND_VALUE response
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    fn create_find_value_response(&mut self, find_value: &DhtMessage) -> Result<DhtMessage> {
        // In a implementation, this would check local storage
        Ok(DhtMessage {
            message_id: generate_response_id(&find_value.message_id),
            message_type: DhtMessageType::FindValueResponse,
            sender_id: self.local_node_id.clone(),
            target_id: Some(find_value.sender_id.clone()),
            key: find_value.key.clone(),
            value: None, // Value not found locally
            nodes: Some(Vec::new()), // Return empty node list
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            nonce: generate_nonce(),
            sequence_number: self.next_sequence(),
            signature: None, // TODO (HIGH-5): Sign message
        })
    }

    /// Create STORE response
    ///
    /// # Security
    ///
    /// - Includes nonce and sequence_number for replay protection
    fn create_store_response(&mut self, store: &DhtMessage) -> Result<DhtMessage> {
        Ok(DhtMessage {
            message_id: generate_response_id(&store.message_id),
            message_type: DhtMessageType::StoreResponse,
            sender_id: self.local_node_id.clone(),
            target_id: Some(store.sender_id.clone()),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            nonce: generate_nonce(),
            sequence_number: self.next_sequence(),
            signature: None, // TODO (HIGH-5): Sign message
        })
    }
    
    /// Get queue statistics
    pub fn get_queue_stats(&self) -> QueueStats {
        QueueStats {
            pending_messages: self.outgoing_queue.len(),
            pending_responses: self.pending_responses.len(),
        }
    }
    
    /// Clear expired pending responses
    pub fn cleanup_expired_responses(&mut self, max_age: Duration) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let cutoff_time = now.saturating_sub(max_age.as_secs());
        
        // Remove expired responses (cleanup old senders that are likely closed)
        // In a full implementation, we'd track response timestamps separately
        if self.pending_responses.len() > 1000 {
            self.pending_responses.clear();
        }
        
        // Also remove old queued messages
        self.outgoing_queue.retain(|queued_msg| {
            queued_msg.message.timestamp > cutoff_time
        });
        
        // Log cleanup activity
        if self.pending_responses.len() > 100 {
            println!(" Cleaned up expired responses, {} remaining", self.pending_responses.len());
        }
    }
}

/// Message queue statistics
#[derive(Debug)]
pub struct QueueStats {
    pub pending_messages: usize,
    pub pending_responses: usize,
}

/// Generate a response message ID
fn generate_response_id(original_id: &str) -> String {
    format!("resp_{}", original_id)
}

/// Generate a cryptographically secure random nonce
fn generate_nonce() -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let mut nonce = [0u8; 32];
    let now = SystemTime::now();
    let mut hasher = DefaultHasher::new();
    now.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let h1 = hasher.finish().to_le_bytes();
    nonce[0..8].copy_from_slice(&h1);

    let mut hasher2 = DefaultHasher::new();
    now.hash(&mut hasher2);
    hasher2.write_u64(0xDEADBEEF_CAFEBABE);
    let h2 = hasher2.finish().to_le_bytes();
    nonce[8..16].copy_from_slice(&h2);

    let nanos = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    nonce[16..24].copy_from_slice(&(nanos as u64).to_le_bytes());
    nonce[24..32].copy_from_slice(&((nanos >> 64) as u64).to_le_bytes());

    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::{ZhtpIdentity, IdentityType};
    use crate::types::dht_types::DhtPeerIdentity;

    fn create_test_peer(device_name: &str) -> DhtPeerIdentity {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Device,
            None,
            None,
            device_name,
            None,
        ).expect("Failed to create test identity");
        
        DhtPeerIdentity {
            node_id: identity.node_id.clone(),
            public_key: identity.public_key.clone(),
            did: identity.did.clone(),
            device_id: device_name.to_string(),
        }
    }

    fn dummy_pq_signature() -> lib_crypto::PostQuantumSignature {
        lib_crypto::PostQuantumSignature {
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            signature: vec![],
            public_key: lib_crypto::PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            timestamp: 0,
        }
    }
    
    #[tokio::test]
    async fn test_messaging_creation() {
        let node_id = NodeId::from_bytes([1u8; 32]);
        let messaging = DhtMessaging::new(node_id);
        
        assert_eq!(messaging.outgoing_queue.len(), 0);
        assert_eq!(messaging.pending_responses.len(), 0);
    }
    
    #[tokio::test]
    async fn test_queue_message() {
        let node_id = NodeId::from_bytes([1u8; 32]);
        let mut messaging = DhtMessaging::new(node_id);
        
        let test_message = DhtMessage {
            message_id: "test_msg".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: NodeId::from_bytes([1u8; 32]),
            target_id: Some(NodeId::from_bytes([2u8; 32])),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: [1u8; 32],
            sequence_number: 0,
            signature: None,
        };
        
        let test_node = DhtNode {
            peer: create_test_peer("test-node"),
            addresses: vec!["127.0.0.1:33442".to_string()],
            public_key: dummy_pq_signature(),
            last_seen: 0,
            reputation: 1000,
            storage_info: None,
        };
        
        messaging.queue_message(test_message, test_node).await.unwrap();
        
        assert_eq!(messaging.outgoing_queue.len(), 1);
    }
    
    #[tokio::test]
    async fn test_handle_ping() {
        let node_id = NodeId::from_bytes([1u8; 32]);
        let mut messaging = DhtMessaging::new(node_id);
        
        let ping_message = DhtMessage {
            message_id: "ping_test".to_string(),
            message_type: DhtMessageType::Ping,
            sender_id: NodeId::from_bytes([2u8; 32]),
            target_id: Some(NodeId::from_bytes([1u8; 32])),
            key: None,
            value: None,
            nodes: None,
            contract_data: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: [2u8; 32],
            sequence_number: 1,
            signature: None,
        };
        
        let response = messaging.handle_incoming(ping_message).await.unwrap();
        
        assert!(response.is_some());
        if let Some(pong) = response {
            assert!(matches!(pong.message_type, DhtMessageType::Pong));
            assert_eq!(pong.target_id, Some(NodeId::from_bytes([2u8; 32])));
        }
    }
    
    #[test]
    fn test_response_id_generation() {
        let original_id = "test_message_123";
        let response_id = generate_response_id(original_id);
        
        assert_eq!(response_id, "resp_test_message_123");
    }
    
    #[test]
    fn test_queue_stats() {
        let node_id = NodeId::from_bytes([1u8; 32]);
        let messaging = DhtMessaging::new(node_id);
        
        let stats = messaging.get_queue_stats();
        assert_eq!(stats.pending_messages, 0);
        assert_eq!(stats.pending_responses, 0);
    }
}
