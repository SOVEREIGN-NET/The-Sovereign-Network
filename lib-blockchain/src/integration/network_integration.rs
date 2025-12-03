//! Network integration for ZHTP blockchain
//! Provides serialization and networking functionality for blockchain components

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::{
    block::Block,
    transaction::Transaction,
};

/// Serialize a block for network transmission
pub fn serialize_block_for_network(block: &Block) -> Result<Vec<u8>> {
    bincode::serialize(block)
        .map_err(|e| anyhow::anyhow!("Failed to serialize block: {}", e))
}

/// Deserialize a block from network data
pub fn deserialize_block_from_network(data: &[u8]) -> Result<Block> {
    bincode::deserialize(data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize block: {}", e))
}

/// Serialize a transaction for network transmission
pub fn serialize_transaction_for_network(transaction: &Transaction) -> Result<Vec<u8>> {
    bincode::serialize(transaction)
        .map_err(|e| anyhow::anyhow!("Failed to serialize transaction: {}", e))
}

/// Deserialize a transaction from network data
pub fn deserialize_transaction_from_network(data: &[u8]) -> Result<Transaction> {
    bincode::deserialize(data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize transaction: {}", e))
}

/// Network message types for blockchain communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// New block announcement
    NewBlock(Block),
    /// New transaction announcement  
    NewTransaction(Transaction),
    /// Block request by height
    BlockRequest(u64),
    /// Block response
    BlockResponse(Option<Block>),
    /// Transaction request by hash
    TransactionRequest([u8; 32]),
    /// Transaction response
    TransactionResponse(Option<Transaction>),
    /// Peer information
    PeerInfo {
        node_id: [u8; 32],
        blockchain_height: u64,
        version: String,
    },
}

impl NetworkMessage {
    /// Serialize network message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize network message: {}", e))
    }

    /// Deserialize network message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize network message: {}", e))
    }

    /// Get message type as string
    pub fn message_type(&self) -> &'static str {
        match self {
            NetworkMessage::NewBlock(_) => "NewBlock",
            NetworkMessage::NewTransaction(_) => "NewTransaction",
            NetworkMessage::BlockRequest(_) => "BlockRequest",
            NetworkMessage::BlockResponse(_) => "BlockResponse",
            NetworkMessage::TransactionRequest(_) => "TransactionRequest",
            NetworkMessage::TransactionResponse(_) => "TransactionResponse",
            NetworkMessage::PeerInfo { .. } => "PeerInfo",
        }
    }
}

/// Network node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub node_id: [u8; 32],
    pub address: String,
    pub port: u16,
    pub last_seen: u64,
    pub blockchain_height: u64,
    pub version: String,
}

impl NetworkNode {
    /// Create new network node
    pub fn new(
        node_id: [u8; 32],
        address: String,
        port: u16,
        blockchain_height: u64,
        version: String,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            node_id,
            address,
            port,
            last_seen: timestamp,
            blockchain_height,
            version,
        }
    }

    /// Update last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Check if node is recently active (within last 5 minutes)
    pub fn is_active(&self) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        current_time - self.last_seen < 300 // 5 minutes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::{TransactionType, types::{Hash, Difficulty}};
    use lib_crypto::KeyPair;

    #[test]
    fn test_block_serialization() -> Result<()> {
        let _keypair = KeyPair::generate()?;
        
        let header = BlockHeader::new(
            1,                          // version
            Hash::default(),            // previous_block_hash
            Hash::default(),            // merkle_root
            1000,                       // timestamp
            Difficulty::minimum(),      // difficulty
            0,                          // height
            0,                          // transaction_count
            0,                          // block_size
            Difficulty::minimum(),      // cumulative_difficulty
        );

        let block = Block::new(header, Vec::new());
        
        let serialized = serialize_block_for_network(&block)?;
        let deserialized = deserialize_block_from_network(&serialized)?;
        
        assert_eq!(block.header.height, deserialized.header.height);
        assert_eq!(block.header.timestamp, deserialized.header.timestamp);
        
        Ok(())
    }

    #[test]
    fn test_transaction_serialization() -> Result<()> {
        let keypair = KeyPair::generate()?;
        
        let transaction = Transaction {
            version: 1,
            chain_id: 0x01, // mainnet
            transaction_type: TransactionType::Transfer,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 100,
            signature: keypair.sign(b"test_data")?,
            memo: b"test memo".to_vec(),
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
        };
        
        let serialized = serialize_transaction_for_network(&transaction)?;
        let deserialized = deserialize_transaction_from_network(&serialized)?;
        
        assert_eq!(transaction.version, deserialized.version);
        assert_eq!(transaction.fee, deserialized.fee);
        assert_eq!(transaction.memo, deserialized.memo);
        
        Ok(())
    }

    #[test]
    fn test_network_message() -> Result<()> {
        let _keypair = KeyPair::generate()?;
        
        let header = BlockHeader::new(
            1,                          // version
            Hash::default(),            // previous_block_hash
            Hash::default(),            // merkle_root
            1000,                       // timestamp
            Difficulty::minimum(),      // difficulty
            1,                          // height
            0,                          // transaction_count
            0,                          // block_size
            Difficulty::minimum(),      // cumulative_difficulty
        );

        let block = Block::new(header, Vec::new());
        let message = NetworkMessage::NewBlock(block);
        
        assert_eq!(message.message_type(), "NewBlock");
        
        let serialized = message.to_bytes()?;
        let deserialized = NetworkMessage::from_bytes(&serialized)?;
        
        match deserialized {
            NetworkMessage::NewBlock(received_block) => {
                assert_eq!(received_block.header.height, 1);
            }
            _ => panic!("Wrong message type"),
        }
        
        Ok(())
    }

    #[test]
    fn test_network_node() {
        let node_id = [1u8; 32];
        let mut node = NetworkNode::new(
            node_id,
            "127.0.0.1".to_string(),
            8080,
            100,
            "1.0.0".to_string(),
        );
        
        assert_eq!(node.node_id, node_id);
        assert_eq!(node.address, "127.0.0.1");
        assert_eq!(node.port, 8080);
        assert_eq!(node.blockchain_height, 100);
        assert!(node.is_active());
        
        // Test updating last seen
        let old_last_seen = node.last_seen;
        std::thread::sleep(std::time::Duration::from_millis(1));
        node.update_last_seen();
        assert!(node.last_seen > old_last_seen);
    }
}
