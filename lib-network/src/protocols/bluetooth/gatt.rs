//! GATT (Generic Attribute Profile) Common Operations
//! 
//! Shared GATT functionality for characteristic read/write operations

use anyhow::{Result, anyhow};
use tracing::{info, debug, warn};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::mtu::{BLE_MIN_MTU, BLE_MAX_MTU};
use crate::fragmentation::{fragment_message, FragmentReassembler as CentralizedReassembler, Fragment};

// Placeholder until blockchain integration is relocated.
type BlockHeader = Vec<u8>;

/// GATT operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GattOperation {
    Read,
    Write,
    WriteWithoutResponse,
    Notify,
    Indicate,
}

/// Parse GATT characteristic properties from string flags
pub fn parse_characteristic_properties(flags: &[String]) -> Vec<GattOperation> {
    let mut operations = Vec::new();
    
    for flag in flags {
        match flag.to_lowercase().as_str() {
            "read" => operations.push(GattOperation::Read),
            "write" => operations.push(GattOperation::Write),
            "write-without-response" => operations.push(GattOperation::WriteWithoutResponse),
            "notify" => operations.push(GattOperation::Notify),
            "indicate" => operations.push(GattOperation::Indicate),
            _ => debug!("Unknown GATT property: {}", flag),
        }
    }
    
    operations
}

/// Check if a characteristic supports a specific operation
pub fn supports_operation(properties: &[String], operation: GattOperation) -> bool {
    parse_characteristic_properties(properties).contains(&operation)
}

/// Validate GATT write data size against MTU
pub fn validate_write_size(data: &[u8], mtu: u16) -> Result<()> {
    // GATT ATT header is 3 bytes
    let max_data_size = (mtu as usize).saturating_sub(3);
    
    if data.len() > max_data_size {
        return Err(anyhow!(
            "Data size {} exceeds MTU limit {} (MTU: {} - 3 byte header)",
            data.len(), max_data_size, mtu
        ));
    }
    
    Ok(())
}

/// Fragment data for GATT transmission
/// 
/// **DEPRECATED**: Use crate::fragmentation::fragment_message for new code.
/// This wrapper maintains backward compatibility.
pub fn fragment_data(data: &[u8], mtu: u16) -> Vec<Vec<u8>> {
    let max_chunk_size = (mtu as usize).saturating_sub(3);
    
    // Simple chunking without headers (backward compatible)
    data.chunks(max_chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Fragment a large message for BLE transmission (with sequencing)
/// 
/// **REFACTORED**: Now uses centralized fragmentation with standardized 8-byte headers.
/// Returns Vec of wire-format fragments ready for GATT transmission.
pub fn fragment_large_message(message_id: u64, data: &[u8], mtu: u16) -> Vec<Vec<u8>> {
    // ATT overhead is 3 bytes, leave room for our 8-byte header
    let chunk_size = (mtu as usize).saturating_sub(3 + 8).max(20);
    
    // Use centralized fragmentation (produces 8-byte headers)
    let fragments = fragment_message(data, chunk_size);
    
    // Convert to wire format
    fragments.into_iter()
        .map(|f| f.to_bytes())
        .collect()
}

/// Fragment reassembler for multi-part BLE messages
/// 
/// **REFACTORED**: Now delegates to centralized FragmentReassembler.
/// Maintains backward compatibility with existing code.
#[derive(Debug)]
pub struct FragmentReassembler {
    inner: CentralizedReassembler,
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self {
            inner: CentralizedReassembler::new(),
        }
    }
    
    /// Add a fragment and return complete message if all fragments received
    /// 
    /// **UPDATED**: Now uses centralized fragmentation (8-byte headers)
    pub fn add_fragment(&mut self, fragment: Vec<u8>) -> Result<Option<Vec<u8>>> {
        // Parse fragment using centralized format
        let parsed = Fragment::from_bytes(&fragment)?;
        
        // Delegate to centralized reassembler
        let result = self.inner.add_fragment(parsed)?;
        
        if let Some(ref data) = result {
            info!("✅ Reassembled message from {} fragments ({} bytes)", 
                self.inner.pending_count(), data.len());
        }
        
        Ok(result)
    }
    
    /// Clear stale fragments older than timeout
    pub fn cleanup_stale_fragments(&mut self, _message_id: u64) {
        // Clear all pending (centralized reassembler doesn't track individual message cleanup)
        self.inner.clear();
        warn!("🗑️ Cleaned up all stale fragments");
    }
}

/// Calculate optimal MTU for connection
pub fn calculate_optimal_mtu(requested_mtu: u16, max_mtu: u16) -> u16 {
    // Use centralized MTU constants
    let effective_max = max_mtu.min(BLE_MAX_MTU as u16);
    requested_mtu.clamp(BLE_MIN_MTU as u16, effective_max)
}

/// GATT message types for unified handling
#[derive(Debug, Clone)]
pub enum GattMessage {
    /// Raw data from GATT write (characteristic UUID, data)
    RawData(String, Vec<u8>),
    /// Mesh handshake (data, optional peripheral_id for macOS)
    MeshHandshake { data: Vec<u8>, peripheral_id: Option<String> },
    /// DHT bridge message
    DhtBridge(String),
    /// ZHTP relay query
    RelayQuery(Vec<u8>),
    /// Edge node headers request (lightweight sync)
    HeadersRequest {
        request_id: u64,
        start_height: u64,
        count: u32,
    },
    /// Edge node headers response
    HeadersResponse {
        request_id: u64,
        headers: Vec<BlockHeader>,
    },
    /// Edge node bootstrap proof request (ZK proof + recent headers)
    BootstrapProofRequest {
        request_id: u64,
        current_height: u64,
    },
    /// Edge node bootstrap proof response
    BootstrapProofResponse {
        request_id: u64,
        proof_data: Vec<u8>,  // Serialized ChainRecursiveProof
        proof_height: u64,
        headers: Vec<BlockHeader>,
    },
    /// Multi-fragment message header (for messages >512 bytes)
    FragmentHeader {
        message_id: u64,
        total_fragments: u16,
        fragment_index: u16,
        data: Vec<u8>,
    },
}

/// Serializable edge sync message for BLE transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeSyncMessage {
    HeadersRequest {
        request_id: u64,
        start_height: u64,
        count: u32,
    },
    HeadersResponse {
        request_id: u64,
        headers: Vec<BlockHeader>,
    },
    BootstrapProofRequest {
        request_id: u64,
        current_height: u64,
    },
    BootstrapProofResponse {
        request_id: u64,
        proof_data: Vec<u8>,
        proof_height: u64,
        headers: Vec<BlockHeader>,
    },
}

impl GattMessage {
    /// Parse raw GATT data into appropriate message type
    pub fn from_raw(char_uuid: &str, data: Vec<u8>) -> Self {
        // Try to parse based on characteristic UUID and data content
        match char_uuid {
            uuid if uuid.contains("6ba7b813") => {
                // Mesh data characteristic - check for edge sync messages
                if data.len() >= 11 && data.starts_with(&[0xED, 0x6E]) {
                    // Edge sync message marker "EDge Node"
                    if let Ok(edge_msg) = bincode::deserialize::<EdgeSyncMessage>(&data[2..]) {
                        match edge_msg {
                            EdgeSyncMessage::HeadersRequest { request_id, start_height, count } => {
                                GattMessage::HeadersRequest { request_id, start_height, count }
                            }
                            EdgeSyncMessage::HeadersResponse { request_id, headers } => {
                                GattMessage::HeadersResponse { request_id, headers }
                            }
                            EdgeSyncMessage::BootstrapProofRequest { request_id, current_height } => {
                                GattMessage::BootstrapProofRequest { request_id, current_height }
                            }
                            EdgeSyncMessage::BootstrapProofResponse { request_id, proof_data, proof_height, headers } => {
                                GattMessage::BootstrapProofResponse { request_id, proof_data, proof_height, headers }
                            }
                        }
                    } else {
                        // Failed to deserialize edge sync message, treat as raw data
                        GattMessage::RawData(uuid.to_string(), data.to_vec())
                    }
                }
                // Check for fragmented message
                else if data.len() >= 11 {
                    // Might be a fragment (has message_id + total_fragments + sequence)
                    GattMessage::FragmentHeader {
                        message_id: u64::from_le_bytes(data[0..8].try_into().unwrap_or_default()),
                        total_fragments: u16::from_le_bytes(data[8..10].try_into().unwrap_or_default()),
                        fragment_index: u16::from_le_bytes(data[10..12].try_into().unwrap_or_default()),
                        data: data[12..].to_vec(),
                    }
                } else if data.len() >= 8 {
                    // Regular mesh handshake
                    GattMessage::MeshHandshake { data, peripheral_id: None }
                } else if let Ok(text) = String::from_utf8(data.clone()) {
                    if text.starts_with("DHT:") {
                        GattMessage::DhtBridge(text)
                    } else {
                        GattMessage::RawData(uuid.to_string(), data)
                    }
                } else {
                    // Too short for any structured message, treat as raw data
                    GattMessage::RawData(uuid.to_string(), data.to_vec())
                }
            }
            _ => GattMessage::RawData(char_uuid.to_string(), data)
        }
    }
    
    /// Serialize edge sync message to bytes (with marker)
    pub fn serialize_edge_sync(msg: &EdgeSyncMessage) -> Result<Vec<u8>> {
        let mut data = vec![0xED, 0x6E]; // "EDge Node" marker
        let serialized = bincode::serialize(msg)
            .map_err(|e| anyhow!("Failed to serialize edge sync message: {}", e))?;
        data.extend_from_slice(&serialized);
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_characteristic_properties() {
        let flags = vec!["read".to_string(), "write".to_string(), "notify".to_string()];
        let ops = parse_characteristic_properties(&flags);
        
        assert_eq!(ops.len(), 3);
        assert!(ops.contains(&GattOperation::Read));
        assert!(ops.contains(&GattOperation::Write));
        assert!(ops.contains(&GattOperation::Notify));
    }
    
    #[test]
    fn test_supports_operation() {
        let flags = vec!["read".to_string(), "write".to_string()];
        
        assert!(supports_operation(&flags, GattOperation::Read));
        assert!(supports_operation(&flags, GattOperation::Write));
        assert!(!supports_operation(&flags, GattOperation::Notify));
    }
    
    #[test]
    fn test_validate_write_size() {
        let data = vec![0u8; 100];
        
        // Should succeed with MTU 150
        assert!(validate_write_size(&data, 150).is_ok());
        
        // Should fail with MTU 50
        assert!(validate_write_size(&data, 50).is_err());
    }
    
    #[test]
    fn test_fragment_data() {
        let data = vec![0u8; 100];
        let fragments = fragment_data(&data, 30); // 30 - 3 = 27 bytes per chunk
        
        assert!(fragments.len() >= 4); // 100 / 27 = ~4 chunks
        assert!(fragments[0].len() <= 27);
    }
    
    #[test]
    fn test_calculate_optimal_mtu() {
        assert_eq!(calculate_optimal_mtu(50, 100), 50);
        assert_eq!(calculate_optimal_mtu(600, 512), 512);
        assert_eq!(calculate_optimal_mtu(10, 100), 23); // Clamps to minimum
    }
}
