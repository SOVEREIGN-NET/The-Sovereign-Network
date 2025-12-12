//! Message Fragmentation and Reassembly
//! 
//! Unified fragmentation logic for breaking large messages into protocol-appropriate
//! chunks and reassembling them on the receiving end.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fragment header containing metadata for reassembly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentHeader {
    /// Unique message identifier
    pub message_id: u64,
    /// Fragment sequence number (0-based)
    pub fragment_index: u16,
    /// Total number of fragments
    pub total_fragments: u16,
    /// Total original message size
    pub total_size: u32,
}

/// A single message fragment
#[derive(Debug, Clone)]
pub struct Fragment {
    /// Fragment metadata
    pub header: FragmentHeader,
    /// Fragment payload data
    pub data: Vec<u8>,
}

/// Fragment a message into chunks suitable for transmission
/// 
/// Splits a large message into smaller fragments that fit within the MTU
/// constraint of the target protocol.
/// 
/// # Arguments
/// 
/// * `message_id` - Unique identifier for this message
/// * `payload` - The complete message to fragment
/// * `chunk_size` - Maximum size of each fragment's data portion
/// 
/// # Returns
/// 
/// Vector of fragments, each containing header and data
/// 
/// # Examples
/// 
/// ```
/// use lib_network::fragmentation::fragment_message;
/// use lib_network::mtu::{get_chunk_size, ProtocolType};
/// 
/// let large_message = vec![0u8; 1000];
/// let chunk_size = get_chunk_size(ProtocolType::BluetoothLE);
/// let fragments = fragment_message(12345, &large_message, chunk_size).unwrap();
/// 
/// assert!(fragments.len() > 1);
/// for fragment in &fragments {
///     assert!(fragment.data.len() <= chunk_size);
/// }
/// ```
pub fn fragment_message(
    message_id: u64,
    payload: &[u8],
    chunk_size: usize,
) -> Result<Vec<Fragment>> {
    if chunk_size == 0 {
        return Err(anyhow!("Chunk size must be greater than 0"));
    }

    if payload.is_empty() {
        return Err(anyhow!("Cannot fragment empty payload"));
    }

    let total_fragments = (payload.len() + chunk_size - 1) / chunk_size;
    
    if total_fragments > u16::MAX as usize {
        return Err(anyhow!(
            "Message too large: would require {} fragments (max {})",
            total_fragments,
            u16::MAX
        ));
    }

    let mut fragments = Vec::with_capacity(total_fragments);

    for (index, chunk) in payload.chunks(chunk_size).enumerate() {
        let header = FragmentHeader {
            message_id,
            fragment_index: index as u16,
            total_fragments: total_fragments as u16,
            total_size: payload.len() as u32,
        };

        fragments.push(Fragment {
            header,
            data: chunk.to_vec(),
        });
    }

    Ok(fragments)
}

/// Serialize a fragment into bytes for transmission
/// 
/// Encodes the fragment header and data into a single byte vector
/// that can be transmitted over the network.
pub fn serialize_fragment(fragment: &Fragment) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    
    // Serialize header (24 bytes fixed size)
    bytes.extend_from_slice(&fragment.header.message_id.to_le_bytes());
    bytes.extend_from_slice(&fragment.header.fragment_index.to_le_bytes());
    bytes.extend_from_slice(&fragment.header.total_fragments.to_le_bytes());
    bytes.extend_from_slice(&fragment.header.total_size.to_le_bytes());
    
    // Append data
    bytes.extend_from_slice(&fragment.data);
    
    Ok(bytes)
}

/// Deserialize a fragment from received bytes
/// 
/// Decodes a transmitted fragment back into header and data components.
pub fn deserialize_fragment(bytes: &[u8]) -> Result<Fragment> {
    const HEADER_SIZE: usize = 16; // 8 + 2 + 2 + 4 bytes
    
    if bytes.len() < HEADER_SIZE {
        return Err(anyhow!("Fragment too small: {} bytes (need at least {})", bytes.len(), HEADER_SIZE));
    }
    
    let message_id = u64::from_le_bytes(bytes[0..8].try_into()?);
    let fragment_index = u16::from_le_bytes(bytes[8..10].try_into()?);
    let total_fragments = u16::from_le_bytes(bytes[10..12].try_into()?);
    let total_size = u32::from_le_bytes(bytes[12..16].try_into()?);
    
    let header = FragmentHeader {
        message_id,
        fragment_index,
        total_fragments,
        total_size,
    };
    
    let data = bytes[HEADER_SIZE..].to_vec();
    
    Ok(Fragment { header, data })
}

/// Fragment reassembly tracker
/// 
/// Manages the collection and reassembly of message fragments as they arrive.
pub struct FragmentAssembler {
    /// Incomplete messages being reassembled (message_id -> fragment storage)
    incomplete_messages: HashMap<u64, MessageReassembly>,
}

/// State for reassembling a single message
struct MessageReassembly {
    /// Expected total number of fragments
    total_fragments: u16,
    /// Expected total message size
    total_size: u32,
    /// Received fragments (fragment_index -> data)
    fragments: HashMap<u16, Vec<u8>>,
    /// Timestamp when first fragment was received
    started_at: std::time::Instant,
}

impl FragmentAssembler {
    /// Create a new fragment assembler
    pub fn new() -> Self {
        Self {
            incomplete_messages: HashMap::new(),
        }
    }

    /// Add a received fragment and attempt reassembly
    /// 
    /// Returns Some(complete_message) if this fragment completes a message,
    /// otherwise returns None.
    /// 
    /// # Arguments
    /// 
    /// * `fragment` - The received fragment to process
    /// 
    /// # Examples
    /// 
    /// ```
    /// use lib_network::fragmentation::{FragmentAssembler, fragment_message};
    /// use lib_network::mtu::{get_chunk_size, ProtocolType};
    /// 
    /// let mut assembler = FragmentAssembler::new();
    /// let message = b"Hello, world!".to_vec();
    /// let chunk_size = get_chunk_size(ProtocolType::BluetoothLE);
    /// let fragments = fragment_message(1, &message, chunk_size).unwrap();
    /// 
    /// for fragment in fragments {
    ///     if let Some(complete) = assembler.add_fragment(fragment).unwrap() {
    ///         assert_eq!(complete, message);
    ///     }
    /// }
    /// ```
    pub fn add_fragment(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>> {
        let message_id = fragment.header.message_id;
        let fragment_index = fragment.header.fragment_index;
        let total_fragments = fragment.header.total_fragments;
        let total_size = fragment.header.total_size;

        // Validate fragment
        if fragment_index >= total_fragments {
            return Err(anyhow!(
                "Invalid fragment index {} for total {}",
                fragment_index,
                total_fragments
            ));
        }

        // Get or create reassembly state
        let reassembly = self.incomplete_messages
            .entry(message_id)
            .or_insert_with(|| MessageReassembly {
                total_fragments,
                total_size,
                fragments: HashMap::new(),
                started_at: std::time::Instant::now(),
            });

        // Validate consistency
        if reassembly.total_fragments != total_fragments {
            return Err(anyhow!(
                "Fragment total mismatch: expected {} got {}",
                reassembly.total_fragments,
                total_fragments
            ));
        }

        if reassembly.total_size != total_size {
            return Err(anyhow!(
                "Message size mismatch: expected {} got {}",
                reassembly.total_size,
                total_size
            ));
        }

        // Store fragment
        reassembly.fragments.insert(fragment_index, fragment.data);

        // Check if complete
        if reassembly.fragments.len() == total_fragments as usize {
            // Reassemble message
            let mut complete_message = Vec::with_capacity(total_size as usize);
            
            for i in 0..total_fragments {
                if let Some(data) = reassembly.fragments.get(&i) {
                    complete_message.extend_from_slice(data);
                } else {
                    return Err(anyhow!("Missing fragment {} during reassembly", i));
                }
            }

            // Verify size
            if complete_message.len() != total_size as usize {
                return Err(anyhow!(
                    "Reassembled size {} doesn't match expected {}",
                    complete_message.len(),
                    total_size
                ));
            }

            // Remove from incomplete set
            self.incomplete_messages.remove(&message_id);

            Ok(Some(complete_message))
        } else {
            Ok(None)
        }
    }

    /// Remove stale incomplete messages
    /// 
    /// Cleans up messages that have been incomplete for longer than the timeout.
    /// 
    /// # Arguments
    /// 
    /// * `timeout` - Duration after which incomplete messages are considered stale
    /// 
    /// # Returns
    /// 
    /// Number of messages removed
    pub fn cleanup_stale(&mut self, timeout: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let initial_count = self.incomplete_messages.len();

        self.incomplete_messages.retain(|_, reassembly| {
            now.duration_since(reassembly.started_at) < timeout
        });

        initial_count - self.incomplete_messages.len()
    }

    /// Get the number of incomplete messages currently being tracked
    pub fn incomplete_count(&self) -> usize {
        self.incomplete_messages.len()
    }

    /// Get statistics about a specific incomplete message
    pub fn get_message_stats(&self, message_id: u64) -> Option<(usize, usize)> {
        self.incomplete_messages.get(&message_id).map(|r| {
            (r.fragments.len(), r.total_fragments as usize)
        })
    }
}

impl Default for FragmentAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mtu::{get_chunk_size, ProtocolType};

    #[test]
    fn test_fragment_small_message() {
        let message = b"Hello, World!";
        let chunks = fragment_message(1, message, 100).unwrap();
        
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].header.fragment_index, 0);
        assert_eq!(chunks[0].header.total_fragments, 1);
        assert_eq!(chunks[0].data, message);
    }

    #[test]
    fn test_fragment_large_message() {
        let message = vec![42u8; 1000];
        let chunks = fragment_message(1, &message, 100).unwrap();
        
        assert_eq!(chunks.len(), 10);
        
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.header.fragment_index, i as u16);
            assert_eq!(chunk.header.total_fragments, 10);
            assert_eq!(chunk.header.total_size, 1000);
            assert!(chunk.data.len() <= 100);
        }
    }

    #[test]
    fn test_reassemble_single_fragment() {
        let mut assembler = FragmentAssembler::new();
        let message = b"Hello!";
        
        let fragments = fragment_message(1, message, 100).unwrap();
        let result = assembler.add_fragment(fragments[0].clone()).unwrap();
        
        assert_eq!(result, Some(message.to_vec()));
    }

    #[test]
    fn test_reassemble_multiple_fragments() {
        let mut assembler = FragmentAssembler::new();
        let message = vec![123u8; 500];
        
        let fragments = fragment_message(1, &message, 100).unwrap();
        assert_eq!(fragments.len(), 5);
        
        // Add fragments in order
        for (i, fragment) in fragments.iter().enumerate() {
            let result = assembler.add_fragment(fragment.clone()).unwrap();
            
            if i < fragments.len() - 1 {
                assert_eq!(result, None, "Should not be complete yet");
            } else {
                assert_eq!(result, Some(message.clone()), "Should be complete now");
            }
        }
    }

    #[test]
    fn test_reassemble_out_of_order() {
        let mut assembler = FragmentAssembler::new();
        let message = vec![99u8; 300];
        
        let mut fragments = fragment_message(1, &message, 100).unwrap();
        assert_eq!(fragments.len(), 3);
        
        // Shuffle fragments (2, 0, 1)
        fragments.swap(0, 2);
        
        // Add in shuffled order
        assert_eq!(assembler.add_fragment(fragments[0].clone()).unwrap(), None);
        assert_eq!(assembler.add_fragment(fragments[1].clone()).unwrap(), None);
        
        let result = assembler.add_fragment(fragments[2].clone()).unwrap();
        assert_eq!(result, Some(message));
    }

    #[test]
    fn test_serialize_deserialize_fragment() {
        let original = Fragment {
            header: FragmentHeader {
                message_id: 12345,
                fragment_index: 3,
                total_fragments: 10,
                total_size: 1000,
            },
            data: vec![1, 2, 3, 4, 5],
        };

        let bytes = serialize_fragment(&original).unwrap();
        let deserialized = deserialize_fragment(&bytes).unwrap();

        assert_eq!(deserialized.header.message_id, original.header.message_id);
        assert_eq!(deserialized.header.fragment_index, original.header.fragment_index);
        assert_eq!(deserialized.header.total_fragments, original.header.total_fragments);
        assert_eq!(deserialized.header.total_size, original.header.total_size);
        assert_eq!(deserialized.data, original.data);
    }

    #[test]
    fn test_cleanup_stale_fragments() {
        let mut assembler = FragmentAssembler::new();
        let message = vec![1u8; 300];
        
        let fragments = fragment_message(1, &message, 100).unwrap();
        
        // Add only first fragment
        assembler.add_fragment(fragments[0].clone()).unwrap();
        assert_eq!(assembler.incomplete_count(), 1);
        
        // Cleanup with very short timeout should remove it
        let removed = assembler.cleanup_stale(std::time::Duration::from_nanos(1));
        assert_eq!(removed, 1);
        assert_eq!(assembler.incomplete_count(), 0);
    }

    #[test]
    fn test_ble_fragmentation() {
        let message = vec![0xABu8; 500];
        let chunk_size = get_chunk_size(ProtocolType::BluetoothLE);
        
        let fragments = fragment_message(1, &message, chunk_size).unwrap();
        
        // Each fragment's data should fit in BLE chunk size
        for fragment in &fragments {
            assert!(fragment.data.len() <= chunk_size);
        }
        
        // Reassemble
        let mut assembler = FragmentAssembler::new();
        for fragment in fragments {
            if let Some(reassembled) = assembler.add_fragment(fragment).unwrap() {
                assert_eq!(reassembled, message);
            }
        }
    }

    #[test]
    fn test_lora_fragmentation() {
        let message = vec![0xCDu8; 1000];
        let chunk_size = get_chunk_size(ProtocolType::LoRaWAN);
        
        let fragments = fragment_message(1, &message, chunk_size).unwrap();
        
        // Verify fragment sizes
        for fragment in &fragments {
            assert!(fragment.data.len() <= chunk_size);
        }
    }

    #[test]
    fn test_error_empty_payload() {
        let result = fragment_message(1, &[], 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_zero_chunk_size() {
        let result = fragment_message(1, b"test", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_fragment_index() {
        let mut assembler = FragmentAssembler::new();
        
        let bad_fragment = Fragment {
            header: FragmentHeader {
                message_id: 1,
                fragment_index: 10, // Greater than total
                total_fragments: 5,
                total_size: 100,
            },
            data: vec![1, 2, 3],
        };

        let result = assembler.add_fragment(bad_fragment);
        assert!(result.is_err());
    }
}
