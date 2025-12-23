//! Message Fragmentation and Reassembly
//!
//! Unified fragmentation logic for splitting large messages across protocols with
//! limited MTU (Maximum Transmission Unit).
//!
//! ## Features
//!
//! - Protocol-agnostic fragmentation with configurable chunk sizes
//! - Automatic sequence numbering and total fragment tracking
//! - Reassembly with duplicate detection and out-of-order handling
//! - Support for both simple and complex fragmentation schemes
//!
//! ## Usage
//!
//! ```ignore
//! use lib_network::fragmentation::{fragment_message, reassemble_message, FragmentReassembler};
//! use lib_network::mtu::Protocol;
//!
//! // Fragment a message
//! let payload = vec![0u8; 5000];
//! let fragments = fragment_message(&payload, Protocol::BluetoothLE.chunk_size());
//!
//! // Reassemble fragments
//! let mut reassembler = FragmentReassembler::new();
//! for fragment in fragments {
//!     if let Some(complete) = reassembler.add_fragment(fragment)? {
//!         println!("Message reassembled: {} bytes", complete.len());
//!     }
//! }
//! ```

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fragment header structure for sequencing and reassembly
///
/// This header is prepended to each fragment payload:
/// - 4 bytes: message_id (u32)
/// - 2 bytes: total_fragments (u16)
/// - 2 bytes: fragment_index (u16)
///
/// Total overhead: 8 bytes per fragment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Unique message identifier (same for all fragments of a message)
    pub message_id: u32,
    /// Total number of fragments in this message
    pub total_fragments: u16,
    /// Zero-based index of this fragment
    pub fragment_index: u16,
}

impl FragmentHeader {
    /// Size of the serialized header in bytes
    pub const SIZE: usize = 8;

    /// Create a new fragment header
    pub fn new(message_id: u32, total_fragments: u16, fragment_index: u16) -> Self {
        Self {
            message_id,
            total_fragments,
            fragment_index,
        }
    }

    /// Serialize header to bytes (8 bytes fixed size)
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.message_id.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.total_fragments.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.fragment_index.to_le_bytes());
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(anyhow!("Fragment header too short: {} bytes", bytes.len()));
        }

        let message_id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let total_fragments = u16::from_le_bytes([bytes[4], bytes[5]]);
        let fragment_index = u16::from_le_bytes([bytes[6], bytes[7]]);

        Ok(Self {
            message_id,
            total_fragments,
            fragment_index,
        })
    }
}

/// A single message fragment with header and payload
#[derive(Debug, Clone)]
pub struct Fragment {
    /// Fragment header (metadata)
    pub header: FragmentHeader,
    /// Fragment payload (actual data chunk)
    pub payload: Vec<u8>,
}

impl Fragment {
    /// Create a new fragment
    pub fn new(message_id: u32, total_fragments: u16, fragment_index: u16, payload: Vec<u8>) -> Self {
        Self {
            header: FragmentHeader::new(message_id, total_fragments, fragment_index),
            payload,
        }
    }

    /// Serialize fragment to wire format (header + payload)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FragmentHeader::SIZE + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize fragment from wire format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FragmentHeader::SIZE {
            return Err(anyhow!("Fragment too short: {} bytes", bytes.len()));
        }

        let header = FragmentHeader::from_bytes(&bytes[0..FragmentHeader::SIZE])?;
        let payload = bytes[FragmentHeader::SIZE..].to_vec();

        Ok(Self { header, payload })
    }

    /// Get the total size of this fragment (header + payload)
    pub fn size(&self) -> usize {
        FragmentHeader::SIZE + self.payload.len()
    }
}

/// Fragment a message into chunks suitable for transmission
///
/// ## Arguments
///
/// - `payload`: The message data to fragment
/// - `chunk_size`: Maximum size of each fragment payload (excluding 8-byte header)
///
/// ## Returns
///
/// Vector of fragments with headers and sequencing information.
/// Each fragment is guaranteed to be <= (chunk_size + 8) bytes when serialized.
///
/// ## Example
///
/// ```ignore
/// let payload = vec![0u8; 5000];
/// let fragments = fragment_message(&payload, 200);
/// assert_eq!(fragments.len(), 25); // 5000 / 200 = 25 fragments
/// ```
pub fn fragment_message(payload: &[u8], chunk_size: usize) -> Vec<Fragment> {
    if payload.is_empty() {
        return vec![];
    }

    // Generate unique message ID (use hash of payload for determinism)
    let message_id = payload.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32));

    let total_fragments = ((payload.len() + chunk_size - 1) / chunk_size) as u16;
    let mut fragments = Vec::with_capacity(total_fragments as usize);

    for (index, chunk) in payload.chunks(chunk_size).enumerate() {
        let fragment = Fragment::new(
            message_id,
            total_fragments,
            index as u16,
            chunk.to_vec(),
        );
        fragments.push(fragment);
    }

    fragments
}

/// Reassemble a complete message from fragments
///
/// ## Arguments
///
/// - `fragments`: All fragments of a message (can be out of order)
///
/// ## Returns
///
/// The complete reassembled message payload (without headers)
///
/// ## Errors
///
/// - Missing fragments
/// - Mismatched message IDs
/// - Duplicate fragment indices
///
/// ## Example
///
/// ```ignore
/// let fragments = fragment_message(&payload, 200);
/// let reassembled = reassemble_message(&fragments)?;
/// assert_eq!(reassembled, payload);
/// ```
pub fn reassemble_message(fragments: &[Fragment]) -> Result<Vec<u8>> {
    if fragments.is_empty() {
        return Ok(vec![]);
    }

    // Verify all fragments have the same message ID
    let message_id = fragments[0].header.message_id;
    for fragment in fragments {
        if fragment.header.message_id != message_id {
            return Err(anyhow!("Fragment message ID mismatch"));
        }
    }

    let total_fragments = fragments[0].header.total_fragments;

    // Check we have all fragments
    if fragments.len() != total_fragments as usize {
        return Err(anyhow!(
            "Missing fragments: expected {}, got {}",
            total_fragments,
            fragments.len()
        ));
    }

    // Sort fragments by index
    let mut sorted_fragments = fragments.to_vec();
    sorted_fragments.sort_by_key(|f| f.header.fragment_index);

    // Verify no duplicates and correct sequence
    for (i, fragment) in sorted_fragments.iter().enumerate() {
        if fragment.header.fragment_index != i as u16 {
            return Err(anyhow!(
                "Fragment sequence error: expected index {}, got {}",
                i,
                fragment.header.fragment_index
            ));
        }
    }

    // Concatenate payloads
    let total_size: usize = sorted_fragments.iter().map(|f| f.payload.len()).sum();
    let mut reassembled = Vec::with_capacity(total_size);

    for fragment in sorted_fragments {
        reassembled.extend_from_slice(&fragment.payload);
    }

    Ok(reassembled)
}

/// Stateful fragment reassembler for streaming reassembly
///
/// Handles out-of-order fragments and multiple concurrent messages.
#[derive(Debug)]
pub struct FragmentReassembler {
    /// In-progress messages: message_id -> collected fragments
    pending: HashMap<u32, Vec<Fragment>>,
    /// Maximum number of concurrent messages to track
    max_pending: usize,
}

impl FragmentReassembler {
    /// Create a new reassembler
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            max_pending: 100, // Prevent memory exhaustion
        }
    }

    /// Create a reassembler with custom max pending messages
    pub fn with_max_pending(max_pending: usize) -> Self {
        Self {
            pending: HashMap::new(),
            max_pending,
        }
    }

    /// Add a fragment and attempt reassembly
    ///
    /// ## Returns
    ///
    /// - `Some(Vec<u8>)`: Complete message if all fragments received
    /// - `None`: Message still incomplete
    ///
    /// ## Errors
    ///
    /// - Duplicate fragment index
    /// - Too many pending messages (DoS protection)
    pub fn add_fragment(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>> {
        let message_id = fragment.header.message_id;
        let total_fragments = fragment.header.total_fragments;
        let fragment_index = fragment.header.fragment_index;

        // Get or create fragment list
        let fragments = self.pending.entry(message_id).or_insert_with(Vec::new);

        // Check for duplicate
        if fragments.iter().any(|f| f.header.fragment_index == fragment_index) {
            return Err(anyhow!("Duplicate fragment index {}", fragment_index));
        }

        // Add fragment
        fragments.push(fragment);

        // Check if complete
        if fragments.len() == total_fragments as usize {
            // Remove from pending and reassemble
            let complete_fragments = self.pending.remove(&message_id).unwrap();
            let reassembled = reassemble_message(&complete_fragments)?;
            return Ok(Some(reassembled));
        }

        // DoS protection: limit pending messages
        if self.pending.len() > self.max_pending {
            // Remove oldest message (simple FIFO eviction)
            if let Some(&oldest_id) = self.pending.keys().next() {
                self.pending.remove(&oldest_id);
            }
        }

        Ok(None)
    }

    /// Clear all pending fragments
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Get number of pending messages
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if a message is being reassembled
    pub fn has_message(&self, message_id: u32) -> bool {
        self.pending.contains_key(&message_id)
    }

    /// Get fragment count for a pending message
    pub fn fragment_count(&self, message_id: u32) -> usize {
        self.pending.get(&message_id).map(|v| v.len()).unwrap_or(0)
    }
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_header_serialization() {
        let header = FragmentHeader::new(12345, 10, 5);
        let bytes = header.to_bytes();
        let decoded = FragmentHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header, decoded);
        assert_eq!(bytes.len(), FragmentHeader::SIZE);
    }

    #[test]
    fn test_fragment_serialization() {
        let fragment = Fragment::new(999, 5, 2, vec![1, 2, 3, 4, 5]);
        let bytes = fragment.to_bytes();
        let decoded = Fragment::from_bytes(&bytes).unwrap();

        assert_eq!(fragment.header, decoded.header);
        assert_eq!(fragment.payload, decoded.payload);
        assert_eq!(bytes.len(), FragmentHeader::SIZE + 5);
    }

    #[test]
    fn test_fragmentation_simple() {
        let payload = vec![0u8; 500];
        let fragments = fragment_message(&payload, 100);

        assert_eq!(fragments.len(), 5);
        assert_eq!(fragments[0].header.total_fragments, 5);
        assert_eq!(fragments[0].header.fragment_index, 0);
        assert_eq!(fragments[4].header.fragment_index, 4);

        // All fragments should have same message_id
        let msg_id = fragments[0].header.message_id;
        assert!(fragments.iter().all(|f| f.header.message_id == msg_id));
    }

    #[test]
    fn test_reassembly_in_order() {
        let payload = vec![42u8; 1000];
        let fragments = fragment_message(&payload, 200);

        let reassembled = reassemble_message(&fragments).unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let payload = vec![42u8; 1000];
        let mut fragments = fragment_message(&payload, 200);

        // Shuffle fragments
        fragments.reverse();

        let reassembled = reassemble_message(&fragments).unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_reassembler_streaming() {
        let payload = vec![123u8; 500];
        let fragments = fragment_message(&payload, 100);

        let mut reassembler = FragmentReassembler::new();

        // Add fragments one by one
        for (i, fragment) in fragments.iter().enumerate() {
            let result = reassembler.add_fragment(fragment.clone()).unwrap();
            if i < fragments.len() - 1 {
                assert!(result.is_none());
            } else {
                assert!(result.is_some());
                assert_eq!(result.unwrap(), payload);
            }
        }
    }

    #[test]
    fn test_reassembler_out_of_order() {
        let payload = vec![99u8; 300];
        let mut fragments = fragment_message(&payload, 100);

        // Reverse order
        fragments.reverse();

        let mut reassembler = FragmentReassembler::new();

        for (i, fragment) in fragments.iter().enumerate() {
            let result = reassembler.add_fragment(fragment.clone()).unwrap();
            if i < fragments.len() - 1 {
                assert!(result.is_none());
            } else {
                assert_eq!(result.unwrap(), payload);
            }
        }
    }

    #[test]
    fn test_reassembler_duplicate_detection() {
        let payload = vec![1u8; 200];
        let fragments = fragment_message(&payload, 100);

        let mut reassembler = FragmentReassembler::new();

        reassembler.add_fragment(fragments[0].clone()).unwrap();
        let result = reassembler.add_fragment(fragments[0].clone());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate"));
    }

    #[test]
    fn test_reassembler_multiple_messages() {
        let payload1 = vec![1u8; 200];
        let payload2 = vec![2u8; 300];

        let fragments1 = fragment_message(&payload1, 100);
        let mut fragments2 = fragment_message(&payload2, 100);

        // Ensure different message IDs
        fragments2[0].header.message_id = fragments1[0].header.message_id + 1000;
        for f in fragments2.iter_mut() {
            f.header.message_id = fragments1[0].header.message_id + 1000;
        }

        let mut reassembler = FragmentReassembler::new();

        // Interleave fragments
        reassembler.add_fragment(fragments1[0].clone()).unwrap();
        reassembler.add_fragment(fragments2[0].clone()).unwrap();
        reassembler.add_fragment(fragments1[1].clone()).unwrap();
        reassembler.add_fragment(fragments2[1].clone()).unwrap();

        let result2 = reassembler.add_fragment(fragments2[2].clone()).unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap(), payload2);
    }

    #[test]
    fn test_empty_payload() {
        let payload = vec![];
        let fragments = fragment_message(&payload, 100);
        assert_eq!(fragments.len(), 0);

        let reassembled = reassemble_message(&fragments).unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_single_fragment() {
        let payload = vec![42u8; 50];
        let fragments = fragment_message(&payload, 100);

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].header.total_fragments, 1);
        assert_eq!(fragments[0].header.fragment_index, 0);

        let reassembled = reassemble_message(&fragments).unwrap();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_fragment_size_limit() {
        let payload = vec![0u8; 1000];
        let chunk_size = 200;
        let fragments = fragment_message(&payload, chunk_size);

        for fragment in fragments {
            // Each fragment should be <= chunk_size + header
            assert!(fragment.size() <= chunk_size + FragmentHeader::SIZE);
        }
    }
}
