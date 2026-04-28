//! ConsensusMessageCodec - Deterministic serialization for consensus messages
//!
//! This module provides a pure, stateless codec for converting `ValidatorMessage` enum
//! between in-memory representation and bytes suitable for network transmission.
//!
//! # CRITICAL ARCHITECTURAL FACT
//!
//! **ValidatorMessage bytes produced by this codec are canonical, signable, and hashable.**
//!
//! This is not optional. The implications are absolute:
//! - Determinism is mandatory (CM-3)
//! - Canonical ordering is mandatory (BTreeMap, never HashMap)
//! - Codec output must be identical across all honest nodes
//! - Two nodes serializing the same ValidatorMessage MUST produce identical bytes
//!
//! If this invariant is violated:
//! - Signatures will not verify across nodes
//! - Hashes will diverge, breaking consensus
//! - Replay protection will fail
//! - The entire consensus protocol fails
//!
//! This is a hard constraint, not a suggestion.
//!
//! # Architectural Invariants
//!
//! This codec enforces 17 non-negotiable invariants:
//!
//! **Purpose & Scope (CM-1, CM-2, CM-15)**:
//! - Only converts messages ↔ bytes (no transport/validation/policy)
//! - Opaque to message semantics (no branching on role/validator/round)
//! - Never fragments (fragmentation is protocol concern)
//!
//! **Determinism & Integrity (CM-3, CM-4)**:
//! - Deterministic (same message → same bytes, no randomization)
//! - Round-trip integrity: `decode(encode(msg)) == msg`
//!
//! **Framing & Safety (CM-5, CM-6, CM-7)**:
//! - Defines only byte boundaries (not meaning)
//! - Handles partial/incomplete data without panic
//! - Rejects oversized messages BEFORE allocation
//!
//! **Purity & Versioning (CM-8, CM-9)**:
//! - Pure, no I/O or side effects
//! - Explicit versioning with forward compatibility
//!
//! **Error Handling (CM-10)**:
//! - Errors distinguish malformed/unsupported/incomplete/size violations
//!
//! **Authority & Validation (CM-11, CM-12, CM-14)**:
//! - Doesn't verify signatures/validity (decoder's job)
//! - Only codec knows serialization format
//! - Under size limit ≠ valid (validation is separate)
//!
//! **Resource Bounds (CM-13)**:
//! - Hard size cap enforced before allocation
//!
//! # Wire Format
//!
//! ```text
//! [4-byte length (BE)] [1-byte version] [bincode payload]
//! └─ Framing ────────┘ └─ Versioning ─┘ └─ Serialization ─┘
//! ```
//!
//! Example:
//! ```text
//! [0x00, 0x01, 0x23, 0x45] [0x01] [... bincode ValidatorMessage ...]
//!  └─ Length: 74,565 ────┘ └─v1─┘ └─ Serialized payload ──────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use lib_consensus::network::{ConsensusMessageCodec, BincodeConsensusCodec};
//! use lib_consensus::validators::validator_protocol::ValidatorMessage;
//!
//! let codec = BincodeConsensusCodec::new();
//!
//! // Encode a message
//! let message = ValidatorMessage::Propose(/* ... */);
//! let framed = codec.encode_framed(&message)?;
//!
//! // Transmit framed bytes over network...
//!
//! // Decode received bytes
//! let decoded = codec.decode_framed(&framed)?;
//! ```

use crate::validator_protocol::ValidatorMessage;
use thiserror::Error;

/// Maximum consensus message size: 8 MB
///
/// Rationale:
/// - Matches QUIC max datagram size for efficient transport
/// - Matches WiFi Direct limit (lib-network fragmentation_v2.rs)
/// - Accommodates post-quantum signatures (Dilithium5: ~4.6KB) + justifications
/// - ProposeMessage with 500 votes × (64B hash + 3KB sig) ≈ 1.5 MB
pub const MAX_CONSENSUS_MESSAGE_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Codec version (v1: bincode serialization, 4-byte BE length prefix)
///
/// Version evolution path:
/// - v1: bincode serialization, 4-byte BE length prefix
/// - v2+: Future extensions (compression, alternate serialization, new message types)
pub const CONSENSUS_CODEC_VERSION: u8 = 1;

// Internal constants
const LENGTH_PREFIX_SIZE: usize = 4;
const VERSION_FIELD_SIZE: usize = 1;
const FRAME_HEADER_SIZE: usize = LENGTH_PREFIX_SIZE + VERSION_FIELD_SIZE; // 5 bytes

/// Codec errors with semantic classification
///
/// **Invariant CM-10**: Errors distinguish malformed/unsupported/incomplete/size violations
///
/// This allows callers to make appropriate decisions:
/// - `Malformed` → drop message, may log
/// - `UnsupportedVersion` → potentially useful for protocol upgrade detection
/// - `Incomplete` → buffer in stream, await more data
/// - `SizeViolation` → drop message, potential DoS attempt
/// - `SerializationFailed` / `DeserializationFailed` → codec internal error
#[derive(Debug, Error, Clone, PartialEq)]
pub enum CodecError {
    /// Malformed data (corrupted payload, invalid bincode, checksum failure)
    #[error("Malformed message: {0}")]
    Malformed(String),

    /// Unsupported version (future version not recognized by this codec)
    ///
    /// First parameter: received version
    /// Second parameter: expected version
    #[error("Unsupported codec version: {0} (expected {1})")]
    UnsupportedVersion(u8, u8),

    /// Incomplete frame (partial read, missing bytes)
    ///
    /// This error indicates the buffer does not contain enough bytes.
    /// Safe to buffer and retry with more data.
    #[error("Incomplete frame: expected {expected} bytes, got {actual}")]
    Incomplete {
        /// Expected number of bytes
        expected: usize,
        /// Actual number of bytes available
        actual: usize,
    },

    /// Size violation (exceeds MAX_CONSENSUS_MESSAGE_SIZE before allocation)
    ///
    /// This is a security invariant preventing DoS via large length prefixes.
    #[error("Message size {0} exceeds maximum {1}")]
    SizeViolation(usize, usize),

    /// Serialization failure (bincode encode error)
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Deserialization failure (bincode decode error)
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
}

// NOTE: No blanket From<bincode::Error> impl.
// encode() and decode() must handle errors separately per CM-10.
// This prevents misclassifying serialization errors as deserialization errors.

/// Consensus message codec trait
///
/// # Architectural Invariants
///
/// This trait enforces 17 non-negotiable invariants (CM-1 through CM-17).
/// See module-level documentation for full details.
///
/// # Thread Safety
///
/// Implementations are stateless and can be safely shared across threads.
pub trait ConsensusMessageCodec: Send + Sync {
    /// Encode a message to raw bytes (NO framing)
    ///
    /// Returns the serialized payload (bincode format).
    ///
    /// **Invariants**: CM-1, CM-3, CM-8, CM-12
    /// - Purpose: Only converts messages to bytes
    /// - Deterministic: Same message → same bytes
    /// - Pure: No I/O, no side effects
    /// - Format: Only codec knows bincode format
    fn encode(&self, message: &ValidatorMessage) -> Result<Vec<u8>, CodecError>;

    /// Decode a message from raw bytes (NO unframing)
    ///
    /// Returns the deserialized ValidatorMessage.
    ///
    /// **Invariants**: CM-1, CM-4, CM-6, CM-8, CM-11, CM-12
    /// - Purpose: Only converts bytes to messages
    /// - Round-trip: decode(encode(x)) == x
    /// - Partial safety: No panic on corrupted data
    /// - Pure: No I/O, no side effects
    /// - No authority: Doesn't verify signatures/validity
    /// - Format: Only codec knows bincode format
    fn decode(&self, bytes: &[u8]) -> Result<ValidatorMessage, CodecError>;

    /// Frame a payload with [length][version][payload]
    ///
    /// Returns framed bytes ready for network transmission.
    ///
    /// **Invariants**: CM-5, CM-7, CM-9, CM-13
    /// - Framing: Only defines byte boundaries
    /// - Size bounds: Rejects oversized messages BEFORE allocation
    /// - Versioning: Explicit version byte
    /// - Hard cap: MAX_CONSENSUS_MESSAGE_SIZE enforced
    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>, CodecError>;

    /// Unframe bytes, extracting version and payload
    ///
    /// Returns tuple: (version, payload)
    ///
    /// **Invariants**: CM-5, CM-6, CM-7, CM-9, CM-10, CM-13
    /// - Framing: Only extracts byte boundaries
    /// - Partial safety: Handles incomplete data without panic
    /// - Size bounds: Rejects oversized messages BEFORE allocation
    /// - Versioning: Explicit version checking
    /// - Error classification: Distinct error types
    /// - Hard cap: MAX_CONSENSUS_MESSAGE_SIZE enforced
    fn unframe(&self, framed: &[u8]) -> Result<(u8, Vec<u8>), CodecError>;

    /// Encode + Frame in one step (convenience)
    ///
    /// Equivalent to: frame(&encode(msg)?)?
    fn encode_framed(&self, message: &ValidatorMessage) -> Result<Vec<u8>, CodecError> {
        let payload = self.encode(message)?;
        self.frame(&payload)
    }

    /// Unframe + Decode in one step (convenience)
    ///
    /// Equivalent to: decode(&unframe(framed)?.1)?
    fn decode_framed(&self, framed: &[u8]) -> Result<ValidatorMessage, CodecError> {
        let (_version, payload) = self.unframe(framed)?;
        self.decode(&payload)
    }
}

/// Bincode-based consensus message codec (version 1)
///
/// This is the primary production codec for ValidatorMessage serialization.
/// It uses bincode for deterministic binary serialization and provides
/// length-prefix framing with explicit version support.
///
/// # Wire Format
///
/// ```text
/// [4-byte BE length][1-byte version][bincode payload]
/// ```
///
/// # Thread Safety
///
/// This codec is stateless and can be safely shared across threads.
/// All methods are pure functions with no side effects.
#[derive(Debug, Clone, Default)]
pub struct BincodeConsensusCodec;

impl BincodeConsensusCodec {
    /// Create a new codec instance
    ///
    /// The codec is stateless, so creating multiple instances is safe
    /// and has no overhead.
    pub fn new() -> Self {
        Self
    }
}

impl ConsensusMessageCodec for BincodeConsensusCodec {
    fn encode(&self, message: &ValidatorMessage) -> Result<Vec<u8>, CodecError> {
        // CM-3: Deterministic serialization (bincode is deterministic)
        // CM-8: Pure function (no I/O, no side effects)
        // CM-10: SerializationFailed is distinct from deserialization errors
        bincode::serialize(message).map_err(|e| CodecError::SerializationFailed(e.to_string()))
    }

    fn decode(&self, bytes: &[u8]) -> Result<ValidatorMessage, CodecError> {
        // CM-4: Round-trip integrity (bincode deserialize)
        // CM-6: Handles partial/corrupted data gracefully (bincode returns error, no panic)
        // CM-11: No signature verification (just deserialization)
        // CRITICAL: Enforce MAX_CONSENSUS_MESSAGE_SIZE during deserialization
        // This bounds memory allocation and prevents untrusted length-prefix attacks
        if bytes.len() > MAX_CONSENSUS_MESSAGE_SIZE {
            return Err(CodecError::SizeViolation(
                bytes.len(),
                MAX_CONSENSUS_MESSAGE_SIZE,
            ));
        }

        bincode::deserialize(bytes).map_err(|e| CodecError::DeserializationFailed(e.to_string()))
    }

    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
        let payload_len = payload.len();

        // CM-7, CM-13: Reject oversized messages BEFORE allocation
        if payload_len > MAX_CONSENSUS_MESSAGE_SIZE {
            return Err(CodecError::SizeViolation(
                payload_len,
                MAX_CONSENSUS_MESSAGE_SIZE,
            ));
        }

        // CM-9: Explicit versioning
        let total_len = FRAME_HEADER_SIZE + payload_len;
        let mut framed = Vec::with_capacity(total_len);

        // 4-byte big-endian length (payload only, not including header)
        let len_u32 = payload_len as u32;
        framed.extend_from_slice(&len_u32.to_be_bytes());

        // 1-byte version
        framed.push(CONSENSUS_CODEC_VERSION);

        // Payload
        framed.extend_from_slice(payload);

        Ok(framed)
    }

    fn unframe(&self, framed: &[u8]) -> Result<(u8, Vec<u8>), CodecError> {
        // CM-6: Handle incomplete frames gracefully
        if framed.len() < FRAME_HEADER_SIZE {
            return Err(CodecError::Incomplete {
                expected: FRAME_HEADER_SIZE,
                actual: framed.len(),
            });
        }

        // Read 4-byte BE length
        let len_bytes: [u8; 4] = framed[0..4]
            .try_into()
            .map_err(|_| CodecError::Malformed("Invalid length prefix".to_string()))?;
        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        // CM-7, CM-13: Reject oversized lengths BEFORE allocation
        if payload_len > MAX_CONSENSUS_MESSAGE_SIZE {
            return Err(CodecError::SizeViolation(
                payload_len,
                MAX_CONSENSUS_MESSAGE_SIZE,
            ));
        }

        // Read version byte
        let version = framed[4];

        // CM-9: Version validation (strict checking, no fallback)
        if version != CONSENSUS_CODEC_VERSION {
            return Err(CodecError::UnsupportedVersion(
                version,
                CONSENSUS_CODEC_VERSION,
            ));
        }

        // Check if we have the full payload
        let expected_total = FRAME_HEADER_SIZE + payload_len;
        if framed.len() < expected_total {
            return Err(CodecError::Incomplete {
                expected: expected_total,
                actual: framed.len(),
            });
        }

        // Extract payload
        let payload = framed[FRAME_HEADER_SIZE..expected_total].to_vec();

        Ok((version, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_consensus_core::types::{ConsensusProof, ConsensusProposal, ConsensusVote};
    use lib_types::consensus::{ConsensusStep, ConsensusType, VoteType};
    use crate::validator_protocol::*;
    use lib_crypto::{Hash, PostQuantumSignature};
    use lib_identity::IdentityId;

    // Helper: Create a simple ValidatorMessage for testing
    fn create_test_message(variant: u8) -> ValidatorMessage {
        let identity = IdentityId::from_bytes(b"test-identity-id-1234567890123");
        let hash = Hash::from_bytes(b"test-hash-1234567890123456789012");

        match variant {
            0 => {
                // Propose message
                ValidatorMessage::Propose(ProposeMessage {
                    message_id: hash,
                    proposer: identity,
                    proposal: create_test_proposal(),
                    justification: None,
                    timestamp: 1234567890,
                    signature: PostQuantumSignature::default(),
                })
            }
            1 => {
                // Vote message
                ValidatorMessage::Vote(VoteMessage {
                    message_id: hash,
                    voter: identity,
                    vote: create_test_vote(),
                    consensus_state: create_test_consensus_state(),
                    timestamp: 1234567890,
                    signature: PostQuantumSignature::default(),
                })
            }
            2 => {
                // Heartbeat message
                ValidatorMessage::Heartbeat(HeartbeatMessage {
                    message_id: hash,
                    validator: identity,
                    height: 100,
                    round: 1,
                    step: ConsensusStep::Propose,
                    network_summary: create_test_network_summary(),
                    timestamp: 1234567890,
                    signature: PostQuantumSignature::default(),
                })
            }
            _ => panic!("Invalid variant"),
        }
    }

    fn create_test_proposal() -> ConsensusProposal {
        ConsensusProposal {
            id: Hash::from_bytes(b"test-proposal-id-123456789012345"),
            proposer: IdentityId::from_bytes(b"test-proposer-id-1234567890123"),
            height: 100,
            round: 1,
            // CONS-501b: was `crate::engines::consensus_engine::
            // CONSENSUS_PROTOCOL_VERSION` when this test lived in
            // lib-consensus. The constant stays in the engine; tests
            // here pin the same numeric value so a bump there breaks
            // this assertion until both sides agree.
            protocol_version: 2,
            previous_hash: Hash::from_bytes(b"prev-hash-123456789012345678901"),
            block_data: vec![1, 2, 3, 4, 5],
            timestamp: 1234567890,
            signature: PostQuantumSignature::default(),
            consensus_proof: create_test_consensus_proof(),
        }
    }

    fn create_test_vote() -> ConsensusVote {
        ConsensusVote {
            id: Hash::from_bytes(b"test-vote-id-12345678901234567890"),
            voter: IdentityId::from_bytes(b"test-voter-id-123456789012345678"),
            proposal_id: Hash::from_bytes(b"test-proposal-id-123456789012345"),
            vote_type: VoteType::PreVote,
            height: 100,
            round: 1,
            timestamp: 1234567890,
            signature: PostQuantumSignature::default(),
        }
    }

    fn create_test_consensus_state() -> ConsensusStateView {
        use std::collections::BTreeMap;

        let mut vote_counts = BTreeMap::new();
        vote_counts.insert(Hash::from_bytes(b"test-proposal-id-123456789012345"), 5);

        ConsensusStateView {
            height: 100,
            round: 1,
            step: ConsensusStep::PreVote,
            known_proposals: vec![Hash::from_bytes(b"test-proposal-id-123456789012345")],
            vote_counts,
        }
    }

    // CONS-201: `create_test_commitment_proof` was deleted along with the
    // `Commit` variant.

    fn create_test_network_summary() -> NetworkSummary {
        NetworkSummary {
            active_validators: 10,
            health_score: 0.95,
            block_rate: 1.0,
        }
    }

    fn create_test_consensus_proof() -> ConsensusProof {
        ConsensusProof {
            consensus_type: ConsensusType::ByzantineFaultTolerance,
            stake_proof: None,
            storage_proof: None,
            work_proof: None,
            zk_did_proof: Some(vec![1, 2, 3, 4]),
            timestamp: 1234567890,
        }
    }

    // ===== ROUND-TRIP TESTS (CM-4) =====

    #[test]
    fn test_roundtrip_propose_message() {
        let codec = BincodeConsensusCodec::new();
        let original = create_test_message(0);

        let encoded = codec.encode(&original).expect("Encode failed");
        let decoded = codec.decode(&encoded).expect("Decode failed");

        assert_eq!(
            std::mem::discriminant(&original),
            std::mem::discriminant(&decoded)
        );
    }

    #[test]
    fn test_roundtrip_vote_message() {
        let codec = BincodeConsensusCodec::new();
        let original = create_test_message(1);

        let encoded = codec.encode(&original).expect("Encode failed");
        let decoded = codec.decode(&encoded).expect("Decode failed");

        assert_eq!(
            std::mem::discriminant(&original),
            std::mem::discriminant(&decoded)
        );
    }

    // CONS-201: `test_roundtrip_commit_message` and
    // `test_roundtrip_round_change_message` were deleted along with the
    // `Commit` and `RoundChange` variants.

    #[test]
    fn test_roundtrip_heartbeat_message() {
        let codec = BincodeConsensusCodec::new();
        let original = create_test_message(2);

        let encoded = codec.encode(&original).expect("Encode failed");
        let decoded = codec.decode(&encoded).expect("Decode failed");

        assert_eq!(
            std::mem::discriminant(&original),
            std::mem::discriminant(&decoded)
        );
    }

    // ===== FRAMING TESTS (CM-5) =====

    #[test]
    fn test_frame_unframe_roundtrip() {
        let codec = BincodeConsensusCodec::new();
        let payload = vec![1, 2, 3, 4, 5];

        let framed = codec.frame(&payload).expect("Frame failed");
        let (version, unframed) = codec.unframe(&framed).expect("Unframe failed");

        assert_eq!(version, CONSENSUS_CODEC_VERSION);
        assert_eq!(payload, unframed);
    }

    // ===== PARTIAL BUFFER TESTS (CM-6) =====

    #[test]
    fn test_unframe_empty_buffer() {
        let codec = BincodeConsensusCodec::new();

        let result = codec.unframe(&[]);
        assert!(matches!(
            result,
            Err(CodecError::Incomplete {
                expected: FRAME_HEADER_SIZE,
                actual: 0
            })
        ));
    }

    #[test]
    fn test_unframe_partial_header() {
        let codec = BincodeConsensusCodec::new();

        // 1 byte (need 5)
        let result = codec.unframe(&[0x00]);
        assert!(matches!(result, Err(CodecError::Incomplete { .. })));

        // 4 bytes (need 5 for header)
        let result = codec.unframe(&[0x00, 0x00, 0x00, 0x10]);
        assert!(matches!(result, Err(CodecError::Incomplete { .. })));
    }

    #[test]
    fn test_unframe_partial_payload() {
        let codec = BincodeConsensusCodec::new();

        // Header says 100 bytes, but only provide 50
        let mut partial = vec![0x00, 0x00, 0x00, 0x64]; // length = 100
        partial.push(CONSENSUS_CODEC_VERSION);
        partial.extend(vec![0u8; 50]); // Only 50 bytes

        let result = codec.unframe(&partial);
        assert!(matches!(
            result,
            Err(CodecError::Incomplete {
                expected: 105,
                actual: 55
            })
        ));
    }

    // ===== SIZE VALIDATION TESTS (CM-7, CM-13) =====

    #[test]
    fn test_frame_oversized_payload() {
        let codec = BincodeConsensusCodec::new();

        // Create MAX + 1 byte payload
        let oversized = vec![0u8; MAX_CONSENSUS_MESSAGE_SIZE + 1];

        let result = codec.frame(&oversized);
        assert!(matches!(result, Err(CodecError::SizeViolation(_, _))));
    }

    #[test]
    fn test_unframe_oversized_length_prefix() {
        let codec = BincodeConsensusCodec::new();

        // Length prefix claims 9 MB (exceeds limit)
        let oversized_len = (MAX_CONSENSUS_MESSAGE_SIZE + 1024) as u32;
        let mut framed = oversized_len.to_be_bytes().to_vec();
        framed.push(CONSENSUS_CODEC_VERSION);

        let result = codec.unframe(&framed);
        assert!(matches!(result, Err(CodecError::SizeViolation(_, _))));
    }

    #[test]
    fn test_frame_max_size_message() {
        let codec = BincodeConsensusCodec::new();

        // Create exactly MAX size payload
        let max_payload = vec![0u8; MAX_CONSENSUS_MESSAGE_SIZE];

        let result = codec.frame(&max_payload);
        assert!(result.is_ok());

        let framed = result.unwrap();
        assert_eq!(framed.len(), FRAME_HEADER_SIZE + MAX_CONSENSUS_MESSAGE_SIZE);
    }

    // ===== VERSION TESTS (CM-9) =====

    #[test]
    fn test_unframe_unknown_version() {
        let codec = BincodeConsensusCodec::new();

        let mut framed = vec![0x00, 0x00, 0x00, 0x10]; // length = 16
        framed.push(99); // Unknown version
        framed.extend(vec![0u8; 16]);

        let result = codec.unframe(&framed);
        assert!(matches!(
            result,
            Err(CodecError::UnsupportedVersion(99, CONSENSUS_CODEC_VERSION))
        ));
    }

    #[test]
    fn test_unframe_correct_version() {
        let codec = BincodeConsensusCodec::new();

        let mut framed = vec![0x00, 0x00, 0x00, 0x05]; // length = 5
        framed.push(CONSENSUS_CODEC_VERSION);
        framed.extend(vec![1, 2, 3, 4, 5]);

        let result = codec.unframe(&framed);
        assert!(result.is_ok());

        let (version, payload) = result.unwrap();
        assert_eq!(version, CONSENSUS_CODEC_VERSION);
        assert_eq!(payload, vec![1, 2, 3, 4, 5]);
    }

    // ===== CORRUPTION TESTS (CM-10) =====

    #[test]
    fn test_decode_corrupted_bincode() {
        let codec = BincodeConsensusCodec::new();

        // Completely invalid bincode data
        let corrupted = vec![0xFF; 100];

        let result = codec.decode(&corrupted);
        assert!(matches!(result, Err(CodecError::DeserializationFailed(_))));
    }

    // ===== DETERMINISM TESTS (CM-3) =====

    #[test]
    fn test_encode_determinism() {
        let codec = BincodeConsensusCodec::new();
        let message = create_test_message(0);

        let encoded1 = codec.encode(&message).expect("First encode failed");
        let encoded2 = codec.encode(&message).expect("Second encode failed");
        let encoded3 = codec.encode(&message).expect("Third encode failed");

        assert_eq!(encoded1, encoded2);
        assert_eq!(encoded2, encoded3);
    }

    // ===== EDGE CASES =====

    #[test]
    fn test_empty_payload_framing() {
        let codec = BincodeConsensusCodec::new();

        let empty = vec![];
        let framed = codec.frame(&empty).expect("Frame empty failed");

        // Should have header (5 bytes) + 0 bytes payload
        assert_eq!(framed.len(), FRAME_HEADER_SIZE);

        let (version, payload) = codec.unframe(&framed).expect("Unframe failed");
        assert_eq!(version, CONSENSUS_CODEC_VERSION);
        assert_eq!(payload.len(), 0);
    }

    #[test]
    fn test_multiple_frames_concatenated() {
        let codec = BincodeConsensusCodec::new();

        let msg1 = create_test_message(0);
        let msg2 = create_test_message(1);

        let framed1 = codec.encode_framed(&msg1).expect("Encode1 failed");
        let framed2 = codec.encode_framed(&msg2).expect("Encode2 failed");

        // Concatenate frames
        let mut combined = framed1.clone();
        combined.extend_from_slice(&framed2);

        // Parse first frame
        let (v1, p1) = codec
            .unframe(&combined[..framed1.len()])
            .expect("Unframe1 failed");
        let decoded1 = codec.decode(&p1).expect("Decode1 failed");

        // Parse second frame
        let (v2, p2) = codec
            .unframe(&combined[framed1.len()..])
            .expect("Unframe2 failed");
        let decoded2 = codec.decode(&p2).expect("Decode2 failed");

        assert_eq!(v1, CONSENSUS_CODEC_VERSION);
        assert_eq!(v2, CONSENSUS_CODEC_VERSION);
        assert!(matches!(decoded1, ValidatorMessage::Propose(_)));
        assert!(matches!(decoded2, ValidatorMessage::Vote(_)));
    }

    #[test]
    fn test_trailing_garbage_in_buffer() {
        let codec = BincodeConsensusCodec::new();

        let payload = vec![1, 2, 3, 4, 5];
        let framed = codec.frame(&payload).expect("Frame failed");

        // Add trailing garbage
        let mut with_garbage = framed.clone();
        with_garbage.extend(vec![99, 99, 99]);

        // unframe should still work, only consuming the expected bytes
        let (version, unframed) = codec.unframe(&with_garbage).expect("Unframe failed");
        assert_eq!(version, CONSENSUS_CODEC_VERSION);
        assert_eq!(unframed, payload);
        // Note: garbage is not consumed, caller must handle
    }

    #[test]
    fn test_fuzz_random_bytes() {
        use rand::Rng;

        let codec = BincodeConsensusCodec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let len = rng.gen_range(0..1000);
            let random_bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();

            // These calls should never panic
            let _ = codec.unframe(&random_bytes);
            let _ = codec.decode(&random_bytes);
        }
    }

    // ===== FULL INTEGRATION TESTS =====

    #[test]
    fn test_full_codec_roundtrip_all_variants() {
        let codec = BincodeConsensusCodec::new();

        // CONS-201: collapsed from 5 variants (Propose / Vote / Commit /
        // RoundChange / Heartbeat) to 3 (Propose / Vote / Heartbeat).
        for variant in 0..3 {
            let original = create_test_message(variant);
            let framed = codec
                .encode_framed(&original)
                .expect(&format!("Encode variant {} failed", variant));
            let decoded = codec
                .decode_framed(&framed)
                .expect(&format!("Decode variant {} failed", variant));

            assert_eq!(
                std::mem::discriminant(&original),
                std::mem::discriminant(&decoded),
                "Variant {} mismatch",
                variant
            );
        }
    }

    // ===== WIRE-FORMAT BYTE-STABILITY (CONS-601) =====
    //
    // Pin specific bytes for fixed-input messages so any change to the
    // codec layout (variant tag width, field reorder, derive change)
    // breaks these tests with a clear diff. The fixtures use
    // deterministic inputs (zero hashes, zero IdentityIds, zero
    // signatures) to keep the expected output byte-stable across runs.
    //
    // CRITICAL: when these tests fail, the wire format CHANGED. That's
    // a CONSENSUS_PROTOCOL_VERSION bump per CONS-203. Bump
    // `lib-consensus/src/engines/consensus_engine/mod.rs::
    // CONSENSUS_PROTOCOL_VERSION` and regenerate the expected byte
    // sequences below. DO NOT silently update the expected bytes
    // without a version bump.

    #[cfg(test)]
    mod byte_stability {
        use super::super::*;
        use lib_consensus_core::types::{
            ConsensusProof, ConsensusProposal, ConsensusStateView, ConsensusVote,
            HeartbeatMessage, NetworkSummary, ProposeMessage, ValidatorMessage, VoteMessage,
        };
        use lib_crypto::{Hash, PostQuantumSignature};
        use lib_identity::IdentityId;
        use lib_types::consensus::{ConsensusStep, ConsensusType, VoteType};

        /// Construct a fully-zero `ValidatorMessage` of the given
        /// variant for stable-byte testing. All hashes, signatures,
        /// and identities are zero-filled so the bincode output is
        /// deterministic and byte-stable across runs.
        fn zero_message(variant: u8) -> ValidatorMessage {
            let zero_hash = Hash::default();
            let zero_id = IdentityId::default();
            let zero_sig = PostQuantumSignature::default();
            let zero_proof = ConsensusProof::empty(ConsensusType::ByzantineFaultTolerance, 0);
            let zero_proposal = ConsensusProposal {
                id: zero_hash.clone(),
                proposer: zero_id.clone(),
                height: 0,
                round: 0,
                protocol_version: 0,
                previous_hash: zero_hash.clone(),
                block_data: vec![],
                timestamp: 0,
                signature: zero_sig.clone(),
                consensus_proof: zero_proof,
            };
            let zero_vote = ConsensusVote {
                id: zero_hash.clone(),
                voter: zero_id.clone(),
                proposal_id: zero_hash.clone(),
                vote_type: VoteType::PreVote,
                height: 0,
                round: 0,
                timestamp: 0,
                signature: zero_sig.clone(),
            };
            match variant {
                0 => ValidatorMessage::Propose(ProposeMessage {
                    message_id: zero_hash.clone(),
                    proposer: zero_id,
                    proposal: zero_proposal,
                    justification: None,
                    timestamp: 0,
                    signature: zero_sig,
                }),
                1 => ValidatorMessage::Vote(VoteMessage {
                    message_id: zero_hash.clone(),
                    voter: zero_id.clone(),
                    vote: zero_vote,
                    consensus_state: ConsensusStateView {
                        height: 0,
                        round: 0,
                        step: ConsensusStep::Propose,
                        known_proposals: vec![],
                        vote_counts: std::collections::BTreeMap::new(),
                    },
                    timestamp: 0,
                    signature: zero_sig,
                }),
                2 => ValidatorMessage::Heartbeat(HeartbeatMessage {
                    message_id: zero_hash.clone(),
                    validator: zero_id,
                    height: 0,
                    round: 0,
                    step: ConsensusStep::Propose,
                    network_summary: NetworkSummary {
                        active_validators: 0,
                        health_score: 0.0,
                        block_rate: 0.0,
                    },
                    timestamp: 0,
                    signature: zero_sig,
                }),
                _ => panic!("invalid variant"),
            }
        }

        /// Pin the encoded byte length of each variant. Length-only
        /// pinning is more robust than full byte sequences (which
        /// vary if `PostQuantumSignature::default()` changes its
        /// internal layout) but still catches accidental field
        /// additions / removals — those change the byte count.
        ///
        /// Run with `--nocapture` to see actual lengths when this
        /// fails; update the expected values **and** bump
        /// `CONSENSUS_PROTOCOL_VERSION` per CONS-203.
        #[test]
        fn propose_message_byte_length_is_pinned() {
            let codec = BincodeConsensusCodec::new();
            let encoded = codec.encode(&zero_message(0)).expect("encode");
            // Bincode-encoded zero ProposeMessage. If this changes,
            // bump CONSENSUS_PROTOCOL_VERSION.
            assert_eq!(
                encoded.len(),
                8_677,
                "ProposeMessage encoded length changed — wire format \
                 drifted. Bump CONSENSUS_PROTOCOL_VERSION (CONS-203)."
            );
        }

        #[test]
        fn vote_message_byte_length_is_pinned() {
            let codec = BincodeConsensusCodec::new();
            let encoded = codec.encode(&zero_message(1)).expect("encode");
            assert_eq!(
                encoded.len(),
                8_684,
                "VoteMessage encoded length changed — wire format \
                 drifted. Bump CONSENSUS_PROTOCOL_VERSION (CONS-203)."
            );
        }

        #[test]
        fn heartbeat_message_byte_length_is_pinned() {
            let codec = BincodeConsensusCodec::new();
            let encoded = codec.encode(&zero_message(2)).expect("encode");
            assert_eq!(
                encoded.len(),
                4_340,
                "HeartbeatMessage encoded length changed — wire format \
                 drifted. Bump CONSENSUS_PROTOCOL_VERSION (CONS-203)."
            );
        }

        /// Variant tag pinning. Bincode encodes enum discriminants as
        /// `u32` little-endian. If the variant order in
        /// `ValidatorMessage` changes, this test breaks loudly —
        /// older nodes would deserialize a Vote as a Heartbeat etc.,
        /// catastrophic on the wire.
        #[test]
        fn variant_tags_are_zero_one_two() {
            let codec = BincodeConsensusCodec::new();
            for (variant, expected_tag) in &[(0u8, 0u32), (1, 1), (2, 2)] {
                let encoded = codec.encode(&zero_message(*variant)).expect("encode");
                let tag = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
                assert_eq!(
                    tag, *expected_tag,
                    "Variant {} tag drifted: expected {}, got {}. \
                     Reordering ValidatorMessage variants is a wire-format \
                     break — bump CONSENSUS_PROTOCOL_VERSION (CONS-203).",
                    variant, expected_tag, tag
                );
            }
        }
    }
}
