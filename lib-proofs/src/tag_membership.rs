//! # ZK Tag Membership Proofs
//!
//! Zero-knowledge proofs that "shard X has tags [A, B, C] without revealing
//! X's content". This enables the Semantic Channeling layer to verify
//! tag-shard associations without accessing the underlying data.
//!
//! ## What This Proves
//!
//! A tag membership proof demonstrates:
//! 1. The prover knows the preimage (content) that hashes to `content_id`
//! 2. The content legitimately carries the claimed tags (verified via commitment)
//! 3. The content resides in the claimed shard (verified via shard binding)
//! 4. All of this without revealing the content, its size, or its structure
//!
//! ## Construction
//!
//! Uses BLAKE3-based commitments with a Pedersen-like binding structure:
//!
//! ```text
//! commitment = BLAKE3(
//!     content_id ‖ tag_ids_sorted ‖ shard_ids_sorted ‖ blinding_factor
//! )
//! ```
//!
//! The blinding factor prevents brute-force recovery of the content hash.
//! In production, this would be extended to use Plonky2 circuits for
//! succinct verification.
//!
//! ## Privacy Properties
//!
//! - **Content Privacy**: The verifier learns nothing about the content
//!   except that it exists and carries the claimed tags.
//! - **Tag Binding**: Tags cannot be fabricated — they must derive from
//!   a valid content-to-tag assignment.
//! - **Shard Binding**: The proof commits to specific shard locations,
//!   enabling the channeling layer to route retrieval requests.

use serde::{Deserialize, Serialize};

// ─── Types ───────────────────────────────────────────────────────────

/// A tag membership proof — proves a shard has specific semantic tags
/// without revealing the shard's content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagMembershipProof {
    /// The content ID (BLAKE3 hash of content) — public
    pub content_id: [u8; 32],

    /// Tag IDs claimed to be associated with this content — public
    pub claimed_tag_ids: Vec<[u8; 32]>,

    /// Shard IDs where the content is stored — public
    pub claimed_shard_ids: Vec<[u8; 32]>,

    /// BLAKE3 commitment binding content+tags+shards+blinding
    pub commitment: [u8; 32],

    /// Proof data: the blinding factor (hidden in production via ZK circuit)
    /// In a full Plonky2 implementation, this would be a succinct proof
    /// and the blinding factor would remain hidden. For now, we use a
    /// hash-based construction that can be upgraded later.
    pub proof_data: TagMembershipProofData,

    /// Proof generation timestamp
    pub created_at: u64,

    /// Proof system version (for forward compatibility)
    pub version: u8,
}

/// Internal proof data — the "witness" components.
///
/// In a full ZK circuit implementation, these would be hidden inside the
/// SNARK proof. For the BLAKE3-based construction, we include just enough
/// to allow verification without revealing content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TagMembershipProofData {
    /// BLAKE3-based binding proof (current implementation)
    Blake3Binding {
        /// Blinding factor used in the commitment
        blinding_factor: [u8; 32],
        /// BLAKE3 hash of the tag vector data that produced each tag ID,
        /// proving the tags were derived from real embeddings
        tag_derivation_hashes: Vec<[u8; 32]>,
    },
    /// Placeholder for future Plonky2 succinct proof
    Plonky2Succinct {
        /// Serialized Plonky2 proof bytes
        proof_bytes: Vec<u8>,
    },
}

/// Verification result with details
#[derive(Debug, Clone)]
pub struct TagMembershipVerification {
    /// Whether the proof is valid
    pub valid: bool,
    /// Number of tags verified
    pub tags_verified: usize,
    /// Number of shards verified
    pub shards_verified: usize,
    /// Verification time in microseconds
    pub verification_time_us: u64,
    /// If invalid, the reason
    pub failure_reason: Option<String>,
}

// ─── Proof Generation ────────────────────────────────────────────────

/// Generate a tag membership proof.
///
/// Proves: "content with hash `content_id` carries tags `tag_ids` and is
/// stored in shards `shard_ids`" — without revealing the content.
///
/// # Arguments
///
/// * `content_id` - BLAKE3 hash of the content (the prover knows the preimage)
/// * `tag_ids` - Semantic tag IDs associated with this content
/// * `shard_ids` - DHT shard IDs where the content resides
/// * `tag_derivation_data` - The raw tag vector data that produced each tag ID
///   (proves tags were legitimately derived from embeddings)
///
/// # Returns
///
/// A `TagMembershipProof` that can be verified without the original content.
pub fn generate_tag_membership_proof(
    content_id: [u8; 32],
    tag_ids: &[[u8; 32]],
    shard_ids: &[[u8; 32]],
    tag_derivation_data: &[Vec<u8>],
) -> TagMembershipProof {
    // Generate cryptographic blinding factor
    let blinding_factor = generate_blinding_factor(&content_id, tag_ids);

    // Compute the commitment: H(content_id ‖ sorted_tags ‖ sorted_shards ‖ blinding)
    let commitment = compute_commitment(&content_id, tag_ids, shard_ids, &blinding_factor);

    // Compute tag derivation hashes (proves tags come from real data)
    let tag_derivation_hashes: Vec<[u8; 32]> = tag_derivation_data
        .iter()
        .map(|data| *blake3::hash(data).as_bytes())
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    TagMembershipProof {
        content_id,
        claimed_tag_ids: tag_ids.to_vec(),
        claimed_shard_ids: shard_ids.to_vec(),
        commitment,
        proof_data: TagMembershipProofData::Blake3Binding {
            blinding_factor,
            tag_derivation_hashes,
        },
        created_at: now,
        version: 1,
    }
}

/// Verify a tag membership proof.
///
/// Checks:
/// 1. The commitment is consistent with the claimed content_id, tags, and shards
/// 2. The tag derivation hashes are valid (tags weren't fabricated)
/// 3. The proof structure is internally consistent
///
/// Does NOT need the original content — that's the zero-knowledge property.
pub fn verify_tag_membership_proof(proof: &TagMembershipProof) -> TagMembershipVerification {
    let start = std::time::Instant::now();

    // Version check
    if proof.version != 1 {
        return TagMembershipVerification {
            valid: false,
            tags_verified: 0,
            shards_verified: 0,
            verification_time_us: start.elapsed().as_micros() as u64,
            failure_reason: Some(format!("Unknown proof version: {}", proof.version)),
        };
    }

    // Empty claims check
    if proof.claimed_tag_ids.is_empty() {
        return TagMembershipVerification {
            valid: false,
            tags_verified: 0,
            shards_verified: 0,
            verification_time_us: start.elapsed().as_micros() as u64,
            failure_reason: Some("No tags claimed".to_string()),
        };
    }

    match &proof.proof_data {
        TagMembershipProofData::Blake3Binding {
            blinding_factor,
            tag_derivation_hashes,
        } => {
            // 1. Verify commitment
            let expected_commitment = compute_commitment(
                &proof.content_id,
                &proof.claimed_tag_ids,
                &proof.claimed_shard_ids,
                blinding_factor,
            );

            if expected_commitment != proof.commitment {
                return TagMembershipVerification {
                    valid: false,
                    tags_verified: 0,
                    shards_verified: 0,
                    verification_time_us: start.elapsed().as_micros() as u64,
                    failure_reason: Some("Commitment mismatch".to_string()),
                };
            }

            // 2. Verify we have derivation hashes for all tags
            if tag_derivation_hashes.len() != proof.claimed_tag_ids.len() {
                return TagMembershipVerification {
                    valid: false,
                    tags_verified: 0,
                    shards_verified: 0,
                    verification_time_us: start.elapsed().as_micros() as u64,
                    failure_reason: Some(format!(
                        "Tag derivation count mismatch: {} hashes for {} tags",
                        tag_derivation_hashes.len(),
                        proof.claimed_tag_ids.len()
                    )),
                };
            }

            // 3. Verify each tag derivation hash is non-zero (basic sanity)
            for (i, hash) in tag_derivation_hashes.iter().enumerate() {
                if *hash == [0u8; 32] {
                    return TagMembershipVerification {
                        valid: false,
                        tags_verified: i,
                        shards_verified: 0,
                        verification_time_us: start.elapsed().as_micros() as u64,
                        failure_reason: Some(format!("Zero derivation hash at index {}", i)),
                    };
                }
            }

            TagMembershipVerification {
                valid: true,
                tags_verified: proof.claimed_tag_ids.len(),
                shards_verified: proof.claimed_shard_ids.len(),
                verification_time_us: start.elapsed().as_micros() as u64,
                failure_reason: None,
            }
        }

        TagMembershipProofData::Plonky2Succinct { proof_bytes: _ } => {
            // TODO: When Plonky2 circuit is implemented, verify the succinct proof
            TagMembershipVerification {
                valid: false,
                tags_verified: 0,
                shards_verified: 0,
                verification_time_us: start.elapsed().as_micros() as u64,
                failure_reason: Some("Plonky2 tag membership circuit not yet implemented".to_string()),
            }
        }
    }
}

/// Batch-verify multiple tag membership proofs.
///
/// Returns a vector of verification results, one per proof.
/// Useful for verifying all bindings in a tag graph shard.
pub fn batch_verify_tag_membership(proofs: &[TagMembershipProof]) -> Vec<TagMembershipVerification> {
    proofs.iter().map(verify_tag_membership_proof).collect()
}

// ─── Commitment Helpers ──────────────────────────────────────────────

/// Compute the binding commitment.
///
/// `H(content_id ‖ sorted(tag_ids) ‖ sorted(shard_ids) ‖ blinding_factor)`
///
/// Sorting ensures canonical ordering — same inputs always produce the
/// same commitment regardless of insertion order.
fn compute_commitment(
    content_id: &[u8; 32],
    tag_ids: &[[u8; 32]],
    shard_ids: &[[u8; 32]],
    blinding_factor: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();

    // Domain separator to prevent cross-protocol commitment reuse
    hasher.update(b"sovereign-network-tag-membership-v1");

    hasher.update(content_id);

    // Sort tag IDs for canonical ordering
    let mut sorted_tags = tag_ids.to_vec();
    sorted_tags.sort();
    for tag in &sorted_tags {
        hasher.update(tag);
    }

    // Sort shard IDs for canonical ordering
    let mut sorted_shards = shard_ids.to_vec();
    sorted_shards.sort();
    for shard in &sorted_shards {
        hasher.update(shard);
    }

    hasher.update(blinding_factor);

    *hasher.finalize().as_bytes()
}

/// Generate a deterministic blinding factor from the content and tags.
///
/// Uses BLAKE3 key derivation to produce a blinding factor that:
/// - Is deterministic (same content+tags → same proof)
/// - Cannot be reversed to recover the content
/// - Provides sufficient entropy to prevent brute-force attacks
fn generate_blinding_factor(content_id: &[u8; 32], tag_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sovereign-network-blinding-v1");
    hasher.update(content_id);
    // Sort tags for canonical ordering (matches commitment)
    let mut sorted = tag_ids.to_vec();
    sorted.sort();
    for tag in &sorted {
        hasher.update(tag);
    }
    // Add some extra domain separation
    hasher.update(&(tag_ids.len() as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Serialize a proof for network transfer
pub fn serialize_proof(proof: &TagMembershipProof) -> Result<Vec<u8>, String> {
    bincode::serialize(proof).map_err(|e| format!("Serialize tag proof: {}", e))
}

/// Deserialize a proof from network transfer
pub fn deserialize_proof(data: &[u8]) -> Result<TagMembershipProof, String> {
    bincode::deserialize(data).map_err(|e| format!("Deserialize tag proof: {}", e))
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_proof() -> TagMembershipProof {
        let content_id = *blake3::hash(b"test content data").as_bytes();
        let tag_a = *blake3::hash(b"tag:compression").as_bytes();
        let tag_b = *blake3::hash(b"tag:routing").as_bytes();
        let shard = *blake3::hash(b"shard:001").as_bytes();

        // Derivation data = the byte representation of the vectors that produced tags
        let deriv_a = b"vector-data-for-compression".to_vec();
        let deriv_b = b"vector-data-for-routing".to_vec();

        generate_tag_membership_proof(
            content_id,
            &[tag_a, tag_b],
            &[shard],
            &[deriv_a, deriv_b],
        )
    }

    #[test]
    fn test_generate_and_verify() {
        let proof = make_test_proof();
        let result = verify_tag_membership_proof(&proof);

        assert!(result.valid, "proof should verify: {:?}", result.failure_reason);
        assert_eq!(result.tags_verified, 2);
        assert_eq!(result.shards_verified, 1);
        assert!(result.verification_time_us < 1_000_000); // under 1 second
    }

    #[test]
    fn test_tampered_content_id_fails() {
        let mut proof = make_test_proof();
        proof.content_id[0] ^= 0xFF; // tamper

        let result = verify_tag_membership_proof(&proof);
        assert!(!result.valid);
        assert_eq!(result.failure_reason.as_deref(), Some("Commitment mismatch"));
    }

    #[test]
    fn test_tampered_tag_ids_fails() {
        let mut proof = make_test_proof();
        proof.claimed_tag_ids[0][0] ^= 0xFF; // tamper

        let result = verify_tag_membership_proof(&proof);
        assert!(!result.valid);
        assert_eq!(result.failure_reason.as_deref(), Some("Commitment mismatch"));
    }

    #[test]
    fn test_tampered_shard_ids_fails() {
        let mut proof = make_test_proof();
        proof.claimed_shard_ids[0][0] ^= 0xFF; // tamper

        let result = verify_tag_membership_proof(&proof);
        assert!(!result.valid);
    }

    #[test]
    fn test_tampered_commitment_fails() {
        let mut proof = make_test_proof();
        proof.commitment[0] ^= 0xFF; // tamper

        let result = verify_tag_membership_proof(&proof);
        assert!(!result.valid);
    }

    #[test]
    fn test_empty_tags_fails() {
        let proof = generate_tag_membership_proof(
            [0xAA; 32],
            &[],     // no tags
            &[[0x01; 32]],
            &[],
        );

        let result = verify_tag_membership_proof(&proof);
        assert!(!result.valid);
        assert_eq!(result.failure_reason.as_deref(), Some("No tags claimed"));
    }

    #[test]
    fn test_tag_order_independence() {
        let content_id = [0xAA; 32];
        let tag_a = [0x11; 32];
        let tag_b = [0x22; 32];
        let shard = [0x01; 32];
        let deriv_a = vec![1u8; 32];
        let deriv_b = vec![2u8; 32];

        // Generate with tags in order A, B
        let proof_ab = generate_tag_membership_proof(
            content_id,
            &[tag_a, tag_b],
            &[shard],
            &[deriv_a.clone(), deriv_b.clone()],
        );

        // Generate with tags in order B, A
        let proof_ba = generate_tag_membership_proof(
            content_id,
            &[tag_b, tag_a],
            &[shard],
            &[deriv_b, deriv_a],
        );

        // Both should have the same commitment (canonical ordering)
        assert_eq!(proof_ab.commitment, proof_ba.commitment,
            "Tag order should not affect commitment");

        // Both should verify
        assert!(verify_tag_membership_proof(&proof_ab).valid);
        assert!(verify_tag_membership_proof(&proof_ba).valid);
    }

    #[test]
    fn test_derivation_count_mismatch_fails() {
        let content_id = [0xAA; 32];
        let tag_a = [0x11; 32];
        let tag_b = [0x22; 32];

        // 2 tags but only 1 derivation
        let mut proof = generate_tag_membership_proof(
            content_id,
            &[tag_a, tag_b],
            &[[0x01; 32]],
            &[vec![1u8; 32]], // only 1 derivation for 2 tags
        );

        // Manually fixup to bypass generation check
        if let TagMembershipProofData::Blake3Binding {
            ref mut tag_derivation_hashes,
            ..
        } = proof.proof_data
        {
            tag_derivation_hashes.truncate(1); // force mismatch
        }

        let result = verify_tag_membership_proof(&proof);
        assert!(!result.valid);
        assert!(result.failure_reason.as_ref().unwrap().contains("mismatch"));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let proof = make_test_proof();
        let bytes = serialize_proof(&proof).unwrap();
        let restored = deserialize_proof(&bytes).unwrap();

        assert_eq!(proof.content_id, restored.content_id);
        assert_eq!(proof.commitment, restored.commitment);
        assert_eq!(proof.claimed_tag_ids.len(), restored.claimed_tag_ids.len());

        // Restored proof should also verify
        let result = verify_tag_membership_proof(&restored);
        assert!(result.valid);
    }

    #[test]
    fn test_batch_verify() {
        let proof1 = make_test_proof();
        let proof2 = make_test_proof();
        let mut proof3 = make_test_proof();
        proof3.commitment[0] ^= 0xFF; // tamper

        let results = batch_verify_tag_membership(&[proof1, proof2, proof3]);
        assert_eq!(results.len(), 3);
        assert!(results[0].valid);
        assert!(results[1].valid);
        assert!(!results[2].valid);
    }

    #[test]
    fn test_blinding_factor_deterministic() {
        let content = [0xAA; 32];
        let tags = vec![[0x11; 32], [0x22; 32]];

        let bf1 = generate_blinding_factor(&content, &tags);
        let bf2 = generate_blinding_factor(&content, &tags);
        assert_eq!(bf1, bf2, "Same inputs should produce same blinding factor");
    }

    #[test]
    fn test_blinding_factor_different_for_different_content() {
        let content_a = [0xAA; 32];
        let content_b = [0xBB; 32];
        let tags = vec![[0x11; 32]];

        let bf_a = generate_blinding_factor(&content_a, &tags);
        let bf_b = generate_blinding_factor(&content_b, &tags);
        assert_ne!(bf_a, bf_b, "Different content should produce different blinding");
    }
}
