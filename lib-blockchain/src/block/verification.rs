//! BFT quorum proof verification.
//!
//! Verifies that a block was finalized by BFT consensus by checking
//! the commit vote signatures in a [`BftQuorumProof`] against a known
//! set of validator consensus keys.

use lib_types::consensus::{compute_bft_quorum_root, BftQuorumProof};
use std::collections::{HashMap, HashSet};

/// Extract the proposal_id that a proof attests to.
///
/// Verifies that all attestations in the proof agree on the same proposal_id,
/// and returns that proposal_id. This ensures the proof is internally consistent.
///
/// # Errors
/// Returns an error if attestations have conflicting proposal_ids.
pub fn extract_consistent_proposal_id(proof: &BftQuorumProof) -> Result<[u8; 32], String> {
    if proof.attestations.is_empty() {
        return Err("proof has no attestations".to_string());
    }

    let expected_proposal_id = proof.proposal_id;

    // Verify all attestations are for the same proposal_id
    for (i, att) in proof.attestations.iter().enumerate() {
        if att.proposal_id != expected_proposal_id {
            return Err(format!(
                "attestation {} has mismatched proposal_id: expected {}, got {}. \
                 Proof contains attestations for different proposals.",
                i,
                hex::encode(&expected_proposal_id[..8]),
                hex::encode(&att.proposal_id[..8]),
            ));
        }
    }

    Ok(expected_proposal_id)
}

/// Verify a BFT quorum proof is bound to a specific proposal.
///
/// This prevents replay attacks where a valid proof for one proposal is
/// applied to a different block at the same height.
///
/// # Arguments
/// * `proof` — The quorum proof to verify.
/// * `expected_proposal_id` — The proposal ID that the proof must attest to.
///   This binds the proof to a specific block content.
/// * `validator_keys` — Mapping of validator IDs to consensus keys.
///
/// # Security
/// This function verifies that:
/// 1. All attestations in the proof are for the same proposal_id
/// 2. The proof's proposal_id matches the expected_proposal_id
/// 3. The signatures are valid and from known validators
/// 4. The quorum threshold is met based on local validator set size
pub fn verify_quorum_proof_for_proposal(
    proof: &BftQuorumProof,
    expected_proposal_id: &[u8; 32],
    validator_keys: &HashMap<[u8; 32], [u8; 2592]>,
) -> Result<(), String> {
    // SECURITY: Verify proof is bound to the expected proposal.
    // This prevents replay attacks where a valid proof for proposal A
    // is applied to a different block B at the same height.
    if proof.proposal_id.as_slice() != expected_proposal_id.as_slice() {
        return Err(format!(
            "proposal ID mismatch: proof attests to {}, expected {}. \
             This may be a replay attack with a proof for a different block.",
            hex::encode(&proof.proposal_id[..8]),
            hex::encode(&expected_proposal_id[..8]),
        ));
    }

    // Verify all attestations are for the same proposal_id
    for (i, att) in proof.attestations.iter().enumerate() {
        if att.proposal_id.as_slice() != expected_proposal_id.as_slice() {
            return Err(format!(
                "attestation {} has mismatched proposal_id: expected {}, got {}. \
                 Proof contains attestations for different proposals.",
                i,
                hex::encode(&expected_proposal_id[..8]),
                hex::encode(&att.proposal_id[..8]),
            ));
        }
    }

    // Delegate to base verification for signature and quorum checks
    verify_quorum_proof(proof, validator_keys)
}

/// Verify that a quorum proof matches the block header root committed by the
/// finalized block.
pub fn verify_quorum_root_binding(
    proof: &BftQuorumProof,
    expected_bft_quorum_root: &[u8; 32],
) -> Result<(), String> {
    let actual_root = compute_bft_quorum_root(proof);
    if &actual_root != expected_bft_quorum_root {
        return Err(format!(
            "bft_quorum_root mismatch: proof root {} does not match block header root {}",
            hex::encode(&actual_root[..8]),
            hex::encode(&expected_bft_quorum_root[..8]),
        ));
    }
    Ok(())
}

/// Verify a BFT quorum proof against a known validator key set.
///
/// # Arguments
/// * `proof` — The quorum proof to verify.
/// * `validator_keys` — Mapping of `validator_id` bytes → registered Dilithium
///   public key bytes.  These must come from the local validator registry,
///   NOT from the proof itself (a malicious peer could forge both).
///
/// # Verification steps
///
/// 1. Check that the proof carries at least `(2n/3) + 1` attestations.
/// 2. For each attestation:
///    a. Reject duplicates (same validator_id).
///    b. Look up the validator's registered consensus key.
///    c. Verify the attestation's public key matches the registered key.
///    d. Reconstruct the vote signing envelope and verify the Dilithium
///       signature.
/// 3. Accept if the number of valid, unique attestations meets the quorum
///    threshold.
pub fn verify_quorum_proof(
    proof: &BftQuorumProof,
    validator_keys: &HashMap<[u8; 32], [u8; 2592]>,
) -> Result<(), String> {
    use lib_types::consensus::threshold::has_supermajority;

    // SECURITY: Use local validator set size as source of truth.
    // Do NOT trust peer-controlled proof.total_validators for quorum threshold.
    // A malicious peer could underreport committee size to accept forged proofs.
    // Example: local set has 7 validators (threshold 5), peer claims 4 (threshold 3).
    let local_validator_count = validator_keys.len() as u64;
    if local_validator_count == 0 {
        return Err("local validator set is empty".to_string());
    }

    // Sanity check: proof's claimed total should match local set size.
    // A mismatch indicates the peer is on a different fork or lying.
    if proof.total_validators as u64 != local_validator_count {
        return Err(format!(
            "validator set size mismatch: proof claims {} validators, local set has {}. \
             Peer may be on different fork or proof is forged",
            proof.total_validators, local_validator_count
        ));
    }

    let n = local_validator_count;

    if !has_supermajority(proof.attestations.len() as u64, n) {
        return Err(format!(
            "insufficient attestations: {} / {} does not meet supermajority",
            proof.attestations.len(),
            n
        ));
    }

    // Phase 1: Validate attestation semantics (cheap checks first)
    let mut seen = HashSet::new();
    for att in &proof.attestations {
        // Reject duplicates
        if !seen.insert(att.validator_id) {
            return Err(format!(
                "duplicate attestation from validator {}",
                hex::encode(&att.validator_id[..8]),
            ));
        }

        // Look up registered consensus key
        let registered_key = validator_keys.get(&att.validator_id).ok_or_else(|| {
            format!(
                "unknown validator {} in quorum proof",
                hex::encode(&att.validator_id[..8]),
            )
        })?;

        // Key in attestation must match registered key
        if att.public_key.as_slice() != registered_key.as_slice() {
            return Err(format!(
                "public key mismatch for validator {}",
                hex::encode(&att.validator_id[..8]),
            ));
        }
    }

    // Phase 2: Verify signatures (expensive crypto operations)
    let mut valid_count = 0u64;
    for att in &proof.attestations {
        let envelope = BftQuorumProof::reconstruct_vote_envelope(att, proof.height);

        let att_public_key_array: [u8; 2592] = match att.public_key.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return Err("invalid attestation public key length, expected 2592 bytes".to_string()),
        };
        let public_key = lib_crypto::PublicKey::new(att_public_key_array);
        let signature = lib_crypto::PostQuantumSignature {
            signature: att.signature.to_vec(),
            public_key: public_key.clone(),
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };

        match public_key.verify(&envelope, &signature) {
            Ok(true) => valid_count += 1,
            Ok(false) => {
                return Err(format!(
                    "invalid signature from validator {}",
                    hex::encode(&att.validator_id[..8]),
                ));
            }
            Err(e) => {
                return Err(format!(
                    "signature verification error for validator {}: {}",
                    hex::encode(&att.validator_id[..8]),
                    e,
                ));
            }
        }
    }

    if has_supermajority(valid_count, n) {
        Ok(())
    } else {
        Err(format!(
            "only {} valid attestations out of {} — does not meet supermajority",
            valid_count, n
        ))
    }
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
