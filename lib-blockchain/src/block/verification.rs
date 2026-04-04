//! BFT quorum proof verification.
//!
//! Verifies that a block was finalized by BFT consensus by checking
//! the commit vote signatures in a [`BftQuorumProof`] against a known
//! set of validator consensus keys.

use lib_types::consensus::BftQuorumProof;
use std::collections::{HashMap, HashSet};

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
    validator_keys: &HashMap<[u8; 32], Vec<u8>>,
) -> Result<(), String> {
    use lib_types::consensus::threshold::has_supermajority;

    let n = proof.total_validators as u64;
    if n == 0 {
        return Err("total_validators is zero".to_string());
    }

    if !has_supermajority(proof.attestations.len() as u64, n) {
        return Err(format!(
            "insufficient attestations: {} / {} does not meet supermajority",
            proof.attestations.len(),
            n
        ));
    }

    let mut seen = HashSet::new();
    let mut valid_count = 0u64;

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

        // Reconstruct the vote signing envelope and verify
        let envelope =
            BftQuorumProof::reconstruct_vote_envelope(att, proof.height);

        let public_key = lib_crypto::PublicKey::new(att.public_key);
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
