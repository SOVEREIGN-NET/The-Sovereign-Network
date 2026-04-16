//! Real Bulletproofs range proof implementation.
//!
//! Replaces the fake Blake3-backed stub with actual zero-knowledge
//! range proofs using the `bulletproofs` crate over Ristretto255.

use anyhow::{anyhow, Result};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

const TRANSCRIPT_LABEL: &[u8] = b"ZHTP Bulletproofs RangeProof v1";

/// Compute the bit length needed for a range proof covering `[min, max]`.
///
/// Bulletproofs only supports bit sizes of 8, 16, 32, or 64.
/// We shift the interval by `min`, so the effective range size is
/// `max - min + 1`.  The result is rounded up to the next supported
/// power of two.
fn bit_length_for_range(min_value: u64, max_value: u64) -> usize {
    let size = max_value.saturating_sub(min_value).saturating_add(1);
    let bits = if size <= 1 {
        8
    } else {
        size.next_power_of_two().trailing_zeros() as usize
    };
    match bits {
        1..=8 => 8,
        9..=16 => 16,
        17..=32 => 32,
        _ => 64,
    }
}

/// Generate a Bulletproofs range proof for `value ∈ [min_value, max_value]`.
///
/// Returns `(proof_bytes, commitment_bytes)` where the commitment is a
/// compressed Ristretto point to `value - min_value`.
pub fn prove_range(
    value: u64,
    min_value: u64,
    max_value: u64,
    blinding: [u8; 32],
) -> Result<(Vec<u8>, [u8; 32])> {
    if value < min_value || value > max_value {
        return Err(anyhow!(
            "Value {} out of range [{}, {}]",
            value,
            min_value,
            max_value
        ));
    }

    let shifted = value - min_value;
    let bit_length = bit_length_for_range(min_value, max_value);

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(bit_length, 1);

    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    transcript.append_message(b"min", &min_value.to_le_bytes());
    transcript.append_message(b"max", &max_value.to_le_bytes());

    // Convert blinding bytes to a Scalar.
    // We clamp the bytes using from_canonical_bytes to ensure a valid scalar.
    let blinding_scalar = Scalar::from_bytes_mod_order(blinding);

    let (proof, commitment) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        shifted as u64,
        &blinding_scalar,
        bit_length,
    )
    .map_err(|e| anyhow!("Bulletproofs prove_range failed: {:?}", e))?;

    let proof_bytes = proof.to_bytes();
    let commitment_bytes = commitment.to_bytes();

    Ok((proof_bytes, commitment_bytes))
}

/// Verify a Bulletproofs range proof.
///
/// The proof must demonstrate that the committed shifted value lies in
/// `[0, 2^bit_length)`, which is equivalent to the original value lying
/// in `[min_value, min_value + 2^bit_length)`.
pub fn verify_range(
    proof_bytes: &[u8],
    commitment_bytes: &[u8; 32],
    min_value: u64,
    max_value: u64,
) -> Result<bool> {
    let bit_length = bit_length_for_range(min_value, max_value);

    let proof = RangeProof::from_bytes(proof_bytes)
        .map_err(|e| anyhow!("Invalid Bulletproofs range proof bytes: {:?}", e))?;

    let commitment = CompressedRistretto::from_slice(commitment_bytes)
        .map_err(|e| anyhow!("Invalid Ristretto commitment: {:?}", e))?;

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(bit_length, 1);

    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    transcript.append_message(b"min", &min_value.to_le_bytes());
    transcript.append_message(b"max", &max_value.to_le_bytes());

    match proof.verify_single(&bp_gens, &pc_gens, &mut transcript, &commitment, bit_length) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::random::SecureRng;

    #[test]
    fn test_bulletproofs_range_proof_roundtrip() {
        let mut rng = SecureRng::new();
        let blinding = rng.generate_key_material();
        let value = 42u64;
        let min = 18u64;
        let max = 150u64;

        let (proof_bytes, commitment) = prove_range(value, min, max, blinding).unwrap();
        assert!(verify_range(&proof_bytes, &commitment, min, max).unwrap());
    }

    #[test]
    fn test_bulletproofs_range_proof_wrong_range_fails() {
        let mut rng = SecureRng::new();
        let blinding = rng.generate_key_material();
        let value = 42u64;
        let min = 18u64;
        let max = 150u64;

        let (proof_bytes, commitment) = prove_range(value, min, max, blinding).unwrap();
        // Verify against a different range should fail
        assert!(!verify_range(&proof_bytes, &commitment, 0, 10).unwrap());
    }

    #[test]
    fn test_bulletproofs_range_proof_out_of_range_rejected_at_generation() {
        let mut rng = SecureRng::new();
        let blinding = rng.generate_key_material();
        assert!(prove_range(10, 18, 150, blinding).is_err());
    }
}
