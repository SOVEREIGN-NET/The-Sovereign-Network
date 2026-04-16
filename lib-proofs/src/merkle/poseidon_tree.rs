//! Poseidon-based Merkle tree helpers for Plonky2 circuits.

#[cfg(feature = "real-proofs")]
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{
        hash_types::{HashOut, NUM_HASH_OUT_ELTS},
        merkle_tree::MerkleTree,
        poseidon::PoseidonHash,
    },
};

/// Build a full Poseidon Merkle tree from already-hashed leaf commitments.
///
/// `leaves` must be 4-element Poseidon hash outputs. The tree is padded to
/// `depth` levels with zero hashes. Returns `(root, siblings)` for `leaf_index`.
#[cfg(feature = "real-proofs")]
pub fn build_poseidon_tree_from_hashes(
    leaves: &[[u64; NUM_HASH_OUT_ELTS]],
    leaf_index: usize,
    depth: usize,
) -> anyhow::Result<([u64; NUM_HASH_OUT_ELTS], Vec<[u64; NUM_HASH_OUT_ELTS]>)> {
    type F = GoldilocksField;

    let max_leaves = 1usize << depth;
    if leaves.is_empty() || leaves.len() > max_leaves {
        return Err(anyhow::anyhow!(
            "Leaf count {} out of range [1, {}]",
            leaves.len(),
            max_leaves
        ));
    }
    if leaf_index >= leaves.len() {
        return Err(anyhow::anyhow!(
            "leaf_index {} out of range [0, {})",
            leaf_index,
            leaves.len()
        ));
    }

    let mut padded: Vec<Vec<F>> = leaves
        .iter()
        .map(|leaf| leaf.iter().map(|&v| F::from_canonical_u64(v)).collect())
        .collect();
    let target_len = padded.len().next_power_of_two();
    while padded.len() < target_len {
        padded.push(HashOut::from([F::ZERO; NUM_HASH_OUT_ELTS]).elements.to_vec());
    }
    while padded.len() < max_leaves {
        padded.push(HashOut::from([F::ZERO; NUM_HASH_OUT_ELTS]).elements.to_vec());
    }

    let tree = MerkleTree::<F, PoseidonHash>::new(padded, 0);
    let proof = tree.prove(leaf_index);
    let root = tree.cap.0[0].elements.map(|f| f.to_canonical_u64());

    let mut siblings = Vec::with_capacity(proof.siblings.len());
    for s in &proof.siblings {
        siblings.push(s.elements.map(|f| f.to_canonical_u64()));
    }
    Ok((root, siblings))
}
