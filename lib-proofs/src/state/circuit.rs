//! Plonky2 state Merkle-inclusion circuit.
//!
//! Proves that a specific (account_id, balance) leaf is present in the state
//! Merkle tree with a given root, without revealing the Merkle siblings.
//! This leverages the sparse Merkle tree infrastructure from Epic E.

/// Fixed Merkle tree depth for the state set.
/// Production will use a larger depth (e.g. 32); 4 is used here
/// to keep tests and benchmarks fast while proving the concept.
pub const STATE_MERKLE_DEPTH: usize = 4;

#[cfg(not(feature = "real-proofs"))]
pub mod real {
    use super::STATE_MERKLE_DEPTH;
    use anyhow::Result;

    /// Stub for non-real-proofs builds.
    pub fn prove_state(
        _state_root: [u64; 4],
        _block_height: u64,
        _account_id: u64,
        _balance: u64,
        _merkle_siblings: &[[u64; 4]; STATE_MERKLE_DEPTH],
        _leaf_index: usize,
    ) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    /// Stub for non-real-proofs builds.
    pub fn verify_state(_proof_bytes: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Stub for non-real-proofs builds.
    pub fn build_state_merkle_tree(
        _leaves: &[[u64; 4]],
        _leaf_index: usize,
    ) -> Result<([u64; 4], Vec<[u64; 4]>)> {
        Ok(([0u64; 4], vec![[0u64; 4]; STATE_MERKLE_DEPTH]))
    }
}

#[cfg(feature = "real-proofs")]
pub mod real {
    use super::STATE_MERKLE_DEPTH;
    use anyhow::{anyhow, Result};
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, PrimeField64},
        },
        hash::{
            hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
            hashing::hash_n_to_hash_no_pad,
            merkle_proofs::MerkleProofTarget,
            merkle_tree::MerkleTree,
            poseidon::{PoseidonHash, PoseidonPermutation},
        },
        iop::{
            target::{BoolTarget, Target},
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitData,
            config::PoseidonGoldilocksConfig,
            proof::ProofWithPublicInputs,
        },
    };
    use serde::{Deserialize, Serialize};
    use std::sync::OnceLock;

    pub type StateProof = ProofWithPublicInputs<F, C, D>;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    const NUM_BITS: usize = 64;

    /// Public inputs: [state_root (4), block_height, account_id, balance]
    pub const STATE_PI_LEN: usize = 4 + 3;

    /// Targets for the state circuit.
    #[derive(Clone, Serialize, Deserialize)]
    pub struct StateTargets {
        pub state_root: [Target; NUM_HASH_OUT_ELTS],
        pub block_height: Target,
        pub account_id: Target,
        pub balance: Target,
        pub merkle_siblings: Vec<[Target; NUM_HASH_OUT_ELTS]>,
        pub leaf_index_bits: Vec<Target>,
    }

    impl StateTargets {
        pub fn state_root_ht(&self) -> HashOutTarget {
            HashOutTarget::from(self.state_root)
        }

        pub fn leaf_index_bits_bt(&self) -> Vec<BoolTarget> {
            self.leaf_index_bits
                .iter()
                .copied()
                .map(BoolTarget::new_unsafe)
                .collect()
        }

        pub fn merkle_siblings_mpt(&self) -> MerkleProofTarget {
            MerkleProofTarget {
                siblings: self
                    .merkle_siblings
                    .iter()
                    .copied()
                    .map(HashOutTarget::from)
                    .collect(),
            }
        }
    }

    pub struct StateCircuit {
        pub data: CircuitData<F, C, D>,
        pub targets: StateTargets,
    }

    impl StateCircuit {
        pub fn build() -> Self {
            let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Public inputs
            let state_root = builder.add_virtual_hash_public_input();
            let block_height = builder.add_virtual_public_input();
            let account_id = builder.add_virtual_public_input();
            let balance = builder.add_virtual_public_input();

            // Private Merkle witnesses
            let leaf_index_bits: Vec<BoolTarget> = (0..STATE_MERKLE_DEPTH)
                .map(|_| builder.add_virtual_bool_target_unsafe())
                .collect();
            let merkle_siblings = MerkleProofTarget {
                siblings: (0..STATE_MERKLE_DEPTH)
                    .map(|_| builder.add_virtual_hash())
                    .collect(),
            };

            // Constraint 1: leaf = Poseidon(account_id, balance)
            let leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![account_id, balance]);

            // Constraint 2: Verify Merkle inclusion of leaf under state_root
            builder.verify_merkle_proof::<PoseidonHash>(
                leaf.elements.to_vec(),
                &leaf_index_bits,
                state_root,
                &merkle_siblings,
            );

            // Constraint 3: Range check block_height
            builder.range_check(block_height, NUM_BITS);

            let data = builder.build::<C>();
            Self {
                data,
                targets: StateTargets {
                    state_root: state_root.elements,
                    block_height,
                    account_id,
                    balance,
                    merkle_siblings: merkle_siblings.siblings.iter().map(|s| s.elements).collect(),
                    leaf_index_bits: leaf_index_bits.iter().map(|b| b.target).collect(),
                },
            }
        }
    }

    pub fn circuit() -> &'static StateCircuit {
        static CIRCUIT: OnceLock<StateCircuit> = OnceLock::new();
        CIRCUIT.get_or_init(StateCircuit::build)
    }

    /// Generate a real state Merkle-inclusion proof.
    pub fn prove_state(
        state_root: [u64; 4],
        block_height: u64,
        account_id: u64,
        balance: u64,
        merkle_siblings: &[[u64; 4]; STATE_MERKLE_DEPTH],
        leaf_index: usize,
    ) -> Result<Vec<u8>> {
        let circuit = circuit();
        let mut pw = PartialWitness::new();
        let t = &circuit.targets;

        // Public inputs
        for i in 0..NUM_HASH_OUT_ELTS {
            pw.set_target(t.state_root[i], F::from_canonical_u64(state_root[i]))?;
        }
        pw.set_target(t.block_height, F::from_canonical_u64(block_height))?;
        pw.set_target(t.account_id, F::from_canonical_u64(account_id))?;
        pw.set_target(t.balance, F::from_canonical_u64(balance))?;

        // Private Merkle witnesses
        for (i, bit_target) in t.leaf_index_bits.iter().enumerate() {
            let bit_val = ((leaf_index >> i) & 1) == 1;
            pw.set_bool_target(BoolTarget::new_unsafe(*bit_target), bit_val)?;
        }
        for (i, sibling) in t.merkle_siblings.iter().enumerate() {
            let s: [F; NUM_HASH_OUT_ELTS] = merkle_siblings[i].map(F::from_canonical_u64);
            pw.set_target_arr(sibling, &s)?;
        }

        let proof = circuit.data.prove(pw)?;
        Ok(bincode::serialize(&proof)?)
    }

    /// Verify a real state proof.
    pub fn verify_state(proof_bytes: &[u8]) -> Result<()> {
        let proof: StateProof = bincode::deserialize(proof_bytes)
            .map_err(|e| anyhow!("Failed to deserialize state proof: {:?}", e))?;
        circuit()
            .data
            .verify(proof)
            .map_err(|e| anyhow!("Plonky2 state verification failed: {:?}", e))
    }

    /// Compute the Poseidon leaf hash for an account.
    pub fn compute_state_leaf(account_id: u64, balance: u64) -> [u64; 4] {
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[
            F::from_canonical_u64(account_id),
            F::from_canonical_u64(balance),
        ]);
        hash.elements.map(|e| e.to_canonical_u64())
    }

    /// Build a Poseidon Merkle tree from already-hashed state leaf commitments.
    ///
    /// Each leaf in `leaves` must be a 4-element Poseidon hash output.
    /// Pads to the next power of two up to `1 << STATE_MERKLE_DEPTH` with zero hashes,
    /// builds the tree, and returns (root, siblings) for the requested leaf index.
    pub fn build_state_merkle_tree(
        leaves: &[[u64; NUM_HASH_OUT_ELTS]],
        leaf_index: usize,
    ) -> Result<([u64; NUM_HASH_OUT_ELTS], Vec<[u64; NUM_HASH_OUT_ELTS]>)> {
        let max_leaves = 1usize << STATE_MERKLE_DEPTH;
        if leaves.is_empty() || leaves.len() > max_leaves {
            return Err(anyhow!(
                "Leaf count {} out of range [1, {}]",
                leaves.len(),
                max_leaves
            ));
        }
        if leaf_index >= leaves.len() {
            return Err(anyhow!(
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_circuit_builds() {
        #[cfg(feature = "real-proofs")]
        {
            let _ = real::circuit();
        }
    }

    #[test]
    fn test_valid_state_proof() {
        #[cfg(feature = "real-proofs")]
        {
            let accounts: Vec<(u64, u64)> = vec![
                (1001, 5000),
                (1002, 3000),
                (1003, 7000),
                (1004, 2000),
            ];

            let leaves: Vec<[u64; 4]> = accounts
                .iter()
                .map(|(id, bal)| real::compute_state_leaf(*id, *bal))
                .collect();

            let leaf_index = 2;
            let (root, siblings) = real::build_state_merkle_tree(&leaves, leaf_index).unwrap();

            // Convert siblings to fixed-size array
            let mut siblings_arr = [[0u64; 4]; STATE_MERKLE_DEPTH];
            for (i, s) in siblings.iter().enumerate() {
                siblings_arr[i] = *s;
            }

            let (account_id, balance) = accounts[leaf_index];
            let block_height = 42;

            let proof_bytes = real::prove_state(
                root, block_height, account_id, balance, &siblings_arr, leaf_index,
            )
            .unwrap();

            assert!(!proof_bytes.is_empty());
            real::verify_state(&proof_bytes).unwrap();
        }
    }

    #[test]
    fn test_invalid_state_proof_wrong_balance() {
        #[cfg(feature = "real-proofs")]
        {
            let accounts: Vec<(u64, u64)> = vec![
                (1001, 5000),
                (1002, 3000),
                (1003, 7000),
                (1004, 2000),
            ];

            let leaves: Vec<[u64; 4]> = accounts
                .iter()
                .map(|(id, bal)| real::compute_state_leaf(*id, *bal))
                .collect();

            let leaf_index = 1;
            let (root, siblings) = real::build_state_merkle_tree(&leaves, leaf_index).unwrap();

            let mut siblings_arr = [[0u64; 4]; STATE_MERKLE_DEPTH];
            for (i, s) in siblings.iter().enumerate() {
                siblings_arr[i] = *s;
            }

            let (account_id, _) = accounts[leaf_index];
            let wrong_balance = 9999;
            let block_height = 10;

            // Proving should fail because the wrong balance doesn't satisfy the circuit constraints
            let result = real::prove_state(
                root,
                block_height,
                account_id,
                wrong_balance,
                &siblings_arr,
                leaf_index,
            );
            assert!(result.is_err(), "Expected proof generation to fail with wrong balance");
        }
    }
}
