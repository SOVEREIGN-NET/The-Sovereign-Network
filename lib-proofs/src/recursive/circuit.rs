//! Plonky2 recursive proof aggregation circuit.
//!
//! Provides a recursive circuit that verifies multiple transaction proofs
//! inside a single outer proof, enabling O(1) verification of a batch.

/// Number of transaction proofs verified per recursive batch.
/// Small value keeps test times fast; production can increase.
pub const RECURSIVE_BATCH_SIZE: usize = 2;

#[cfg(not(feature = "real-proofs"))]
pub mod real {
    use anyhow::Result;

    /// Stub for non-real-proofs builds.
    pub fn prove_recursive_batch(
        _tx_proofs: &[crate::transaction::circuit::real::TxProof],
    ) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    /// Stub for non-real-proofs builds.
    pub fn verify_recursive_batch(_proof_bytes: &[u8]) -> Result<()> {
        Ok(())
    }
}

#[cfg(feature = "real-proofs")]
pub mod real {
    use super::RECURSIVE_BATCH_SIZE;
    use anyhow::{anyhow, Result};
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, PrimeField64},
        },
        plonk::config::PoseidonGoldilocksConfig,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitData,
            config::GenericConfig,
            proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
        },
    };
    use std::sync::OnceLock;

    pub type RecursiveBatchProof = ProofWithPublicInputs<F, C, D>;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    pub struct RecursiveBatchCircuit {
        pub data: CircuitData<F, C, D>,
        pub proof_targets: Vec<ProofWithPublicInputsTarget<D>>,
        pub dummy_tx_proof: crate::transaction::circuit::real::TxProof,
    }

    impl RecursiveBatchCircuit {
        pub fn build() -> Self {
            let tx_circuit = crate::transaction::circuit::real::circuit();
            let inner_cd = &tx_circuit.data.common;

            let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let mut proof_targets = Vec::with_capacity(RECURSIVE_BATCH_SIZE);
            for _ in 0..RECURSIVE_BATCH_SIZE {
                let pt = builder.add_virtual_proof_with_pis(inner_cd);
                let inner_vd = builder.constant_verifier_data::<C>(&tx_circuit.data.verifier_only);
                builder.verify_proof::<C>(&pt, &inner_vd, inner_cd);
                proof_targets.push(pt);
            }

            let data = builder.build::<C>();

            // Build a dummy valid transaction proof for padding empty slots.
            let leaf0 = crate::transaction::circuit::real::compute_leaf_commitment(1, 1, 1000);
            let leaves_hashed = vec![leaf0];
            let (root, siblings) =
                crate::transaction::circuit::real::build_merkle_tree_from_hashes(&leaves_hashed, 0)
                    .expect("dummy tree must build");
            let root_f: [F; 4] = root.map(F::from_canonical_u64);
            let mut siblings_f = [[F::ZERO; 4]; crate::transaction::circuit::MERKLE_DEPTH];
            for (i, s) in siblings.iter().enumerate() {
                siblings_f[i] = s.map(F::from_canonical_u64);
            }
            let dummy_tx_proof = crate::transaction::circuit::real::prove_transaction(
                1000, 100, 10, 1, 1, root_f, 0, &siblings_f,
            )
            .expect("dummy proof must generate");

            Self {
                data,
                proof_targets,
                dummy_tx_proof,
            }
        }
    }

    pub fn circuit() -> &'static RecursiveBatchCircuit {
        static CIRCUIT: OnceLock<RecursiveBatchCircuit> = OnceLock::new();
        CIRCUIT.get_or_init(RecursiveBatchCircuit::build)
    }

    /// Generate a recursive batch proof that verifies `tx_proofs`.
    /// The slice length must be in `[1, RECURSIVE_BATCH_SIZE]`.
    pub fn prove_recursive_batch(
        tx_proofs: &[crate::transaction::circuit::real::TxProof],
    ) -> Result<Vec<u8>> {
        if tx_proofs.is_empty() || tx_proofs.len() > RECURSIVE_BATCH_SIZE {
            return Err(anyhow!(
                "Need 1..={} transaction proofs, got {}",
                RECURSIVE_BATCH_SIZE,
                tx_proofs.len()
            ));
        }

        let circuit = circuit();
        let mut pw = PartialWitness::new();

        for i in 0..RECURSIVE_BATCH_SIZE {
            let proof = tx_proofs.get(i).unwrap_or(&circuit.dummy_tx_proof);
            let pt = &circuit.proof_targets[i];
            pw.set_proof_with_pis_target(pt, proof)?;
        }

        let proof = circuit.data.prove(pw)?;
        Ok(bincode::serialize(&proof)?)
    }

    /// Verify a recursive batch proof.
    pub fn verify_recursive_batch(proof_bytes: &[u8]) -> Result<()> {
        let proof: RecursiveBatchProof = bincode::deserialize(proof_bytes)
            .map_err(|e| anyhow!("Failed to deserialize recursive batch proof: {:?}", e))?;
        circuit()
            .data
            .verify(proof)
            .map_err(|e| anyhow!("Plonky2 recursive batch verification failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recursive_batch_circuit_builds() {
        #[cfg(feature = "real-proofs")]
        {
            let _ = real::circuit();
        }
    }

    #[test]
    fn test_recursive_batch_proof_valid() {
        #[cfg(feature = "real-proofs")]
        {
            // Build a small Merkle tree for transaction proofs using hashed leaves
            // so the tree height matches MERKLE_DEPTH.
            let leaf0 = crate::transaction::circuit::real::compute_leaf_commitment(1, 10, 1000);
            let leaf1 = crate::transaction::circuit::real::compute_leaf_commitment(2, 20, 2000);
            let leaves_hashed = vec![leaf0, leaf1];
            let (root, siblings0) =
                crate::transaction::circuit::real::build_merkle_tree_from_hashes(&leaves_hashed, 0)
                    .unwrap();
            let (_, siblings1) =
                crate::transaction::circuit::real::build_merkle_tree_from_hashes(&leaves_hashed, 1)
                    .unwrap();

            let root_f = root.map(plonky2::field::types::Field::from_canonical_u64);
            let mut s0 = [[plonky2::field::types::Field::ZERO; 4]; crate::transaction::circuit::MERKLE_DEPTH];
            let mut s1 = [[plonky2::field::types::Field::ZERO; 4]; crate::transaction::circuit::MERKLE_DEPTH];
            for i in 0..crate::transaction::circuit::MERKLE_DEPTH {
                s0[i] = siblings0[i].map(plonky2::field::types::Field::from_canonical_u64);
                s1[i] = siblings1[i].map(plonky2::field::types::Field::from_canonical_u64);
            }

            let tx1 = crate::transaction::circuit::real::prove_transaction(
                1000, 100, 10, 10, 1, root_f, 0, &s0,
            )
            .unwrap();
            let tx2 = crate::transaction::circuit::real::prove_transaction(
                2000, 200, 20, 20, 2, root_f, 1, &s1,
            )
            .unwrap();

            let proof_bytes = real::prove_recursive_batch(&[tx1, tx2]).unwrap();
            assert!(!proof_bytes.is_empty());
            real::verify_recursive_batch(&proof_bytes).unwrap();
        }
    }
}
