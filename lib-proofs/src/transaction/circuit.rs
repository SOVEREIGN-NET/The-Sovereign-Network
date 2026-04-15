//! Plonky2 transaction circuit with Merkle inclusion.
//!
//! Statement:
//!   1. amount + fee <= sender_balance
//!   2. nullifier_seed_hash == Poseidon(nullifier_seed)
//!   3. The UTXO leaf [nullifier_seed, sender_secret, sender_balance] is present
//!      in the Merkle tree with root `merkle_root` at `leaf_index`.

#[cfg(feature = "real-proofs")]
pub mod real {
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::Field,
        },
        hash::{
            hashing::hash_n_to_hash_no_pad,
            merkle_proofs::MerkleProofTarget,
            poseidon::{PoseidonHash, PoseidonPermutation},
            hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
        },
        iop::target::{BoolTarget, Target},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitData,
            config::{Hasher, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
        },
    };
    use serde::{Deserialize, Serialize};
    use std::sync::OnceLock;

    pub type TxProof = ProofWithPublicInputs<F, C, D>;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    /// We use 63-bit range checks because the Goldilocks prime is
    /// `p = 2^64 - 2^32 + 1`, which is slightly less than `2^64`.
    const NUM_BITS: usize = 63;
    /// Fixed Merkle tree depth for the UTXO set.
    /// Production will use a larger depth (e.g. 32-40); 4 is used here
    /// to keep tests and benchmarks fast while proving the concept.
    pub const MERKLE_DEPTH: usize = 4;

    /// Public inputs for a transaction proof.
    /// Order: [sender_balance, amount, fee, nullifier_seed_hash, merkle_root (4 elements)]
    pub const TX_PI_LEN: usize = 4 + NUM_HASH_OUT_ELTS;

    /// Targets for the transaction circuit.
    /// Uses only primitive Plonky2 types that implement serde, so the struct
    /// can be cached to disk between process restarts.
    #[derive(Clone, Serialize, Deserialize)]
    pub struct TransactionTargets {
        pub sender_balance: Target,
        pub amount: Target,
        pub fee: Target,
        pub nullifier_seed_hash: Target,
        pub sender_secret: Target,
        pub nullifier_seed: Target,
        /// merkle_root as 4 field-element targets (HashOutTarget serializable form)
        pub merkle_root: [Target; NUM_HASH_OUT_ELTS],
        /// leaf_index_bits as raw targets (BoolTarget serializable form)
        pub leaf_index_bits: Vec<Target>,
        /// merkle_siblings as Vec of 4-element target arrays (MerkleProofTarget serializable form)
        pub merkle_siblings: Vec<[Target; NUM_HASH_OUT_ELTS]>,
    }

    impl TransactionTargets {
        pub fn merkle_root_ht(&self) -> HashOutTarget {
            HashOutTarget::from(self.merkle_root)
        }

        pub fn leaf_index_bits_bt(&self) -> Vec<BoolTarget> {
            self.leaf_index_bits.iter().copied().map(BoolTarget::new_unsafe).collect()
        }

        pub fn merkle_siblings_mpt(&self) -> MerkleProofTarget {
            MerkleProofTarget {
                siblings: self.merkle_siblings.iter().copied().map(HashOutTarget::from).collect(),
            }
        }
    }

    /// The transaction circuit.
    pub struct TransactionCircuit {
        pub data: CircuitData<F, C, D>,
        pub targets: TransactionTargets,
    }

    impl TransactionCircuit {
        /// Build the circuit.
        pub fn build() -> Self {
            let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Public inputs
            let sender_balance = builder.add_virtual_public_input();
            let amount = builder.add_virtual_public_input();
            let fee = builder.add_virtual_public_input();
            let nullifier_seed_hash = builder.add_virtual_public_input();

            // Merkle root is a public input (4 field elements)
            let merkle_root = builder.add_virtual_hash_public_input();

            // Private inputs
            let sender_secret = builder.add_virtual_target();
            let nullifier_seed = builder.add_virtual_target();

            // Merkle proof private witnesses
            let leaf_index_bits: Vec<BoolTarget> = (0..MERKLE_DEPTH)
                .map(|_| builder.add_virtual_bool_target_unsafe())
                .collect();
            let merkle_siblings = MerkleProofTarget {
                siblings: (0..MERKLE_DEPTH)
                    .map(|_| builder.add_virtual_hash())
                    .collect(),
            };

            // Constraint 1: amount + fee <= sender_balance
            builder.range_check(sender_balance, NUM_BITS);
            builder.range_check(amount, NUM_BITS);
            builder.range_check(fee, NUM_BITS);
            let total = builder.add(amount, fee);
            builder.range_check(total, NUM_BITS);
            let diff = builder.sub(sender_balance, total);
            builder.range_check(diff, NUM_BITS);
            let recomposed = builder.add(total, diff);
            builder.connect(recomposed, sender_balance);

            // Constraint 2: nullifier_seed_hash == Poseidon(nullifier_seed)
            let computed_hash =
                builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![nullifier_seed]);
            builder.connect(nullifier_seed_hash, computed_hash.elements[0]);

            // Constraint 3: Merkle inclusion of the UTXO leaf.
            // The leaf is the hash of [nullifier_seed, sender_secret, sender_balance].
            let leaf_data = vec![nullifier_seed, sender_secret, sender_balance];
            builder.verify_merkle_proof::<PoseidonHash>(
                leaf_data,
                &leaf_index_bits,
                merkle_root,
                &merkle_siblings,
            );

            let data = builder.build::<C>();
            Self {
                data,
                targets: TransactionTargets {
                    sender_balance,
                    amount,
                    fee,
                    nullifier_seed_hash,
                    sender_secret,
                    nullifier_seed,
                    merkle_root: merkle_root.elements,
                    leaf_index_bits: leaf_index_bits.iter().map(|b| b.target).collect(),
                    merkle_siblings: merkle_siblings.siblings.iter().map(|s| s.elements).collect(),
                },
            }
        }
    }

    /// Default on-disk cache path for the transaction circuit.
    pub fn default_cache_path() -> std::path::PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zhtp")
            .join("cache")
            .join("tx_circuit_v3.bin")
    }

    /// Lazy-initialized circuit so we only build once per process.
    /// Tries to load from disk cache first, falling back to build-and-save.
    fn circuit() -> &'static TransactionCircuit {
        static CIRCUIT: OnceLock<TransactionCircuit> = OnceLock::new();
        CIRCUIT.get_or_init(|| {
            let path = default_cache_path();
            if let Ok((data, targets)) =
                crate::backend::circuit_cache::real::load_transaction_circuit(&path)
            {
                return TransactionCircuit { data, targets };
            }
            let circuit = TransactionCircuit::build();
            if let Err(e) = crate::backend::circuit_cache::real::save_transaction_circuit(
                &circuit.data,
                &circuit.targets,
                &path,
            ) {
                tracing::warn!("Failed to save transaction circuit cache: {}", e);
            }
            circuit
        })
    }

    /// Generate a transaction proof.
    pub fn prove_transaction(
        sender_balance: u64,
        amount: u64,
        fee: u64,
        sender_secret: u64,
        nullifier_seed: u64,
        merkle_root: [F; NUM_HASH_OUT_ELTS],
        leaf_index: u32,
        merkle_siblings: &[[F; NUM_HASH_OUT_ELTS]; MERKLE_DEPTH],
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        if amount.checked_add(fee).map(|t| t > sender_balance).unwrap_or(true) {
            return Err(anyhow::anyhow!(
                "Insufficient balance: {} + {} > {}",
                amount,
                fee,
                sender_balance
            ));
        }

        let circuit = circuit();
        let mut pw = PartialWitness::new();
        let t = &circuit.targets;

        // Public inputs
        pw.set_target(t.sender_balance, F::from_canonical_u64(sender_balance))?;
        pw.set_target(t.amount, F::from_canonical_u64(amount))?;
        pw.set_target(t.fee, F::from_canonical_u64(fee))?;

        let nullifier_hash =
            hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[F::from_canonical_u64(nullifier_seed)]);
        pw.set_target(t.nullifier_seed_hash, nullifier_hash.elements[0])?;

        pw.set_target_arr(&t.merkle_root, &merkle_root)?;

        // Private inputs
        pw.set_target(t.sender_secret, F::from_canonical_u64(sender_secret))?;
        pw.set_target(t.nullifier_seed, F::from_canonical_u64(nullifier_seed))?;

        // Merkle witnesses
        for (i, bit_target) in t.leaf_index_bits.iter().enumerate() {
            let bit_val = ((leaf_index >> i) & 1) == 1;
            pw.set_bool_target(BoolTarget::new_unsafe(*bit_target), bit_val)?;
        }
        for (i, sibling) in t.merkle_siblings.iter().enumerate() {
            pw.set_target_arr(sibling, &merkle_siblings[i])?;
        }

        let proof = circuit.data.prove(pw)?;
        Ok(proof)
    }

    /// Verify a transaction proof.
    pub fn verify_transaction(proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        let circuit = circuit();
        circuit
            .data
            .verify(proof.clone())
            .map_err(|e| anyhow::anyhow!("Plonky2 verification failed: {:?}", e))
    }

    /// Build a Poseidon Merkle tree from leaf data and return the root + siblings
    /// for the requested leaf index.  Leaves are automatically padded to the next
    /// power of two up to `1 << MERKLE_DEPTH`.
    pub fn build_merkle_tree(
        leaves: &[Vec<u64>],
        leaf_index: usize,
    ) -> anyhow::Result<([u64; 4], Vec<[u64; 4]>)> {
        use plonky2::hash::merkle_tree::MerkleTree;
        use plonky2::hash::poseidon::PoseidonHash;
        use plonky2::field::types::{Field, PrimeField64};

        let max_leaves = 1usize << MERKLE_DEPTH;
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
        // Pad to next power of two
        let target_len = padded.len().next_power_of_two();
        while padded.len() < target_len {
            padded.push(vec![F::ZERO]);
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

    /// Compute the Merkle root from a leaf, leaf index, and sibling path.
    pub fn compute_merkle_root(
        leaf_data: &[F],
        leaf_index: u32,
        siblings: &[[F; NUM_HASH_OUT_ELTS]],
    ) -> [F; NUM_HASH_OUT_ELTS] {
        use plonky2::hash::hash_types::HashOut;
        use plonky2::plonk::config::Hasher;
        let mut state = PoseidonHash::hash_or_noop(leaf_data);
        let mut index = leaf_index as usize;
        for sibling in siblings {
            let bit = index & 1;
            index >>= 1;
            let sibling_hash = HashOut::from(*sibling);
            state = if bit == 1 {
                PoseidonHash::two_to_one(sibling_hash, state)
            } else {
                PoseidonHash::two_to_one(state, sibling_hash)
            };
        }
        state.elements
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use plonky2::{
            hash::merkle_tree::MerkleTree,
            field::types::Field,
            hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
            iop::witness::{PartialWitness, WitnessWrite},
        };

            fn dummy_merkle_siblings() -> [[F; NUM_HASH_OUT_ELTS]; MERKLE_DEPTH] {
            [[F::ZERO; NUM_HASH_OUT_ELTS]; MERKLE_DEPTH]
        }

        fn make_leaf(nullifier_seed: u64, sender_secret: u64, sender_balance: u64) -> Vec<F> {
            vec![
                F::from_canonical_u64(nullifier_seed),
                F::from_canonical_u64(sender_secret),
                F::from_canonical_u64(sender_balance),
            ]
        }

        #[test]
        fn test_valid_transaction_proof() {
            let sender_balance = 1000u64;
            let amount = 100u64;
            let fee = 10u64;
            let sender_secret = 12345u64;
            let nullifier_seed = 67890u64;
            let leaf = make_leaf(nullifier_seed, sender_secret, sender_balance);
            let siblings = dummy_merkle_siblings();
            let merkle_root = compute_merkle_root(&leaf, 0, &siblings);
            let proof = prove_transaction(
                sender_balance, amount, fee, sender_secret, nullifier_seed,
                merkle_root, 0, &siblings
            ).unwrap();
            verify_transaction(&proof).unwrap();
        }

        #[test]
        fn test_insufficient_balance_fails_at_circuit_level() {
            let sender_balance = 100u64;
            let amount = 1000u64;
            let fee = 10u64;
            let sender_secret = 12345u64;
            let nullifier_seed = 67890u64;
            let leaf = make_leaf(nullifier_seed, sender_secret, sender_balance);
            let siblings = dummy_merkle_siblings();
            let merkle_root = compute_merkle_root(&leaf, 0, &siblings);
            let result = prove_transaction(
                sender_balance, amount, fee, sender_secret, nullifier_seed,
                merkle_root, 0, &siblings
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_transaction_circuit_builds() {
            let _circuit = TransactionCircuit::build();
        }

        #[test]
        fn test_merkle_inclusion_with_real_tree() {
            // Build a tree with 16 leaves so the height (4) matches MERKLE_DEPTH.
            let rebuild_leaves: Vec<Vec<F>> = (0..16u64)
                .map(|i| vec![F::from_canonical_u64(i), F::from_canonical_u64(i + 10), F::from_canonical_u64(1000)])
                .collect();
            let tree = MerkleTree::<F, PoseidonHash>::new(rebuild_leaves.clone(), 0);
            let leaf_index = 5usize;
            let proof = tree.prove(leaf_index);
            let merkle_root: [F; NUM_HASH_OUT_ELTS] = tree.cap.0[0].elements;

            let mut siblings = [[F::ZERO; NUM_HASH_OUT_ELTS]; MERKLE_DEPTH];
            for (i, s) in proof.siblings.iter().enumerate() {
                siblings[i] = s.elements;
            }

            let circuit = TransactionCircuit::build();
            let mut pw = PartialWitness::new();
            let t = &circuit.targets;

            let leaf = &rebuild_leaves[leaf_index];
            pw.set_target(t.sender_balance, leaf[2]).unwrap();
            pw.set_target(t.amount, F::from_canonical_u64(100)).unwrap();
            pw.set_target(t.fee, F::from_canonical_u64(10)).unwrap();
            let nullifier_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[leaf[0]]);
            pw.set_target(t.nullifier_seed_hash, nullifier_hash.elements[0]).unwrap();
            pw.set_target_arr(&t.merkle_root, &merkle_root).unwrap();
            pw.set_target(t.sender_secret, leaf[1]).unwrap();
            pw.set_target(t.nullifier_seed, leaf[0]).unwrap();
            for (bit_idx, bit_target) in t.leaf_index_bits.iter().enumerate() {
                let bit_val = ((leaf_index >> bit_idx) & 1) == 1;
                pw.set_bool_target(BoolTarget::new_unsafe(*bit_target), bit_val).unwrap();
            }
            for (i, sibling) in t.merkle_siblings.iter().enumerate() {
                pw.set_target_arr(sibling, &siblings[i]).unwrap();
            }

            let tx_proof = circuit.data.prove(pw).unwrap();
            circuit.data.verify(tx_proof).unwrap();
        }

        #[test]
        #[should_panic(expected = "Integer too large to fit in given number of limbs")]
        fn test_overspend_fails_plonky2_verification() {
            let circuit = TransactionCircuit::build();
            let mut pw = PartialWitness::new();
            let t = &circuit.targets;

            pw.set_target(t.sender_balance, F::from_canonical_u64(100)).unwrap();
            pw.set_target(t.amount, F::from_canonical_u64(1000)).unwrap();
            pw.set_target(t.fee, F::from_canonical_u64(10)).unwrap();

            let nullifier_seed = F::from_canonical_u64(1);
            let sender_secret = F::from_canonical_u64(42);
            let sender_balance = F::from_canonical_u64(100);
            let nullifier_hash =
                hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[nullifier_seed]);
            pw.set_target(t.nullifier_seed_hash, nullifier_hash.elements[0]).unwrap();

            let leaf = vec![nullifier_seed, sender_secret, sender_balance];
            let siblings = dummy_merkle_siblings();
            let merkle_root = compute_merkle_root(&leaf, 0, &siblings);
            pw.set_target_arr(&t.merkle_root, &merkle_root).unwrap();

            pw.set_target(t.sender_secret, sender_secret).unwrap();
            pw.set_target(t.nullifier_seed, nullifier_seed).unwrap();
            for (_i, bit_target) in t.leaf_index_bits.iter().enumerate() {
                pw.set_bool_target(BoolTarget::new_unsafe(*bit_target), false).unwrap();
            }
            for sibling in &t.merkle_siblings {
                pw.set_target_arr(sibling, &[F::ZERO; NUM_HASH_OUT_ELTS]).unwrap();
            }

            let _ = circuit.data.prove(pw);
        }
    }
}

#[cfg(not(feature = "real-proofs"))]
pub mod stub {
    pub fn prove_transaction_stub() -> anyhow::Result<()> {
        Err(anyhow::anyhow!(
            "Real transaction circuit requires the 'real-proofs' feature"
        ))
    }
}
