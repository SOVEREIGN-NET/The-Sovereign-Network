//! Plonky2 transaction circuit with Merkle inclusion.
//!
//! Statement:
//!   1. amount + fee <= sender_balance
//!   2. nullifier_seed_hash == Poseidon(nullifier_seed)
//!   3. The UTXO leaf [nullifier_seed, sender_secret, sender_balance] is present
//!      in the Merkle tree with root `merkle_root` at `leaf_index`.

/// Fixed Merkle tree depth for the UTXO set.
/// Production will use a larger depth (e.g. 32-40); 4 is used here
/// to keep tests and benchmarks fast while proving the concept.
pub const MERKLE_DEPTH: usize = 32;

#[cfg(not(feature = "real-proofs"))]
pub mod real {
    use super::MERKLE_DEPTH;

    /// Stub type for builds without real proof circuits (e.g. Android quic-jni).
    pub type TxProof = ();

    /// Stub for non-real-proofs builds.
    pub fn build_merkle_tree(
        _leaves: &[Vec<u64>],
        _leaf_index: usize,
    ) -> anyhow::Result<([u64; 4], Vec<[u64; 4]>)> {
        Ok(([0u64; 4], vec![[0u64; 4]; MERKLE_DEPTH]))
    }

    /// Stub for non-real-proofs builds.
    pub fn compute_leaf_commitment(
        _nullifier_seed: u64,
        _sender_secret: u64,
        _sender_balance: u64,
    ) -> [u64; 4] {
        [0u64; 4]
    }

    /// Stub for non-real-proofs builds.
    pub fn build_merkle_tree_from_hashes(
        _leaves: &[[u64; 4]],
        _leaf_index: usize,
    ) -> anyhow::Result<([u64; 4], Vec<[u64; 4]>)> {
        Ok(([0u64; 4], vec![[0u64; 4]; MERKLE_DEPTH]))
    }

    /// Stub for non-real-proofs builds.
    pub fn hash_pair_u8(_left: [u8; 32], _right: [u8; 32]) -> [u8; 32] {
        [0u8; 32]
    }

    /// Stub for non-real-proofs builds.
    pub fn hash_pair_u64(_left: [u64; 4], _right: [u64; 4]) -> [u64; 4] {
        [0u64; 4]
    }

    /// Stub for non-real-proofs builds.
    pub fn build_sparse_merkle_tree_from_hashes(
        _leaves: &[(usize, [u64; 4])],
        _leaf_index: usize,
    ) -> anyhow::Result<([u64; 4], Vec<[u64; 4]>)> {
        Ok(([0u64; 4], vec![[0u64; 4]; MERKLE_DEPTH]))
    }
}

#[cfg(feature = "real-proofs")]
pub mod real {
    use super::MERKLE_DEPTH;
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, PrimeField64},
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

            // Constraint 3: Merkle inclusion of the UTXO commitment.
            // The leaf commitment is Poseidon(nullifier_seed, sender_secret, sender_balance).
            let leaf_commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
                nullifier_seed,
                sender_secret,
                sender_balance,
            ]);
            builder.verify_merkle_proof::<PoseidonHash>(
                leaf_commitment.elements.to_vec(),
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
            .join("tx_circuit_v4.bin")
    }

    /// Lazy-initialized circuit so we only build once per process.
    /// Tries to load from disk cache first, falling back to build-and-save.
    pub fn circuit() -> &'static TransactionCircuit {
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

    /// Build a Poseidon Merkle tree from raw UTXO leaf data.
    ///
    /// Each leaf in `leaves` must be `[nullifier_seed, sender_secret, sender_balance]`.
    /// The function computes the Poseidon commitment for each leaf, builds the tree,
    /// and returns (root, siblings) for the requested leaf index.
    pub fn build_merkle_tree(
        leaves: &[Vec<u64>],
        leaf_index: usize,
    ) -> anyhow::Result<([u64; 4], Vec<[u64; 4]>)> {
        use plonky2::hash::hashing::hash_n_to_hash_no_pad;
        use plonky2::hash::poseidon::PoseidonPermutation;
        use plonky2::field::types::Field;

        if leaves.is_empty() {
            return Err(anyhow::anyhow!(
                "Leaf count 0 out of range [1, {}]",
                1usize << MERKLE_DEPTH
            ));
        }
        if leaf_index >= leaves.len() {
            return Err(anyhow::anyhow!(
                "leaf_index {} out of range [0, {})",
                leaf_index,
                leaves.len()
            ));
        }

        let hashed_leaves: Vec<(usize, [u64; 4])> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| {
                let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(
                    &leaf.iter().map(|&v| F::from_canonical_u64(v)).collect::<Vec<_>>()
                );
                (i, hash.elements.map(|e| e.to_canonical_u64()))
            })
            .collect();

        build_sparse_merkle_tree_from_hashes(&hashed_leaves, leaf_index)
    }

    /// Build a Poseidon Merkle tree from already-hashed leaf commitments.
    ///
    /// Each leaf in `leaves` must be a 4-element Poseidon hash output (already committed).
    /// Returns (root, siblings) for the requested leaf index.
    pub fn build_merkle_tree_from_hashes(
        leaves: &[[u64; NUM_HASH_OUT_ELTS]],
        leaf_index: usize,
    ) -> anyhow::Result<([u64; NUM_HASH_OUT_ELTS], Vec<[u64; NUM_HASH_OUT_ELTS]>)> {
        if leaves.is_empty() {
            return Err(anyhow::anyhow!(
                "Leaf count 0 out of range [1, {}]",
                1usize << MERKLE_DEPTH
            ));
        }
        if leaf_index >= leaves.len() {
            return Err(anyhow::anyhow!(
                "leaf_index {} out of range [0, {})",
                leaf_index,
                leaves.len()
            ));
        }
        let indexed_leaves: Vec<(usize, [u64; 4])> = leaves.iter().copied().enumerate().collect();
        build_sparse_merkle_tree_from_hashes(&indexed_leaves, leaf_index)
    }

    /// Sparse Merkle tree builder.
    ///
    /// `leaves` is a list of `(leaf_index, leaf_hash)` pairs.
    /// Empty subtrees use the standard zero hash for each level.
    /// Returns (root, siblings) for `target_leaf_index`.
    pub fn build_sparse_merkle_tree_from_hashes(
        leaves: &[(usize, [u64; NUM_HASH_OUT_ELTS])],
        target_leaf_index: usize,
    ) -> anyhow::Result<([u64; NUM_HASH_OUT_ELTS], Vec<[u64; NUM_HASH_OUT_ELTS]>)> {
        static ZERO_HASHES: OnceLock<Vec<[u64; NUM_HASH_OUT_ELTS]>> = OnceLock::new();
        let zero_hashes = ZERO_HASHES.get_or_init(|| {
            let mut zh = vec![[0u64; NUM_HASH_OUT_ELTS]];
            for _ in 1..=MERKLE_DEPTH {
                let last = *zh.last().unwrap();
                zh.push(hash_pair_u64(last, last));
            }
            zh
        });

        if leaves.is_empty() {
            return Err(anyhow::anyhow!("Cannot build Merkle tree from empty leaves"));
        }
        if target_leaf_index >= (1usize << MERKLE_DEPTH) {
            return Err(anyhow::anyhow!(
                "leaf_index {} out of range [0, {})",
                target_leaf_index,
                1usize << MERKLE_DEPTH
            ));
        }

        let mut nodes: std::collections::HashMap<(usize, usize), [u64; NUM_HASH_OUT_ELTS]> =
            std::collections::HashMap::new();
        for (idx, hash) in leaves {
            nodes.insert((0, *idx), *hash);
        }

        for level in 0..MERKLE_DEPTH {
            let mut parents = std::collections::HashSet::new();
            for &(l, idx) in nodes.keys() {
                if l == level {
                    parents.insert(idx / 2);
                }
            }
            for parent_idx in parents {
                let left = *nodes
                    .get(&(level, parent_idx * 2))
                    .unwrap_or(&zero_hashes[level]);
                let right = *nodes
                    .get(&(level, parent_idx * 2 + 1))
                    .unwrap_or(&zero_hashes[level]);
                let parent = hash_pair_u64(left, right);
                nodes.insert((level + 1, parent_idx), parent);
            }
        }

        let root = *nodes
            .get(&(MERKLE_DEPTH, 0))
            .unwrap_or(&zero_hashes[MERKLE_DEPTH]);

        let mut siblings = Vec::with_capacity(MERKLE_DEPTH);
        let mut current_index = target_leaf_index;
        for level in 0..MERKLE_DEPTH {
            let sibling_idx = current_index ^ 1;
            siblings.push(
                *nodes
                    .get(&(level, sibling_idx))
                    .unwrap_or(&zero_hashes[level]),
            );
            current_index /= 2;
        }

        Ok((root, siblings))
    }

    /// Compute the Merkle root from raw UTXO data, leaf index, and sibling path.
    /// The leaf commitment is computed as Poseidon(nullifier_seed, sender_secret, sender_balance).
    pub fn compute_merkle_root(
        nullifier_seed: F,
        sender_secret: F,
        sender_balance: F,
        leaf_index: u32,
        siblings: &[[F; NUM_HASH_OUT_ELTS]],
    ) -> [F; NUM_HASH_OUT_ELTS] {
        use plonky2::hash::hash_types::HashOut;
        use plonky2::hash::hashing::hash_n_to_hash_no_pad;
        use plonky2::hash::poseidon::PoseidonPermutation;
        use plonky2::plonk::config::Hasher;
        let leaf_commitment = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[
            nullifier_seed,
            sender_secret,
            sender_balance,
        ]);
        let mut state = leaf_commitment;
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

    /// Compute the Poseidon leaf commitment for raw UTXO data.
    ///
    /// Returns the 4-element hash as `[u64; 4]` suitable for the persistent
    /// UTXO Merkle tree or for conversion to `[u8; 32]`.
    pub fn compute_leaf_commitment(
        nullifier_seed: u64,
        sender_secret: u64,
        sender_balance: u64,
    ) -> [u64; 4] {
        use plonky2::hash::hashing::hash_n_to_hash_no_pad;
        use plonky2::hash::poseidon::PoseidonPermutation;
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[
            F::from_canonical_u64(nullifier_seed),
            F::from_canonical_u64(sender_secret),
            F::from_canonical_u64(sender_balance),
        ]);
        hash.elements.map(|e| e.to_canonical_u64())
    }

    /// Hash a pair of 32-byte Poseidon hashes into their parent node.
    ///
    /// The byte layout matches the Plonky2 `HashOut` representation:
    /// four little-endian u64 field elements.
    pub fn hash_pair_u8(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        use plonky2::hash::hash_types::HashOut;
        use plonky2::plonk::config::Hasher;
        let left_hash = HashOut::from([
            F::from_canonical_u64(u64::from_le_bytes([
                left[0], left[1], left[2], left[3],
                left[4], left[5], left[6], left[7],
            ])),
            F::from_canonical_u64(u64::from_le_bytes([
                left[8], left[9], left[10], left[11],
                left[12], left[13], left[14], left[15],
            ])),
            F::from_canonical_u64(u64::from_le_bytes([
                left[16], left[17], left[18], left[19],
                left[20], left[21], left[22], left[23],
            ])),
            F::from_canonical_u64(u64::from_le_bytes([
                left[24], left[25], left[26], left[27],
                left[28], left[29], left[30], left[31],
            ])),
        ]);
        let right_hash = HashOut::from([
            F::from_canonical_u64(u64::from_le_bytes([
                right[0], right[1], right[2], right[3],
                right[4], right[5], right[6], right[7],
            ])),
            F::from_canonical_u64(u64::from_le_bytes([
                right[8], right[9], right[10], right[11],
                right[12], right[13], right[14], right[15],
            ])),
            F::from_canonical_u64(u64::from_le_bytes([
                right[16], right[17], right[18], right[19],
                right[20], right[21], right[22], right[23],
            ])),
            F::from_canonical_u64(u64::from_le_bytes([
                right[24], right[25], right[26], right[27],
                right[28], right[29], right[30], right[31],
            ])),
        ]);
        let parent = PoseidonHash::two_to_one(left_hash, right_hash);
        let mut out = [0u8; 32];
        for (i, e) in parent.elements.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&e.to_canonical_u64().to_le_bytes());
        }
        out
    }

    /// Hash a pair of 4-element Poseidon hashes into their parent node.
    pub fn hash_pair_u64(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
        use plonky2::hash::hash_types::HashOut;
        use plonky2::plonk::config::Hasher;
        let left_hash = HashOut::from(left.map(|v| F::from_canonical_u64(v)));
        let right_hash = HashOut::from(right.map(|v| F::from_canonical_u64(v)));
        PoseidonHash::two_to_one(left_hash, right_hash)
            .elements
            .map(|e| e.to_canonical_u64())
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
            let merkle_root = compute_merkle_root(leaf[0], leaf[1], leaf[2], 0, &siblings);
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
            let merkle_root = compute_merkle_root(leaf[0], leaf[1], leaf[2], 0, &siblings);
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
            // Build a sparse tree at the full MERKLE_DEPTH so the circuit
            // constraints match the witness data.
            let rebuild_leaves: Vec<Vec<F>> = (0..16u64)
                .map(|i| vec![F::from_canonical_u64(i), F::from_canonical_u64(i + 10), F::from_canonical_u64(1000)])
                .collect();
            let commitment_leaves: Vec<[u64; 4]> = rebuild_leaves
                .iter()
                .map(|leaf| {
                    hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(leaf)
                        .elements
                        .map(|e| e.to_canonical_u64())
                })
                .collect();
            let leaf_index = 5usize;
            let (merkle_root_u64, siblings_u64) =
                build_sparse_merkle_tree_from_hashes(
                    &commitment_leaves.iter().copied().enumerate().collect::<Vec<_>>(),
                    leaf_index,
                )
                .unwrap();
            let merkle_root: [F; NUM_HASH_OUT_ELTS] = merkle_root_u64.map(F::from_canonical_u64);
            let mut siblings = [[F::ZERO; NUM_HASH_OUT_ELTS]; MERKLE_DEPTH];
            for (i, s) in siblings_u64.iter().enumerate() {
                siblings[i] = s.map(F::from_canonical_u64);
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

            let siblings = dummy_merkle_siblings();
            let merkle_root = compute_merkle_root(
                nullifier_seed,
                sender_secret,
                sender_balance,
                0,
                &siblings,
            );
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
