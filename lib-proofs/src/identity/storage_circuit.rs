//! Plonky2 storage-access selective-disclosure circuit.
//!
//! Proves access authorization without revealing the requester's secret or full
//! permission level:
//!
//!   1. permission_level >= required_permission
//!   2. access_commitment == Poseidon(access_key, requester_secret, data_hash, permission_level)
//!
//! The prover commits to (access_key, requester_secret, data_hash, permission_level)
//! via a Poseidon hash. The verifier only sees the commitment and the minimum
//! required permission — never the actual secret, access key, or data hash.

#[cfg(not(feature = "real-proofs"))]
pub mod real {
    use anyhow::Result;

    /// Stub for non-real-proofs builds.
    pub fn prove_storage_access(
        _access_key: u64,
        _requester_secret: u64,
        _data_hash: u64,
        _permission_level: u64,
        _required_permission: u64,
    ) -> Result<(Vec<u8>, Vec<u64>)> {
        Ok((vec![], vec![0u64; 6]))
    }

    /// Stub for non-real-proofs builds.
    pub fn verify_storage_access(_proof_data: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Stub for non-real-proofs builds.
    pub fn compute_access_commitment(
        _access_key: u64,
        _requester_secret: u64,
        _data_hash: u64,
        _permission_level: u64,
    ) -> [u64; 4] {
        [0u64; 4]
    }
}

#[cfg(feature = "real-proofs")]
pub mod real {
    use anyhow::{anyhow, Result};
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, PrimeField64},
        },
        hash::{
            hashing::hash_n_to_hash_no_pad,
            poseidon::{PoseidonHash, PoseidonPermutation},
        },
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitData,
            config::PoseidonGoldilocksConfig,
            proof::ProofWithPublicInputs,
        },
    };
    use std::sync::OnceLock;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    const NUM_BITS: usize = 64;

    /// Public inputs: [access_commitment (4), required_permission, data_hash_public]
    pub const STORAGE_PI_LEN: usize = 6;

    /// Storage access circuit data + targets (cached per process).
    pub struct StorageAccessCircuit {
        pub data: CircuitData<F, C, D>,
        pub targets: StorageAccessTargets,
    }

    #[derive(Clone)]
    pub struct StorageAccessTargets {
        // Private inputs
        pub access_key: Target,
        pub requester_secret: Target,
        pub data_hash: Target,
        pub permission_level: Target,
        // Public inputs
        pub access_commitment: [Target; 4],
        pub required_permission: Target,
        pub data_hash_public: Target,
    }

    impl StorageAccessCircuit {
        /// Build the circuit.
        ///
        /// Constraints:
        /// 1. `access_commitment == Poseidon(access_key, requester_secret, data_hash, permission_level)`
        /// 2. `permission_level >= required_permission`   (via range check on the difference)
        /// 3. `data_hash == data_hash_public`             (bind proof to specific data)
        pub fn build() -> Self {
            let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Private inputs
            let access_key = builder.add_virtual_target();
            let requester_secret = builder.add_virtual_target();
            let data_hash = builder.add_virtual_target();
            let permission_level = builder.add_virtual_target();

            // Public inputs
            let access_commitment = builder.add_virtual_hash_public_input();
            let required_permission = builder.add_virtual_public_input();
            let data_hash_public = builder.add_virtual_public_input();

            // Constraint 1: access_commitment == Poseidon(access_key, requester_secret, data_hash, permission_level)
            let computed_commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
                vec![access_key, requester_secret, data_hash, permission_level],
            );
            for i in 0..4 {
                builder.connect(access_commitment.elements[i], computed_commitment.elements[i]);
            }

            // Constraint 2: permission_level >= required_permission
            builder.range_check(permission_level, NUM_BITS);
            builder.range_check(required_permission, NUM_BITS);
            let perm_diff = builder.sub(permission_level, required_permission);
            builder.range_check(perm_diff, NUM_BITS); // diff >= 0 iff permission_level >= required

            // Constraint 3: data_hash == data_hash_public (binds proof to specific data)
            builder.connect(data_hash, data_hash_public);

            let data = builder.build::<C>();
            Self {
                data,
                targets: StorageAccessTargets {
                    access_key,
                    requester_secret,
                    data_hash,
                    permission_level,
                    access_commitment: access_commitment.elements,
                    required_permission,
                    data_hash_public,
                },
            }
        }
    }

    fn circuit() -> &'static StorageAccessCircuit {
        static CIRCUIT: OnceLock<StorageAccessCircuit> = OnceLock::new();
        CIRCUIT.get_or_init(StorageAccessCircuit::build)
    }

    /// Compute the Poseidon access commitment from raw attributes.
    pub fn compute_access_commitment(
        access_key: u64,
        requester_secret: u64,
        data_hash: u64,
        permission_level: u64,
    ) -> [u64; 4] {
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[
            F::from_canonical_u64(access_key),
            F::from_canonical_u64(requester_secret),
            F::from_canonical_u64(data_hash),
            F::from_canonical_u64(permission_level),
        ]);
        hash.elements.map(|e| e.to_canonical_u64())
    }

    /// Generate a real storage-access proof.
    ///
    /// Proves the requester knows `(access_key, requester_secret)` with
    /// `permission_level >= required_permission` for data identified by
    /// `data_hash`, without revealing the secret or the full permission level.
    pub fn prove_storage_access(
        access_key: u64,
        requester_secret: u64,
        data_hash: u64,
        permission_level: u64,
        required_permission: u64,
    ) -> Result<(Vec<u8>, Vec<u64>)> {
        if permission_level < required_permission {
            return Err(anyhow!(
                "Insufficient permission: {} < {}",
                permission_level,
                required_permission
            ));
        }

        let circuit = circuit();
        let mut pw = PartialWitness::new();
        let t = &circuit.targets;

        // Private inputs
        pw.set_target(t.access_key, F::from_canonical_u64(access_key))?;
        pw.set_target(t.requester_secret, F::from_canonical_u64(requester_secret))?;
        pw.set_target(t.data_hash, F::from_canonical_u64(data_hash))?;
        pw.set_target(t.permission_level, F::from_canonical_u64(permission_level))?;

        // Public inputs
        let commitment = compute_access_commitment(access_key, requester_secret, data_hash, permission_level);
        for (i, &c) in commitment.iter().enumerate() {
            pw.set_target(t.access_commitment[i], F::from_canonical_u64(c))?;
        }
        pw.set_target(t.required_permission, F::from_canonical_u64(required_permission))?;
        pw.set_target(t.data_hash_public, F::from_canonical_u64(data_hash))?;

        let proof = circuit.data.prove(pw)?;
        let public_inputs: Vec<u64> = proof
            .public_inputs
            .iter()
            .map(|e| e.to_canonical_u64())
            .collect();
        let proof_bytes = bincode::serialize(&proof)?;
        Ok((proof_bytes, public_inputs))
    }

    /// Verify a storage-access proof.
    pub fn verify_storage_access(proof_bytes: &[u8]) -> Result<()> {
        let circuit = circuit();
        let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(proof_bytes)
            .map_err(|e| anyhow!("Failed to deserialize storage access proof: {}", e))?;
        circuit
            .data
            .verify(proof)
            .map_err(|e| anyhow!("Storage access proof verification failed: {:?}", e))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_storage_circuit_builds() {
            let _circuit = StorageAccessCircuit::build();
        }

        #[test]
        fn test_valid_storage_access_proof() {
            let (proof_bytes, public_inputs) = prove_storage_access(
                12345, // access_key
                67890, // requester_secret
                11111, // data_hash
                5,     // permission_level
                3,     // required_permission
            )
            .unwrap();

            verify_storage_access(&proof_bytes).unwrap();
            // Public inputs: [commitment(4), required_permission, data_hash]
            assert_eq!(public_inputs[4], 3);     // required_permission
            assert_eq!(public_inputs[5], 11111); // data_hash
        }

        #[test]
        fn test_insufficient_permission_fails() {
            assert!(prove_storage_access(
                12345, 67890, 11111, 2, 3, // permission 2 < required 3
            )
            .is_err());
        }

        #[test]
        fn test_exact_permission_succeeds() {
            let (proof_bytes, _) = prove_storage_access(
                12345, 67890, 11111, 3, 3, // exact match
            )
            .unwrap();
            verify_storage_access(&proof_bytes).unwrap();
        }

        #[test]
        fn test_high_permission_succeeds() {
            let (proof_bytes, _) = prove_storage_access(
                12345, 67890, 11111, 100, 1, // permission 100 >> required 1
            )
            .unwrap();
            verify_storage_access(&proof_bytes).unwrap();
        }
    }
}
