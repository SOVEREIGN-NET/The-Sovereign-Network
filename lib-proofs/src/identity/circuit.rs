//! Plonky2 identity selective-disclosure circuit.
//!
//! Proves three possible claims without revealing the underlying identity data:
//!   1. age >= min_age
//!   2. jurisdiction_hash == required_jurisdiction
//!   3. kyc_level >= min_kyc_level
//!
//! The prover commits to (identity_secret, age, jurisdiction_hash, kyc_level)
//! via a Poseidon hash that serves as the public identity commitment.

#[cfg(not(feature = "real-proofs"))]
pub mod real {
    use anyhow::Result;

    /// Stub for non-real-proofs builds.
    pub fn prove_identity(
        _identity_secret: u64,
        _age: u64,
        _jurisdiction_hash: u64,
        _kyc_level: u64,
        _min_age: u64,
        _required_jurisdiction: u64,
        _min_kyc_level: u64,
        _claim_bitmap: u8,
    ) -> Result<(Vec<u8>, Vec<u64>)> {
        Ok((vec![], vec![0u64; 6]))
    }

    /// Stub for non-real-proofs builds.
    pub fn verify_identity(_proof_data: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Stub for non-real-proofs builds.
    pub fn compute_identity_commitment(
        _identity_secret: u64,
        _age: u64,
        _jurisdiction_hash: u64,
        _kyc_level: u64,
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

    /// Public inputs: [identity_commitment (4), min_age, required_jurisdiction, min_kyc_level, claim_bitmap]
    pub const IDENTITY_PI_LEN: usize = 4 + 4;

    /// Identity circuit data + targets (cached per process).
    pub struct IdentityCircuit {
        pub data: CircuitData<F, C, D>,
        pub targets: IdentityTargets,
    }

    #[derive(Clone)]
    pub struct IdentityTargets {
        /// Private inputs
        pub identity_secret: Target,
        pub age: Target,
        pub jurisdiction_hash: Target,
        pub kyc_level: Target,
        /// Public inputs
        pub identity_commitment: [Target; 4],
        pub min_age: Target,
        pub required_jurisdiction: Target,
        pub min_kyc_level: Target,
        pub claim_bitmap: Target,
    }

    impl IdentityCircuit {
        /// Build the circuit.
        pub fn build() -> Self {
            let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Private inputs
            let identity_secret = builder.add_virtual_target();
            let age = builder.add_virtual_target();
            let jurisdiction_hash = builder.add_virtual_target();
            let kyc_level = builder.add_virtual_target();

            // Public inputs
            let identity_commitment = builder.add_virtual_hash_public_input();
            let min_age = builder.add_virtual_public_input();
            let required_jurisdiction = builder.add_virtual_public_input();
            let min_kyc_level = builder.add_virtual_public_input();
            let claim_bitmap = builder.add_virtual_public_input();

            // Constraint 1: identity_commitment == Poseidon(identity_secret, age, jurisdiction_hash, kyc_level)
            let computed_commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
                vec![identity_secret, age, jurisdiction_hash, kyc_level],
            );
            for i in 0..4 {
                builder.connect(identity_commitment.elements[i], computed_commitment.elements[i]);
            }

            // Helper: extract boolean claim bits from claim_bitmap.
            // We treat the low 3 bits as: bit0 = claim_age, bit1 = claim_jurisdiction, bit2 = claim_kyc.
            let claim_bits = builder.split_le(claim_bitmap, 3);
            let claim_age = claim_bits[0];
            let claim_jurisdiction = claim_bits[1];
            let claim_kyc = claim_bits[2];

            // Constraint 2: if claim_age == 1, then age >= min_age.
            builder.range_check(age, NUM_BITS);
            builder.range_check(min_age, NUM_BITS);
            let age_diff = builder.sub(age, min_age);
            let constrained_age_diff = builder.mul(claim_age.target, age_diff);
            builder.range_check(constrained_age_diff, NUM_BITS);

            // Constraint 3: if claim_jurisdiction == 1, then jurisdiction_hash == required_jurisdiction.
            let jurisdiction_diff = builder.sub(jurisdiction_hash, required_jurisdiction);
            let constrained_jurisdiction_diff = builder.mul(claim_jurisdiction.target, jurisdiction_diff);
            let zero = builder.zero();
            builder.connect(constrained_jurisdiction_diff, zero);

            // Constraint 4: if claim_kyc == 1, then kyc_level >= min_kyc_level.
            builder.range_check(kyc_level, NUM_BITS);
            builder.range_check(min_kyc_level, NUM_BITS);
            let kyc_diff = builder.sub(kyc_level, min_kyc_level);
            let constrained_kyc_diff = builder.mul(claim_kyc.target, kyc_diff);
            builder.range_check(constrained_kyc_diff, NUM_BITS);

            let data = builder.build::<C>();
            Self {
                data,
                targets: IdentityTargets {
                    identity_secret,
                    age,
                    jurisdiction_hash,
                    kyc_level,
                    identity_commitment: identity_commitment.elements,
                    min_age,
                    required_jurisdiction,
                    min_kyc_level,
                    claim_bitmap,
                },
            }
        }
    }

    fn circuit() -> &'static IdentityCircuit {
        static CIRCUIT: OnceLock<IdentityCircuit> = OnceLock::new();
        CIRCUIT.get_or_init(IdentityCircuit::build)
    }

    /// Compute the Poseidon identity commitment from raw attributes.
    pub fn compute_identity_commitment(
        identity_secret: u64,
        age: u64,
        jurisdiction_hash: u64,
        kyc_level: u64,
    ) -> [u64; 4] {
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&[
            F::from_canonical_u64(identity_secret),
            F::from_canonical_u64(age),
            F::from_canonical_u64(jurisdiction_hash),
            F::from_canonical_u64(kyc_level),
        ]);
        hash.elements.map(|e| e.to_canonical_u64())
    }

    /// Generate a real identity proof.
    pub fn prove_identity(
        identity_secret: u64,
        age: u64,
        jurisdiction_hash: u64,
        kyc_level: u64,
        min_age: u64,
        required_jurisdiction: u64,
        min_kyc_level: u64,
        claim_bitmap: u8,
    ) -> Result<(Vec<u8>, Vec<u64>)> {
        // Pre-checks: only enforce the checks for claims that are requested.
        if (claim_bitmap & 1) != 0 && age < min_age {
            return Err(anyhow!("Age requirement not met"));
        }
        if (claim_bitmap & 2) != 0 && required_jurisdiction != 0 && jurisdiction_hash != required_jurisdiction {
            return Err(anyhow!("Jurisdiction requirement not met"));
        }
        if (claim_bitmap & 4) != 0 && kyc_level < min_kyc_level {
            return Err(anyhow!("KYC level requirement not met"));
        }

        let circuit = circuit();
        let mut pw = PartialWitness::new();
        let t = &circuit.targets;

        // Private inputs
        pw.set_target(t.identity_secret, F::from_canonical_u64(identity_secret))?;
        pw.set_target(t.age, F::from_canonical_u64(age))?;
        pw.set_target(t.jurisdiction_hash, F::from_canonical_u64(jurisdiction_hash))?;
        pw.set_target(t.kyc_level, F::from_canonical_u64(kyc_level))?;

        // Public inputs
        let commitment = compute_identity_commitment(identity_secret, age, jurisdiction_hash, kyc_level);
        for (i, &c) in commitment.iter().enumerate() {
            pw.set_target(t.identity_commitment[i], F::from_canonical_u64(c))?;
        }
        pw.set_target(t.min_age, F::from_canonical_u64(min_age))?;
        pw.set_target(t.required_jurisdiction, F::from_canonical_u64(required_jurisdiction))?;
        pw.set_target(t.min_kyc_level, F::from_canonical_u64(min_kyc_level))?;
        pw.set_target(t.claim_bitmap, F::from_canonical_u64(claim_bitmap as u64))?;

        let proof = circuit.data.prove(pw)?;
        let public_inputs: Vec<u64> = proof
            .public_inputs
            .iter()
            .map(|e| e.to_canonical_u64())
            .collect();
        let proof_bytes = bincode::serialize(&proof)?;
        Ok((proof_bytes, public_inputs))
    }

    /// Verify an identity proof.
    pub fn verify_identity(proof_bytes: &[u8]) -> Result<()> {
        let circuit = circuit();
        let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(proof_bytes)
            .map_err(|e| anyhow!("Failed to deserialize identity proof: {}", e))?;
        circuit.data.verify(proof).map_err(|e| anyhow!("Identity proof verification failed: {:?}", e))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_identity_circuit_builds() {
            let _circuit = IdentityCircuit::build();
        }

        #[test]
        fn test_valid_identity_proof_age_only() {
            let (proof_bytes, public_inputs) = prove_identity(
                12345, 25, 840, 2, 18, 0, 1, 1, // claim_bitmap = 1 (age only)
            )
            .unwrap();
            verify_identity(&proof_bytes).unwrap();
            assert_eq!(public_inputs[4], 18); // min_age
            assert_eq!(public_inputs[5], 0);  // required_jurisdiction
            assert_eq!(public_inputs[6], 1);  // min_kyc_level
            assert_eq!(public_inputs[7], 1);  // claim_bitmap
        }

        #[test]
        fn test_valid_identity_proof_all_claims() {
            let (proof_bytes, _public_inputs) = prove_identity(
                12345, 25, 840, 2, 18, 840, 1, 0b111, // all claims
            )
            .unwrap();
            verify_identity(&proof_bytes).unwrap();
        }

        #[test]
        fn test_invalid_age_fails() {
            assert!(prove_identity(
                12345, 16, 840, 2, 18, 0, 1, 1, // age 16 < 18
            )
            .is_err());
        }

        #[test]
        fn test_invalid_jurisdiction_fails() {
            assert!(prove_identity(
                12345, 25, 999, 2, 18, 840, 1, 0b010, // wrong jurisdiction
            )
            .is_err());
        }

        #[test]
        fn test_invalid_kyc_fails() {
            assert!(prove_identity(
                12345, 25, 840, 0, 18, 0, 1, 0b100, // kyc 0 < 1
            )
            .is_err());
        }

        #[test]
        fn test_no_claims_always_valid() {
            let (proof_bytes, _) = prove_identity(
                12345, 0, 999, 0, 18, 840, 1, 0, // no claims
            )
            .unwrap();
            verify_identity(&proof_bytes).unwrap();
        }
    }
}
