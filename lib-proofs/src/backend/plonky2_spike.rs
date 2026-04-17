//! Spike: verify that Plonky2 actually proves and verifies on this machine.
//!
//! This is a temporary module for Epic E. It will be removed once the real
//! transaction circuit is wired up.

#[cfg(feature = "real-proofs")]
pub mod real {
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::Field,
        },
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// Build a tiny circuit: prove that `a + b = c`.
    pub fn build_addition_circuit() -> plonky2::plonk::circuit_data::CircuitData<F, C, D> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Public inputs
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let c = builder.add_virtual_target();

        let sum = builder.add(a, b);
        builder.connect(sum, c);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(c);

        builder.build::<C>()
    }

    /// Generate a proof for `a + b = c`.
    pub fn prove_addition(
        data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
        a: u64,
        b: u64,
        c: u64,
    ) -> anyhow::Result<plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        let targets = data.prover_only.public_inputs.clone();
        pw.set_target(targets[0], F::from_canonical_u64(a))?;
        pw.set_target(targets[1], F::from_canonical_u64(b))?;
        pw.set_target(targets[2], F::from_canonical_u64(c))?;
        let proof = data.prove(pw)?;
        Ok(proof)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_plonky2_addition_proof() {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let a = builder.add_virtual_target();
            let b = builder.add_virtual_target();
            let c = builder.add_virtual_target();
            let sum = builder.add(a, b);
            builder.connect(sum, c);
            builder.register_public_input(a);
            builder.register_public_input(b);
            builder.register_public_input(c);

            let data = builder.build::<C>();
            let mut pw = PartialWitness::new();
            pw.set_target(a, F::from_canonical_u64(7)).unwrap();
            pw.set_target(b, F::from_canonical_u64(13)).unwrap();
            pw.set_target(c, F::from_canonical_u64(20)).unwrap();

            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        }
    }
}

#[cfg(not(feature = "real-proofs"))]
pub mod stub {
    /// Dummy placeholder when real-proofs is disabled.
    pub fn spike_unavailable() -> anyhow::Result<()> {
        Err(anyhow::anyhow!(
            "Plonky2 spike requires the 'real-proofs' feature"
        ))
    }
}
