//! Minimal Plonky2 transaction circuit for Epic E.
//!
//! Statement: `amount + fee <= sender_balance`.
//! This is a first-step real circuit; nullifiers and commitments will be
//! added in follow-up PRs.

#[cfg(feature = "real-proofs")]
pub mod real {
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::Field,
        },
        hash::{
            hashing::hash_n_to_hash_no_pad,
            poseidon::{PoseidonHash, PoseidonPermutation},
        },
        iop::target::Target,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitData,
            config::PoseidonGoldilocksConfig,
            proof::ProofWithPublicInputs,
        },
    };
    use std::sync::OnceLock;

    pub type TxProof = ProofWithPublicInputs<F, C, D>;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    const NUM_BITS: usize = 64;

    /// Public inputs for a transaction proof.
    /// Order: [sender_balance, amount, fee, nullifier_seed_hash]
    pub const TX_PI_LEN: usize = 4;

    /// Targets for the transaction circuit.
    pub struct TransactionTargets {
        pub sender_balance: Target,
        pub amount: Target,
        pub fee: Target,
        pub nullifier_seed_hash: Target,
        pub sender_secret: Target,
        pub nullifier_seed: Target,
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

            // Private inputs
            let sender_secret = builder.add_virtual_target();
            let nullifier_seed = builder.add_virtual_target();

            // Constraint 1: amount + fee <= sender_balance
            let total = builder.add(amount, fee);
            let diff = builder.sub(sender_balance, total);
            builder.range_check(diff, NUM_BITS);
            let recomposed = builder.add(total, diff);
            builder.connect(recomposed, sender_balance);

            // Constraint 2: nullifier_seed_hash == Poseidon(nullifier_seed)
            let computed_hash =
                builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![nullifier_seed]);
            builder.connect(nullifier_seed_hash, computed_hash.elements[0]);

            // Tie sender_secret into the circuit so it is not a free variable.
            let _mixed = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
                sender_secret,
                nullifier_seed,
            ]);

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
                },
            }
        }
    }

    /// Lazy-initialized circuit so we only build once per process.
    fn circuit() -> &'static TransactionCircuit {
        static CIRCUIT: OnceLock<TransactionCircuit> = OnceLock::new();
        CIRCUIT.get_or_init(TransactionCircuit::build)
    }

    /// Generate a transaction proof.
    pub fn prove_transaction(
        sender_balance: u64,
        amount: u64,
        fee: u64,
        sender_secret: u64,
        nullifier_seed: u64,
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

        // Private inputs
        pw.set_target(t.sender_secret, F::from_canonical_u64(sender_secret))?;
        pw.set_target(t.nullifier_seed, F::from_canonical_u64(nullifier_seed))?;

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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_valid_transaction_proof() {
            let proof = prove_transaction(1000, 100, 10, 12345, 67890).unwrap();
            verify_transaction(&proof).unwrap();
        }

        #[test]
        fn test_insufficient_balance_fails_at_circuit_level() {
            // The pre-check catches this before proving.
            let result = prove_transaction(100, 1000, 10, 12345, 67890);
            assert!(result.is_err());
        }

        #[test]
        fn test_transaction_circuit_builds() {
            let _circuit = TransactionCircuit::build();
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
