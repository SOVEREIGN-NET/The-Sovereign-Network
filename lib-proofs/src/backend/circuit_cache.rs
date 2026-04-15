//! Circuit caching / PK-VK persistence for Plonky2.
//!
//! Plonky2's CircuitData is large and expensive to rebuild. This module
//! provides load/save helpers so the prover/verifier keys can be cached
//! on disk between process restarts.

#[cfg(feature = "real-proofs")]
pub mod real {
    use crate::transaction::circuit::real::TransactionTargets;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{
            circuit_data::CircuitData,
            config::PoseidonGoldilocksConfig,
        },
        util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
    };
    use std::{
        io::{Read, Write},
        path::Path,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// Load CircuitData from a cached file.
    pub fn load_circuit_data<P: AsRef<Path>>(path: P) -> anyhow::Result<CircuitData<F, C, D>> {
        let bytes = std::fs::read(path)?;
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
        let data = CircuitData::from_bytes(&bytes, &gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::anyhow!("CircuitData deserialization failed: {:?}", e))?;
        Ok(data)
    }

    /// Save CircuitData to a cache file.
    pub fn save_circuit_data<P: AsRef<Path>>(
        data: &CircuitData<F, C, D>,
        path: P,
    ) -> anyhow::Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
        let bytes = data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::anyhow!("CircuitData serialization failed: {:?}", e))?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Load a full transaction circuit (data + targets) from a cached file.
    ///
    /// File format:
    ///   [8 bytes: targets bincode length (little-endian u64)]
    ///   [targets_len bytes: bincode-serialized TransactionTargets]
    ///   [remaining bytes: native Plonky2 CircuitData]
    pub fn load_transaction_circuit<P: AsRef<Path>>(
        path: P,
    ) -> anyhow::Result<(CircuitData<F, C, D>, TransactionTargets)> {
        let bytes = std::fs::read(path)?;
        let mut cursor = std::io::Cursor::new(&bytes);

        let mut len_buf = [0u8; 8];
        cursor.read_exact(&mut len_buf)?;
        let targets_len = u64::from_le_bytes(len_buf) as usize;

        let pos = cursor.position() as usize;
        let targets_bytes = &bytes[pos..pos + targets_len];
        let targets: TransactionTargets = bincode::deserialize(targets_bytes)?;

        let data_bytes = &bytes[pos + targets_len..];
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
        let data = CircuitData::from_bytes(data_bytes, &gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::anyhow!("CircuitData deserialization failed: {:?}", e))?;

        Ok((data, targets))
    }

    /// Save a full transaction circuit (data + targets) to a cache file.
    pub fn save_transaction_circuit<P: AsRef<Path>>(
        data: &CircuitData<F, C, D>,
        targets: &TransactionTargets,
        path: P,
    ) -> anyhow::Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let targets_bytes = bincode::serialize(targets)?;
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
        let data_bytes = data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::anyhow!("CircuitData serialization failed: {:?}", e))?;

        let mut file = std::fs::File::create(path)?;
        file.write_all(&(targets_bytes.len() as u64).to_le_bytes())?;
        file.write_all(&targets_bytes)?;
        file.write_all(&data_bytes)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::transaction::circuit::real::TransactionCircuit;
        use plonky2::{
            field::types::Field,
            hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
            iop::witness::{PartialWitness, WitnessWrite},
        };

        #[test]
        fn test_circuit_data_roundtrip() {
            let circuit = TransactionCircuit::build();
            let tmp = std::env::temp_dir().join("zhtp_tx_circuit_cache_test.bin");
            save_circuit_data(&circuit.data, &tmp).unwrap();
            let loaded = load_circuit_data(&tmp).unwrap();

            // Verify that the loaded data can verify a proof
            let mut pw = PartialWitness::new();
            let t = &circuit.targets;
            type GF = plonky2::field::goldilocks_field::GoldilocksField;
            pw.set_target(t.sender_balance, GF::from_canonical_u64(1000)).unwrap();
            pw.set_target(t.amount, GF::from_canonical_u64(100)).unwrap();
            pw.set_target(t.fee, GF::from_canonical_u64(10)).unwrap();
            let hash = hash_n_to_hash_no_pad::<GF, PoseidonPermutation<GF>>(&[GF::from_canonical_u64(1)]);
            pw.set_target(t.nullifier_seed_hash, hash.elements[0]).unwrap();
            pw.set_target(t.sender_secret, GF::from_canonical_u64(42)).unwrap();
            pw.set_target(t.nullifier_seed, GF::from_canonical_u64(1)).unwrap();

            let proof = loaded.prove(pw).unwrap();
            loaded.verify(proof).unwrap();

            let _ = std::fs::remove_file(&tmp);
        }

        #[test]
        fn test_transaction_circuit_roundtrip() {
            let circuit = TransactionCircuit::build();
            let tmp = std::env::temp_dir().join("zhtp_tx_circuit_full_cache_test.bin");

            save_transaction_circuit(&circuit.data, &circuit.targets, &tmp).unwrap();
            let (loaded_data, loaded_targets) = load_transaction_circuit(&tmp).unwrap();

            // Build a proof using the *loaded* targets and *loaded* data
            let mut pw = PartialWitness::new();
            type GF = plonky2::field::goldilocks_field::GoldilocksField;
            pw.set_target(loaded_targets.sender_balance, GF::from_canonical_u64(1000))
                .unwrap();
            pw.set_target(loaded_targets.amount, GF::from_canonical_u64(100))
                .unwrap();
            pw.set_target(loaded_targets.fee, GF::from_canonical_u64(10))
                .unwrap();
            let hash = hash_n_to_hash_no_pad::<GF, PoseidonPermutation<GF>>(&[GF::from_canonical_u64(1)]);
            pw.set_target(loaded_targets.nullifier_seed_hash, hash.elements[0])
                .unwrap();
            pw.set_target(loaded_targets.sender_secret, GF::from_canonical_u64(42))
                .unwrap();
            pw.set_target(loaded_targets.nullifier_seed, GF::from_canonical_u64(1))
                .unwrap();

            let proof = loaded_data.prove(pw).unwrap();
            loaded_data.verify(proof).unwrap();

            let _ = std::fs::remove_file(&tmp);
        }
    }
}

#[cfg(not(feature = "real-proofs"))]
pub mod stub {
    pub fn circuit_cache_unavailable() -> anyhow::Result<()> {
        Err(anyhow::anyhow!(
            "Circuit cache requires the 'real-proofs' feature"
        ))
    }
}
