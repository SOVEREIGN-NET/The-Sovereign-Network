//! Plonky2-specific implementation of `ProofBackend`.
//!
//! This is a thin wrapper around the legacy `ZkProofSystem` that serializes
//! `Plonky2Proof` into the opaque `BackendProof.data` blob.
//!
//! Transaction proofs (Epic E) bypass the legacy stub and use a real Plonky2
//! circuit when the `real-proofs` feature is enabled.

use super::{BackendProof, ProofBackend};
use crate::plonky2::{Plonky2Proof, ZkProofSystem};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Serialized envelope for Bulletproofs range proofs stored in `BackendProof.data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BulletproofsRangeEnvelope {
    pub proof_bytes: Vec<u8>,
    pub commitment: [u8; 32],
    pub min_value: u64,
    pub max_value: u64,
}

/// Plonky2 backend wrapper.
pub struct Plonky2Backend {
    inner: ZkProofSystem,
}

impl Plonky2Backend {
    /// Create a new Plonky2 backend.
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: ZkProofSystem::new()?,
        })
    }

    fn encode(proof: &Plonky2Proof) -> Result<Vec<u8>> {
        Ok(bincode::serialize(proof)?)
    }

    fn decode(data: &[u8]) -> Result<Plonky2Proof> {
        Ok(bincode::deserialize(data)?)
    }

    #[cfg(feature = "real-proofs")]
    fn encode_tx_proof(proof: &crate::transaction::circuit::real::TxProof) -> Result<Vec<u8>> {
        Ok(bincode::serialize(proof)?)
    }

    #[cfg(feature = "real-proofs")]
    fn decode_tx_proof(data: &[u8]) -> Result<crate::transaction::circuit::real::TxProof> {
        Ok(bincode::deserialize(data)?)
    }
}

impl ProofBackend for Plonky2Backend {
    fn name(&self) -> &str {
        "plonky2"
    }

    fn prove_transaction(
        &self,
        sender_balance: u64,
        amount: u64,
        fee: u64,
        sender_secret: u64,
        nullifier_seed: u64,
        merkle_root: [u64; 4],
        leaf_index: u32,
        merkle_siblings: &[[u64; 4]],
    ) -> Result<BackendProof> {
        #[cfg(feature = "real-proofs")]
        {
            use plonky2::field::goldilocks_field::GoldilocksField;
            use plonky2::field::types::Field;
            use crate::transaction::circuit::MERKLE_DEPTH;

            if merkle_siblings.len() != MERKLE_DEPTH {
                return Err(anyhow::anyhow!(
                    "Expected {} Merkle siblings, got {}",
                    MERKLE_DEPTH,
                    merkle_siblings.len()
                ));
            }

            let f = |v: u64| GoldilocksField::from_canonical_u64(v);
            let root: [GoldilocksField; 4] = [
                f(merkle_root[0]), f(merkle_root[1]), f(merkle_root[2]), f(merkle_root[3]),
            ];
            let mut siblings = [[GoldilocksField::ZERO; 4]; MERKLE_DEPTH];
            for (i, s) in merkle_siblings.iter().enumerate() {
                siblings[i] = [f(s[0]), f(s[1]), f(s[2]), f(s[3])];
            }

            let proof = crate::transaction::circuit::real::prove_transaction(
                sender_balance,
                amount,
                fee,
                sender_secret,
                nullifier_seed,
                root,
                leaf_index,
                &siblings,
            )?;
            Ok(BackendProof {
                proof_system: "plonky2-real-transaction".to_string(),
                data: Self::encode_tx_proof(&proof)?,
            })
        }
        #[cfg(not(feature = "real-proofs"))]
        {
            let plonky2_proof = self
                .inner
                .prove_transaction(sender_balance, amount, fee, sender_secret, nullifier_seed)?;
            Ok(BackendProof {
                proof_system: plonky2_proof.proof_system.clone(),
                data: Self::encode(&plonky2_proof)?,
            })
        }
    }

    fn verify_transaction(&self, proof: &BackendProof) -> Result<bool> {
        #[cfg(feature = "real-proofs")]
        {
            if proof.proof_system == "plonky2-real-transaction" {
                let tx_proof = Self::decode_tx_proof(&proof.data)?;
                crate::transaction::circuit::real::verify_transaction(&tx_proof)
                    .map(|_| true)
            } else {
                // Fallback: old stub proof format
                let plonky2_proof = Self::decode(&proof.data)?;
                self.inner.verify_transaction(&plonky2_proof)
            }
        }
        #[cfg(not(feature = "real-proofs"))]
        {
            let plonky2_proof = Self::decode(&proof.data)?;
            self.inner.verify_transaction(&plonky2_proof)
        }
    }

    fn prove_identity(
        &self,
        identity_secret: u64,
        age: u64,
        jurisdiction_hash: u64,
        credential_hash: u64,
        min_age: u64,
        required_jurisdiction: u64,
        verification_level: u64,
    ) -> Result<BackendProof> {
        let plonky2_proof = self.inner.prove_identity(
            identity_secret,
            age,
            jurisdiction_hash,
            credential_hash,
            min_age,
            required_jurisdiction,
            verification_level,
        )?;
        Ok(BackendProof {
            proof_system: plonky2_proof.proof_system.clone(),
            data: Self::encode(&plonky2_proof)?,
        })
    }

    fn verify_identity(&self, proof: &BackendProof) -> Result<bool> {
        let plonky2_proof = Self::decode(&proof.data)?;
        self.inner.verify_identity(&plonky2_proof)
    }

    fn prove_range(
        &self,
        value: u64,
        blinding_factor: u64,
        min_value: u64,
        max_value: u64,
    ) -> Result<BackendProof> {
        // Range proofs are implemented via Bulletproofs, not Plonky2.
        let mut blinding = [0u8; 32];
        blinding[..8].copy_from_slice(&blinding_factor.to_le_bytes());
        let (proof_bytes, commitment) =
            crate::range::bulletproofs::prove_range(value, min_value, max_value, blinding)?;
        let data = bincode::serialize(&BulletproofsRangeEnvelope {
            proof_bytes,
            commitment,
            min_value,
            max_value,
        })?;
        Ok(BackendProof {
            proof_system: "Bulletproofs".to_string(),
            data,
        })
    }

    fn verify_range(&self, proof: &BackendProof) -> Result<bool> {
        if proof.proof_system == "Bulletproofs" {
            let envelope: BulletproofsRangeEnvelope = bincode::deserialize(&proof.data)?;
            return crate::range::bulletproofs::verify_range(
                &envelope.proof_bytes,
                &envelope.commitment,
                envelope.min_value,
                envelope.max_value,
            );
        }
        // Legacy fallback for old Plonky2-stub range proofs (test compat only).
        let plonky2_proof = Self::decode(&proof.data)?;
        self.inner.verify_range(&plonky2_proof)
    }

    fn prove_storage_access(
        &self,
        access_key: u64,
        requester_secret: u64,
        data_hash: u64,
        permission_level: u64,
        required_permission: u64,
    ) -> Result<BackendProof> {
        let plonky2_proof = self.inner.prove_storage_access(
            access_key,
            requester_secret,
            data_hash,
            permission_level,
            required_permission,
        )?;
        Ok(BackendProof {
            proof_system: plonky2_proof.proof_system.clone(),
            data: Self::encode(&plonky2_proof)?,
        })
    }

    fn verify_storage_access(&self, proof: &BackendProof) -> Result<bool> {
        let plonky2_proof = Self::decode(&proof.data)?;
        self.inner.verify_storage_access(&plonky2_proof)
    }

    fn prove_merkle(
        &self,
        leaf: [u8; 32],
        path: &[[u8; 32]],
        indices: &[bool],
        root: [u8; 32],
    ) -> Result<BackendProof> {
        let plonky2_proof = self.inner.prove_merkle(leaf, path, indices, root)?;
        Ok(BackendProof {
            proof_system: plonky2_proof.proof_system.clone(),
            data: Self::encode(&plonky2_proof)?,
        })
    }

    fn verify_merkle(&self, proof: &BackendProof, root: [u8; 32]) -> Result<bool> {
        let plonky2_proof = Self::decode(&proof.data)?;
        self.inner.verify_merkle(&plonky2_proof, root)
    }
}
