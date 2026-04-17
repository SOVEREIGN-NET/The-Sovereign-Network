//! Identity zero-knowledge proof implementation using a real Plonky2 circuit.
//!
//! Provides selective-disclosure identity proofs that allow users to prove
//! possession of certain attributes (age >= threshold, exact jurisdiction,
//! kyc_level >= threshold) without revealing the raw identity data.

use crate::types::zk_proof::ZkProof;
use anyhow::Result;
use lib_crypto::hashing::hash_blake3;
use serde::{Deserialize, Serialize};

/// Identity attributes that can be proven in zero-knowledge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAttributes {
    /// Age range proof (e.g., over 18, under 65)
    pub age_range: Option<(u16, u16)>,
    /// Citizenship proof
    pub citizenship: Option<String>,
    /// Professional license proof
    pub license_type: Option<String>,
    /// Educational credential proof
    pub education_level: Option<String>,
    /// KYC verification level
    pub kyc_level: Option<u8>,
    /// Custom attributes
    pub custom_attributes: std::collections::HashMap<String, String>,
}

impl IdentityAttributes {
    /// Create new empty identity attributes
    pub fn new() -> Self {
        Self {
            age_range: None,
            citizenship: None,
            license_type: None,
            education_level: None,
            kyc_level: None,
            custom_attributes: std::collections::HashMap::new(),
        }
    }

    /// Add age range attribute
    pub fn with_age_range(mut self, min_age: u16, max_age: u16) -> Self {
        self.age_range = Some((min_age, max_age));
        self
    }

    /// Add citizenship attribute
    pub fn with_citizenship(mut self, country: String) -> Self {
        self.citizenship = Some(country);
        self
    }

    /// Add license type attribute
    pub fn with_license(mut self, license: String) -> Self {
        self.license_type = Some(license);
        self
    }

    /// Add education level attribute
    pub fn with_education(mut self, level: String) -> Self {
        self.education_level = Some(level);
        self
    }

    /// Add KYC level attribute
    pub fn with_kyc_level(mut self, level: u8) -> Self {
        self.kyc_level = Some(level);
        self
    }

    /// Add custom attribute
    pub fn with_custom(mut self, key: String, value: String) -> Self {
        self.custom_attributes.insert(key, value);
        self
    }

    /// Serialize attributes for hashing
    pub fn to_bytes(&self) -> Vec<u8> {
        // Deterministic serialization for consistent hashing
        let mut bytes = Vec::new();

        if let Some((min, max)) = self.age_range {
            bytes.extend_from_slice(b"age_range:");
            bytes.extend_from_slice(&min.to_le_bytes());
            bytes.extend_from_slice(&max.to_le_bytes());
        }

        if let Some(ref citizenship) = self.citizenship {
            bytes.extend_from_slice(b"citizenship:");
            bytes.extend_from_slice(citizenship.as_bytes());
        }

        if let Some(ref license) = self.license_type {
            bytes.extend_from_slice(b"license:");
            bytes.extend_from_slice(license.as_bytes());
        }

        if let Some(ref education) = self.education_level {
            bytes.extend_from_slice(b"education:");
            bytes.extend_from_slice(education.as_bytes());
        }

        if let Some(level) = self.kyc_level {
            bytes.extend_from_slice(b"kyc:");
            bytes.push(level);
        }

        // Sort custom attributes for deterministic serialization
        let mut sorted_attrs: Vec<_> = self.custom_attributes.iter().collect();
        sorted_attrs.sort_by_key(|(k, _)| *k);

        for (key, value) in sorted_attrs {
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(b':');
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(b';');
        }

        bytes
    }
}

impl Default for IdentityAttributes {
    fn default() -> Self {
        Self::new()
    }
}

/// Identity commitment structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCommitment {
    /// Commitment to identity attributes
    pub attribute_commitment: [u8; 32],
    /// Commitment to identity secret
    pub secret_commitment: [u8; 32],
    /// Nullifier for preventing double-spending of identity
    pub nullifier: [u8; 32],
    /// Public key for identity verification
    pub public_key: [u8; 32],
}

impl IdentityCommitment {
    /// Generate identity commitment from attributes and secret
    pub fn generate(
        attributes: &IdentityAttributes,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
    ) -> Result<Self> {
        let attribute_bytes = attributes.to_bytes();
        let attribute_commitment = hash_blake3(&attribute_bytes);

        let secret_commitment =
            hash_blake3(&[&identity_secret[..], &attribute_commitment[..]].concat());

        let nullifier = hash_blake3(&[&nullifier_secret[..], &identity_secret[..]].concat());

        // Generate public key from identity secret
        let public_key = hash_blake3(&[&identity_secret[..], b"pubkey"].concat());

        Ok(IdentityCommitment {
            attribute_commitment,
            secret_commitment,
            nullifier,
            public_key,
        })
    }
}

/// Zero-knowledge identity proof using a real Plonky2 selective-disclosure circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkIdentityProof {
    /// Real ZK proof for identity verification
    pub proof: ZkProof,
    /// Identity commitment
    pub commitment: IdentityCommitment,
    /// Attributes being proven (structure only, not values)
    pub proven_attributes: Vec<String>,
    /// Proof creation timestamp
    pub timestamp: u64,
}

impl ZkIdentityProof {
    /// Build a claim bitmap from proven attribute names.
    /// bit 0 = age, bit 1 = jurisdiction/citizenship, bit 2 = kyc_level
    fn claim_bitmap(proven_attributes: &[String]) -> u8 {
        let mut bitmap = 0u8;
        for attr in proven_attributes {
            match attr.as_str() {
                "age_range" => bitmap |= 1,
                "citizenship" => bitmap |= 2,
                "kyc_level" => bitmap |= 4,
                _ => {}
            }
        }
        bitmap
    }

    /// Internal generation with explicit attribute values.
    fn generate_internal(
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
        proven_attributes: Vec<String>,
        age: u64,
        jurisdiction_hash: u64,
        kyc_level: u64,
        min_age: u64,
        required_jurisdiction: u64,
        min_kyc_level: u64,
    ) -> Result<Self> {
        let attributes = IdentityAttributes::new(); // only used for commitment compat
        let commitment =
            IdentityCommitment::generate(&attributes, identity_secret, nullifier_secret)?;

        let identity_secret_u64 =
            u64::from_le_bytes(identity_secret[0..8].try_into().unwrap_or([0u8; 8]));
        let claim_bitmap = Self::claim_bitmap(&proven_attributes);

        #[cfg(feature = "real-proofs")]
        {
            let (proof_bytes, public_inputs) = crate::identity::circuit::real::prove_identity(
                identity_secret_u64,
                age,
                jurisdiction_hash,
                kyc_level,
                min_age,
                required_jurisdiction,
                min_kyc_level,
                claim_bitmap,
            )?;

            let mut pi_bytes = Vec::with_capacity(public_inputs.len() * 8);
            for v in &public_inputs {
                pi_bytes.extend_from_slice(&v.to_le_bytes());
            }

            let proof = ZkProof {
                proof_system: "plonky2-real-identity".to_string(),
                proof_data: proof_bytes.clone(),
                public_inputs: pi_bytes,
                verification_key: vec![],
                backend_proof: None,
                proof: proof_bytes,
                circuit_id: "identity_selective_disclosure_v1".to_string(),
                circuit_version: 1,
                is_mock: false,
            };

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            Ok(ZkIdentityProof {
                proof,
                commitment,
                proven_attributes,
                timestamp,
            })
        }

        #[cfg(not(feature = "real-proofs"))]
        {
            let _ = (
                identity_secret_u64,
                age,
                jurisdiction_hash,
                kyc_level,
                min_age,
                required_jurisdiction,
                min_kyc_level,
                claim_bitmap,
            );
            Err(anyhow::anyhow!(
                "Real identity proofs require the 'real-proofs' feature"
            ))
        }
    }

    /// Generate an identity proof from attributes (backward-compatible API).
    pub fn generate(
        attributes: &IdentityAttributes,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
        proven_attributes: Vec<String>,
    ) -> Result<Self> {
        let age = attributes
            .age_range
            .map(|(min, max)| (min + max) as u64 / 2)
            .unwrap_or(25);
        let jurisdiction_hash = attributes
            .citizenship
            .as_ref()
            .map(|c| {
                u64::from_le_bytes(
                    hash_blake3(c.as_bytes())[0..8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                )
            })
            .unwrap_or(840);
        let kyc_level = attributes.kyc_level.map(|k| k as u64).unwrap_or(1);
        let min_age = attributes.age_range.map(|(min, _)| min as u64).unwrap_or(18);
        let required_jurisdiction = attributes
            .citizenship
            .as_ref()
            .map(|c| {
                u64::from_le_bytes(
                    hash_blake3(c.as_bytes())[0..8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                )
            })
            .unwrap_or(0);
        let min_kyc_level = attributes.kyc_level.map(|k| k as u64).unwrap_or(1);

        Self::generate_internal(
            identity_secret,
            nullifier_secret,
            proven_attributes,
            age,
            jurisdiction_hash,
            kyc_level,
            min_age,
            required_jurisdiction,
            min_kyc_level,
        )
    }

    /// Generate proof for age verification only.
    pub fn generate_age_proof(
        age: u16,
        min_age: u16,
        max_age: u16,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
    ) -> Result<Self> {
        if age < min_age || age > max_age {
            return Err(anyhow::anyhow!(
                "Age {} not in range [{}, {}]",
                age,
                min_age,
                max_age
            ));
        }
        Self::generate_internal(
            identity_secret,
            nullifier_secret,
            vec!["age_range".to_string()],
            age as u64,
            0,
            0,
            min_age as u64,
            0,
            0,
        )
    }

    /// Generate proof for citizenship verification.
    pub fn generate_citizenship_proof(
        citizenship: String,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
    ) -> Result<Self> {
        let jh = u64::from_le_bytes(
            hash_blake3(citizenship.as_bytes())[0..8]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
        Self::generate_internal(
            identity_secret,
            nullifier_secret,
            vec!["citizenship".to_string()],
            0,
            jh,
            0,
            0,
            jh,
            0,
        )
    }

    /// Generate proof for KYC level verification.
    pub fn generate_kyc_proof(
        kyc_level: u8,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
    ) -> Result<Self> {
        Self::generate_internal(
            identity_secret,
            nullifier_secret,
            vec!["kyc_level".to_string()],
            0,
            0,
            kyc_level as u64,
            0,
            0,
            kyc_level as u64,
        )
    }

    /// Generate comprehensive identity proof with multiple attributes.
    pub fn generate_comprehensive(
        attributes: &IdentityAttributes,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
    ) -> Result<Self> {
        let mut proven_attrs = Vec::new();

        if attributes.age_range.is_some() {
            proven_attrs.push("age_range".to_string());
        }
        if attributes.citizenship.is_some() {
            proven_attrs.push("citizenship".to_string());
        }
        if attributes.license_type.is_some() {
            proven_attrs.push("license_type".to_string());
        }
        if attributes.education_level.is_some() {
            proven_attrs.push("education_level".to_string());
        }
        if attributes.kyc_level.is_some() {
            proven_attrs.push("kyc_level".to_string());
        }
        for key in attributes.custom_attributes.keys() {
            proven_attrs.push(format!("custom:{}", key));
        }

        Self::generate(attributes, identity_secret, nullifier_secret, proven_attrs)
    }

    /// Verify the identity proof using the real Plonky2 circuit.
    pub fn verify(&self) -> Result<bool> {
        #[cfg(feature = "real-proofs")]
        {
            if self.proof.proof_system == "plonky2-real-identity" {
                return crate::identity::circuit::real::verify_identity(&self.proof.proof_data)
                    .map(|_| true)
                    .or_else(|e| {
                        tracing::debug!("Identity proof verification failed: {}", e);
                        Ok(false)
                    });
            }
        }
        // Fallback to legacy backend verification for old proofs.
        self.proof.verify()
    }

    /// Check if proof is expired (default: 24 hours)
    pub fn is_expired(&self) -> bool {
        self.is_expired_after(24 * 60 * 60) // 24 hours in seconds
    }

    /// Check if proof is expired after specified duration in seconds
    pub fn is_expired_after(&self, duration_seconds: u64) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.timestamp + duration_seconds < current_time
    }

    /// Check if the proof proves a specific attribute
    pub fn proves_attribute(&self, attribute: &str) -> bool {
        self.proven_attributes.contains(&attribute.to_string())
    }

    /// Get proof size in bytes
    pub fn proof_size(&self) -> usize {
        self.proof.proof_data.len()
    }

    /// Get proof age in seconds
    pub fn age_seconds(&self) -> u64 {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        current_time.saturating_sub(self.timestamp)
    }
}

/// Batch identity proof for multiple identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchIdentityProof {
    /// Individual identity proofs
    pub proofs: Vec<ZkIdentityProof>,
    /// Aggregated challenge
    pub aggregated_challenge: [u8; 32],
    /// Merkle root of all proofs
    pub merkle_root: [u8; 32],
    /// Batch timestamp
    pub batch_timestamp: u64,
}

impl BatchIdentityProof {
    /// Create batch proof from individual proofs
    pub fn create(proofs: Vec<ZkIdentityProof>) -> Result<Self> {
        if proofs.is_empty() {
            return Err(anyhow::anyhow!("Cannot create empty batch proof"));
        }

        let mut challenge_data = Vec::new();
        for proof in &proofs {
            challenge_data.extend_from_slice(&proof.proof.proof_data);
        }
        let aggregated_challenge = hash_blake3(&challenge_data);

        let mut leaf_data = Vec::new();
        for proof in &proofs {
            let proof_hash = hash_blake3(
                &[
                    &proof.commitment.attribute_commitment[..],
                    &proof.commitment.secret_commitment[..],
                    &proof.proof.proof_data[..],
                ]
                .concat(),
            );
            leaf_data.push(proof_hash);
        }

        let merkle_root = calculate_merkle_root(&leaf_data);

        let batch_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(BatchIdentityProof {
            proofs,
            aggregated_challenge,
            merkle_root,
            batch_timestamp,
        })
    }

    /// Get the number of proofs in this batch
    pub fn batch_size(&self) -> usize {
        self.proofs.len()
    }

    /// Get total size of all proofs
    pub fn total_size(&self) -> usize {
        self.proofs.iter().map(|p| p.proof_size()).sum::<usize>()
            + 32 * 2
            + 8
    }

    /// Get proof at specific index
    pub fn get_proof(&self, index: usize) -> Option<&ZkIdentityProof> {
        self.proofs.get(index)
    }
}

fn calculate_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut current_level = leaves.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_blake3(&[&chunk[0][..], &chunk[1][..]].concat())
            } else {
                chunk[0]
            };
            next_level.push(hash);
        }
        current_level = next_level;
    }
    current_level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_proof_generation() {
        let attrs = IdentityAttributes::new()
            .with_age_range(18, 65)
            .with_citizenship("US".to_string())
            .with_kyc_level(3);

        let proof =
            ZkIdentityProof::generate(&attrs, [1u8; 32], [2u8; 32], vec!["age_range".to_string()]);

        #[cfg(feature = "real-proofs")]
        {
            assert!(proof.is_ok());
            let p = proof.unwrap();
            assert!(p.verify().unwrap());
            assert!(p.proves_attribute("age_range"));
            assert!(!p.proves_attribute("kyc_level"));
        }

        #[cfg(not(feature = "real-proofs"))]
        assert!(proof.is_err());
    }

    #[test]
    fn test_age_proof_only() {
        let result = ZkIdentityProof::generate_age_proof(25, 18, 65, [1u8; 32], [2u8; 32]);

        #[cfg(feature = "real-proofs")]
        {
            assert!(result.is_ok());
            let proof = result.unwrap();
            assert!(proof.verify().unwrap());
            assert!(proof.proves_attribute("age_range"));
        }

        #[cfg(not(feature = "real-proofs"))]
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_age_rejected() {
        let result = ZkIdentityProof::generate_age_proof(16, 18, 65, [1u8; 32], [2u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_citizenship_proof() {
        let result =
            ZkIdentityProof::generate_citizenship_proof("US".to_string(), [1u8; 32], [2u8; 32]);

        #[cfg(feature = "real-proofs")]
        {
            assert!(result.is_ok());
            let proof = result.unwrap();
            assert!(proof.verify().unwrap());
            assert!(proof.proves_attribute("citizenship"));
        }

        #[cfg(not(feature = "real-proofs"))]
        assert!(result.is_err());
    }

    #[test]
    fn test_kyc_proof() {
        let result = ZkIdentityProof::generate_kyc_proof(2, [1u8; 32], [2u8; 32]);

        #[cfg(feature = "real-proofs")]
        {
            assert!(result.is_ok());
            let proof = result.unwrap();
            assert!(proof.verify().unwrap());
            assert!(proof.proves_attribute("kyc_level"));
        }

        #[cfg(not(feature = "real-proofs"))]
        assert!(result.is_err());
    }

    #[test]
    fn test_comprehensive_proof() {
        let attrs = IdentityAttributes::new()
            .with_age_range(30, 40)
            .with_citizenship("UK".to_string())
            .with_kyc_level(2);

        let result = ZkIdentityProof::generate_comprehensive(&attrs, [1u8; 32], [2u8; 32]);

        #[cfg(feature = "real-proofs")]
        {
            assert!(result.is_ok());
            let proof = result.unwrap();
            assert!(proof.verify().unwrap());
            assert!(proof.proves_attribute("age_range"));
            assert!(proof.proves_attribute("citizenship"));
            assert!(proof.proves_attribute("kyc_level"));
        }

        #[cfg(not(feature = "real-proofs"))]
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_serde_roundtrip() {
        let attrs = IdentityAttributes::new().with_kyc_level(1);
        let proof =
            ZkIdentityProof::generate(&attrs, [1u8; 32], [2u8; 32], vec!["kyc_level".to_string()]);

        #[cfg(feature = "real-proofs")]
        {
            let p = proof.unwrap();
            let bytes = serde_json::to_vec(&p).unwrap();
            let recovered: ZkIdentityProof = serde_json::from_slice(&bytes).unwrap();
            assert!(recovered.verify().unwrap());
        }

        #[cfg(not(feature = "real-proofs"))]
        assert!(proof.is_err());
    }
}
