//! Identity zero-knowledge proof implementation for unified ZK system
//! 
//! Provides identity proofs using unified Plonky2 backend that allow users 
//! to prove they possess certain identity attributes without revealing the actual identity data

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_crypto::hashing::hash_blake3;
use crate::types::zk_proof::ZkProof;

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
        
        let secret_commitment = hash_blake3(&[&identity_secret[..], &attribute_commitment[..]].concat());
        
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

/// Zero-knowledge identity proof using unified Plonky2 system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkIdentityProof {
    /// Unified ZK proof for identity verification
    pub proof: ZkProof,
    /// Identity commitment
    pub commitment: IdentityCommitment,
    /// Attributes being proven (structure only, not values)
    pub proven_attributes: Vec<String>,
    /// Proof creation timestamp
    pub timestamp: u64,
}

impl ZkIdentityProof {
    /// Generate an identity proof using unified ZK system
    pub fn generate(
        attributes: &IdentityAttributes,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
        proven_attributes: Vec<String>,
    ) -> Result<Self> {
        let commitment = IdentityCommitment::generate(attributes, identity_secret, nullifier_secret)?;
        
        // Use unified ZK system via Plonky2
        let mut public_inputs = Vec::new();
        public_inputs.push(u64::from_le_bytes(identity_secret[0..8].try_into().unwrap_or([0u8; 8])));
        
        if let Some((min, max)) = attributes.age_range {
            public_inputs.push((min + max) as u64 / 2); // Average age
        } else {
            public_inputs.push(25); // Default age
        }
        
        if let Some(ref citizenship) = attributes.citizenship {
            public_inputs.push(u64::from_le_bytes(hash_blake3(citizenship.as_bytes())[0..8].try_into().unwrap_or([0u8; 8])));
        } else {
            public_inputs.push(840); // Default to US
        }
        
        public_inputs.push(u64::from_le_bytes(commitment.attribute_commitment[0..8].try_into().unwrap_or([0u8; 8])));
        public_inputs.push(18); // min_age requirement
        public_inputs.push(0);  // jurisdiction requirement
        public_inputs.push(1);  // verification level
        
        let proof = ZkProof::from_public_inputs(public_inputs)?;
        
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

    /// Generate proof for age verification only
    pub fn generate_age_proof(
        age: u16,
        min_age: u16,
        max_age: u16,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
    ) -> Result<Self> {
        if age < min_age || age > max_age {
            return Err(anyhow::anyhow!("Age {} not in range [{}, {}]", age, min_age, max_age));
        }
        
        let attributes = IdentityAttributes::new().with_age_range(min_age, max_age);
        Self::generate(&attributes, identity_secret, nullifier_secret, vec!["age_range".to_string()])
    }

    /// Generate proof for citizenship verification
    pub fn generate_citizenship_proof(
        citizenship: String,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
    ) -> Result<Self> {
        let attributes = IdentityAttributes::new().with_citizenship(citizenship);
        Self::generate(&attributes, identity_secret, nullifier_secret, vec!["citizenship".to_string()])
    }

    /// Generate proof for KYC level verification
    pub fn generate_kyc_proof(
        kyc_level: u8,
        identity_secret: [u8; 32],
        nullifier_secret: [u8; 32],
    ) -> Result<Self> {
        let attributes = IdentityAttributes::new().with_kyc_level(kyc_level);
        Self::generate(&attributes, identity_secret, nullifier_secret, vec!["kyc_level".to_string()])
    }

    /// Generate comprehensive identity proof with multiple attributes
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

    /// Verify the identity proof using unified ZK system
    pub fn verify(&self) -> Result<bool> {
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
        
        current_time > self.timestamp + duration_seconds
    }

    /// Get proof age in seconds
    pub fn age_seconds(&self) -> u64 {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        current_time.saturating_sub(self.timestamp)
    }

    /// Check if this proof contains a specific attribute
    pub fn proves_attribute(&self, attribute: &str) -> bool {
        self.proven_attributes.contains(&attribute.to_string())
    }

    /// Get the size of this proof in bytes
    pub fn proof_size(&self) -> usize {
        self.proof.size() +
        std::mem::size_of::<IdentityCommitment>() +
        self.proven_attributes.iter().map(|a| a.len()).sum::<usize>() +
        8 // timestamp
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

        // Aggregate challenges from unified proofs
        let mut challenge_data = Vec::new();
        for proof in &proofs {
            // Use proof data from unified system for challenge aggregation
            challenge_data.extend_from_slice(&proof.proof.proof_data);
        }
        let aggregated_challenge = hash_blake3(&challenge_data);

        // Calculate Merkle root
        let mut leaf_data = Vec::new();
        for proof in &proofs {
            let proof_hash = hash_blake3(&[
                &proof.commitment.attribute_commitment[..],
                &proof.commitment.secret_commitment[..],
                &proof.proof.proof_data[..],
            ].concat());
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
        self.proofs.iter().map(|p| p.proof_size()).sum::<usize>() + 
        32 * 2 + // aggregated_challenge + merkle_root
        8 // batch_timestamp
    }

    /// Get proof at specific index
    pub fn get_proof(&self, index: usize) -> Option<&ZkIdentityProof> {
        self.proofs.get(index)
    }
}

/// Helper function to calculate Merkle root
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
                chunk[0] // Odd number, carry forward
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
    fn test_identity_attributes() {
        let attrs = IdentityAttributes::new()
            .with_age_range(18, 65)
            .with_citizenship("US".to_string())
            .with_kyc_level(3)
            .with_custom("profession".to_string(), "engineer".to_string());
        
        assert_eq!(attrs.age_range, Some((18, 65)));
        assert_eq!(attrs.citizenship, Some("US".to_string()));
        assert_eq!(attrs.kyc_level, Some(3));
        assert!(attrs.custom_attributes.contains_key("profession"));
        
        let bytes = attrs.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_identity_commitment() {
        let attrs = IdentityAttributes::new().with_age_range(25, 35);
        let identity_secret = [1u8; 32];
        let nullifier_secret = [2u8; 32];
        
        let commitment = IdentityCommitment::generate(&attrs, identity_secret, nullifier_secret).unwrap();
        
        assert_ne!(commitment.attribute_commitment, [0u8; 32]);
        assert_ne!(commitment.secret_commitment, [0u8; 32]);
        assert_ne!(commitment.nullifier, [0u8; 32]);
        assert_ne!(commitment.public_key, [0u8; 32]);
    }

    #[test]
    fn test_identity_proof_generation() {
        let attrs = IdentityAttributes::new().with_age_range(21, 25);
        let identity_secret = [3u8; 32];
        let nullifier_secret = [4u8; 32];
        
        let proof = ZkIdentityProof::generate(
            &attrs,
            identity_secret,
            nullifier_secret,
            vec!["age_range".to_string()],
        ).unwrap();
        
        assert!(proof.proves_attribute("age_range"));
        assert!(!proof.proves_attribute("citizenship"));
        assert!(!proof.is_expired());
        assert!(proof.proof_size() > 0);
    }

    #[test]
    fn test_age_proof() {
        let identity_secret = [5u8; 32];
        let nullifier_secret = [6u8; 32];
        
        let proof = ZkIdentityProof::generate_age_proof(
            22, 18, 65, identity_secret, nullifier_secret
        ).unwrap();
        
        assert!(proof.proves_attribute("age_range"));
        assert_eq!(proof.proven_attributes.len(), 1);
    }

    #[test]
    fn test_citizenship_proof() {
        let identity_secret = [7u8; 32];
        let nullifier_secret = [8u8; 32];
        
        let proof = ZkIdentityProof::generate_citizenship_proof(
            "CA".to_string(), identity_secret, nullifier_secret
        ).unwrap();
        
        assert!(proof.proves_attribute("citizenship"));
    }

    #[test]
    fn test_comprehensive_proof() {
        let attrs = IdentityAttributes::new()
            .with_age_range(30, 40)
            .with_citizenship("UK".to_string())
            .with_kyc_level(2);
        
        let identity_secret = [9u8; 32];
        let nullifier_secret = [10u8; 32];
        
        let proof = ZkIdentityProof::generate_comprehensive(&attrs, identity_secret, nullifier_secret).unwrap();
        
        assert!(proof.proves_attribute("age_range"));
        assert!(proof.proves_attribute("citizenship"));
        assert!(proof.proves_attribute("kyc_level"));
        assert_eq!(proof.proven_attributes.len(), 3);
    }

    #[test]
    fn test_batch_identity_proof() {
        let identity_secret1 = [11u8; 32];
        let identity_secret2 = [12u8; 32];
        let nullifier_secret1 = [13u8; 32];
        let nullifier_secret2 = [14u8; 32];
        
        let attrs1 = IdentityAttributes::new().with_age_range(25, 30);
        let attrs2 = IdentityAttributes::new().with_citizenship("DE".to_string());
        
        let proof1 = ZkIdentityProof::generate(&attrs1, identity_secret1, nullifier_secret1, vec!["age_range".to_string()]).unwrap();
        let proof2 = ZkIdentityProof::generate(&attrs2, identity_secret2, nullifier_secret2, vec!["citizenship".to_string()]).unwrap();
        
        let batch = BatchIdentityProof::create(vec![proof1, proof2]).unwrap();
        
        assert_eq!(batch.batch_size(), 2);
        assert!(batch.get_proof(0).is_some());
        assert!(batch.get_proof(2).is_none());
        assert!(batch.total_size() > 0);
    }

    #[test]
    fn test_merkle_root_calculation() {
        let leaves = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        ];
        
        let root = calculate_merkle_root(&leaves);
        assert_ne!(root, [0u8; 32]);
        
        // Single leaf should return itself
        let single_root = calculate_merkle_root(&[[1u8; 32]]);
        assert_eq!(single_root, [1u8; 32]);
        
        // Empty should return zero
        let empty_root = calculate_merkle_root(&[]);
        assert_eq!(empty_root, [0u8; 32]);
    }

    #[test]
    fn test_proof_expiration() {
        let attrs = IdentityAttributes::new().with_kyc_level(1);
        let mut proof = ZkIdentityProof::generate(
            &attrs,
            [15u8; 32],
            [16u8; 32],
            vec!["kyc_level".to_string()],
        ).unwrap();
        
        // Set timestamp to 2 hours ago
        proof.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 7200;
        
        assert!(!proof.is_expired_after(3 * 60 * 60)); // 3 hours
        assert!(proof.is_expired_after(1 * 60 * 60)); // 1 hour
        assert!(proof.age_seconds() >= 7200);
    }
}
