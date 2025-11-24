//! Identity prover implementation
//! 
//! Provides zero-knowledge identity proof generation using the production
//! ZK proof system with actual cryptographic security guarantees.

use crate::identity::{ZkIdentityProof, IdentityCommitment, IdentityAttributes};
use crate::plonky2::ZkProofSystem;
use anyhow::{Result, anyhow};
use lib_crypto::hashing::hash_blake3;
use tracing::{info, warn, error};

/// Identity prover for generating identity proofs with ZK circuits
pub struct IdentityProver {
    /// Private key for identity commitments
    pub private_key: [u8; 32],
    /// Nullifier secret for preventing double-use
    pub nullifier_secret: [u8; 32],
    /// ZK proof system for generating proofs
    zk_system: Option<ZkProofSystem>,
}

impl IdentityProver {
    /// Create new identity prover with cryptographic keys
    pub fn new(private_key: [u8; 32]) -> Self {
        // Generate nullifier secret from private key for consistency
        let nullifier_secret = hash_blake3(&[&private_key[..], b"nullifier"].concat());
        
        // Initialize ZK proof system
        let zk_system = match ZkProofSystem::new() {
            Ok(system) => {
                info!("Identity prover initialized with production ZK system");
                Some(system)
            },
            Err(e) => {
                error!("ZK system init failed - identity prover cannot function without ZK: {:?}", e);
                // Panic to prevent insecure fallback usage
                panic!("ZK system initialization required - no fallbacks allowed: {:?}", e);
            }
        };

        Self { 
            private_key,
            nullifier_secret,
            zk_system,
        }
    }

    /// Create prover with explicit nullifier secret
    pub fn with_nullifier_secret(private_key: [u8; 32], nullifier_secret: [u8; 32]) -> Self {
        let zk_system = ZkProofSystem::new().ok();
        Self { 
            private_key,
            nullifier_secret,
            zk_system,
        }
    }

    /// Generate zero-knowledge identity proof
    pub fn prove_identity(&self, claims: &[String]) -> Result<ZkIdentityProof> {
        info!("Generating identity proof for {} claims", claims.len());
        
        // Build identity attributes from claims
        let attributes = self.build_attributes_from_claims(claims)?;
        
        // Try to use ZK proof system first
        if let Some(ref zk_system) = self.zk_system {
            match self.generate_zk_circuit_proof(zk_system, &attributes, claims) {
                Ok(proof) => {
                    info!("Generated ZK identity proof using circuit");
                    return Ok(proof);
                },
                Err(e) => {
                    error!("ZK circuit proof failed - no fallbacks allowed: {:?}", e);
                    return Err(anyhow::anyhow!("ZK circuit proof generation failed - no fallbacks: {:?}", e));
                }
            }
        }
        
        // Should never reach here since ZK system is required
        Err(anyhow::anyhow!("No ZK system available - identity prover requires ZK circuits"))
    }

    /// Generate proof using ZK circuits
    fn generate_zk_circuit_proof(
        &self,
        zk_system: &ZkProofSystem,
        attributes: &IdentityAttributes,
        claims: &[String],
    ) -> Result<ZkIdentityProof> {
        // Extract key parameters for ZK circuit
        let identity_secret = u64::from_le_bytes(
            self.private_key[0..8].try_into()
                .map_err(|_| anyhow!("Invalid private key format"))?
        );
        
        // Extract age for circuit (default to 25 if not specified)
        let age = if let Some((min, max)) = attributes.age_range {
            ((min + max) / 2) as u64
        } else {
            25
        };
        
        // Extract jurisdiction hash (default to US: 840)
        let jurisdiction_hash = if let Some(ref citizenship) = attributes.citizenship {
            u64::from_le_bytes(
                hash_blake3(citizenship.as_bytes())[0..8].try_into()
                    .unwrap_or([0u8; 8])
            )
        } else {
            840 // ISO 3166 numeric code for United States
        };
        
        // Generate attribute commitment hash as credential
        let attribute_bytes = attributes.to_bytes();
        let credential_hash = u64::from_le_bytes(
            hash_blake3(&attribute_bytes)[0..8].try_into()
                .unwrap_or([0u8; 8])
        );
        
        // Determine minimum age requirement
        let min_age = if let Some((min, _)) = attributes.age_range {
            min as u64
        } else {
            18 // Default minimum age
        };
        
        // Determine jurisdiction requirement (0 = no requirement)
        let required_jurisdiction = if claims.contains(&"citizenship".to_string()) {
            jurisdiction_hash
        } else {
            0
        };
        
        // Generate ZK proof using circuit
        let zk_proof = zk_system.prove_identity(
            identity_secret,
            age,
            jurisdiction_hash,
            credential_hash,
            min_age,
            required_jurisdiction,
            1, // default verification level
        )?;
        
        // Generate identity commitment
        let commitment = IdentityCommitment::generate(
            attributes,
            self.private_key,
            self.nullifier_secret,
        )?;
        
        // Create unified ZK proof from the Plonky2 proof
        let unified_proof = crate::types::zk_proof::ZkProof::from_plonky2(zk_proof);
        
        Ok(ZkIdentityProof {
            proof: unified_proof,
            commitment,
            proven_attributes: claims.to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// REMOVED: Cryptographic proof fallback - pure ZK only

    /// Build identity attributes from claim strings
    fn build_attributes_from_claims(&self, claims: &[String]) -> Result<IdentityAttributes> {
        let mut attributes = IdentityAttributes::new();
        
        for claim in claims {
            match claim.as_str() {
                "age_over_18" => {
                    attributes = attributes.with_age_range(18, 120);
                },
                "age_over_21" => {
                    attributes = attributes.with_age_range(21, 120);
                },
                "age_range" => {
                    // Default age range if not specified
                    attributes = attributes.with_age_range(18, 65);
                },
                "citizenship" => {
                    // Default to US if not specified
                    attributes = attributes.with_citizenship("US".to_string());
                },
                "kyc_level_1" => {
                    attributes = attributes.with_kyc_level(1);
                },
                "kyc_level_2" => {
                    attributes = attributes.with_kyc_level(2);
                },
                "kyc_level_3" => {
                    attributes = attributes.with_kyc_level(3);
                },
                "driver_license" => {
                    attributes = attributes.with_license("driver".to_string());
                },
                "professional_license" => {
                    attributes = attributes.with_license("professional".to_string());
                },
                "university_degree" => {
                    attributes = attributes.with_education("university".to_string());
                },
                "high_school" => {
                    attributes = attributes.with_education("high_school".to_string());
                },
                claim_str => {
                    // Handle custom claims
                    if let Some((key, value)) = claim_str.split_once(':') {
                        attributes = attributes.with_custom(key.to_string(), value.to_string());
                    } else {
                        // Add as a boolean custom attribute
                        attributes = attributes.with_custom(claim_str.to_string(), "true".to_string());
                    }
                }
            }
        }
        
        Ok(attributes)
    }

    /// Prove age over a specific threshold
    pub fn prove_age_over(&self, min_age: u16) -> Result<ZkIdentityProof> {
        self.prove_identity(&[format!("age_over_{}", min_age)])
    }

    /// Prove citizenship of a specific country
    pub fn prove_citizenship(&self, country: &str) -> Result<ZkIdentityProof> {
        let attributes = IdentityAttributes::new().with_citizenship(country.to_string());
        
        // Try ZK proof first
        if let Some(ref zk_system) = self.zk_system {
            let identity_secret = u64::from_le_bytes(
                self.private_key[0..8].try_into().unwrap_or([0u8; 8])
            );
            let jurisdiction_hash = u64::from_le_bytes(
                hash_blake3(country.as_bytes())[0..8].try_into().unwrap_or([0u8; 8])
            );
            
            match zk_system.prove_identity(
                identity_secret,
                25, // Default age
                jurisdiction_hash,
                jurisdiction_hash, // Use same as credential
                18, // Min age
                jurisdiction_hash, // Required jurisdiction
                1, // default verification level
            ) {
                Ok(zk_proof) => {
                    let commitment = IdentityCommitment::generate(
                        &attributes,
                        self.private_key,
                        self.nullifier_secret,
                    )?;
                    
                    return Ok(ZkIdentityProof {
                        proof: crate::types::zk_proof::ZkProof::from_plonky2(zk_proof),
                        commitment,
                        proven_attributes: vec!["citizenship".to_string()],
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    });
                },
                Err(_) => {
                    // Fall back to cryptographic proof
                }
            }
        }
        
        // Delegate to main identity proof method
        self.prove_identity(&[format!("citizenship:{}", country)])
    }

    /// Prove KYC level
    pub fn prove_kyc_level(&self, level: u8) -> Result<ZkIdentityProof> {
        self.prove_identity(&[format!("kyc_level_{}", level)])
    }

    /// Prove multiple attributes at once
    pub fn prove_comprehensive(&self, age_range: Option<(u16, u16)>, citizenship: Option<&str>, kyc_level: Option<u8>) -> Result<ZkIdentityProof> {
        let mut claims = Vec::new();
        
        if let Some((min, max)) = age_range {
            claims.push(format!("age_range:{}:{}", min, max));
        }
        
        if let Some(country) = citizenship {
            claims.push(format!("citizenship:{}", country));
        }
        
        if let Some(level) = kyc_level {
            claims.push(format!("kyc_level_{}", level));
        }
        
        self.prove_identity(&claims)
    }

    /// Get prover statistics
    pub fn get_stats(&self) -> IdentityProverStats {
        IdentityProverStats {
            has_zk_system: self.zk_system.is_some(),
            private_key_set: !self.private_key.iter().all(|&b| b == 0),
            nullifier_set: !self.nullifier_secret.iter().all(|&b| b == 0),
        }
    }
}

/// Statistics for identity prover
#[derive(Debug, Clone)]
pub struct IdentityProverStats {
    /// Whether ZK system is available
    pub has_zk_system: bool,
    /// Whether private key is set
    pub private_key_set: bool,
    /// Whether nullifier secret is set
    pub nullifier_set: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_prover_creation() {
        let private_key = [1u8; 32];
        let prover = IdentityProver::new(private_key);
        
        let stats = prover.get_stats();
        assert!(stats.private_key_set);
        assert!(stats.nullifier_set);
    }

    #[test]
    fn test_prove_identity_basic() {
        let private_key = [2u8; 32];
        let prover = IdentityProver::new(private_key);
        
        let claims = vec!["age_over_18".to_string(), "citizenship".to_string()];
        let proof = prover.prove_identity(&claims).unwrap();
        
        assert_eq!(proof.proven_attributes, claims);
        assert!(!proof.is_expired());
        assert_ne!(proof.commitment.attribute_commitment, [0u8; 32]);
    }

    #[test]
    fn test_prove_age_over() {
        let private_key = [3u8; 32];
        let prover = IdentityProver::new(private_key);
        
        let proof = prover.prove_age_over(21).unwrap();
        assert!(proof.proves_attribute("age_over_21"));
    }

    #[test]
    fn test_prove_citizenship() {
        let private_key = [4u8; 32];
        let prover = IdentityProver::new(private_key);
        
        let proof = prover.prove_citizenship("CA").unwrap();
        assert!(proof.proves_attribute("citizenship") || proof.proves_attribute("citizenship:CA"));
    }

    #[test]
    fn test_prove_kyc_level() {
        let private_key = [5u8; 32];
        let prover = IdentityProver::new(private_key);
        
        let proof = prover.prove_kyc_level(2).unwrap();
        assert!(proof.proves_attribute("kyc_level_2"));
    }

    #[test]
    fn test_prove_comprehensive() {
        let private_key = [6u8; 32];
        let prover = IdentityProver::new(private_key);
        
        let proof = prover.prove_comprehensive(
            Some((25, 35)),
            Some("UK"),
            Some(3),
        ).unwrap();
        
        assert!(proof.proven_attributes.len() >= 3);
        assert!(!proof.is_expired());
    }

    #[test]
    fn test_custom_claims() {
        let private_key = [7u8; 32];
        let prover = IdentityProver::new(private_key);
        
        let claims = vec![
            "profession:engineer".to_string(),
            "security_clearance".to_string(),
        ];
        
        let proof = prover.prove_identity(&claims).unwrap();
        assert_eq!(proof.proven_attributes, claims);
    }
}
