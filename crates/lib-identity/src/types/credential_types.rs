//! Credential type definitions from the original identity.rs

use serde::{Deserialize, Serialize};

/// Credential types in the ZHTP identity system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum CredentialType {
    /// Age verification credential
    AgeVerification,
    /// Government ID verification
    GovernmentId,
    /// Educational credential
    Education,
    /// Professional certification
    Professional,
    /// Reputation score
    Reputation,
    /// Financial verification
    Financial,
    /// Biometric template
    Biometric,
    /// Custom credential type
    Custom(String),
}

impl CredentialType {
    /// Convert credential type to string representation
    pub fn as_str(&self) -> &str {
        match self {
            CredentialType::AgeVerification => "AgeVerification",
            CredentialType::GovernmentId => "GovernmentId",
            CredentialType::Education => "Education",
            CredentialType::Professional => "Professional",
            CredentialType::Reputation => "Reputation",
            CredentialType::Financial => "Financial",
            CredentialType::Biometric => "Biometric",
            CredentialType::Custom(s) => s,
        }
    }
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::AgeVerification => write!(f, "AgeVerification"),
            CredentialType::GovernmentId => write!(f, "GovernmentId"),
            CredentialType::Education => write!(f, "Education"),
            CredentialType::Professional => write!(f, "Professional"),
            CredentialType::Reputation => write!(f, "Reputation"),
            CredentialType::Financial => write!(f, "Financial"),
            CredentialType::Biometric => write!(f, "Biometric"),
            CredentialType::Custom(s) => write!(f, "Custom({})", s),
        }
    }
}

/// Types of identity attestations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationType {
    /// Identity verification attestation
    IdentityVerification,
    /// Reputation attestation
    Reputation,
    /// Skill/competency attestation
    Competency(String),
    /// Relationship attestation (e.g., employment)
    Relationship(String),
    /// Asset ownership attestation
    AssetOwnership,
    /// Custom attestation type
    Custom(String),
}
