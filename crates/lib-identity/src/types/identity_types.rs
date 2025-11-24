//! Identity type definitions from the original identity.rs

use serde::{Deserialize, Serialize};

use lib_crypto::Hash;

/// Unique identity identifier
pub type IdentityId = Hash;

/// Identity types supported by ZHTP
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IdentityType {
    /// Human user identity
    Human,
    /// Autonomous agent/AI identity
    Agent,
    /// Smart contract identity
    Contract,
    /// Organization identity
    Organization,
    /// Device/IoT identity
    Device,
}

/// Web4 access levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessLevel {
    /// Full citizen access to all services
    FullCitizen,
    /// Visitor access (limited services)
    Visitor,
    /// Organization access
    Organization,
    /// Device/IoT access
    Device,
    /// Restricted access
    Restricted,
}

impl Default for AccessLevel {
    fn default() -> Self {
        AccessLevel::Visitor
    }
}

impl std::fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessLevel::FullCitizen => write!(f, "FullCitizen"),
            AccessLevel::Visitor => write!(f, "Visitor"),
            AccessLevel::Organization => write!(f, "Organization"),
            AccessLevel::Device => write!(f, "Device"),
            AccessLevel::Restricted => write!(f, "Restricted"),
        }
    }
}

/// Private identity data (never transmitted)
#[derive(Debug, Clone)]
pub struct PrivateIdentityData {
    /// Private signing key
    pub private_key: Vec<u8>,
    /// Identity seed for key derivation
    pub seed: [u8; 32],
    /// Recovery phrases
    pub recovery_phrases: Vec<String>,
    /// Biometric templates (hashed)
    pub biometric_hashes: Vec<Hash>,
}

impl PrivateIdentityData {
    /// Create new private identity data
    pub fn new(private_key: Vec<u8>, seed: [u8; 32], recovery_phrases: Vec<String>) -> Self {
        Self {
            private_key,
            seed,
            recovery_phrases,
            biometric_hashes: Vec::new(),
        }
    }

    /// Get the seed as a slice
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Get the private key
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Get recovery phrases
    pub fn recovery_phrases(&self) -> &[String] {
        &self.recovery_phrases
    }
}

impl Default for PrivateIdentityData {
    fn default() -> Self {
        Self {
            private_key: Vec::new(),
            seed: [0u8; 32],
            recovery_phrases: Vec::new(),
            biometric_hashes: Vec::new(),
        }
    }
}
