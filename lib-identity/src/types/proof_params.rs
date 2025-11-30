//! Identity proof parameters from the original identity.rs

use serde::{Deserialize, Serialize};
use super::CredentialType;

/// Zero-knowledge identity proof parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProofParams {
    /// Minimum age requirement (years)
    pub min_age: Option<u8>,
    /// Required citizenship/jurisdiction
    pub jurisdiction: Option<String>,
    /// Required credential types
    pub required_credentials: Vec<CredentialType>,
    /// Privacy level (0 = public, 100 = maximum privacy)
    pub privacy_level: u8,
    /// Minimum reputation score required
    pub min_reputation: Option<u64>,
    /// Proof type identifier
    pub proof_type: String,
    /// Require citizenship status
    pub require_citizenship: bool,
    /// Required location/jurisdiction
    pub required_location: Option<String>,
}

impl IdentityProofParams {
    /// Create new identity proof parameters
    pub fn new(
        min_age: Option<u8>,
        jurisdiction: Option<String>,
        required_credentials: Vec<CredentialType>,
        privacy_level: u8,
    ) -> Self {
        Self {
            min_age,
            jurisdiction,
            required_credentials,
            privacy_level,
            min_reputation: None,
            proof_type: "basic_identity".to_string(),
            require_citizenship: false,
            required_location: None,
        }
    }
    
    /// Set minimum reputation requirement
    pub fn with_min_reputation(mut self, min_reputation: u64) -> Self {
        self.min_reputation = Some(min_reputation);
        self
    }
    
    /// Set proof type
    pub fn with_proof_type(mut self, proof_type: String) -> Self {
        self.proof_type = proof_type;
        self
    }
    
    /// Require citizenship
    pub fn with_citizenship_requirement(mut self) -> Self {
        self.require_citizenship = true;
        self
    }
    
    /// Set location requirement
    pub fn with_location_requirement(mut self, location: String) -> Self {
        self.required_location = Some(location);
        self
    }
}
