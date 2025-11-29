//! Identity verification result types from the original identity.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::{IdentityId, CredentialType};

/// Identity verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityVerification {
    /// Identity being verified
    pub identity_id: IdentityId,
    /// Verification success
    pub verified: bool,
    /// Met requirements
    pub requirements_met: Vec<CredentialType>,
    /// Failed requirements
    pub requirements_failed: Vec<CredentialType>,
    /// Privacy score achieved
    pub privacy_score: u8,
    /// Verification timestamp
    pub verified_at: u64,
}

/// Verification levels for different security requirements
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationLevel {
    /// Basic verification - minimal requirements
    Basic,
    /// Standard verification - normal security
    Standard,
    /// High security verification
    HighSecurity,
    /// Privacy-preserving verification using ZK proofs
    PrivacyPreserving,
    /// Complete verification - all checks
    Complete,
}

/// Comprehensive verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub verified: bool,
    /// Level of verification performed
    pub verification_level: VerificationLevel,
    /// Trust score (0.0 to 1.0)
    pub trust_score: f64,
    /// Methods used for verification
    pub verification_methods: Vec<String>,
    /// Any errors encountered
    pub errors: Vec<String>,
    /// Warnings from verification
    pub warnings: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// When verification was performed
    pub verified_at: u64,
    /// When this result expires
    pub expires_at: u64,
}
