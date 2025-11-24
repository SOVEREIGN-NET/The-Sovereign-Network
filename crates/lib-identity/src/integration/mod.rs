//! Integration and verification modules for ZHTP Identity

pub mod cross_package_integration;
pub mod requirements_verification;
pub mod proof_generation;
pub mod trusted_issuers;
pub mod verification_cache;

// Explicit re-exports to avoid naming conflicts
pub use cross_package_integration::{
    CrossPackageIntegration, IntegrationResponse
};
pub use requirements_verification::{
    RequirementsVerifier, RequirementVerificationResult, CachedVerificationResult,
    TrustLevel as RequirementTrustLevel, PrivacyLevel as RequirementPrivacyLevel
};
// Re-export PrivacyScore from privacy module to avoid confusion
pub use crate::privacy::PrivacyScore;
pub use proof_generation::{
    ProofGenerator, ProofGenerationStats, ProofGenerationRequest, ProofGenerationResult,
    PrivacyLevel as ProofPrivacyLevel
};
pub use trusted_issuers::{
    TrustedIssuer, TrustedIssuersRegistry, IssuerVerificationResult,
    TrustLevel as IssuerTrustLevel
};
pub use verification_cache::{
    VerificationCache, CacheConfig, CachedVerificationResult as CachedResult
};
