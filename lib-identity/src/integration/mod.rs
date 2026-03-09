//! Integration and verification modules for ZHTP Identity

pub mod cross_package_integration;
pub mod proof_generation;
pub mod requirements_verification;
pub mod trusted_issuers;
pub mod verification_cache;

// Explicit re-exports to avoid naming conflicts
pub use cross_package_integration::{CrossPackageIntegration, IntegrationResponse};
pub use requirements_verification::{
    CachedVerificationResult, PrivacyLevel as RequirementPrivacyLevel,
    RequirementVerificationResult, RequirementsVerifier, TrustLevel as RequirementTrustLevel,
};
// Re-export PrivacyScore from privacy module to avoid confusion
pub use crate::privacy::PrivacyScore;
pub use proof_generation::{
    PrivacyLevel as ProofPrivacyLevel, ProofGenerationRequest, ProofGenerationResult,
    ProofGenerationStats, ProofGenerator,
};
pub use trusted_issuers::{
    IssuerVerificationResult, TrustLevel as IssuerTrustLevel, TrustedIssuer, TrustedIssuersRegistry,
};
pub use verification_cache::{
    CacheConfig, CachedVerificationResult as CachedResult, VerificationCache,
};
