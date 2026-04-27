//! ZHTP Consensus Package
//!
//! Multi-layered consensus system combining Proof of Stake, Proof of Storage,
//! Proof of Useful Work, and Byzantine Fault Tolerance for the ZHTP blockchain network.
//!
//! This package provides modular consensus mechanisms with integrated DAO governance,
//! economic incentives, and post-quantum security.

#[cfg(all(not(debug_assertions), feature = "dev-insecure"))]
compile_error!("dev-insecure must not be enabled in release builds");

pub mod byzantine;
// Back-compat shim — actual DAO implementation lives in lib_governance::dao
// per CONS-106 / AD-003. The `pub mod dao` here re-exports the new home so
// existing `lib_consensus::dao::*` paths keep working until CONS-508 deletes
// lib-consensus entirely.
pub mod dao;
pub mod engines;
pub mod evidence;
pub mod fault_model;
pub mod invariants;
pub mod network;
pub mod proof_verify;
pub mod slashing;
pub mod testing;
pub mod types;
pub mod validators;

// Re-export commonly used types
pub use engines::consensus_engine::ValidatorSetUpdate;
pub use engines::ConsensusEngine;
pub use evidence::{
    isolation_action, Evidence, EvidenceRecord, EvidenceStore, IsolationAction, SlashingParams,
};
pub use invariants::{
    check_invariant, enforce_consensus_invariants, ConsensusInvariant, ConsensusState,
};
pub use network::{
    check_consensus_health, BincodeConsensusCodec, CodecError, ConsensusMessageCodec,
    ConsensusMetrics,
};
// Consensus-mechanism proof types moved to lib-proofs (CONS-104 / AD-003).
// Re-exported here for backward compatibility while in-flight migration completes.
pub use lib_proofs::consensus::{ProofOfUsefulWork, StakeDelegation, StakeProof, WorkProof};
// Storage attestation re-exports (these were never in lib-consensus's proofs/
// module body — they were always lib-storage types re-exported through here).
pub use lib_storage::proofs::{
    ChallengeResult, ProofVerifier, RetrievalProof, StorageCapacityAttestation, StorageChallenge,
    StorageProof, StorageProofProvider, StorageProofSummary, VerificationResult,
};
pub use slashing::{
    calculate_slash_amount, check_unjail_eligibility, check_unjail_eligibility_legacy,
    jail_end_block, liveness_jail_status, safety_ban_status, stake_after_unjail, BanReason,
    JailStatus, RecoveryError, SlashPolicyError, SlashSeverity, DOUBLE_SIGN_SLASH_PERCENT,
    JAIL_DURATION_BLOCKS, JAIL_EXIT_WAIT_BLOCKS, LIVENESS_SLASH_PERCENT, MIN_STAKE_TO_UNJAIL,
    REMOVAL_SLASH_COUNT, SAFETY_OFFENSE_ALWAYS_PERMANENT,
};
pub use testing::NoOpBroadcaster;
pub use types::*;
pub use validators::{
    Validator, ValidatorManager, MAX_VALIDATORS, MAX_VALIDATORS_HARD_CAP, MIN_VALIDATORS,
};

// CONS-106 / AD-003: dao module moved to lib-governance. Re-exported here so
// callers using `lib_consensus::Dao*` paths keep working during the rewrite.
pub use dao::*;

pub use byzantine::*;

/// Result type alias for consensus operations
pub type ConsensusResult<T> = Result<T, ConsensusError>;

/// Consensus error types
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Invalid consensus type: {0}")]
    InvalidConsensusType(String),

    #[error("Validator error: {0}")]
    ValidatorError(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Byzantine fault detected: {0}")]
    ByzantineFault(String),

    #[error("DAO governance error: {0}")]
    DaoError(String),

    #[error("Reward calculation error: {0}")]
    RewardError(String),

    #[error("Network state error: {0}")]
    NetworkStateError(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] anyhow::Error),

    #[error("Identity error: {0}")]
    IdentityError(String),

    #[error("Storage error: {0}")]
    StorageError(#[from] lib_storage::StorageError),
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("ZK proof error: {0}")]
    ZkError(String),

    #[error("Invalid previous hash: {0}")]
    InvalidPreviousHash(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("System time error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),

    #[error("Fee collection failed: {0}")]
    FeeCollectionFailed(String),

    #[error("Fee distribution failed: {0}")]
    FeeDistributionFailed(String),
}

/// Initialize the consensus system with configuration and message broadcaster
///
/// Invariant CE-ENG-1: The broadcaster is dependency-injected, not configured internally.
/// No defaults. No globals. No feature flags.
pub fn init_consensus(
    config: ConsensusConfig,
    broadcaster: std::sync::Arc<dyn MessageBroadcaster>,
) -> ConsensusResult<ConsensusEngine> {
    tracing::info!(" Initializing ZHTP consensus system");
    Ok(ConsensusEngine::new(config, broadcaster)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple mock broadcaster for testing
    struct MockBroadcaster;

    #[async_trait::async_trait]
    impl MessageBroadcaster for MockBroadcaster {
        async fn broadcast_to_validators(
            &self,
            _message: ValidatorMessage,
            _validator_ids: &[lib_identity::IdentityId],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    #[test]
    fn test_consensus_initialization() {
        let config = ConsensusConfig::default();
        let broadcaster = std::sync::Arc::new(MockBroadcaster);
        let result = init_consensus(config, broadcaster);
        assert!(result.is_ok());
    }
}
pub mod finality_model;
