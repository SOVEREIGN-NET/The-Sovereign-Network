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
pub mod chain_evaluation;
pub mod dao;
pub mod difficulty;
pub mod engines;
pub mod evidence;
pub mod mempool;
pub mod mining;
pub mod network;
pub mod proofs;
pub mod rewards;
pub mod slashing;
pub mod testing;
pub mod types;
pub mod validators;
pub mod fault_model;

// Re-export commonly used types
pub use chain_evaluation::{ChainDecision, ChainEvaluator, ChainMergeResult, ChainSummary};
pub use difficulty::{DifficultyConfig, DifficultyError, DifficultyManager, DifficultyResult};
pub use engines::enhanced_bft_engine::{ConsensusStatus, EnhancedBftEngine};
pub use engines::ConsensusEngine;
pub use mempool::{Mempool, MempoolTransaction, MempoolStats};
pub use mining::{should_mine_block, IdentityData};
pub use network::{
    check_consensus_health, BincodeConsensusCodec, CodecError, ConsensusMessageCodec,
    ConsensusMetrics,
};
pub use proofs::*;
pub use testing::NoOpBroadcaster;
pub use types::*;
pub use validators::{
    Validator, ValidatorManager,
    MIN_VALIDATORS, MAX_VALIDATORS, MAX_VALIDATORS_HARD_CAP,
};
pub use evidence::{Evidence, EvidenceStore, EvidenceRecord, SlashingParams, IsolationAction, isolation_action};
pub use slashing::{
    DOUBLE_SIGN_SLASH_PERCENT,
    LIVENESS_SLASH_PERCENT,
    JAIL_DURATION_BLOCKS,
    SAFETY_OFFENSE_ALWAYS_PERMANENT,
    REMOVAL_SLASH_COUNT,
    JAIL_EXIT_WAIT_BLOCKS,
    MIN_STAKE_TO_UNJAIL,
    SlashSeverity,
    SlashPolicyError,
    JailStatus,
    BanReason,
    RecoveryError,
    check_unjail_eligibility,
    check_unjail_eligibility_legacy,
    liveness_jail_status,
    safety_ban_status,
    stake_after_unjail,
    calculate_slash_amount,
    jail_end_block,
};

#[cfg(feature = "dao")]
pub use dao::*;

#[cfg(feature = "byzantine")]
pub use byzantine::*;

#[cfg(feature = "rewards")]
pub use rewards::*;

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

    // #[error("Storage error: {0}")]
    // StorageError(#[from] lib_storage::StorageError),  // TODO: Uncomment when storage is implemented
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
