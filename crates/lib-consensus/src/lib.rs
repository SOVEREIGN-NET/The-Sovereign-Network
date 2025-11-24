//! ZHTP Consensus Package
//! 
//! Multi-layered consensus system combining Proof of Stake, Proof of Storage,
//! Proof of Useful Work, and Byzantine Fault Tolerance for the ZHTP blockchain network.
//!
//! This package provides modular consensus mechanisms with integrated DAO governance,
//! economic incentives, and post-quantum security.

pub mod types;
pub mod engines;
pub mod validators;
pub mod proofs;
pub mod byzantine;
pub mod dao;
pub mod rewards;
pub mod chain_evaluation;
pub mod mining;

// Re-export commonly used types
pub use types::*;
pub use engines::ConsensusEngine;
pub use engines::enhanced_bft_engine::{EnhancedBftEngine, ConsensusStatus};
pub use validators::{Validator, ValidatorManager};
pub use proofs::*;
pub use chain_evaluation::{ChainEvaluator, ChainDecision, ChainMergeResult, ChainSummary};
pub use mining::{should_mine_block, IdentityData};

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
}

/// Initialize the consensus system with configuration
pub fn init_consensus(config: ConsensusConfig) -> ConsensusResult<ConsensusEngine> {
    tracing::info!(" Initializing ZHTP consensus system");
    Ok(ConsensusEngine::new(config)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_initialization() {
        let config = ConsensusConfig::default();
        let result = init_consensus(config);
        assert!(result.is_ok());
    }
}
