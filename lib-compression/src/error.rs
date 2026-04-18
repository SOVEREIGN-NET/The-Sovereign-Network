//! Error types for compression operations

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CompressionError>;

#[derive(Error, Debug)]
pub enum CompressionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Chunking failed: {0}")]
    ChunkingFailed(String),

    #[error("Invalid shard: {0}")]
    InvalidShard(String),

    #[error("Shard not found: {0}")]
    ShardNotFound(String),

    #[error("ZK proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("ZK proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("DHT storage failed: {0}")]
    DhtStorageFailed(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Reassembly failed: {0}")]
    ReassemblyFailed(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Transport failed: {0}")]
    TransportFailed(String),
}
