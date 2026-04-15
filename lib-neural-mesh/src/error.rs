//! Error types for neural mesh operations

use thiserror::Error;

pub type Result<T> = std::result::Result<T, NeuralMeshError>;

#[derive(Error, Debug)]
pub enum NeuralMeshError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Model loading failed: {0}")]
    ModelLoadFailed(String),

    #[error("Inference failed: {0}")]
    InferenceFailed(String),

    #[error("Training failed: {0}")]
    TrainingFailed(String),

    #[error("Invalid model: {0}")]
    InvalidModel(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Network state error: {0}")]
    NetworkState(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Feature extraction failed: {0}")]
    FeatureExtractionFailed(String),

    #[error("Anomaly detected: {0}")]
    AnomalyDetected(String),
}
