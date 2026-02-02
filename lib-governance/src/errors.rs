//! Governance Errors

use thiserror::Error;
use lib_types::{BlockHeight, TokenId};

use crate::fields::ConfigField;

/// Error during governance operations
#[derive(Error, Debug, Clone)]
pub enum GovernanceError {
    #[error("Immediate activation not allowed: activates_at={activates_at}, current={current_height}")]
    ImmediateActivation {
        activates_at: BlockHeight,
        current_height: BlockHeight,
    },

    #[error("Activation too far in future: activates_at={activates_at}, max={max_allowed}")]
    ActivationTooFar {
        activates_at: BlockHeight,
        max_allowed: BlockHeight,
    },

    #[error("Field not governable: {0:?}")]
    FieldNotGovernable(ConfigField),

    #[error("Conflicting change exists for {target:?}.{field:?} at height {existing_activation}")]
    ConflictingChange {
        target: TokenId,
        field: ConfigField,
        existing_activation: BlockHeight,
    },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Target not found: {0:?}")]
    TargetNotFound(TokenId),

    #[error("Storage error: {0}")]
    Storage(String),
}

/// Result type for governance operations
pub type GovernanceResult<T> = Result<T, GovernanceError>;
