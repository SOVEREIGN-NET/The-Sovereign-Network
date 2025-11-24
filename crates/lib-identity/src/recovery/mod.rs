//! Recovery mechanisms for ZHTP Identity

pub mod recovery_phrases;

// Re-exports
pub use recovery_phrases::*;

// RecoveryKey now integrated into IdentityManager
pub use crate::identity::manager::RecoveryKey;
