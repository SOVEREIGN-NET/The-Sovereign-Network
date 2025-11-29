//! Blockchain integration modules

pub mod enhanced_zk_crypto;
pub mod crypto_integration;
pub mod zk_integration;
pub mod network_integration;
pub mod economic_integration;
pub mod storage_integration;
pub mod identity_integration;
pub mod consensus_integration;

// Re-export for convenience
pub use enhanced_zk_crypto::*;
pub use crypto_integration::*;
pub use zk_integration::*;
pub use network_integration::*;
pub use economic_integration::*;
pub use storage_integration::*;
pub use identity_integration::*;
pub use consensus_integration::*;
