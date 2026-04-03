//! Blockchain integration modules

pub mod consensus_integration;
pub mod crypto_integration;
pub mod economic_integration;
pub mod enhanced_zk_crypto;
pub mod identity_integration;
pub mod network_integration;
pub mod storage_integration;
pub mod zk_integration;

// Re-export for convenience
pub use consensus_integration::*;
pub use crypto_integration::*;
pub use economic_integration::*;
pub use enhanced_zk_crypto::*;
pub use identity_integration::*;
pub use network_integration::*;
pub use storage_integration::*;
pub use zk_integration::*;
