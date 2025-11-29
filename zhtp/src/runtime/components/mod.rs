// Component modules - thin wrappers that delegate to services
pub mod crypto;
pub mod zk;
pub mod identity;
pub mod storage;
pub mod network;
pub mod blockchain;
pub mod consensus;
pub mod economics;
pub mod protocols;
pub mod api;

// Re-export component types
pub use crypto::CryptoComponent;
pub use zk::ZKComponent;
pub use identity::IdentityComponent;
pub use storage::StorageComponent;
pub use network::{NetworkComponent, RoutingRewardStats, StorageRewardStats};
pub use blockchain::BlockchainComponent;
pub use consensus::{ConsensusComponent, BlockchainValidatorAdapter};
pub use economics::EconomicsComponent;
pub use protocols::ProtocolsComponent;
pub use api::ApiComponent;

// Re-export helper functions
pub use identity::create_default_storage_config;

// Re-export GenesisValidator from services for backward compatibility
pub use crate::runtime::services::GenesisValidator;
