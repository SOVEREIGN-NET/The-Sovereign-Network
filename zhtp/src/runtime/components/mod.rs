// Component modules - thin wrappers that delegate to services
pub mod api;
pub mod blockchain;
pub mod consensus;
pub mod crypto;
pub mod economics;
pub mod identity;
pub mod network;
pub mod neural_mesh;
pub mod oracle;
pub mod protocols;
pub mod simulation;
pub mod storage;
pub mod zk;

// Re-export component types
pub use api::ApiComponent;
pub use blockchain::BlockchainComponent;
pub use consensus::{BlockchainValidatorAdapter, ConsensusComponent};
pub use crypto::CryptoComponent;
pub use economics::EconomicsComponent;
pub use identity::IdentityComponent;
pub use network::{NetworkComponent, RoutingRewardStats, StorageRewardStats};
pub use neural_mesh::NeuralMeshComponent;
pub use protocols::ProtocolsComponent;
pub use storage::StorageComponent;
pub use zk::ZKComponent;

// Re-export helper functions
pub use identity::create_default_storage_config;

// Re-export GenesisValidator from services for backward compatibility
pub use crate::runtime::services::GenesisValidator;
