//! API Handlers Module
//! 
//! Clean, minimal handler modules for ZHTP API

pub mod identity;
pub mod blockchain;
pub mod storage;
pub mod protocol;
pub mod network;
pub mod wallet;
pub mod dao;
pub mod dht;
pub mod web4;
pub mod dns;
pub mod mesh;

pub use identity::IdentityHandler;
pub use blockchain::BlockchainHandler;
pub use storage::StorageHandler;
pub use protocol::ProtocolHandler;
pub use network::NetworkHandler;
pub use wallet::WalletHandler;
pub use dao::DaoHandler;
pub use dht::DhtHandler;
pub use web4::Web4Handler;
pub use dns::DnsHandler;
pub use mesh::MeshHandler;