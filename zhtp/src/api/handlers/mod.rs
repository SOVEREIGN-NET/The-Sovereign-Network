//! API Handlers Module
//!
//! Clean, minimal handler modules for ZHTP API

pub mod bearer_auth;
pub mod blockchain;
pub mod bonding_curve;
pub mod cbe;
pub mod constants;
pub mod crypto;
pub mod dao;
pub mod dht;
pub mod dns;
pub mod guardian;
pub mod identity;
pub mod marketplace;
pub mod mesh;
pub mod nft;
pub mod mobile_auth;
pub mod monitor;
pub mod network;
pub mod observer;
pub mod oracle;
pub mod pouw;
pub mod protocol;
pub mod storage;
pub mod token;
pub mod validator;
pub mod wallet;
pub mod wallet_content;
pub mod web4;
pub mod zkp;

pub use bearer_auth::BearerAuthMiddleware;
pub use blockchain::BlockchainHandler;
pub use cbe::CbeHandler;
pub use crypto::CryptoHandler;
pub use dao::DaoHandler;
pub use dht::DhtHandler;
pub use dns::DnsHandler;
pub use guardian::GuardianHandler;
pub use identity::IdentityHandler;
pub use marketplace::MarketplaceHandler;
pub use mesh::MeshHandler;
pub use mobile_auth::MobileAuthHandler;
pub use monitor::MonitorHandler;
pub use network::NetworkHandler;
pub use observer::ObserverHandler;
pub use protocol::ProtocolHandler;
pub use storage::StorageHandler;
pub use token::TokenHandler;
pub use validator::ValidatorHandler;
pub use wallet::WalletHandler;
pub use wallet_content::WalletContentHandler;
pub use web4::Web4Handler;
pub use zkp::ZkpHandler;
