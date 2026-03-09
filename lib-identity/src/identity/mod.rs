//! Core identity implementations

pub mod activity_tracking;
pub mod lib_identity;
pub mod manager;
pub mod private_data;

// Re-exports
pub use lib_identity::ZhtpIdentity;
pub use manager::IdentityManager;
pub use private_data::PrivateIdentityData;
