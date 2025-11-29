//! Core identity implementations

pub mod lib_identity;
pub mod private_data;
pub mod manager;
pub mod activity_tracking;
mod services; // Private service implementations

// Re-exports
pub use lib_identity::ZhtpIdentity;
pub use private_data::PrivateIdentityData;
pub use manager::IdentityManager;
