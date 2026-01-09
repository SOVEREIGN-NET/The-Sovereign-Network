//! Core blockchain types module
//!
//! Contains fundamental blockchain type definitions including transaction types,
//! hash utilities, difficulty calculations, and contract-related types.

// Blockchain core types
pub mod transaction_type;
pub mod hash;
pub mod difficulty;
pub mod mining;

// DAO and SOV economy types
pub mod dao;

// Contract types (available when contracts feature is enabled)
#[cfg(feature = "contracts")]
pub mod contract_call;
#[cfg(feature = "contracts")]
pub mod contract_type;
#[cfg(feature = "contracts")]
pub mod contract_logs;
#[cfg(feature = "contracts")]
pub mod contract_permissions;
#[cfg(feature = "contracts")]
pub mod contract_result;
#[cfg(feature = "contracts")]
pub mod message_type;

// Re-export blockchain core types
pub use transaction_type::*;
pub use hash::*;
pub use difficulty::*;
pub use mining::*;

// Re-export DAO and SOV economy types
pub use dao::{DAOType, TokenClass, DAOMetadata, TreasuryAllocation, SectorDao, DifficultyParameterUpdateData};

// Re-export contract types when contracts feature is enabled
#[cfg(feature = "contracts")]
pub use contract_call::{ContractCall, CallPermissions};
#[cfg(feature = "contracts")]
pub use contract_type::ContractType;
#[cfg(feature = "contracts")]
pub use contract_logs::{ContractLog, EventType};
#[cfg(feature = "contracts")]
pub use contract_permissions::ContractPermissions;
#[cfg(feature = "contracts")]
pub use contract_result::ContractResult;
#[cfg(feature = "contracts")]
pub use message_type::MessageType;
