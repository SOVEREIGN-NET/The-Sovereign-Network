//! Core blockchain types module
//!
//! Contains fundamental blockchain type definitions including transaction types,
//! hash utilities, difficulty calculations, and contract-related types.

// Blockchain core types
pub mod difficulty;
pub mod hash;
pub mod mining;
pub mod transaction_type;

// DAO and SOV economy types
pub mod dao;
pub mod sector;

// Contract types (available when contracts feature is enabled)
#[cfg(feature = "contracts")]
pub mod contract_call;
#[cfg(feature = "contracts")]
pub mod contract_logs;
#[cfg(feature = "contracts")]
pub mod contract_permissions;
#[cfg(feature = "contracts")]
pub mod contract_result;
#[cfg(feature = "contracts")]
pub mod contract_type;
#[cfg(feature = "contracts")]
pub mod message_type;

// Explicit re-exports from transaction_type module
pub use transaction_type::TransactionType;

// Explicit re-exports from hash module
pub use hash::{blake3_hash, hash_to_hex, hex_to_hash, is_zero_hash, zero_hash, Hash, Hashable};

// Explicit re-exports from difficulty module
pub use difficulty::{
    adjust_difficulty, adjust_difficulty_with_config, calculate_target, difficulty_to_work,
    max_target, meets_difficulty, min_target, target_to_difficulty, Difficulty, DifficultyConfig,
};

// Explicit re-exports from mining module
pub use mining::{
    get_mining_config_from_env, validate_mining_for_chain, MiningConfig, MiningProfile,
};

// Re-export DAO and SOV economy types
pub use dao::{
    DAOMetadata, DAOType, DifficultyParameterUpdateData, SectorDao, TokenClass, TreasuryAllocation,
};

// Re-export canonical welfare sector types (Issue #658)
pub use sector::{
    default_sector_floors, effective_verification_level, get_sector_floor, SectorVerificationFloor,
    VerificationLevel as SectorVerificationLevel, WelfareSectorId,
};

// Re-export contract types when contracts feature is enabled
#[cfg(feature = "contracts")]
pub use contract_call::{CallPermissions, ContractCall};
#[cfg(feature = "contracts")]
pub use contract_logs::{ContractLog, EventType};
#[cfg(feature = "contracts")]
pub use contract_permissions::ContractPermissions;
#[cfg(feature = "contracts")]
pub use contract_result::ContractResult;
#[cfg(feature = "contracts")]
pub use contract_type::ContractType;
#[cfg(feature = "contracts")]
pub use message_type::MessageType;
