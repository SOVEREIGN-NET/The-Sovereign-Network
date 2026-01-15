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
pub mod sector;

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

// Explicit re-exports from transaction_type module
pub use transaction_type::TransactionType;

// Explicit re-exports from hash module
pub use hash::{
    Hash,
    blake3_hash,
    hash_to_hex,
    hex_to_hash,
    zero_hash,
    is_zero_hash,
    Hashable,
};

// Explicit re-exports from difficulty module
pub use difficulty::{
    Difficulty,
    DifficultyConfig,
    calculate_target,
    meets_difficulty,
    target_to_difficulty,
    max_target,
    min_target,
    adjust_difficulty,
    adjust_difficulty_with_config,
    difficulty_to_work,
};

// Explicit re-exports from mining module
pub use mining::{
    MiningProfile,
    MiningConfig,
    get_mining_config_from_env,
    validate_mining_for_chain,
};

// Re-export DAO and SOV economy types
pub use dao::{DAOType, TokenClass, DAOMetadata, TreasuryAllocation, SectorDao, DifficultyParameterUpdateData};

// Re-export canonical welfare sector types (Issue #658)
pub use sector::{
    WelfareSectorId, SectorVerificationFloor, VerificationLevel as SectorVerificationLevel,
    default_sector_floors, get_sector_floor, effective_verification_level,
};

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
