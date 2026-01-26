//! DAO Contracts Module
//!
//! This module contains DAO-related contracts for the SOV economic system:
//!
//! - `dao_treasury`: DOC 03 - Generic DAO Treasury template (Week 3)
//! - HealthcareDAOTreasury: Healthcare sector DAO
//! - EducationDAOTreasury: Education sector DAO
//! - EnergyDAOTreasury: Energy sector DAO
//! - HousingDAOTreasury: Housing sector DAO
//! - FoodDAOTreasury: Food security sector DAO

pub mod dao_treasury;

// Re-export key types
pub use dao_treasury::{
    DaoTreasury, SpendingProposal, SpendingRecord, SpendingCategory, ProposalStatus,
    DaoTreasuryError, DAO_ALLOCATION_PERCENTAGE, NUM_SECTOR_DAOS, PER_DAO_ALLOCATION_PERCENTAGE,
    DAO_TIMELOCK_SECONDS, MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
};
