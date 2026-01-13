//! Canonical Welfare Sector Types (Issue #658)
//!
//! This module provides the single source of truth for welfare sector definitions
//! used across the SOV blockchain ecosystem.
//!
//! # Canonical Enum
//!
//! The `WelfareSectorId` enum is the immutable, u8-repr enum that defines
//! the five original welfare sectors. These sectors cannot be removed or
//! reordered, only extended via governance.
//!
//! # Migration
//!
//! All other sector enums (lib-economy/fee_distribution.rs, etc.) should
//! be deprecated in favor of this canonical definition.

use serde::{Deserialize, Serialize};

/// Immutable welfare sector identifier
///
/// This is the canonical enum for welfare sectors in the SOV ecosystem.
/// The underlying `u8` representation is stable and must never change
/// to preserve on-chain compatibility.
///
/// # Invariants
///
/// 1. **Immutable Order**: Variant discriminants are fixed (1-5)
/// 2. **No Removal**: Original five sectors cannot be removed
/// 3. **Extension Only**: New sectors require governance approval
/// 4. **Namespace Binding**: Each sector maps to exactly one `*.dao.sov` root
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WelfareSectorId {
    /// Healthcare sector - manages health.dao.sov
    Healthcare = 1,
    /// Education sector - manages edu.dao.sov
    Education = 2,
    /// Energy sector - manages energy.dao.sov
    Energy = 3,
    /// Housing sector - manages housing.dao.sov
    Housing = 4,
    /// Food security sector - manages food.dao.sov
    Food = 5,
}

impl WelfareSectorId {
    /// All original welfare sectors (immutable set)
    pub const ALL: [WelfareSectorId; 5] = [
        WelfareSectorId::Healthcare,
        WelfareSectorId::Education,
        WelfareSectorId::Energy,
        WelfareSectorId::Housing,
        WelfareSectorId::Food,
    ];

    /// Get the namespace name for this sector (e.g., "health.dao.sov")
    pub fn namespace_name(&self) -> &'static str {
        match self {
            WelfareSectorId::Healthcare => "health.dao.sov",
            WelfareSectorId::Education => "edu.dao.sov",
            WelfareSectorId::Energy => "energy.dao.sov",
            WelfareSectorId::Housing => "housing.dao.sov",
            WelfareSectorId::Food => "food.dao.sov",
        }
    }

    /// Get the zone root label (without .dao.sov suffix)
    pub fn zone_root(&self) -> &'static str {
        match self {
            WelfareSectorId::Healthcare => "health",
            WelfareSectorId::Education => "edu",
            WelfareSectorId::Energy => "energy",
            WelfareSectorId::Housing => "housing",
            WelfareSectorId::Food => "food",
        }
    }

    /// Get the numeric ID (stable, used for storage)
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Try to create from a numeric ID
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(WelfareSectorId::Healthcare),
            2 => Some(WelfareSectorId::Education),
            3 => Some(WelfareSectorId::Energy),
            4 => Some(WelfareSectorId::Housing),
            5 => Some(WelfareSectorId::Food),
            _ => None,
        }
    }

    /// Try to create from a zone root string (case-insensitive)
    pub fn from_zone_root(root: &str) -> Option<Self> {
        match root.to_lowercase().as_str() {
            "health" => Some(WelfareSectorId::Healthcare),
            "edu" | "education" => Some(WelfareSectorId::Education),
            "energy" => Some(WelfareSectorId::Energy),
            "housing" => Some(WelfareSectorId::Housing),
            "food" => Some(WelfareSectorId::Food),
            _ => None,
        }
    }

    /// Try to create from a namespace name (case-insensitive)
    pub fn from_namespace_name(name: &str) -> Option<Self> {
        let normalized = name.to_lowercase();
        match normalized.as_str() {
            "health.dao.sov" => Some(WelfareSectorId::Healthcare),
            "edu.dao.sov" => Some(WelfareSectorId::Education),
            "energy.dao.sov" => Some(WelfareSectorId::Energy),
            "housing.dao.sov" => Some(WelfareSectorId::Housing),
            "food.dao.sov" => Some(WelfareSectorId::Food),
            _ => None,
        }
    }

    /// Get the display name for this sector
    pub fn display_name(&self) -> &'static str {
        match self {
            WelfareSectorId::Healthcare => "Healthcare",
            WelfareSectorId::Education => "Education",
            WelfareSectorId::Energy => "Energy",
            WelfareSectorId::Housing => "Housing",
            WelfareSectorId::Food => "Food",
        }
    }
}

/// Verification floor for a welfare sector
///
/// Root governance defines minimum verification levels per sector.
/// DAOs cannot lower these floors, only raise requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectorVerificationFloor {
    /// The welfare sector
    pub sector: WelfareSectorId,
    /// Minimum verification level required
    pub min_level: VerificationLevel,
}

/// Verification level enum (matches root_registry/types.rs)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum VerificationLevel {
    /// Unverified - Not allowed for any `.sov` root issuance
    L0Unverified = 0,
    /// Natural Person / Basic DID - Wallet-bound DID + liveness/anti-sybil
    L1BasicDID = 1,
    /// Verified Entity - Legal entity verification anchored via VC
    L2VerifiedEntity = 2,
    /// Constitutional Actor - Core Welfare DAO or Root-level institution
    L3ConstitutionalActor = 3,
}

impl VerificationLevel {
    /// Check if this level meets or exceeds the minimum
    pub fn meets_minimum(&self, minimum: VerificationLevel) -> bool {
        (*self as u8) >= (minimum as u8)
    }
}

/// Default verification floors for welfare sectors
///
/// These are the root-governance defined minimums:
/// - Healthcare: L2 (due to sensitive health data)
/// - Education, Energy, Housing, Food: L1 (basic verification)
pub fn default_sector_floors() -> [SectorVerificationFloor; 5] {
    [
        SectorVerificationFloor {
            sector: WelfareSectorId::Healthcare,
            min_level: VerificationLevel::L2VerifiedEntity,
        },
        SectorVerificationFloor {
            sector: WelfareSectorId::Education,
            min_level: VerificationLevel::L1BasicDID,
        },
        SectorVerificationFloor {
            sector: WelfareSectorId::Energy,
            min_level: VerificationLevel::L1BasicDID,
        },
        SectorVerificationFloor {
            sector: WelfareSectorId::Housing,
            min_level: VerificationLevel::L1BasicDID,
        },
        SectorVerificationFloor {
            sector: WelfareSectorId::Food,
            min_level: VerificationLevel::L1BasicDID,
        },
    ]
}

/// Get the default verification floor for a sector
pub fn get_sector_floor(sector: WelfareSectorId) -> VerificationLevel {
    match sector {
        WelfareSectorId::Healthcare => VerificationLevel::L2VerifiedEntity,
        _ => VerificationLevel::L1BasicDID,
    }
}

/// Calculate effective verification level
///
/// Returns max(root_floor, dao_policy) - DAOs cannot lower floors
pub fn effective_verification_level(
    root_floor: VerificationLevel,
    dao_policy: VerificationLevel,
) -> VerificationLevel {
    if (dao_policy as u8) > (root_floor as u8) {
        dao_policy
    } else {
        root_floor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sector_id_stability() {
        // These values MUST remain stable for on-chain compatibility
        assert_eq!(WelfareSectorId::Healthcare as u8, 1);
        assert_eq!(WelfareSectorId::Education as u8, 2);
        assert_eq!(WelfareSectorId::Energy as u8, 3);
        assert_eq!(WelfareSectorId::Housing as u8, 4);
        assert_eq!(WelfareSectorId::Food as u8, 5);
    }

    #[test]
    fn test_sector_id_roundtrip() {
        for sector in WelfareSectorId::ALL.iter() {
            let id = sector.as_u8();
            let recovered = WelfareSectorId::from_u8(id);
            assert_eq!(recovered, Some(*sector));
        }
    }

    #[test]
    fn test_namespace_names() {
        assert_eq!(WelfareSectorId::Healthcare.namespace_name(), "health.dao.sov");
        assert_eq!(WelfareSectorId::Education.namespace_name(), "edu.dao.sov");
        assert_eq!(WelfareSectorId::Energy.namespace_name(), "energy.dao.sov");
        assert_eq!(WelfareSectorId::Housing.namespace_name(), "housing.dao.sov");
        assert_eq!(WelfareSectorId::Food.namespace_name(), "food.dao.sov");
    }

    #[test]
    fn test_zone_root_parsing() {
        assert_eq!(
            WelfareSectorId::from_zone_root("health"),
            Some(WelfareSectorId::Healthcare)
        );
        assert_eq!(
            WelfareSectorId::from_zone_root("HEALTH"),
            Some(WelfareSectorId::Healthcare)
        );
        assert_eq!(
            WelfareSectorId::from_zone_root("edu"),
            Some(WelfareSectorId::Education)
        );
        assert_eq!(
            WelfareSectorId::from_zone_root("education"),
            Some(WelfareSectorId::Education)
        );
        assert_eq!(WelfareSectorId::from_zone_root("unknown"), None);
    }

    #[test]
    fn test_namespace_parsing() {
        assert_eq!(
            WelfareSectorId::from_namespace_name("health.dao.sov"),
            Some(WelfareSectorId::Healthcare)
        );
        assert_eq!(
            WelfareSectorId::from_namespace_name("HEALTH.DAO.SOV"),
            Some(WelfareSectorId::Healthcare)
        );
        assert_eq!(
            WelfareSectorId::from_namespace_name("invalid.sov"),
            None
        );
    }

    #[test]
    fn test_default_floors() {
        // Healthcare requires L2
        assert_eq!(
            get_sector_floor(WelfareSectorId::Healthcare),
            VerificationLevel::L2VerifiedEntity
        );
        // Others require L1
        assert_eq!(
            get_sector_floor(WelfareSectorId::Food),
            VerificationLevel::L1BasicDID
        );
    }

    #[test]
    fn test_effective_verification_level() {
        // DAO policy higher than floor -> use policy
        assert_eq!(
            effective_verification_level(
                VerificationLevel::L1BasicDID,
                VerificationLevel::L2VerifiedEntity
            ),
            VerificationLevel::L2VerifiedEntity
        );

        // DAO policy lower than floor -> use floor
        assert_eq!(
            effective_verification_level(
                VerificationLevel::L2VerifiedEntity,
                VerificationLevel::L1BasicDID
            ),
            VerificationLevel::L2VerifiedEntity
        );

        // Equal -> use either (same result)
        assert_eq!(
            effective_verification_level(
                VerificationLevel::L1BasicDID,
                VerificationLevel::L1BasicDID
            ),
            VerificationLevel::L1BasicDID
        );
    }

    #[test]
    fn test_verification_level_ordering() {
        assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L0Unverified));
        assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L2VerifiedEntity));
        assert!(!VerificationLevel::L1BasicDID.meets_minimum(VerificationLevel::L2VerifiedEntity));
    }

    #[test]
    fn test_all_sectors_constant() {
        assert_eq!(WelfareSectorId::ALL.len(), 5);
        assert!(WelfareSectorId::ALL.contains(&WelfareSectorId::Healthcare));
        assert!(WelfareSectorId::ALL.contains(&WelfareSectorId::Education));
        assert!(WelfareSectorId::ALL.contains(&WelfareSectorId::Energy));
        assert!(WelfareSectorId::ALL.contains(&WelfareSectorId::Housing));
        assert!(WelfareSectorId::ALL.contains(&WelfareSectorId::Food));
    }
}
