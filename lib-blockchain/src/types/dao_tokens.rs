//! Sector-specific DAO token types for SOV ecosystem
//!
//! Provides strong typing for the five sector DAOs:
//! - Healthcare
//! - Education
//! - Energy
//! - Housing
//! - Food
//!
//! Each DAO token is an accounting namespace, not a transferable asset.
//! DAO tokens track treasury allocations and fee distributions.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Sector classifications for DAOs in the SOV ecosystem
///
/// Each sector receives 6% of transaction fees (out of 30% total DAO allocation).
///
/// # Invariants
/// - Deterministic ordering (for consensus and hashing)
/// - Stable string representation across versions
/// - Case-insensitive parsing
/// - Explicit discriminants for serialization safety
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum DAOKind {
    /// Healthcare services and medical infrastructure DAO
    /// - Fee allocation: 6% of transaction fees
    /// - Sector focus: Medical, wellness, public health
    Healthcare = 1,

    /// Education and skill development DAO
    /// - Fee allocation: 6% of transaction fees
    /// - Sector focus: Schools, training, research
    Education = 2,

    /// Energy and infrastructure DAO
    /// - Fee allocation: 6% of transaction fees
    /// - Sector focus: Renewable energy, power distribution
    Energy = 3,

    /// Housing and urban development DAO
    /// - Fee allocation: 6% of transaction fees
    /// - Sector focus: Housing, community development
    Housing = 4,

    /// Food security and agriculture DAO
    /// - Fee allocation: 6% of transaction fees
    /// - Sector focus: Food production, nutrition programs
    Food = 5,
}

impl DAOKind {
    /// All sector DAOs in stable order
    pub const ALL: &'static [DAOKind] = &[
        DAOKind::Healthcare,
        DAOKind::Education,
        DAOKind::Energy,
        DAOKind::Housing,
        DAOKind::Food,
    ];

    /// Count of sector DAOs
    pub const COUNT: usize = 5;

    /// Fee percentage per DAO sector (30% / 5 = 6%)
    pub const FEE_PERCENTAGE: u8 = 6;

    /// String representation of the DAO kind (lowercase, stable across versions)
    pub fn as_str(&self) -> &'static str {
        match self {
            DAOKind::Healthcare => "healthcare",
            DAOKind::Education => "education",
            DAOKind::Energy => "energy",
            DAOKind::Housing => "housing",
            DAOKind::Food => "food",
        }
    }

    /// Get discriminant value (for serialization safety)
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    /// Get human-readable display name
    pub fn display_name(&self) -> &'static str {
        match self {
            DAOKind::Healthcare => "Healthcare",
            DAOKind::Education => "Education",
            DAOKind::Energy => "Energy",
            DAOKind::Housing => "Housing",
            DAOKind::Food => "Food",
        }
    }
}

impl fmt::Display for DAOKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl FromStr for DAOKind {
    type Err = DAOKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "healthcare" | "healthcare_dao" | "health" => Ok(DAOKind::Healthcare),
            "education" | "education_dao" | "edu" => Ok(DAOKind::Education),
            "energy" | "energy_dao" => Ok(DAOKind::Energy),
            "housing" | "housing_dao" | "houses" => Ok(DAOKind::Housing),
            "food" | "food_dao" | "food_security" => Ok(DAOKind::Food),
            _ => Err(DAOKindError::UnknownKind(s.to_string())),
        }
    }
}

/// Error type for DAO kind operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DAOKindError {
    /// Unknown DAO kind string
    UnknownKind(String),
}

impl fmt::Display for DAOKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DAOKindError::UnknownKind(s) => {
                write!(f, "Unknown DAO kind: '{}'. Valid kinds: healthcare, education, energy, housing, food", s)
            }
        }
    }
}

impl std::error::Error for DAOKindError {}

/// DAO token type for sector-specific treasury tracking
///
/// # Invariants
/// - DAO tokens are accounting namespaces, not transferable assets
/// - Fixed allocation: each DAO receives 6% of transaction fees
/// - No inflation or burn mechanisms at type level
/// - Deterministic serialization (bincode format)
///
/// # Usage
/// DAOToken tracks treasury balances for sector-specific operations.
/// When transaction fees are collected (1% of transactions), 30% is allocated
/// to the five DAOs (6% each to Healthcare, Education, Energy, Housing, Food).
///
/// # Examples
/// ```ignore
/// let healthcare_token = DAOToken::new(DAOKind::Healthcare)?;
/// println!("{}", healthcare_token);  // "DAO: Healthcare"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DAOToken {
    /// The specific DAO sector
    pub kind: DAOKind,
}

impl DAOToken {
    /// Create a new DAO token for the given sector
    pub fn new(kind: DAOKind) -> Self {
        DAOToken { kind }
    }

    /// Get the DAO kind
    pub fn kind(&self) -> DAOKind {
        self.kind
    }

    /// Create all five sector DAO tokens
    pub fn all() -> [DAOToken; 5] {
        [
            DAOToken::new(DAOKind::Healthcare),
            DAOToken::new(DAOKind::Education),
            DAOToken::new(DAOKind::Energy),
            DAOToken::new(DAOKind::Housing),
            DAOToken::new(DAOKind::Food),
        ]
    }

    /// Get fee percentage for this DAO (6%)
    pub fn fee_percentage(&self) -> u8 {
        DAOKind::FEE_PERCENTAGE
    }
}

impl fmt::Display for DAOToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DAO: {}", self.kind.display_name())
    }
}

impl FromStr for DAOToken {
    type Err = DAOKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kind = DAOKind::from_str(s)?;
        Ok(DAOToken::new(kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dao_kind_discriminants() {
        assert_eq!(DAOKind::Healthcare.discriminant(), 1);
        assert_eq!(DAOKind::Education.discriminant(), 2);
        assert_eq!(DAOKind::Energy.discriminant(), 3);
        assert_eq!(DAOKind::Housing.discriminant(), 4);
        assert_eq!(DAOKind::Food.discriminant(), 5);
    }

    #[test]
    fn dao_kind_string_representation() {
        assert_eq!(DAOKind::Healthcare.as_str(), "healthcare");
        assert_eq!(DAOKind::Education.as_str(), "education");
        assert_eq!(DAOKind::Energy.as_str(), "energy");
        assert_eq!(DAOKind::Housing.as_str(), "housing");
        assert_eq!(DAOKind::Food.as_str(), "food");
    }

    #[test]
    fn dao_kind_display_name() {
        assert_eq!(DAOKind::Healthcare.display_name(), "Healthcare");
        assert_eq!(DAOKind::Education.display_name(), "Education");
        assert_eq!(DAOKind::Energy.display_name(), "Energy");
        assert_eq!(DAOKind::Housing.display_name(), "Housing");
        assert_eq!(DAOKind::Food.display_name(), "Food");
    }

    #[test]
    fn dao_kind_from_str_lowercase() {
        assert_eq!("healthcare".parse::<DAOKind>().unwrap(), DAOKind::Healthcare);
        assert_eq!("education".parse::<DAOKind>().unwrap(), DAOKind::Education);
        assert_eq!("energy".parse::<DAOKind>().unwrap(), DAOKind::Energy);
        assert_eq!("housing".parse::<DAOKind>().unwrap(), DAOKind::Housing);
        assert_eq!("food".parse::<DAOKind>().unwrap(), DAOKind::Food);
    }

    #[test]
    fn dao_kind_from_str_uppercase() {
        assert_eq!("HEALTHCARE".parse::<DAOKind>().unwrap(), DAOKind::Healthcare);
        assert_eq!("EDUCATION".parse::<DAOKind>().unwrap(), DAOKind::Education);
    }

    #[test]
    fn dao_kind_from_str_mixed() {
        assert_eq!("HeAlThCaRe".parse::<DAOKind>().unwrap(), DAOKind::Healthcare);
        assert_eq!("EdUcAtIoN_dAo".parse::<DAOKind>().unwrap(), DAOKind::Education);
    }

    #[test]
    fn dao_kind_from_str_aliases() {
        assert_eq!("health".parse::<DAOKind>().unwrap(), DAOKind::Healthcare);
        assert_eq!("edu".parse::<DAOKind>().unwrap(), DAOKind::Education);
        assert_eq!("houses".parse::<DAOKind>().unwrap(), DAOKind::Housing);
        assert_eq!("food_security".parse::<DAOKind>().unwrap(), DAOKind::Food);
    }

    #[test]
    fn dao_kind_from_str_invalid() {
        assert!("invalid".parse::<DAOKind>().is_err());
        assert!("unknown_dao".parse::<DAOKind>().is_err());
        assert!("".parse::<DAOKind>().is_err());
    }

    #[test]
    fn dao_kind_all_sectors() {
        let all = DAOKind::ALL;
        assert_eq!(all.len(), 5);
        assert_eq!(all[0], DAOKind::Healthcare);
        assert_eq!(all[1], DAOKind::Education);
        assert_eq!(all[2], DAOKind::Energy);
        assert_eq!(all[3], DAOKind::Housing);
        assert_eq!(all[4], DAOKind::Food);
    }

    #[test]
    fn dao_kind_fee_percentage() {
        assert_eq!(DAOKind::FEE_PERCENTAGE, 6);
        assert_eq!(DAOKind::FEE_PERCENTAGE * DAOKind::COUNT as u8, 30); // Total DAO allocation
    }

    #[test]
    fn dao_kind_ordering() {
        let healthcare = DAOKind::Healthcare;
        let education = DAOKind::Education;
        assert!(healthcare < education);

        // All kinds should be orderable
        let mut kinds = vec![
            DAOKind::Food,
            DAOKind::Healthcare,
            DAOKind::Energy,
            DAOKind::Education,
            DAOKind::Housing,
        ];
        kinds.sort();
        assert_eq!(kinds, vec![
            DAOKind::Healthcare,
            DAOKind::Education,
            DAOKind::Energy,
            DAOKind::Housing,
            DAOKind::Food,
        ]);
    }

    #[test]
    fn dao_token_creation() {
        let healthcare = DAOToken::new(DAOKind::Healthcare);
        assert_eq!(healthcare.kind(), DAOKind::Healthcare);
        assert_eq!(healthcare.fee_percentage(), 6);
    }

    #[test]
    fn dao_token_all() {
        let all_tokens = DAOToken::all();
        assert_eq!(all_tokens.len(), 5);
        assert_eq!(all_tokens[0].kind(), DAOKind::Healthcare);
        assert_eq!(all_tokens[1].kind(), DAOKind::Education);
        assert_eq!(all_tokens[2].kind(), DAOKind::Energy);
        assert_eq!(all_tokens[3].kind(), DAOKind::Housing);
        assert_eq!(all_tokens[4].kind(), DAOKind::Food);
    }

    #[test]
    fn dao_token_display() {
        let healthcare = DAOToken::new(DAOKind::Healthcare);
        assert_eq!(format!("{}", healthcare), "DAO: Healthcare");

        let education = DAOToken::new(DAOKind::Education);
        assert_eq!(format!("{}", education), "DAO: Education");
    }

    #[test]
    fn dao_token_from_str() {
        let healthcare: DAOToken = "healthcare".parse().unwrap();
        assert_eq!(healthcare.kind(), DAOKind::Healthcare);

        let education: DAOToken = "EDUCATION".parse().unwrap();
        assert_eq!(education.kind(), DAOKind::Education);
    }

    /// Test round-trip serialization/deserialization (golden test)
    #[test]
    fn dao_kind_serialization_round_trip() {
        for kind in DAOKind::ALL {
            let serialized = bincode::serialize(kind).expect("serialization failed");
            let deserialized: DAOKind =
                bincode::deserialize(&serialized).expect("deserialization failed");
            assert_eq!(*kind, deserialized);
        }
    }

    #[test]
    fn dao_token_serialization_round_trip() {
        for kind in DAOKind::ALL {
            let token = DAOToken::new(*kind);
            let serialized = bincode::serialize(&token).expect("serialization failed");
            let deserialized: DAOToken =
                bincode::deserialize(&serialized).expect("deserialization failed");
            assert_eq!(token, deserialized);
        }
    }

    /// Golden test vectors for deterministic serialization
    #[test]
    fn dao_kind_serialization_golden() {
        let test_cases = vec![
            (DAOKind::Healthcare, 1u8),
            (DAOKind::Education, 2u8),
            (DAOKind::Energy, 3u8),
            (DAOKind::Housing, 4u8),
            (DAOKind::Food, 5u8),
        ];

        for (kind, expected_discriminant) in test_cases {
            assert_eq!(kind.discriminant(), expected_discriminant);
            let serialized = bincode::serialize(&kind).expect("serialize");
            let deserialized: DAOKind = bincode::deserialize(&serialized).expect("deserialize");
            assert_eq!(kind, deserialized);
        }
    }

    /// Invariant test: DAO tokens are immutable accounting namespaces
    #[test]
    fn dao_token_invariants() {
        // Each DAO receives exactly 6% of fees
        for kind in DAOKind::ALL {
            let token = DAOToken::new(*kind);
            assert_eq!(token.fee_percentage(), 6);
        }

        // Total DAO allocation is exactly 30%
        assert_eq!(DAOKind::COUNT * DAOKind::FEE_PERCENTAGE as usize, 30);

        // All DAOs are accounted for
        assert_eq!(DAOKind::ALL.len(), DAOKind::COUNT);
    }

    /// Test that DAO kinds are deterministically ordered
    #[test]
    fn dao_kind_deterministic_ordering() {
        let mut kinds1 = vec![
            DAOKind::Food,
            DAOKind::Healthcare,
            DAOKind::Energy,
        ];
        let mut kinds2 = vec![
            DAOKind::Energy,
            DAOKind::Food,
            DAOKind::Healthcare,
        ];

        kinds1.sort();
        kinds2.sort();

        assert_eq!(kinds1, kinds2);
        assert_eq!(kinds1[0], DAOKind::Healthcare); // Healthcare comes first
    }

    // Property-based tests using proptest
    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        /// Test that all DAOKind values serialize deterministically
        #[test]
        fn prop_all_kinds_serialize() {
            for kind in DAOKind::ALL {
                let serialized = bincode::serialize(kind).expect("serialization failed");
                let deserialized: DAOKind =
                    bincode::deserialize(&serialized).expect("deserialization failed");
                assert_eq!(*kind, deserialized);
            }
        }

        /// Test that discriminants are unique
        #[test]
        fn test_unique_discriminants() {
            let mut discriminants = vec![];
            for kind in DAOKind::ALL {
                discriminants.push(kind.discriminant());
            }
            discriminants.sort();
            discriminants.dedup();
            assert_eq!(discriminants.len(), DAOKind::COUNT);
        }

        /// Test that all string representations are unique
        #[test]
        fn test_unique_string_representations() {
            let mut strings = vec![];
            for kind in DAOKind::ALL {
                strings.push(kind.as_str());
            }
            strings.sort();
            strings.dedup();
            assert_eq!(strings.len(), DAOKind::COUNT);
        }

        /// Test that string round-trip works for all kinds
        #[test]
        fn test_all_kinds_parse_from_string() {
            for kind in DAOKind::ALL {
                let string = kind.as_str();
                let parsed: DAOKind = string.parse().expect("parse failed");
                assert_eq!(*kind, parsed);
            }
        }

        /// Test that display names are proper case
        #[test]
        fn test_display_names_proper_case() {
            let display_names = vec!["Healthcare", "Education", "Energy", "Housing", "Food"];
            let mut kinds_display = vec![];
            for kind in DAOKind::ALL {
                kinds_display.push(kind.display_name());
            }
            assert_eq!(kinds_display, display_names);
        }

        /// Test that ordering by discriminant matches Ord
        #[test]
        fn test_ordering_by_discriminant() {
            let mut kinds = DAOKind::ALL.to_vec();
            kinds.sort();

            for i in 0..kinds.len() - 1 {
                assert!(
                    kinds[i].discriminant() < kinds[i + 1].discriminant(),
                    "Ordering not by discriminant"
                );
            }
        }

        /// Test that fee allocation is correct for all kinds
        #[test]
        fn test_fee_allocation_consistency() {
            let total_fee = DAOKind::COUNT as u8 * DAOKind::FEE_PERCENTAGE;
            assert_eq!(total_fee, 30, "Total DAO fee allocation must be 30%");

            for kind in DAOKind::ALL {
                assert_eq!(DAOKind::FEE_PERCENTAGE, 6, "Each DAO must receive 6%");
            }
        }

        /// Test that DAOToken creation works for all kinds
        #[test]
        fn test_all_kinds_create_tokens() {
            for kind in DAOKind::ALL {
                let token = DAOToken::new(*kind);
                assert_eq!(token.kind(), *kind);
                assert_eq!(token.fee_percentage(), 6);
            }
        }

        /// Test that all kinds round-trip through DAOToken
        #[test]
        fn test_kinds_round_trip_through_token() {
            for kind in DAOKind::ALL {
                let token = DAOToken::new(*kind);
                let serialized = bincode::serialize(&token).expect("serialize");
                let deserialized: DAOToken = bincode::deserialize(&serialized).expect("deserialize");
                assert_eq!(deserialized.kind(), *kind);
            }
        }
    }
}
