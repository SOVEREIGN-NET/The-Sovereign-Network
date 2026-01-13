//! Domain Name Validation and Classification
//!
//! [Issue #655] Phase 0: Domain Reservation Enforcement - Validation Logic
//!
//! Implements the validation order from the specification:
//! 1. Check if name matches reserved welfare set → REJECT commercial
//! 2. Check if name is `dao.sov` → REJECT (meta-governance only)
//! 3. Check if name starts with `dao.` → Enforce parent ownership rule
//! 4. Check if name is under welfare namespace → Route to WelfareDAORegistry
//! 5. Otherwise → Route to CommercialRegistry with L2 verification

use super::types::*;
use thiserror::Error;

// ============================================================================
// Validation Errors
// ============================================================================

/// Errors that can occur during name validation
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// Name is empty
    #[error("Name cannot be empty")]
    EmptyName,

    /// Name exceeds maximum length
    #[error("Name exceeds maximum length of {max} characters (got {actual})")]
    NameTooLong { max: usize, actual: usize },

    /// Label exceeds maximum length
    #[error("Label '{label}' exceeds maximum length of {max} characters")]
    LabelTooLong { label: String, max: usize },

    /// Label is too short
    #[error("Label '{label}' is too short (minimum {min} characters)")]
    LabelTooShort { label: String, min: usize },

    /// Invalid characters in label
    #[error("Label '{label}' contains invalid characters (only alphanumeric and hyphens allowed)")]
    InvalidCharacters { label: String },

    /// Label starts or ends with hyphen
    #[error("Label '{label}' cannot start or end with a hyphen")]
    InvalidHyphenPosition { label: String },

    /// Name doesn't end with .sov
    #[error("Name must end with .sov TLD")]
    InvalidTLD,

    /// Exceeded maximum depth
    #[error("Name exceeds maximum depth of {max} levels (got {actual})")]
    DepthExceeded { max: usize, actual: usize },

    /// Reserved welfare namespace cannot be registered commercially
    #[error("'{name}' is a reserved welfare namespace")]
    ReservedWelfare { name: String },

    /// dao.sov is reserved for meta-governance
    #[error("dao.sov is reserved for meta-governance and cannot be registered")]
    ReservedMetaGovernance,

    /// dao.X requires control of X.sov
    #[error("dao.{parent} requires control of {parent}.sov")]
    DaoPrefixRequiresParent { parent: String },

    /// Insufficient verification level
    #[error("Verification level {actual:?} does not meet minimum {required:?} for {classification:?}")]
    InsufficientVerification {
        actual: VerificationLevel,
        required: VerificationLevel,
        classification: NameClassification,
    },

    /// High-risk label requires extra verification
    #[error("High-risk label '{label}' requires additional verification")]
    HighRiskLabel { label: String },

    /// Parent domain does not exist
    #[error("Parent domain '{parent}' does not exist")]
    ParentNotFound { parent: String },

    /// Parent domain is not active
    #[error("Parent domain '{parent}' is not in active state")]
    ParentNotActive { parent: String },

    /// Not authorized to delegate under parent
    #[error("Not authorized to delegate under '{parent}'")]
    UnauthorizedDelegation { parent: String },
}

/// Result type for validation operations
pub type ValidationResult<T> = Result<T, ValidationError>;

// ============================================================================
// Name Parsing
// ============================================================================

/// Parsed components of a domain name
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedName {
    /// The full name (e.g., "kitchen.food.sov")
    pub full_name: String,
    /// Individual labels from right to left (e.g., ["sov", "food", "kitchen"])
    pub labels: Vec<String>,
    /// The TLD (should always be "sov")
    pub tld: String,
    /// Classification of this name
    pub classification: NameClassification,
    /// Parent name (if any)
    pub parent: Option<String>,
    /// Depth in the hierarchy (0 for root-level like "shoes.sov")
    pub depth: usize,
}

impl ParsedName {
    /// Get the first label (excluding TLD)
    pub fn first_label(&self) -> Option<&str> {
        self.labels.get(1).map(|s| s.as_str())
    }

    /// Check if this is a dao.X name (e.g., "dao.shoes.sov")
    pub fn is_dao_prefix(&self) -> bool {
        // For "dao.shoes.sov", labels = ["sov", "shoes", "dao"]
        // The leftmost label (dao) is at the end of the reversed array
        self.labels.len() >= 3 && self.labels.last() == Some(&"dao".to_string())
    }

    /// Get the welfare sector if this is a welfare domain
    pub fn welfare_sector(&self) -> Option<WelfareSector> {
        match self.classification {
            NameClassification::ReservedWelfare | NameClassification::WelfareDelegated => {
                // For welfare domains, find the sector label
                // e.g., "kitchen.food.sov" -> "food"
                // e.g., "food.dao.sov" -> "food"
                for label in &self.labels {
                    if let Some(sector) = WelfareSector::from_subdomain(label) {
                        return Some(sector);
                    }
                }
                None
            }
            _ => None,
        }
    }
}

// ============================================================================
// Validation Functions
// ============================================================================

/// High-risk labels that require extra verification
const HIGH_RISK_LABELS: &[&str] = &[
    "bank", "banks", "banking",
    "gov", "govt", "government",
    "hospital", "hospitals",
    "police", "emergency",
    "tax", "taxes", "irs",
    "fbi", "cia", "nsa",
    "military", "army", "navy",
    "court", "courts", "legal",
    "passport", "visa",
];

/// Parse and validate a domain name
///
/// This is the main entry point for name validation. It:
/// 1. Validates the name format (length, characters, labels)
/// 2. Parses into components
/// 3. Classifies the name according to the specification
pub fn parse_and_validate(name: &str) -> ValidationResult<ParsedName> {
    // Basic validation
    if name.is_empty() {
        return Err(ValidationError::EmptyName);
    }

    let name = name.to_lowercase();

    if name.len() > limits::MAX_NAME_LENGTH {
        return Err(ValidationError::NameTooLong {
            max: limits::MAX_NAME_LENGTH,
            actual: name.len(),
        });
    }

    // Must end with .sov
    if !name.ends_with(".sov") {
        return Err(ValidationError::InvalidTLD);
    }

    // Parse into labels
    let labels: Vec<String> = name.split('.').rev().map(|s| s.to_string()).collect();

    // Validate each label
    for (i, label) in labels.iter().enumerate() {
        // Skip TLD validation (it's "sov")
        if i == 0 {
            continue;
        }

        validate_label(label)?;
    }

    // Check depth (depth 0 = root level like "a.sov", depth 1 = "b.a.sov", etc.)
    let depth = labels.len().saturating_sub(2); // -2 for TLD and first label
    if depth >= limits::MAX_DEPTH {
        return Err(ValidationError::DepthExceeded {
            max: limits::MAX_DEPTH,
            actual: depth,
        });
    }

    // Classify the name
    let classification = classify_name(&labels)?;

    // Build parent name
    let parent = if labels.len() > 2 {
        // e.g., ["sov", "food", "kitchen"] -> "food.sov"
        let parent_labels: Vec<&str> = labels[..labels.len() - 1].iter().map(|s| s.as_str()).collect();
        Some(parent_labels.iter().rev().cloned().collect::<Vec<_>>().join("."))
    } else {
        None
    };

    Ok(ParsedName {
        full_name: name,
        labels,
        tld: "sov".to_string(),
        classification,
        parent,
        depth,
    })
}

/// Validate a single label
fn validate_label(label: &str) -> ValidationResult<()> {
    if label.len() < limits::MIN_LABEL_LENGTH {
        return Err(ValidationError::LabelTooShort {
            label: label.to_string(),
            min: limits::MIN_LABEL_LENGTH,
        });
    }

    if label.len() > limits::MAX_LABEL_LENGTH {
        return Err(ValidationError::LabelTooLong {
            label: label.to_string(),
            max: limits::MAX_LABEL_LENGTH,
        });
    }

    // Check for valid characters (alphanumeric and hyphens only)
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(ValidationError::InvalidCharacters {
            label: label.to_string(),
        });
    }

    // Cannot start or end with hyphen
    if label.starts_with('-') || label.ends_with('-') {
        return Err(ValidationError::InvalidHyphenPosition {
            label: label.to_string(),
        });
    }

    Ok(())
}

/// Classify a name according to the specification
///
/// # Classification Order (from spec)
/// 1. Check if name matches reserved welfare set → ReservedWelfare
/// 2. Check if name is `dao.sov` → ReservedMeta
/// 3. Check if name starts with `dao.` → ReservedByRule
/// 4. Check if name is under welfare namespace → WelfareDelegated
/// 5. Otherwise → Commercial
fn classify_name(labels: &[String]) -> ValidationResult<NameClassification> {
    // labels are in reverse order: ["sov", "food", "kitchen"]

    // Case: just "*.sov" (root-level domain)
    if labels.len() == 2 {
        let first_label = &labels[1];

        // Check reserved welfare: {food,health,edu,housing,energy}.sov would be weird
        // but these aren't directly reserved - only X.dao.sov are

        // "dao.sov" is reserved meta-governance
        if first_label == "dao" {
            return Err(ValidationError::ReservedMetaGovernance);
        }

        return Ok(NameClassification::Commercial);
    }

    // Case: "*.*.sov" and deeper
    if labels.len() >= 3 {
        let second_label = &labels[1]; // e.g., "food" in "kitchen.food.sov"
        let third_label = &labels[2];  // e.g., "kitchen" in "kitchen.food.sov"

        // Check for reserved welfare: {sector}.dao.sov and subdomains
        if second_label == "dao" {
            if WELFARE_SECTORS.contains(&third_label.as_str()) {
                // This is "{sector}.dao.sov" or "*.{sector}.dao.sov"
                // All are part of the reserved welfare namespace
                // Spec: welfare subdomains live under "*.{sector}.sov", not "*.{sector}.dao.sov"
                // Therefore, anything under "*.{sector}.dao.sov" is still part of the reserved
                // welfare namespace and must be treated as reserved, not as a normal welfare
                // delegation target.
                return Ok(NameClassification::ReservedWelfare);
            }
        }

        // Check for dao.X pattern (where X is any domain)
        // e.g., "dao.shoes.sov" - this requires control of "shoes.sov"
        // Only match exact pattern "dao.X.sov", not deeper subdomains like "sub.dao.X.sov"
        if labels.len() == 3 && labels[2] == "dao" {
            // Exact "dao.X.sov" pattern - reserved by rule
            return Ok(NameClassification::ReservedByRule);
        }

        // Check if under welfare namespace: *.{sector}.sov
        // e.g., "communitykitchen.food.sov"
        if WELFARE_SECTORS.contains(&second_label.as_str()) {
            return Ok(NameClassification::WelfareDelegated);
        }
    }

    // Default: commercial
    Ok(NameClassification::Commercial)
}

/// Check if a label is high-risk requiring extra verification
pub fn is_high_risk_label(label: &str) -> bool {
    HIGH_RISK_LABELS.contains(&label.to_lowercase().as_str())
}

/// Validate that verification level meets requirements for classification
pub fn validate_verification_level(
    classification: NameClassification,
    level: VerificationLevel,
) -> ValidationResult<()> {
    let required = classification.minimum_verification_level();

    if !level.meets_minimum(required) {
        return Err(ValidationError::InsufficientVerification {
            actual: level,
            required,
            classification,
        });
    }

    Ok(())
}

/// Check for high-risk labels in a parsed name
pub fn check_high_risk_labels(parsed: &ParsedName) -> ValidationResult<()> {
    for label in &parsed.labels {
        if label != "sov" && is_high_risk_label(label) {
            return Err(ValidationError::HighRiskLabel {
                label: label.clone(),
            });
        }
    }
    Ok(())
}

/// Compute the BLAKE3 hash of a name for indexing
pub fn compute_name_hash(name: &str) -> NameHash {
    let hash = blake3::hash(name.to_lowercase().as_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_validation() {
        // Valid commercial domain
        let parsed = parse_and_validate("shoes.sov").unwrap();
        assert_eq!(parsed.full_name, "shoes.sov");
        assert_eq!(parsed.classification, NameClassification::Commercial);
        assert_eq!(parsed.depth, 0);
        assert!(parsed.parent.is_none());

        // Valid subdomain
        let parsed = parse_and_validate("store.shoes.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::Commercial);
        assert_eq!(parsed.depth, 1);
        assert_eq!(parsed.parent, Some("shoes.sov".to_string()));
    }

    #[test]
    fn test_invalid_names() {
        // Empty
        assert!(matches!(
            parse_and_validate(""),
            Err(ValidationError::EmptyName)
        ));

        // Wrong TLD
        assert!(matches!(
            parse_and_validate("shoes.com"),
            Err(ValidationError::InvalidTLD)
        ));

        // Invalid characters
        assert!(matches!(
            parse_and_validate("shoes@store.sov"),
            Err(ValidationError::InvalidCharacters { .. })
        ));

        // Hyphen at start
        assert!(matches!(
            parse_and_validate("-shoes.sov"),
            Err(ValidationError::InvalidHyphenPosition { .. })
        ));

        // Hyphen at end
        assert!(matches!(
            parse_and_validate("shoes-.sov"),
            Err(ValidationError::InvalidHyphenPosition { .. })
        ));
    }

    #[test]
    fn test_reserved_meta_governance() {
        // dao.sov is reserved
        assert!(matches!(
            parse_and_validate("dao.sov"),
            Err(ValidationError::ReservedMetaGovernance)
        ));
    }

    #[test]
    fn test_reserved_welfare() {
        // {sector}.dao.sov are reserved welfare
        let parsed = parse_and_validate("food.dao.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedWelfare);

        let parsed = parse_and_validate("health.dao.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedWelfare);

        let parsed = parse_and_validate("edu.dao.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedWelfare);

        let parsed = parse_and_validate("housing.dao.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedWelfare);

        let parsed = parse_and_validate("energy.dao.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedWelfare);
    }

    #[test]
    fn test_welfare_delegated() {
        // *.{sector}.sov are welfare delegated
        let parsed = parse_and_validate("communitykitchen.food.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::WelfareDelegated);
        assert_eq!(parsed.welfare_sector(), Some(WelfareSector::Food));

        let parsed = parse_and_validate("clinic.health.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::WelfareDelegated);
    }

    #[test]
    fn test_dao_prefix_rule() {
        // dao.X requires control of X.sov
        let parsed = parse_and_validate("dao.shoes.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedByRule);
        assert!(parsed.is_dao_prefix());

        // Non-welfare dao.X
        let parsed = parse_and_validate("dao.mycompany.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedByRule);
    }

    #[test]
    fn test_commercial_classification() {
        // Regular commercial domains
        let cases = vec![
            "shoes.sov",
            "mystore.sov",
            "company123.sov",
            "my-brand.sov",
        ];

        for name in cases {
            let parsed = parse_and_validate(name).unwrap();
            assert_eq!(
                parsed.classification,
                NameClassification::Commercial,
                "Expected {} to be Commercial",
                name
            );
        }
    }

    #[test]
    fn test_dao_at_deeper_levels() {
        // "dao.X.sov" should be ReservedByRule (exact pattern)
        let parsed = parse_and_validate("dao.shoes.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedByRule);

        // "sub.dao.shoes.sov" is a subdomain of "dao.shoes.sov"
        // This is NOT the exact "dao.X.sov" pattern, so it's Commercial
        let parsed = parse_and_validate("sub.dao.shoes.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::Commercial);

        // "x.y.dao.example.sov" is deeper, so also Commercial
        let parsed = parse_and_validate("x.y.dao.example.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::Commercial);

        // "sub.example.sov" where dao is NOT present should be Commercial
        let parsed = parse_and_validate("sub.example.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::Commercial);
    }

    #[test]
    fn test_subdomain_under_reserved_welfare() {
        // "food.dao.sov" should be ReservedWelfare
        let parsed = parse_and_validate("food.dao.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedWelfare);

        // "sub.food.dao.sov" should also be ReservedWelfare (not WelfareDelegated)
        let parsed = parse_and_validate("sub.food.dao.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::ReservedWelfare);

        // "kitchen.food.sov" under welfare namespace should be WelfareDelegated
        let parsed = parse_and_validate("kitchen.food.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::WelfareDelegated);
    }

    #[test]
    fn test_high_risk_labels() {
        assert!(is_high_risk_label("bank"));
        assert!(is_high_risk_label("BANK"));
        assert!(is_high_risk_label("government"));
        assert!(is_high_risk_label("hospital"));
        assert!(!is_high_risk_label("shoes"));
        assert!(!is_high_risk_label("mystore"));
    }

    #[test]
    fn test_verification_level_validation() {
        // Commercial requires L2
        assert!(validate_verification_level(
            NameClassification::Commercial,
            VerificationLevel::L2VerifiedEntity
        ).is_ok());

        assert!(validate_verification_level(
            NameClassification::Commercial,
            VerificationLevel::L1BasicDID
        ).is_err());

        // Welfare delegated requires L1
        assert!(validate_verification_level(
            NameClassification::WelfareDelegated,
            VerificationLevel::L1BasicDID
        ).is_ok());

        assert!(validate_verification_level(
            NameClassification::WelfareDelegated,
            VerificationLevel::L0Unverified
        ).is_err());

        // Reserved welfare requires L3
        assert!(validate_verification_level(
            NameClassification::ReservedWelfare,
            VerificationLevel::L3ConstitutionalActor
        ).is_ok());

        assert!(validate_verification_level(
            NameClassification::ReservedWelfare,
            VerificationLevel::L2VerifiedEntity
        ).is_err());
    }

    #[test]
    fn test_name_hash() {
        let hash1 = compute_name_hash("shoes.sov");
        let hash2 = compute_name_hash("SHOES.SOV");
        assert_eq!(hash1, hash2, "Hash should be case-insensitive");

        let hash3 = compute_name_hash("boots.sov");
        assert_ne!(hash1, hash3, "Different names should have different hashes");
    }

    #[test]
    fn test_case_insensitivity() {
        let lower = parse_and_validate("shoes.sov").unwrap();
        let upper = parse_and_validate("SHOES.SOV").unwrap();
        let mixed = parse_and_validate("ShOeS.SoV").unwrap();

        assert_eq!(lower.full_name, upper.full_name);
        assert_eq!(lower.full_name, mixed.full_name);
    }

    #[test]
    fn test_depth_calculation() {
        assert_eq!(parse_and_validate("a.sov").unwrap().depth, 0);
        assert_eq!(parse_and_validate("b.a.sov").unwrap().depth, 1);
        assert_eq!(parse_and_validate("c.b.a.sov").unwrap().depth, 2);
        assert_eq!(parse_and_validate("d.c.b.a.sov").unwrap().depth, 3);
    }

    #[test]
    fn test_max_depth() {
        // 8 levels should be OK
        let deep_name = "a.b.c.d.e.f.g.h.sov"; // 8 levels
        let parsed = parse_and_validate(deep_name);
        assert!(parsed.is_ok());

        // 9 levels should fail
        let too_deep = "a.b.c.d.e.f.g.h.i.sov"; // 9 levels
        assert!(matches!(
            parse_and_validate(too_deep),
            Err(ValidationError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn test_mydao_is_commercial() {
        // "mydao.sov" - "dao" in name but not prefix, should be Commercial
        let parsed = parse_and_validate("mydao.sov").unwrap();
        assert_eq!(parsed.classification, NameClassification::Commercial);
    }

    #[test]
    fn test_parent_extraction() {
        let parsed = parse_and_validate("sub.domain.sov").unwrap();
        assert_eq!(parsed.parent, Some("domain.sov".to_string()));

        let parsed = parse_and_validate("deep.sub.domain.sov").unwrap();
        assert_eq!(parsed.parent, Some("sub.domain.sov".to_string()));
    }
}
