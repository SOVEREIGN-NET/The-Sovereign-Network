//! Namespace policy enforcement for the root registry.
//!
//! [Phase 5] This module implements verification requirements for domain registration.
//! Root-level .sov issuance requires identity-anchored proofs with graduated access
//! control based on domain classification.
//!
//! # Verification Level Mapping
//! | Domain Class       | Required Level          | Example              |
//! |--------------------|-------------------------|----------------------|
//! | Commercial root    | L2 – Verified Entity    | shoes.sov            |
//! | Welfare child      | L1 – Basic DID          | clinic.health.sov    |
//! | Welfare root       | L3 – Constitutional     | health.dao.sov       |
//! | Reserved sector    | L3 + governance         | food.dao.sov         |
//!
//! # Hard Rule
//! L0 can NEVER register a .sov root. The `.zhtp` TLD may remain permissive
//! for experimentation; `.sov` is sovereign-grade.

use std::collections::HashSet;
use super::types::{
    hash_name, normalize_name, NameClass, NameHash, ReservedReason, VerificationLevel,
    VerificationError, VerificationProof, WelfareSector, Timestamp,
};

const IMMUTABLE_RESERVED: &[&str] = &[
    "food.dao.sov",
    "health.dao.sov",
    "edu.dao.sov",
    "housing.dao.sov",
    "energy.dao.sov",
    "dao.sov",
];

/// Namespace policy for the root registry
/// 
/// [Phase 5] Implements verification gate for domain registration.
/// Determines what verification is needed and validates proofs.
#[derive(Debug, Clone)]
pub struct NamespacePolicy {
    governance_added_reserved: HashSet<NameHash>,
}

impl NamespacePolicy {
    pub fn new() -> Self {
        Self {
            governance_added_reserved: HashSet::new(),
        }
    }

    pub fn add_reserved_namespace(&mut self, name_hash: NameHash) {
        self.governance_added_reserved.insert(name_hash);
    }

    pub fn is_reserved_hash(&self, name_hash: &NameHash) -> bool {
        self.governance_added_reserved.contains(name_hash)
            || immutable_reserved_hashes().contains(name_hash)
    }

    // ========================================================================
    // Phase 5: Verification Gate Interface
    // ========================================================================

    /// Get the required verification level for a name classification
    ///
    /// [Phase 5] Maps domain class to required verification level.
    /// This is the core policy decision for .sov issuance requirements.
    ///
    /// # Returns
    /// The minimum verification level required to register a domain of this class.
    pub fn required_verification(&self, name_class: &NameClass) -> VerificationLevel {
        match name_class {
            // Reserved roots (welfare sectors, dao.sov) require L3 Constitutional Actor
            NameClass::Reserved { reason } => match reason {
                ReservedReason::MetaGovernance => VerificationLevel::L3ConstitutionalActor,
                ReservedReason::WelfareRoot => VerificationLevel::L3ConstitutionalActor,
                ReservedReason::GovernanceAdded => VerificationLevel::L3ConstitutionalActor,
                ReservedReason::HighRiskLabel => VerificationLevel::L3ConstitutionalActor,
            },
            // Commercial roots require L2 Verified Entity
            NameClass::Commercial { .. } => VerificationLevel::L2VerifiedEntity,
            // Welfare children require L1 Basic DID (sector may raise floor)
            NameClass::WelfareChild { .. } => VerificationLevel::L1BasicDID,
            // dao.* prefixed names are virtual, cannot be registered
            // Return L3 as they should be rejected before this check anyway
            NameClass::DaoPrefixed { .. } => VerificationLevel::L3ConstitutionalActor,
        }
    }

    /// Verify that a subject meets the verification requirements for a domain class
    ///
    /// [Phase 5] This is the verification gate - the core security check that
    /// ensures only appropriately verified entities can register .sov domains.
    ///
    /// # Arguments
    /// * `name_class` - Classification of the domain being registered
    /// * `provided_level` - The verification level the registrant claims
    /// * `proof` - Optional verification proof (required for .sov domains)
    /// * `current_time` - Current timestamp for expiration checking
    /// * `expected_context` - Expected context hash (domain || operation || nonce)
    ///
    /// # Returns
    /// * `Ok(())` - Verification passed
    /// * `Err(VerificationError)` - Verification failed with specific reason
    ///
    /// # Invariants (Phase 5)
    /// - V1: .sov root issuance is impossible without verification
    /// - V2: Verification requirements are name-class dependent
    /// - V7: Missing verification fails loudly and deterministically
    pub fn verify(
        &self,
        name_class: &NameClass,
        provided_level: VerificationLevel,
        proof: Option<&VerificationProof>,
        _current_time: Timestamp, // Reserved for future credential expiration checking
        expected_context: Option<&[u8; 32]>,
    ) -> Result<(), VerificationError> {
        let required = self.required_verification(name_class);

        // Hard rule: L0 can NEVER register a .sov root
        if provided_level == VerificationLevel::L0Unverified {
            return Err(VerificationError::L0NotAllowedForSov);
        }

        // Check if provided level meets minimum requirement
        if !provided_level.meets_minimum(required) {
            return Err(VerificationError::InsufficientLevel {
                required,
                provided: provided_level,
            });
        }

        // For .sov domains, proof is required
        let proof = proof.ok_or(VerificationError::MissingProof)?;

        // Validate proof has data
        if !proof.has_proof_data() {
            return Err(VerificationError::InvalidProof {
                reason: "Empty proof data".to_string(),
            });
        }

        // Validate context hash if provided (prevents replay attacks)
        if let Some(expected) = expected_context {
            if &proof.context != expected {
                return Err(VerificationError::ContextMismatch);
            }
        }

        // TODO: In production, verify the ZK proof cryptographically
        // This would involve:
        // 1. Verifying the ZK proof using lib-proofs
        // 2. Checking credential_ref against trusted issuer registry
        // 3. Verifying the proof demonstrates the claimed verification level
        // 
        // For now, we trust the provided level if proof structure is valid.
        // The actual ZK verification will be integrated when lib-proofs is wired in.

        Ok(())
    }

    /// Check if a TLD allows permissive (L0) registration
    ///
    /// [Phase 5] .zhtp may remain permissive for experimentation;
    /// .sov is sovereign-grade and requires verification.
    pub fn is_permissive_tld(name: &str) -> bool {
        let normalized = normalize_name(name);
        normalized.ends_with(".zhtp")
    }

    // ========================================================================
    // Classification (existing)
    // ========================================================================

    pub fn classify_name(&self, name: &str) -> NameClass {
        let normalized = normalize_name(name);

        if normalized == "dao.sov" {
            return NameClass::Reserved {
                reason: ReservedReason::MetaGovernance,
            };
        }

        if let Some(_sector) = welfare_sector_from_root(&normalized) {
            return NameClass::Reserved {
                reason: ReservedReason::WelfareRoot,
            };
        }

        if self.governance_added_reserved.contains(&hash_name(&normalized)) {
            return NameClass::Reserved {
                reason: ReservedReason::GovernanceAdded,
            };
        }

        if let Some((sector, zone_root)) = welfare_child_info(&normalized) {
            return NameClass::WelfareChild {
                sector,
                zone_root_hash: zone_root,
            };
        }

        if let Some(parent_hash) = dao_prefixed_parent(&normalized) {
            return NameClass::DaoPrefixed { parent_hash };
        }

        // [Phase 5] Commercial roots require L2 Verified Entity
        // This is enforced by required_verification() + verify()
        NameClass::Commercial {
            min_verification: VerificationLevel::L2VerifiedEntity,
        }
    }
}

impl Default for NamespacePolicy {
    fn default() -> Self {
        Self::new()
    }
}

pub fn immutable_reserved_hashes() -> HashSet<NameHash> {
    IMMUTABLE_RESERVED
        .iter()
        .map(|name| hash_name(name))
        .collect()
}

fn welfare_sector_from_root(name: &str) -> Option<WelfareSector> {
    match name {
        "food.dao.sov" => Some(WelfareSector::Food),
        "health.dao.sov" => Some(WelfareSector::Health),
        "edu.dao.sov" => Some(WelfareSector::Education),
        "housing.dao.sov" => Some(WelfareSector::Housing),
        "energy.dao.sov" => Some(WelfareSector::Energy),
        _ => None,
    }
}

fn welfare_child_info(name: &str) -> Option<(WelfareSector, NameHash)> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 4 {
        return None;
    }

    let sector = match parts[parts.len() - 3] {
        "food" => WelfareSector::Food,
        "health" => WelfareSector::Health,
        "edu" => WelfareSector::Education,
        "housing" => WelfareSector::Housing,
        "energy" => WelfareSector::Energy,
        _ => return None,
    };

    if parts[parts.len() - 2] != "dao" || parts[parts.len() - 1] != "sov" {
        return None;
    }

    let zone_root = format!("{}.dao.sov", parts[parts.len() - 3]);
    Some((sector, hash_name(&zone_root)))
}

fn dao_prefixed_parent(name: &str) -> Option<NameHash> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    if parts[0] != "dao" || parts[2] != "sov" {
        return None;
    }
    let parent = format!("{}.sov", parts[1]);
    Some(hash_name(&parent))
}
