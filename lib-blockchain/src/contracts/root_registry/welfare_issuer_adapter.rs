//! Welfare Issuer Adapter (Issue #658 - Phase 3)
//!
//! This contract provides a bridge between sector DAOs and the RootRegistry,
//! enforcing the issuance ratification workflow for welfare subdomains.
//!
//! # Workflow
//!
//! 1. **Claim**: DAO claims a sector binding (food.dao.sov → Food sector)
//! 2. **Ratification**: Root governance ratifies the claim
//! 3. **Issuance**: DAO can then issue subdomains under their sector
//!
//! # Security Model
//!
//! - Only ratified DAOs can issue welfare subdomains
//! - Root can suspend a DAO's issuance capability
//! - Verification level floors are enforced per sector

use crate::contracts::approval_verifier::{
    ApprovalProof, IssuanceApprovalVerifier, IssuanceRequest, VerificationError,
};
use crate::types::{
    WelfareSectorId, SectorVerificationLevel, get_sector_floor, effective_verification_level,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Welfare metadata attached to issued names
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelfareMetadata {
    /// The sector this name belongs to
    pub sector: WelfareSectorId,
    /// The issuing DAO ID
    pub issuing_dao: [u8; 32],
    /// Block height when issued
    pub issued_at: u64,
    /// Optional DAO-defined category (max 32 chars)
    pub category: Option<String>,
}

/// Status of a sector binding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingStatus {
    /// Claim submitted, awaiting ratification
    Pending,
    /// Ratified by root governance
    Active,
    /// Suspended by root (can be reinstated)
    SuspendedByRoot {
        /// Block height when suspended
        suspended_at: u64,
        /// Reason code
        reason: SuspensionReason,
    },
    /// Revoked (cannot be reinstated without new claim)
    Revoked {
        /// Block height when revoked
        revoked_at: u64,
    },
}

/// Reason for suspension
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspensionReason {
    /// Governance violation
    GovernanceViolation,
    /// Security incident
    SecurityIncident,
    /// Compliance issue
    ComplianceIssue,
    /// Constitutional amendment
    ConstitutionalAmendment,
    /// Other (with code)
    Other(u8),
}

/// A pending claim for sector binding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingClaim {
    /// The DAO making the claim
    pub dao_id: [u8; 32],
    /// The sector being claimed
    pub sector: WelfareSectorId,
    /// Block height when claim was submitted
    pub claimed_at: u64,
    /// Claim metadata/justification hash
    pub justification_hash: [u8; 32],
}

/// An active sector binding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectorBinding {
    /// The DAO bound to this sector
    pub dao_id: [u8; 32],
    /// The sector
    pub sector: WelfareSectorId,
    /// Block height when ratified
    pub ratified_at: u64,
    /// Current status
    pub status: BindingStatus,
    /// DAO's verification policy (floor or higher)
    pub verification_policy: SectorVerificationLevel,
    /// Number of names issued
    pub names_issued: u64,
}

/// DAO's verification policy for issuance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoVerificationPolicy {
    /// Minimum verification level required (must be >= sector floor)
    pub min_level: SectorVerificationLevel,
    /// Whether to require additional attestations
    pub require_attestations: bool,
}

impl Default for DaoVerificationPolicy {
    fn default() -> Self {
        Self {
            min_level: SectorVerificationLevel::L1BasicDID,
            require_attestations: false,
        }
    }
}

/// Result of an issuance operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceResult {
    /// The issued name hash
    pub name_hash: [u8; 32],
    /// The welfare metadata
    pub metadata: WelfareMetadata,
    /// Block height of issuance
    pub issued_at: u64,
}

/// Errors from the welfare issuer adapter
#[derive(Debug, Clone, PartialEq)]
pub enum WelfareIssuerError {
    /// Sector already has an active binding
    SectorAlreadyBound {
        sector: WelfareSectorId,
        existing_dao: [u8; 32],
    },
    /// DAO already has a pending claim
    ClaimAlreadyPending {
        dao_id: [u8; 32],
        sector: WelfareSectorId,
    },
    /// No pending claim found
    NoPendingClaim {
        dao_id: [u8; 32],
        sector: WelfareSectorId,
    },
    /// DAO not authorized for this sector
    DaoNotAuthorized {
        dao_id: [u8; 32],
        sector: WelfareSectorId,
    },
    /// DAO binding is suspended
    DaoSuspended {
        dao_id: [u8; 32],
        reason: SuspensionReason,
    },
    /// Insufficient verification level
    InsufficientVerification {
        provided: SectorVerificationLevel,
        required: SectorVerificationLevel,
    },
    /// Approval verification failed
    ApprovalVerificationFailed {
        error: VerificationError,
    },
    /// Invalid label
    InvalidLabel {
        label: String,
        reason: String,
    },
    /// Not root authority
    NotRootAuthority,
    /// Operation not allowed
    OperationNotAllowed {
        reason: String,
    },
}

impl std::fmt::Display for WelfareIssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WelfareIssuerError::SectorAlreadyBound { sector, existing_dao } => {
                write!(
                    f,
                    "Sector {:?} already bound to DAO {:?}",
                    sector,
                    &existing_dao[..8]
                )
            }
            WelfareIssuerError::ClaimAlreadyPending { dao_id, sector } => {
                write!(
                    f,
                    "DAO {:?} already has pending claim for sector {:?}",
                    &dao_id[..8],
                    sector
                )
            }
            WelfareIssuerError::NoPendingClaim { dao_id, sector } => {
                write!(
                    f,
                    "No pending claim found for DAO {:?} in sector {:?}",
                    &dao_id[..8],
                    sector
                )
            }
            WelfareIssuerError::DaoNotAuthorized { dao_id, sector } => {
                write!(
                    f,
                    "DAO {:?} not authorized for sector {:?}",
                    &dao_id[..8],
                    sector
                )
            }
            WelfareIssuerError::DaoSuspended { dao_id, reason } => {
                write!(f, "DAO {:?} is suspended: {:?}", &dao_id[..8], reason)
            }
            WelfareIssuerError::InsufficientVerification { provided, required } => {
                write!(
                    f,
                    "Insufficient verification: {:?} < {:?}",
                    provided, required
                )
            }
            WelfareIssuerError::ApprovalVerificationFailed { error } => {
                write!(f, "Approval verification failed: {}", error)
            }
            WelfareIssuerError::InvalidLabel { label, reason } => {
                write!(f, "Invalid label '{}': {}", label, reason)
            }
            WelfareIssuerError::NotRootAuthority => {
                write!(f, "Caller is not root authority")
            }
            WelfareIssuerError::OperationNotAllowed { reason } => {
                write!(f, "Operation not allowed: {}", reason)
            }
        }
    }
}

impl std::error::Error for WelfareIssuerError {}

/// The Welfare Issuer Adapter contract
///
/// This contract manages the relationship between sector DAOs and the
/// RootRegistry, enforcing the issuance workflow and verification requirements.
pub struct WelfareIssuerAdapter {
    /// Root authority public key (for ratification and suspension)
    root_authority: [u8; 32],
    /// Pending claims: (dao_id, sector) -> PendingClaim
    pending_claims: HashMap<([u8; 32], WelfareSectorId), PendingClaim>,
    /// Active bindings: sector -> SectorBinding
    sector_bindings: HashMap<WelfareSectorId, SectorBinding>,
    /// Reverse lookup: dao_id -> sector
    dao_to_sector: HashMap<[u8; 32], WelfareSectorId>,
    /// Approval verifiers by DAO
    verifiers: HashMap<[u8; 32], Box<dyn IssuanceApprovalVerifier>>,
    /// Current block height
    current_block: u64,
}

impl WelfareIssuerAdapter {
    /// Create a new adapter with the given root authority
    pub fn new(root_authority: [u8; 32]) -> Self {
        Self {
            root_authority,
            pending_claims: HashMap::new(),
            sector_bindings: HashMap::new(),
            dao_to_sector: HashMap::new(),
            verifiers: HashMap::new(),
            current_block: 0,
        }
    }

    /// Set the current block height
    pub fn set_current_block(&mut self, block: u64) {
        self.current_block = block;
    }

    /// Check if caller is root authority
    fn is_root_authority(&self, caller: &[u8; 32]) -> bool {
        *caller == self.root_authority
    }

    // ========== Claim Workflow ==========

    /// Submit a claim for a sector binding
    ///
    /// A DAO calls this to claim the right to issue welfare subdomains
    /// in a specific sector. The claim must be ratified by root governance.
    pub fn submit_claim(
        &mut self,
        dao_id: [u8; 32],
        sector: WelfareSectorId,
        justification_hash: [u8; 32],
    ) -> Result<(), WelfareIssuerError> {
        // Check if sector already has an active binding
        if let Some(binding) = self.sector_bindings.get(&sector) {
            if matches!(binding.status, BindingStatus::Active | BindingStatus::Pending) {
                return Err(WelfareIssuerError::SectorAlreadyBound {
                    sector,
                    existing_dao: binding.dao_id,
                });
            }
        }

        // Check if DAO already has a pending claim for this sector
        let key = (dao_id, sector);
        if self.pending_claims.contains_key(&key) {
            return Err(WelfareIssuerError::ClaimAlreadyPending { dao_id, sector });
        }

        // Create the pending claim
        let claim = PendingClaim {
            dao_id,
            sector,
            claimed_at: self.current_block,
            justification_hash,
        };

        self.pending_claims.insert(key, claim);
        Ok(())
    }

    /// Ratify a pending claim (root authority only)
    ///
    /// This converts a pending claim into an active sector binding.
    pub fn ratify_claim(
        &mut self,
        caller: [u8; 32],
        dao_id: [u8; 32],
        sector: WelfareSectorId,
        verification_policy: Option<DaoVerificationPolicy>,
    ) -> Result<SectorBinding, WelfareIssuerError> {
        // Check root authority
        if !self.is_root_authority(&caller) {
            return Err(WelfareIssuerError::NotRootAuthority);
        }

        // Find and remove the pending claim
        let key = (dao_id, sector);
        let _claim = self
            .pending_claims
            .remove(&key)
            .ok_or(WelfareIssuerError::NoPendingClaim { dao_id, sector })?;

        // Determine verification policy
        let sector_floor = get_sector_floor(sector);
        let policy = verification_policy.unwrap_or_default();
        let effective_level = effective_verification_level(sector_floor, policy.min_level);

        // Create the binding
        let binding = SectorBinding {
            dao_id,
            sector,
            ratified_at: self.current_block,
            status: BindingStatus::Active,
            verification_policy: effective_level,
            names_issued: 0,
        };

        // Store the binding
        self.sector_bindings.insert(sector, binding.clone());
        self.dao_to_sector.insert(dao_id, sector);

        Ok(binding)
    }

    /// Reject a pending claim (root authority only)
    pub fn reject_claim(
        &mut self,
        caller: [u8; 32],
        dao_id: [u8; 32],
        sector: WelfareSectorId,
    ) -> Result<(), WelfareIssuerError> {
        if !self.is_root_authority(&caller) {
            return Err(WelfareIssuerError::NotRootAuthority);
        }

        let key = (dao_id, sector);
        self.pending_claims
            .remove(&key)
            .ok_or(WelfareIssuerError::NoPendingClaim { dao_id, sector })?;

        Ok(())
    }

    // ========== Suspension/Revocation ==========

    /// Suspend a DAO's issuance capability (root authority only)
    pub fn suspend_dao(
        &mut self,
        caller: [u8; 32],
        dao_id: [u8; 32],
        reason: SuspensionReason,
    ) -> Result<(), WelfareIssuerError> {
        if !self.is_root_authority(&caller) {
            return Err(WelfareIssuerError::NotRootAuthority);
        }

        let sector = self.dao_to_sector.get(&dao_id).ok_or(
            WelfareIssuerError::DaoNotAuthorized {
                dao_id,
                sector: WelfareSectorId::Food, // placeholder
            },
        )?;

        let binding = self.sector_bindings.get_mut(sector).ok_or(
            WelfareIssuerError::DaoNotAuthorized {
                dao_id,
                sector: *sector,
            },
        )?;

        binding.status = BindingStatus::SuspendedByRoot {
            suspended_at: self.current_block,
            reason,
        };

        Ok(())
    }

    /// Reinstate a suspended DAO (root authority only)
    pub fn reinstate_dao(
        &mut self,
        caller: [u8; 32],
        dao_id: [u8; 32],
    ) -> Result<(), WelfareIssuerError> {
        if !self.is_root_authority(&caller) {
            return Err(WelfareIssuerError::NotRootAuthority);
        }

        let sector = self.dao_to_sector.get(&dao_id).ok_or(
            WelfareIssuerError::DaoNotAuthorized {
                dao_id,
                sector: WelfareSectorId::Food,
            },
        )?;

        let binding = self.sector_bindings.get_mut(sector).ok_or(
            WelfareIssuerError::DaoNotAuthorized {
                dao_id,
                sector: *sector,
            },
        )?;

        if !matches!(binding.status, BindingStatus::SuspendedByRoot { .. }) {
            return Err(WelfareIssuerError::OperationNotAllowed {
                reason: "DAO is not suspended".to_string(),
            });
        }

        binding.status = BindingStatus::Active;
        Ok(())
    }

    // ========== Verifier Registration ==========

    /// Register an approval verifier for a DAO
    pub fn register_verifier(
        &mut self,
        dao_id: [u8; 32],
        verifier: Box<dyn IssuanceApprovalVerifier>,
    ) {
        self.verifiers.insert(dao_id, verifier);
    }

    // ========== Issuance ==========

    /// Issue a welfare subdomain
    ///
    /// This is called by the DAO to issue a new welfare subdomain.
    /// The request must be accompanied by a valid approval proof.
    pub fn issue_welfare_name(
        &mut self,
        dao_id: [u8; 32],
        label: String,
        recipient: [u8; 32],
        recipient_verification_level: u8,
        proof: ApprovalProof,
        category: Option<String>,
    ) -> Result<IssuanceResult, WelfareIssuerError> {
        // Validate label
        self.validate_label(&label)?;

        // Get the sector (copy to avoid borrow issues)
        let sector = *self
            .dao_to_sector
            .get(&dao_id)
            .ok_or(WelfareIssuerError::DaoNotAuthorized {
                dao_id,
                sector: WelfareSectorId::Food,
            })?;

        // First pass: validate binding state and verification level (immutable borrow)
        let verification_policy = {
            let binding = self.sector_bindings.get(&sector).ok_or(
                WelfareIssuerError::DaoNotAuthorized {
                    dao_id,
                    sector,
                },
            )?;

            // Check binding status
            match binding.status {
                BindingStatus::Active => {}
                BindingStatus::SuspendedByRoot { reason, .. } => {
                    return Err(WelfareIssuerError::DaoSuspended { dao_id, reason });
                }
                _ => {
                    return Err(WelfareIssuerError::DaoNotAuthorized {
                        dao_id,
                        sector,
                    });
                }
            }

            binding.verification_policy
        };

        // Check verification level
        let recipient_level = match recipient_verification_level {
            0 => SectorVerificationLevel::L0Unverified,
            1 => SectorVerificationLevel::L1BasicDID,
            2 => SectorVerificationLevel::L2VerifiedEntity,
            3 => SectorVerificationLevel::L3ConstitutionalActor,
            _ => SectorVerificationLevel::L0Unverified,
        };

        if !recipient_level.meets_minimum(verification_policy) {
            return Err(WelfareIssuerError::InsufficientVerification {
                provided: recipient_level,
                required: verification_policy,
            });
        }

        // Verify the approval proof
        let request = IssuanceRequest {
            label: label.clone(),
            sector_id: sector.as_u8(),
            recipient,
            recipient_verification_level,
            requester: dao_id,
            current_block: self.current_block,
        };

        // Get verifier for this DAO
        if let Some(verifier) = self.verifiers.get(&dao_id) {
            verifier
                .verify_issuance_approval(&request, &proof, dao_id)
                .map_err(|e| WelfareIssuerError::ApprovalVerificationFailed { error: e })?;
        }
        // If no verifier registered, skip verification (permissive mode)

        // Compute name hash (no mutable borrow active)
        let name_hash = self.compute_welfare_name_hash(sector, &label);

        // Create metadata
        let metadata = WelfareMetadata {
            sector,
            issuing_dao: dao_id,
            issued_at: self.current_block,
            category,
        };

        // Update binding stats (separate mutable borrow)
        if let Some(binding) = self.sector_bindings.get_mut(&sector) {
            binding.names_issued += 1;
        }

        Ok(IssuanceResult {
            name_hash,
            metadata,
            issued_at: self.current_block,
        })
    }

    /// Validate a label for welfare subdomain issuance
    fn validate_label(&self, label: &str) -> Result<(), WelfareIssuerError> {
        if label.is_empty() {
            return Err(WelfareIssuerError::InvalidLabel {
                label: label.to_string(),
                reason: "Label cannot be empty".to_string(),
            });
        }

        if label.len() > 63 {
            return Err(WelfareIssuerError::InvalidLabel {
                label: label.to_string(),
                reason: "Label too long (max 63 chars)".to_string(),
            });
        }

        // Check for valid characters (alphanumeric and hyphens)
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(WelfareIssuerError::InvalidLabel {
                label: label.to_string(),
                reason: "Invalid characters (only alphanumeric and hyphens allowed)".to_string(),
            });
        }

        // Cannot start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(WelfareIssuerError::InvalidLabel {
                label: label.to_string(),
                reason: "Label cannot start or end with hyphen".to_string(),
            });
        }

        Ok(())
    }

    /// Compute the name hash for a welfare subdomain
    fn compute_welfare_name_hash(&self, sector: WelfareSectorId, label: &str) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"WELFARE_NAME_V1");
        hasher.update(&[sector.as_u8()]);
        hasher.update(label.as_bytes());
        let hash = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    // ========== Query Methods ==========

    /// Get a sector binding
    pub fn get_binding(&self, sector: WelfareSectorId) -> Option<&SectorBinding> {
        self.sector_bindings.get(&sector)
    }

    /// Get a DAO's sector
    pub fn get_dao_sector(&self, dao_id: &[u8; 32]) -> Option<WelfareSectorId> {
        self.dao_to_sector.get(dao_id).copied()
    }

    /// Get pending claims for a sector
    pub fn get_pending_claims(&self, sector: WelfareSectorId) -> Vec<&PendingClaim> {
        self.pending_claims
            .values()
            .filter(|c| c.sector == sector)
            .collect()
    }

    /// Check if a DAO is authorized for a sector
    pub fn is_dao_authorized(&self, dao_id: &[u8; 32], sector: WelfareSectorId) -> bool {
        if let Some(bound_sector) = self.dao_to_sector.get(dao_id) {
            if *bound_sector == sector {
                if let Some(binding) = self.sector_bindings.get(&sector) {
                    return matches!(binding.status, BindingStatus::Active);
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_root_authority() -> [u8; 32] {
        [0xAA; 32]
    }

    fn make_dao_id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn test_submit_claim() {
        let mut adapter = WelfareIssuerAdapter::new(make_root_authority());
        adapter.set_current_block(1000);

        let dao_id = make_dao_id(1);
        let result = adapter.submit_claim(dao_id, WelfareSectorId::Food, [0u8; 32]);
        assert!(result.is_ok());

        // Check pending claim exists
        let claims = adapter.get_pending_claims(WelfareSectorId::Food);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].dao_id, dao_id);
    }

    #[test]
    fn test_duplicate_claim_rejected() {
        let mut adapter = WelfareIssuerAdapter::new(make_root_authority());

        let dao_id = make_dao_id(1);
        adapter
            .submit_claim(dao_id, WelfareSectorId::Food, [0u8; 32])
            .unwrap();

        // Second claim should fail
        let result = adapter.submit_claim(dao_id, WelfareSectorId::Food, [0u8; 32]);
        assert!(matches!(
            result,
            Err(WelfareIssuerError::ClaimAlreadyPending { .. })
        ));
    }

    #[test]
    fn test_ratify_claim() {
        let root = make_root_authority();
        let mut adapter = WelfareIssuerAdapter::new(root);
        adapter.set_current_block(1000);

        let dao_id = make_dao_id(1);
        adapter
            .submit_claim(dao_id, WelfareSectorId::Food, [0u8; 32])
            .unwrap();

        adapter.set_current_block(2000);
        let result = adapter.ratify_claim(root, dao_id, WelfareSectorId::Food, None);
        assert!(result.is_ok());

        let binding = result.unwrap();
        assert_eq!(binding.dao_id, dao_id);
        assert_eq!(binding.sector, WelfareSectorId::Food);
        assert!(matches!(binding.status, BindingStatus::Active));
        assert_eq!(binding.ratified_at, 2000);
    }

    #[test]
    fn test_non_root_cannot_ratify() {
        let root = make_root_authority();
        let mut adapter = WelfareIssuerAdapter::new(root);

        let dao_id = make_dao_id(1);
        let non_root = make_dao_id(99);
        adapter
            .submit_claim(dao_id, WelfareSectorId::Food, [0u8; 32])
            .unwrap();

        let result = adapter.ratify_claim(non_root, dao_id, WelfareSectorId::Food, None);
        assert!(matches!(result, Err(WelfareIssuerError::NotRootAuthority)));
    }

    #[test]
    fn test_suspend_and_reinstate() {
        let root = make_root_authority();
        let mut adapter = WelfareIssuerAdapter::new(root);

        let dao_id = make_dao_id(1);
        adapter
            .submit_claim(dao_id, WelfareSectorId::Food, [0u8; 32])
            .unwrap();
        adapter
            .ratify_claim(root, dao_id, WelfareSectorId::Food, None)
            .unwrap();

        // Suspend
        adapter
            .suspend_dao(root, dao_id, SuspensionReason::SecurityIncident)
            .unwrap();

        let binding = adapter.get_binding(WelfareSectorId::Food).unwrap();
        assert!(matches!(
            binding.status,
            BindingStatus::SuspendedByRoot { .. }
        ));

        // Cannot issue while suspended
        assert!(!adapter.is_dao_authorized(&dao_id, WelfareSectorId::Food));

        // Reinstate
        adapter.reinstate_dao(root, dao_id).unwrap();
        assert!(adapter.is_dao_authorized(&dao_id, WelfareSectorId::Food));
    }

    #[test]
    fn test_issue_welfare_name() {
        let root = make_root_authority();
        let mut adapter = WelfareIssuerAdapter::new(root);
        adapter.set_current_block(1000);

        let dao_id = make_dao_id(1);
        adapter
            .submit_claim(dao_id, WelfareSectorId::Food, [0u8; 32])
            .unwrap();
        adapter
            .ratify_claim(root, dao_id, WelfareSectorId::Food, None)
            .unwrap();

        // Issue a name (no verifier registered, so permissive mode)
        let result = adapter.issue_welfare_name(
            dao_id,
            "farm".to_string(),
            [2u8; 32],
            1, // L1
            ApprovalProof::GovernanceVote {
                proposal_id: [0u8; 32],
                vote_concluded_at: 999,
                votes_for: 100,
                votes_against: 10,
                merkle_proof: vec![],
            },
            Some("agriculture".to_string()),
        );

        assert!(result.is_ok());
        let issuance = result.unwrap();
        assert_eq!(issuance.metadata.sector, WelfareSectorId::Food);
        assert_eq!(issuance.metadata.issuing_dao, dao_id);
        assert_eq!(issuance.metadata.category, Some("agriculture".to_string()));

        // Check names_issued incremented
        let binding = adapter.get_binding(WelfareSectorId::Food).unwrap();
        assert_eq!(binding.names_issued, 1);
    }

    #[test]
    fn test_verification_level_enforcement() {
        let root = make_root_authority();
        let mut adapter = WelfareIssuerAdapter::new(root);

        let dao_id = make_dao_id(1);
        adapter
            .submit_claim(dao_id, WelfareSectorId::Healthcare, [0u8; 32])
            .unwrap();

        // Ratify with default policy (Healthcare requires L2)
        adapter
            .ratify_claim(root, dao_id, WelfareSectorId::Healthcare, None)
            .unwrap();

        // Try to issue with L1 (should fail - Healthcare floor is L2)
        let result = adapter.issue_welfare_name(
            dao_id,
            "clinic".to_string(),
            [2u8; 32],
            1, // L1 - below Healthcare floor of L2
            ApprovalProof::GovernanceVote {
                proposal_id: [0u8; 32],
                vote_concluded_at: 999,
                votes_for: 100,
                votes_against: 10,
                merkle_proof: vec![],
            },
            None,
        );

        assert!(matches!(
            result,
            Err(WelfareIssuerError::InsufficientVerification { .. })
        ));

        // Issue with L2 (should succeed)
        let result = adapter.issue_welfare_name(
            dao_id,
            "clinic".to_string(),
            [2u8; 32],
            2, // L2
            ApprovalProof::GovernanceVote {
                proposal_id: [0u8; 32],
                vote_concluded_at: 999,
                votes_for: 100,
                votes_against: 10,
                merkle_proof: vec![],
            },
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_label_validation() {
        let root = make_root_authority();
        let mut adapter = WelfareIssuerAdapter::new(root);

        let dao_id = make_dao_id(1);
        adapter
            .submit_claim(dao_id, WelfareSectorId::Food, [0u8; 32])
            .unwrap();
        adapter
            .ratify_claim(root, dao_id, WelfareSectorId::Food, None)
            .unwrap();

        // Empty label
        let result = adapter.issue_welfare_name(
            dao_id,
            "".to_string(),
            [2u8; 32],
            1,
            ApprovalProof::GovernanceVote {
                proposal_id: [0u8; 32],
                vote_concluded_at: 999,
                votes_for: 100,
                votes_against: 10,
                merkle_proof: vec![],
            },
            None,
        );
        assert!(matches!(
            result,
            Err(WelfareIssuerError::InvalidLabel { .. })
        ));

        // Label starting with hyphen
        let result = adapter.issue_welfare_name(
            dao_id,
            "-farm".to_string(),
            [2u8; 32],
            1,
            ApprovalProof::GovernanceVote {
                proposal_id: [0u8; 32],
                vote_concluded_at: 999,
                votes_for: 100,
                votes_against: 10,
                merkle_proof: vec![],
            },
            None,
        );
        assert!(matches!(
            result,
            Err(WelfareIssuerError::InvalidLabel { .. })
        ));
    }
}
