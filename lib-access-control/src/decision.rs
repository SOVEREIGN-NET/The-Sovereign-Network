//! Access decision and reason codes.
//!
//! Every policy evaluation must produce a machine-readable `ReasonCode`.
//! These codes are logged, tested, and observable — never shown to callers
//! in a way that leaks enumeration surface.

use serde::{Deserialize, Serialize};

/// Result of an access control evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessDecision {
    Allow(ReasonCode),
    Deny(ReasonCode),
}

impl AccessDecision {
    /// Returns `true` if this decision is `Allow`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, AccessDecision::Allow(_))
    }

    /// Returns `true` if this decision is `Deny`.
    pub fn is_denied(&self) -> bool {
        matches!(self, AccessDecision::Deny(_))
    }

    /// Get the reason code regardless of allow/deny.
    pub fn reason(&self) -> ReasonCode {
        match self {
            AccessDecision::Allow(r) | AccessDecision::Deny(r) => *r,
        }
    }
}

/// Machine-readable reason code for every access control decision.
///
/// These codes support audit logging, regression testing, and operational
/// observability without leaking sensitive structure to unauthorized callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReasonCode {
    // ── Allow reasons ────────────────────────────────────────────────
    /// Self access: principal is the subject identity.
    AllowSelfFullAccess,
    /// Public access permitted to core identity fields only.
    AllowPublicCoreIdentity,
    /// Device accessing its owner identity within scoped limits.
    AllowDeviceOwnerScope,
    /// Council member granted investigation-scoped read.
    AllowCouncilInvestigation,
    /// Governance-scoped read permitted.
    AllowGovernanceRead,
    /// Node-type-scoped access for mesh or sync operations.
    AllowNodeTierScope,
    /// Emergency break-glass override granted.
    AllowEmergencyOverride,
    /// Explicit delegated capability granted the access.
    AllowDelegatedCapability,
    /// System process performing internal maintenance.
    AllowSystemProcess,

    // ── Deny reasons ─────────────────────────────────────────────────
    /// Attempt to access sensitive data across identities.
    DenyCrossIdentitySensitive,
    /// Attempt to access private ZK witness material.
    DenyPrivateZk,
    /// Attempt to traverse the identity graph without authorization.
    DenyGraphTraversal,
    /// Role does not meet the minimum required for this domain/operation.
    DenyInsufficientRole,
    /// Node type is restricted from this domain/operation.
    DenyNodeTierRestriction,
    /// Missing required delegated capability.
    DenyMissingCapability,
    /// Enumeration or listing not permitted for this principal.
    DenyEnumeration,
    /// Subscription not permitted for this principal.
    DenySubscription,
    /// Emergency mode not active or principal lacks emergency role.
    DenyNotEmergency,
    /// Catch-all for policy violations not covered above.
    DenyDefault,
}
