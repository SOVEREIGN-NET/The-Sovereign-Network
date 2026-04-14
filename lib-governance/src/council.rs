//! Council action types and validation for governance oversight.
//!
//! Council actions are scoped investigations and interventions that elected
//! council members may propose. Each action carries its own access-control
//! requirements enforced by the policy engine.

use lib_access_control::{AccessDomain, AccessOperation, AccessPolicy, Capability, ReasonCode, SecurityPrincipal, SubjectRelation};
use serde::{Deserialize, Serialize};

/// Scope of a council audit request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditScope {
    /// Audit core identity metadata only.
    CoreIdentity,
    /// Audit wallet ownership and transaction history.
    WalletGraph,
    /// Audit node participation and control graph.
    NodeGraph,
    /// Audit governance voting history.
    Governance,
    /// Full investigation scope (all of the above).
    Full,
}

/// A council action that may be proposed by an elected council member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CouncilAction {
    /// Request a scoped audit of an identity.
    AuditRequest {
        target_did_hash: [u8; 32],
        scope: AuditScope,
        reason: String,
    },
    /// Freeze an identity under investigation.
    FreezeIdentity {
        did_hash: [u8; 32],
        reason: String,
    },
    /// Unfreeze an identity after investigation concludes.
    UnfreezeIdentity {
        did_hash: [u8; 32],
    },
    /// Adjust the UBI distribution rate (parts per million).
    AdjustUbiRate {
        new_rate_ppm: u64,
    },
    /// Emergency break-glass parameter change.
    EmergencyParameterChange {
        parameter: String,
        new_value_hash: [u8; 32],
    },
}

/// Council proposal wrapping an action and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CouncilProposal {
    /// The action being proposed.
    pub action: CouncilAction,
    /// DID of the proposer.
    pub proposer_did: String,
    /// Block height when the proposal was created.
    pub proposed_at: u64,
    /// Required vote threshold (e.g., simple majority = 51, super majority = 67).
    pub required_threshold_percent: u8,
}

/// Validate whether a principal is authorized to propose a council action.
///
/// This is the governance integration point for the access control policy
/// engine. Council members must hold the `Investigate` capability for
/// identity-related actions and `VoteGovernance` for parameter changes.
pub fn validate_council_action(
    principal: &SecurityPrincipal,
    action: &CouncilAction,
) -> Result<(), (ReasonCode, String)> {
    let policy = AccessPolicy::default();

    // All council actions require the Council role as a baseline.
    if principal.role != lib_access_control::Role::Council {
        return Err((
            ReasonCode::DenyInsufficientRole,
            "Council actions require Council role".to_string(),
        ));
    }

    match action {
        CouncilAction::AuditRequest { scope, .. } => {
            // Identity investigation scope requires Investigate capability.
            if !principal.has_capability(&Capability::Investigate) {
                return Err((
                    ReasonCode::DenyMissingCapability,
                    "Identity council actions require Investigate capability".to_string(),
                ));
            }

            // Validate read access for every domain implied by the requested scope.
            let required_domains: &[AccessDomain] = match scope {
                AuditScope::CoreIdentity => &[AccessDomain::CoreIdentity],
                AuditScope::WalletGraph => &[AccessDomain::WalletGraph],
                AuditScope::NodeGraph => &[AccessDomain::NodeGraph],
                AuditScope::Governance => &[AccessDomain::Governance],
                AuditScope::Full => &[
                    AccessDomain::CoreIdentity,
                    AccessDomain::WalletGraph,
                    AccessDomain::NodeGraph,
                    AccessDomain::Governance,
                ],
            };

            for domain in required_domains {
                let decision = policy.check_access(
                    principal,
                    SubjectRelation::External,
                    *domain,
                    AccessOperation::Read,
                );
                if !decision.is_allowed() {
                    return Err((
                        ReasonCode::DenyInsufficientRole,
                        "Council member lacks read access for the requested scope".to_string(),
                    ));
                }
            }
        }
        CouncilAction::FreezeIdentity { .. } | CouncilAction::UnfreezeIdentity { .. } => {
            if !principal.has_capability(&Capability::Investigate) {
                return Err((
                    ReasonCode::DenyMissingCapability,
                    "Identity council actions require Investigate capability".to_string(),
                ));
            }

            let decision = policy.check_access(
                principal,
                SubjectRelation::External,
                AccessDomain::CoreIdentity,
                AccessOperation::Read,
            );
            if !decision.is_allowed() {
                return Err((
                    ReasonCode::DenyInsufficientRole,
                    "Council member lacks read access for identity actions".to_string(),
                ));
            }
        }
        CouncilAction::AdjustUbiRate { .. }
        | CouncilAction::EmergencyParameterChange { .. } => {
            // Parameter changes require VoteGovernance capability.
            if !principal.has_capability(&Capability::VoteGovernance) {
                return Err((
                    ReasonCode::DenyMissingCapability,
                    "Parameter council actions require VoteGovernance capability".to_string(),
                ));
            }

            let decision = policy.check_access(
                principal,
                SubjectRelation::External,
                AccessDomain::Governance,
                AccessOperation::Read,
            );
            if !decision.is_allowed() {
                return Err((
                    ReasonCode::DenyInsufficientRole,
                    "Council member lacks governance read access".to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_types::NodeType;

    fn council(cap: Capability) -> SecurityPrincipal {
        SecurityPrincipal::new("did:zhtp:council", lib_access_control::Role::Council, NodeType::FullNode)
            .with_capability(cap)
    }

    fn citizen() -> SecurityPrincipal {
        SecurityPrincipal::new("did:zhtp:citizen", lib_access_control::Role::Citizen, NodeType::FullNode)
    }

    #[test]
    fn non_council_cannot_propose() {
        let action = CouncilAction::AuditRequest {
            target_did_hash: [0u8; 32],
            scope: AuditScope::CoreIdentity,
            reason: "test".to_string(),
        };
        assert!(validate_council_action(&citizen(), &action).is_err());
    }

    #[test]
    fn council_without_investigate_denied_for_audit() {
        let p = council(Capability::VoteGovernance);
        let action = CouncilAction::AuditRequest {
            target_did_hash: [0u8; 32],
            scope: AuditScope::CoreIdentity,
            reason: "test".to_string(),
        };
        assert!(validate_council_action(&p, &action).is_err());
    }

    #[test]
    fn council_with_investigate_allowed_for_audit() {
        let p = council(Capability::Investigate);
        let action = CouncilAction::AuditRequest {
            target_did_hash: [0u8; 32],
            scope: AuditScope::CoreIdentity,
            reason: "test".to_string(),
        };
        assert!(validate_council_action(&p, &action).is_ok());
    }

    #[test]
    fn council_with_votegovernance_allowed_for_parameter_change() {
        let p = council(Capability::VoteGovernance);
        let action = CouncilAction::AdjustUbiRate { new_rate_ppm: 1000 };
        assert!(validate_council_action(&p, &action).is_ok());
    }

    #[test]
    fn council_without_votegovernance_denied_for_parameter_change() {
        let p = council(Capability::Investigate);
        let action = CouncilAction::AdjustUbiRate { new_rate_ppm: 1000 };
        assert!(validate_council_action(&p, &action).is_err());
    }
}
