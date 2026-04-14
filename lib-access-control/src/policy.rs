//! Relationship-aware access policy engine.
//!
//! Evaluates access decisions per (principal, subject relation, domain, operation).
//! The default for any unmatched combination is DENY.

use crate::decision::{AccessDecision, ReasonCode};
use crate::principal::SecurityPrincipal;
use crate::types::{AccessDomain, AccessOperation, Capability, Role, SubjectRelation};

/// Centralized policy engine.
///
/// This struct is stateless; all policy logic lives in `check_access`.
/// In future phases it may load dynamic rules from on-chain governance.
#[derive(Debug, Clone, Default)]
pub struct AccessPolicy;

impl AccessPolicy {
    /// Evaluate whether `principal` may perform `operation` on `domain`
    /// with respect to a subject identity having `relation` to the principal.
    pub fn check_access(
        &self,
        principal: &SecurityPrincipal,
        relation: SubjectRelation,
        domain: AccessDomain,
        op: AccessOperation,
    ) -> AccessDecision {
        use AccessDecision::{Allow, Deny};
        use AccessDomain::*;
        use AccessOperation::*;
        use ReasonCode::*;
        use Role::*;
        use SubjectRelation::*;

        // System bypass — internal maintenance only.
        if principal.role == System {
            return Allow(AllowSystemProcess);
        }

        // ── Citizen ─────────────────────────────────────────────────────
        if principal.role == Citizen {
            return match (relation, domain, op) {
                // Self: full access except private ZK witness material.
                (Self_, ZkProofPrivate, _) => Deny(DenyPrivateZk),
                (Self_, _, _) => Allow(AllowSelfFullAccess),

                // Same DAO: limited cooperation scope.
                (SameDao, CoreIdentity, _) => Allow(AllowGovernanceRead),
                (SameDao, Governance, Read | Resolve) => Allow(AllowGovernanceRead),
                (SameDao, ServiceEndpoints, Resolve) => Allow(AllowPublicCoreIdentity),
                (SameDao, _, _) => Deny(DenyCrossIdentitySensitive),

                // Delegate: governed by explicit capability.
                (Delegate, _, _) => {
                    if capability_allows(principal, domain, op) {
                        Allow(AllowDelegatedCapability)
                    } else {
                        Deny(DenyMissingCapability)
                    }
                }

                // External / Public to Citizen: minimal exposure.
                (_, CoreIdentity, Resolve | Read) => Allow(AllowPublicCoreIdentity),
                (_, ServiceEndpoints, Resolve) => Allow(AllowPublicCoreIdentity),
                (_, _, Traverse | Enumerate | Subscribe) => Deny(DenyGraphTraversal),
                (_, _, _) => Deny(DenyCrossIdentitySensitive),
            };
        }

        // ── Council ──────────────────────────────────────────────────────
        if principal.role == Council {
            return match (relation, domain, op) {
                // Self: full except private data refs.
                (Self_, PrivateDataRef, _) => Deny(DenyCrossIdentitySensitive),
                (Self_, _, _) => Allow(AllowSelfFullAccess),

                // Investigation scope: can read governance and filtered graphs.
                (_, Governance, Read | Resolve | Traverse) => {
                    if principal.has_capability(&Capability::Investigate) {
                        Allow(AllowCouncilInvestigation)
                    } else if principal.has_capability(&Capability::VoteGovernance) {
                        Allow(AllowGovernanceRead)
                    } else {
                        Deny(DenyMissingCapability)
                    }
                }
                (_, CoreIdentity, Read | Resolve) => Allow(AllowPublicCoreIdentity),
                (_, ServiceEndpoints, Resolve) => Allow(AllowPublicCoreIdentity),
                (_, NodeGraph | WalletGraph, Read) => {
                    if principal.has_capability(&Capability::Investigate) {
                        Allow(AllowCouncilInvestigation)
                    } else {
                        Deny(DenyMissingCapability)
                    }
                }
                (_, NodeGraph | WalletGraph, Traverse | Enumerate) => Deny(DenyGraphTraversal),
                (_, ZkProofPrivate | PrivateDataRef, _) => Deny(DenyPrivateZk),
                (_, _, Subscribe) => Deny(DenySubscription),
                (_, _, _) => Deny(DenyInsufficientRole),
            };
        }

        // ── InfraAdmin ───────────────────────────────────────────────────
        if principal.role == InfraAdmin {
            return match (relation, domain, op) {
                // Self: normal full access.
                (Self_, _, _) => Allow(AllowSelfFullAccess),
                // Others: limited to node/system scope.
                (_, CoreIdentity, Read | Resolve) => Allow(AllowNodeTierScope),
                (_, NodeGraph, Read | Resolve | Traverse) => Allow(AllowNodeTierScope),
                (_, ServiceEndpoints, Resolve) => Allow(AllowNodeTierScope),
                (_, Governance, Read | Resolve) => Allow(AllowGovernanceRead),
                (_, _, _) => Deny(DenyInsufficientRole),
            };
        }

        // ── PolicyAdmin ──────────────────────────────────────────────────
        if principal.role == PolicyAdmin {
            return match (relation, domain, op) {
                // Can read governance/policy data only.
                (_, Governance, Read | Resolve) => Allow(AllowGovernanceRead),
                (_, CoreIdentity, Read | Resolve) => Allow(AllowPublicCoreIdentity),
                (_, _, _) => Deny(DenyInsufficientRole),
            };
        }

        // ── Emergency ────────────────────────────────────────────────────
        if principal.role == Emergency {
            return match (relation, domain, op) {
                // Must hold the emergency capability.
                _ if !principal.has_capability(&Capability::EmergencyOverride) => {
                    Deny(DenyNotEmergency)
                }
                // Break-glass: all access permitted, but reason code is explicit.
                (_, _, _) => Allow(AllowEmergencyOverride),
            };
        }

        // ── Device ───────────────────────────────────────────────────────
        if principal.role == Device {
            return match (relation, domain, op) {
                // Owner identity: scoped access for reward and node ops.
                (Owner, CoreIdentity, _) => Allow(AllowDeviceOwnerScope),
                (Owner, WalletGraph, Read | Resolve) => Allow(AllowDeviceOwnerScope),
                (Owner, NodeGraph, Read | Resolve | Traverse) => Allow(AllowDeviceOwnerScope),
                (Owner, ServiceEndpoints, Resolve) => Allow(AllowDeviceOwnerScope),
                (Owner, _, _) => Deny(DenyInsufficientRole),

                // Others: bare minimum.
                (_, CoreIdentity, Resolve | Read) => Allow(AllowPublicCoreIdentity),
                (_, _, _) => Deny(DenyInsufficientRole),
            };
        }

        // ── Node ─────────────────────────────────────────────────────────
        if principal.role == Node {
            return match (relation, domain, op) {
                // Self: node managing its own identity record.
                (Self_, _, _) => Allow(AllowSelfFullAccess),
                // Mesh-level access depends on node type capabilities.
                (_, CoreIdentity, Resolve | Read) => {
                    if node_may_read_core_identity(&principal.node_type) {
                        Allow(AllowNodeTierScope)
                    } else {
                        Deny(DenyNodeTierRestriction)
                    }
                }
                (_, ServiceEndpoints, Resolve) => {
                    if node_may_resolve_endpoints(&principal.node_type) {
                        Allow(AllowNodeTierScope)
                    } else {
                        Deny(DenyNodeTierRestriction)
                    }
                }
                (_, NodeGraph, Read | Resolve | Traverse) => {
                    if node_may_traverse_graph(&principal.node_type) {
                        Allow(AllowNodeTierScope)
                    } else {
                        Deny(DenyGraphTraversal)
                    }
                }
                (_, _, Traverse | Enumerate | Subscribe) => Deny(DenyGraphTraversal),
                (_, _, _) => Deny(DenyInsufficientRole),
            };
        }

        // ── Public / Unauthenticated ─────────────────────────────────────
        if principal.role == Role::Public {
            return match (domain, op) {
                (CoreIdentity, Resolve | Read) => Allow(AllowPublicCoreIdentity),
                (ServiceEndpoints, Resolve) => Allow(AllowPublicCoreIdentity),
                (_, Traverse | Enumerate | Subscribe) => Deny(DenyGraphTraversal),
                (_, _) => Deny(DenyInsufficientRole),
            };
        }

        // Default deny — anything not explicitly matched above.
        Deny(DenyDefault)
    }
}

// ── Helper functions ───────────────────────────────────────────────────────

fn capability_allows(
    principal: &SecurityPrincipal,
    domain: AccessDomain,
    op: AccessOperation,
) -> bool {
    use AccessDomain::*;
    use AccessOperation::*;
    use Capability::*;

    principal.capabilities.iter().any(|cap| match (cap, domain, op) {
        (ReadIdentity, CoreIdentity, Read | Resolve) => true,
        (ReadIdentity, ServiceEndpoints, Resolve) => true,
        (ReadBalance, WalletGraph, Read | Resolve) => true,
        (VoteGovernance, Governance, Read | Resolve) => true,
        (Web4Deploy, ServiceEndpoints, _) => true,
        (ServiceAccess, ServiceEndpoints, Resolve) => true,
        (Investigate, NodeGraph | WalletGraph | Governance, Read | Resolve) => true,
        (EmergencyOverride, _, _) => true,
        _ => false,
    })
}

fn node_may_read_core_identity(node_type: &lib_types::NodeType) -> bool {
    use lib_types::NodeType;
    matches!(node_type, NodeType::FullNode | NodeType::Validator)
}

fn node_may_resolve_endpoints(node_type: &lib_types::NodeType) -> bool {
    use lib_types::NodeType;
    matches!(node_type, NodeType::FullNode | NodeType::Validator | NodeType::EdgeNode)
}

fn node_may_traverse_graph(node_type: &lib_types::NodeType) -> bool {
    use lib_types::NodeType;
    matches!(node_type, NodeType::FullNode | NodeType::Validator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessDomain::*, AccessOperation::*, Role::*, SubjectRelation::*};
    use lib_types::NodeType;

    fn principal(role: Role) -> SecurityPrincipal {
        SecurityPrincipal::new("did:zhtp:test", role, NodeType::FullNode)
    }

    #[test]
    fn citizen_self_gets_full_access_except_private_zk() {
        let p = principal(Role::Citizen);
        let policy = AccessPolicy;

        assert!(policy
            .check_access(&p, SubjectRelation::Self_, CoreIdentity, Read)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::Self_, WalletGraph, Read)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::Self_, Governance, Read)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::Self_, ZkProofMeta, Read)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::Self_, ZkProofPrivate, Read)
            .is_denied());
    }

    #[test]
    fn citizen_external_gets_minimal_access() {
        let p = principal(Role::Citizen);
        let policy = AccessPolicy;

        assert!(policy
            .check_access(&p, SubjectRelation::External, CoreIdentity, Read)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::External, WalletGraph, Read)
            .is_denied());
        assert!(policy
            .check_access(&p, SubjectRelation::External, WalletGraph, Traverse)
            .is_denied());
    }

    #[test]
    fn council_investigation_requires_capability() {
        let p = principal(Role::Council);
        let policy = AccessPolicy;

        // Without Investigate capability: denied.
        assert!(policy
            .check_access(&p, SubjectRelation::External, Governance, Read)
            .is_denied());

        // With Investigate capability: allowed.
        let p = principal(Role::Council).with_capability(Capability::Investigate);
        assert!(policy
            .check_access(&p, SubjectRelation::External, Governance, Read)
            .is_allowed());
    }

    #[test]
    fn public_only_gets_core_identity() {
        let p = SecurityPrincipal::public();
        let policy = AccessPolicy;

        assert!(policy
            .check_access(&p, SubjectRelation::Public, CoreIdentity, Resolve)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::Public, WalletGraph, Read)
            .is_denied());
        assert!(policy
            .check_access(&p, SubjectRelation::Public, Governance, Read)
            .is_denied());
    }

    #[test]
    fn admin_roles_are_not_god_mode() {
        let infra = principal(Role::InfraAdmin);
        let policy = AccessPolicy;

        // InfraAdmin can read node graph but not private ZK of others.
        assert!(policy
            .check_access(&infra, SubjectRelation::External, NodeGraph, Traverse)
            .is_allowed());
        assert!(policy
            .check_access(&infra, SubjectRelation::External, ZkProofPrivate, Read)
            .is_denied());

        let policy_admin = principal(Role::PolicyAdmin);
        assert!(policy
            .check_access(&policy_admin, SubjectRelation::External, Governance, Read)
            .is_allowed());
        assert!(policy
            .check_access(&policy_admin, SubjectRelation::External, WalletGraph, Read)
            .is_denied());
    }

    #[test]
    fn emergency_requires_capability() {
        let p = principal(Role::Emergency);
        let policy = AccessPolicy;

        // Without EmergencyOverride capability: denied.
        assert!(policy
            .check_access(&p, SubjectRelation::External, ZkProofPrivate, Read)
            .is_denied());

        let p = principal(Role::Emergency).with_capability(Capability::EmergencyOverride);
        assert!(policy
            .check_access(&p, SubjectRelation::External, ZkProofPrivate, Read)
            .is_allowed());
    }

    #[test]
    fn device_owner_scope_is_limited() {
        let p = principal(Role::Device);
        let policy = AccessPolicy;

        assert!(policy
            .check_access(&p, SubjectRelation::Owner, CoreIdentity, Read)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::Owner, WalletGraph, Read)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::Owner, Governance, Read)
            .is_denied());
        assert!(policy
            .check_access(&p, SubjectRelation::External, CoreIdentity, Read)
            .is_allowed());
        assert!(policy
            .check_access(&p, SubjectRelation::External, WalletGraph, Read)
            .is_denied());
    }

    #[test]
    fn node_role_respects_node_type() {
        let validator = SecurityPrincipal::new("did:zhtp:node", Role::Node, NodeType::Validator);
        let relay = SecurityPrincipal::new("did:zhtp:node", Role::Node, NodeType::Relay);
        let policy = AccessPolicy;

        assert!(policy
            .check_access(&validator, SubjectRelation::External, NodeGraph, Traverse)
            .is_allowed());
        assert!(policy
            .check_access(&relay, SubjectRelation::External, NodeGraph, Traverse)
            .is_denied());
    }

    #[test]
    fn system_role_bypasses_all() {
        let p = SecurityPrincipal::system();
        let policy = AccessPolicy;

        assert!(policy
            .check_access(&p, External, ZkProofPrivate, Read)
            .is_allowed());
    }
}
