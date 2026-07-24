//! CI policy matrix: Role × SubjectRelation × AccessDomain × AccessOperation.
//!
//! Snapshot expectations so policy changes are intentional (#2935 Phase 2).
//! Default DENY for unmatched combinations is covered by the matrix rows that
//! assert denial.

#![cfg(test)]

use crate::policy::AccessPolicy;
use crate::principal::SecurityPrincipal;
use crate::types::{
    AccessDomain, AccessOperation, Capability, Role, SubjectRelation,
};
use lib_types::NodeType;

fn p(role: Role) -> SecurityPrincipal {
    SecurityPrincipal::new("did:zhtp:matrix", role, NodeType::FullNode)
}

fn allow(
    policy: &AccessPolicy,
    role: Role,
    rel: SubjectRelation,
    domain: AccessDomain,
    op: AccessOperation,
) {
    assert!(
        policy.check_access(&p(role), rel, domain, op).is_allowed(),
        "expected Allow for {:?} {:?} {:?} {:?}",
        role,
        rel,
        domain,
        op
    );
}

fn deny(
    policy: &AccessPolicy,
    role: Role,
    rel: SubjectRelation,
    domain: AccessDomain,
    op: AccessOperation,
) {
    assert!(
        policy.check_access(&p(role), rel, domain, op).is_denied(),
        "expected Deny for {:?} {:?} {:?} {:?}",
        role,
        rel,
        domain,
        op
    );
}

#[test]
fn matrix_citizen_self_wallet_and_core() {
    let policy = AccessPolicy;
    allow(
        &policy,
        Role::Citizen,
        SubjectRelation::Self_,
        AccessDomain::WalletGraph,
        AccessOperation::Read,
    );
    allow(
        &policy,
        Role::Citizen,
        SubjectRelation::Self_,
        AccessDomain::WalletGraph,
        AccessOperation::Enumerate,
    );
    allow(
        &policy,
        Role::Citizen,
        SubjectRelation::Self_,
        AccessDomain::CoreIdentity,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::Citizen,
        SubjectRelation::Self_,
        AccessDomain::ZkProofPrivate,
        AccessOperation::Read,
    );
}

#[test]
fn matrix_citizen_external_no_wallet() {
    let policy = AccessPolicy;
    allow(
        &policy,
        Role::Citizen,
        SubjectRelation::External,
        AccessDomain::CoreIdentity,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::Citizen,
        SubjectRelation::External,
        AccessDomain::WalletGraph,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::Citizen,
        SubjectRelation::External,
        AccessDomain::WalletGraph,
        AccessOperation::Enumerate,
    );
    deny(
        &policy,
        Role::Citizen,
        SubjectRelation::External,
        AccessDomain::WalletGraph,
        AccessOperation::Traverse,
    );
    deny(
        &policy,
        Role::Citizen,
        SubjectRelation::External,
        AccessDomain::UbiData,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::Citizen,
        SubjectRelation::External,
        AccessDomain::Governance,
        AccessOperation::Read,
    );
}

#[test]
fn matrix_public_minimal() {
    let policy = AccessPolicy;
    allow(
        &policy,
        Role::Public,
        SubjectRelation::Public,
        AccessDomain::CoreIdentity,
        AccessOperation::Resolve,
    );
    deny(
        &policy,
        Role::Public,
        SubjectRelation::Public,
        AccessDomain::WalletGraph,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::Public,
        SubjectRelation::Public,
        AccessDomain::Governance,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::Public,
        SubjectRelation::Public,
        AccessDomain::NodeGraph,
        AccessOperation::Traverse,
    );
}

#[test]
fn matrix_council_bootstrap_audit() {
    let policy = AccessPolicy;
    allow(
        &policy,
        Role::Council,
        SubjectRelation::External,
        AccessDomain::WalletGraph,
        AccessOperation::Read,
    );
    allow(
        &policy,
        Role::Council,
        SubjectRelation::External,
        AccessDomain::Governance,
        AccessOperation::Read,
    );
    allow(
        &policy,
        Role::Council,
        SubjectRelation::External,
        AccessDomain::NodeGraph,
        AccessOperation::Traverse,
    );
    deny(
        &policy,
        Role::Council,
        SubjectRelation::External,
        AccessDomain::ZkProofPrivate,
        AccessOperation::Read,
    );
}

#[test]
fn matrix_infra_admin_not_god_mode() {
    let policy = AccessPolicy;
    allow(
        &policy,
        Role::InfraAdmin,
        SubjectRelation::Self_,
        AccessDomain::WalletGraph,
        AccessOperation::Read,
    );
    allow(
        &policy,
        Role::InfraAdmin,
        SubjectRelation::External,
        AccessDomain::NodeGraph,
        AccessOperation::Traverse,
    );
    allow(
        &policy,
        Role::InfraAdmin,
        SubjectRelation::External,
        AccessDomain::CoreIdentity,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::InfraAdmin,
        SubjectRelation::External,
        AccessDomain::WalletGraph,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::InfraAdmin,
        SubjectRelation::External,
        AccessDomain::ZkProofPrivate,
        AccessOperation::Read,
    );
}

#[test]
fn matrix_policy_admin_governance_only() {
    let policy = AccessPolicy;
    allow(
        &policy,
        Role::PolicyAdmin,
        SubjectRelation::External,
        AccessDomain::Governance,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::PolicyAdmin,
        SubjectRelation::External,
        AccessDomain::WalletGraph,
        AccessOperation::Read,
    );
    deny(
        &policy,
        Role::PolicyAdmin,
        SubjectRelation::External,
        AccessDomain::NodeGraph,
        AccessOperation::Traverse,
    );
}

#[test]
fn matrix_delegate_requires_capability() {
    let policy = AccessPolicy;
    deny(
        &policy,
        Role::Citizen,
        SubjectRelation::Delegate,
        AccessDomain::WalletGraph,
        AccessOperation::Read,
    );
    let with_cap = p(Role::Citizen).with_capability(Capability::ReadBalance);
    assert!(policy
        .check_access(
            &with_cap,
            SubjectRelation::Delegate,
            AccessDomain::WalletGraph,
            AccessOperation::Read,
        )
        .is_allowed());
}

#[test]
fn matrix_default_deny_unknown_role_path() {
    // System is the only god-mode path today; Public without matching domain is deny.
    let policy = AccessPolicy;
    deny(
        &policy,
        Role::Public,
        SubjectRelation::Public,
        AccessDomain::PrivateDataRef,
        AccessOperation::Read,
    );
}

/// Perf budget: single check_access should be well under 1ms (#328 / #2935 Phase 2).
#[test]
fn check_access_perf_budget_under_1ms_average() {
    let policy = AccessPolicy;
    let principal = p(Role::Citizen);
    let iters = 50_000u32;
    let start = std::time::Instant::now();
    for _ in 0..iters {
        let _ = policy.check_access(
            &principal,
            SubjectRelation::External,
            AccessDomain::WalletGraph,
            AccessOperation::Read,
        );
        let _ = policy.check_access(
            &principal,
            SubjectRelation::Self_,
            AccessDomain::CoreIdentity,
            AccessOperation::Read,
        );
        let _ = policy.check_access(
            &SecurityPrincipal::public(),
            SubjectRelation::Public,
            AccessDomain::CoreIdentity,
            AccessOperation::Resolve,
        );
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / (iters as u128 * 3);
    // 1ms = 1_000_000 ns. Allow headroom on slow CI; still fail if pathological.
    assert!(
        avg_ns < 1_000_000,
        "avg check_access {avg_ns}ns exceeds 1ms budget (total {:?})",
        elapsed
    );
}
