//! Core type definitions for access control.

use serde::{Deserialize, Serialize};

/// Decentralized Identifier.
///
/// In the ZHTP system this takes the form `did:zhtp:<64-hex-chars>`.
pub type Did = String;

/// Role of the security principal.
///
/// Roles define broad privilege classes, but the policy engine also considers
/// relationship to the subject, operation type, and domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Infrastructure administrator: nodes, system state, protocol health.
    InfraAdmin,
    /// Policy administrator: access rules, governance parameters.
    PolicyAdmin,
    /// Emergency break-glass role: time-limited, heavily audited.
    Emergency,
    /// Elected council member: governance reads, fraud investigation scope.
    Council,
    /// Verified citizen: full access to own data, limited access to others.
    Citizen,
    /// Autonomous device identity.
    Device,
    /// Network node operating as a principal.
    Node,
    /// Unauthenticated or minimally authenticated public caller.
    Public,
    /// Internal system process.
    System,
}

/// Relationship between the principal and the subject identity.
///
/// This is evaluated at request time based on on-chain or local identity graph
/// state (owner fields, delegation certificates, DAO membership, etc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubjectRelation {
    /// The principal is the subject identity itself.
    Self_,
    /// The principal owns the subject (e.g., a user owns a device identity).
    Owner,
    /// The principal has been explicitly delegated authority by the subject.
    Delegate,
    /// The principal and subject share a DAO membership context.
    SameDao,
    /// The principal has no special relationship to the subject.
    External,
    /// The call is unauthenticated public access.
    Public,
}

/// Domain of data or functionality being accessed.
///
/// Domains are intentionally fine-grained so that least-privilege is possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessDomain {
    /// Minimal identity fields: DID, display name, reputation, identity type.
    CoreIdentity,
    /// DID service endpoints. Visibility varies by endpoint type.
    ServiceEndpoints,
    /// Wallet ownership graph and references.
    WalletGraph,
    /// Node ownership and control graph.
    NodeGraph,
    /// DAO governance participation and voting records.
    Governance,
    /// Universal Basic Income eligibility and distribution data.
    UbiData,
    /// Public ZK verification metadata (proof type, issuer, expiration).
    ZkProofMeta,
    /// Private ZK witness material, secret refs, and raw proof data.
    ZkProofPrivate,
    /// Reference to encrypted private identity data.
    PrivateDataRef,
}

/// Operation being attempted on a domain.
///
/// Graph traversal is a first-class concern: protecting `Traverse` prevents
/// attackers from inferring structure through iterative queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessOperation {
    /// DID resolution — discovering the identity document.
    Resolve,
    /// Direct read of a specific field or record.
    Read,
    /// Expansion across the identity graph (e.g., owner → wallets → nodes).
    Traverse,
    /// Listing collections owned by or related to the subject.
    Enumerate,
    /// Subscribing to change notifications.
    Subscribe,
}

/// Granular capability that may be granted via delegation or attestation.
///
/// This is intentionally simpler than the mobile-delegation `Capability` enum
/// in `lib-identity` to keep the access-control crate dependency-light.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// Read on-chain balance or state.
    ReadBalance,
    /// Submit transactions bounded by a max amount.
    SubmitTx { max_amount_tokens: u64 },
    /// Participate in DAO governance votes.
    VoteGovernance,
    /// Deploy or update Web4 content.
    Web4Deploy,
    /// Read identity metadata.
    ReadIdentity,
    /// Access limited service endpoints.
    ServiceAccess,
    /// Perform fraud investigation (council scope).
    Investigate,
    /// Break-glass emergency override.
    EmergencyOverride,
}
