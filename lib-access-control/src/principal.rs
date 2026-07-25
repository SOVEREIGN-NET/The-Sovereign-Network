//! Security principal — the "who" in every access control decision.

use crate::grant::ScopedGrant;
use crate::types::{AccessDomain, AccessOperation, Capability, Did, Role};
use lib_types::NodeType;
use serde::{Deserialize, Serialize};

/// The caller context against which all access policies are evaluated.
///
/// Every read operation in the system must be performed on behalf of a
/// `SecurityPrincipal`. There are no anonymous internal calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPrincipal {
    /// DID of the principal. For the `System` role this is a well-known
    /// system DID (e.g. `did:zhtp:system`).
    pub did: Did,
    /// Primary role of the principal.
    pub role: Role,
    /// Node type when the principal represents a network node.
    pub node_type: NodeType,
    /// Delegated or attested capabilities.
    pub capabilities: Vec<Capability>,
    /// Active scoped grants (Phase 3). Evaluated early as elevation over role deny.
    #[serde(default)]
    pub grants: Vec<ScopedGrant>,
}

impl SecurityPrincipal {
    /// Create a new principal.
    pub fn new(did: impl Into<Did>, role: Role, node_type: NodeType) -> Self {
        Self {
            did: did.into(),
            role,
            node_type,
            capabilities: Vec::new(),
            grants: Vec::new(),
        }
    }

    /// Add a capability.
    pub fn with_capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Add multiple capabilities.
    pub fn with_capabilities(mut self, caps: Vec<Capability>) -> Self {
        self.capabilities.extend(caps);
        self
    }

    /// Attach scoped grants (truncated to [`crate::grant::MAX_GRANTS_PER_PRINCIPAL`]).
    ///
    /// Prefer [`Self::with_authenticated_grants`] on production paths after
    /// [`crate::grant_auth::verify_grant_proof`]. This method remains for tests
    /// and trusted server-side attach of already-verified grants.
    pub fn with_grants(mut self, mut grants: Vec<ScopedGrant>) -> Self {
        if grants.len() > crate::grant::MAX_GRANTS_PER_PRINCIPAL {
            grants.truncate(crate::grant::MAX_GRANTS_PER_PRINCIPAL);
        }
        self.grants = grants;
        self
    }

    /// Attach grants derived from dual-auth-verified [`crate::grant_auth::GrantRecord`]s.
    ///
    /// Caller must have run `verify_grant_proof` for each record. Only Active
    /// exercisable records are attached.
    pub fn with_authenticated_grants(
        self,
        records: &[crate::grant_auth::GrantRecord],
        now_unix: u64,
    ) -> Self {
        let grants: Vec<ScopedGrant> = records
            .iter()
            .filter(|r| r.is_exercisable(now_unix) && r.grantee_did == self.did)
            .map(|r| r.to_scoped_grant())
            .collect();
        self.with_grants(grants)
    }

    /// Check if the principal possesses a specific capability.
    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Whether an active grant covers domain/op at `now_unix`.
    pub fn grant_allows(&self, domain: AccessDomain, op: AccessOperation, now_unix: u64) -> bool {
        crate::grant::grants_allow(&self.grants, &self.did, domain, op, now_unix)
    }

    /// Convenience constructor for an unauthenticated public principal.
    pub fn public() -> Self {
        Self::new("did:zhtp:public", Role::Public, NodeType::Relay)
    }

    /// Convenience constructor for a system process principal.
    ///
    /// Phase 3: `Role::System` is **not** god-mode. Prefer ScopedGrant for
    /// privileged maintenance paths.
    pub fn system() -> Self {
        Self::new("did:zhtp:system", Role::System, NodeType::FullNode)
    }
}
