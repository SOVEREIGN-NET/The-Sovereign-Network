//! Scoped grants — time-bounded, domain-scoped elevation (#2935 Phase 3).
//!
//! Replaces ad-hoc `Role::System` god-mode and overuse of Council for ops.
//! Issuance is council-only at the API layer; this module is pure evaluation.
//!
//! # What is enforceable without a grant store
//!
//! Grants are attached to a per-request `SecurityPrincipal` and are **not**
//! mutated across requests. Evaluation therefore only enforces:
//! - domain / operation coverage
//! - absolute time expiry (`expires_at_unix`)
//! - sticky revoke (`consumed` already true when loaded)
//!
//! **Use limits (`max_uses`) are intentionally absent.** A counter on a
//! throwaway principal cannot enforce "use once" across requests. When a
//! server-side grant store exists (keyed by grant id, atomically decremented
//! on successful use), reintroduce use limits there — not on this type.
//!
//! # Hot-path bound
//!
//! `MAX_GRANTS_PER_PRINCIPAL` caps grants attached to a principal so
//! `grants_allow` stays O(1)-bounded on the authz path. Future council
//! issuance must refuse to exceed this.

use crate::types::{AccessDomain, AccessOperation, Did};
use serde::{Deserialize, Serialize};

/// Upper bound on grants attached to a single principal (authz hot path).
/// Council-only issuance APIs must reject or truncate beyond this.
pub const MAX_GRANTS_PER_PRINCIPAL: usize = 32;

/// A council-issued (or future-governance-issued) scoped grant held by a principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedGrant {
    /// Stable grant id (hex or uuid string). Used as key when a store lands.
    pub id: String,
    /// DID that may exercise this grant.
    pub grantee_did: Did,
    /// Issuer DID (typically a council member).
    pub issuer_did: Did,
    /// Domains covered by this grant.
    pub domains: Vec<AccessDomain>,
    /// Operations covered by this grant.
    pub operations: Vec<AccessOperation>,
    /// Optional absolute expiry (unix seconds). `None` = no time expiry.
    pub expires_at_unix: Option<u64>,
    /// Sticky revoke flag. Meaningful when set by a persistent store (or
    /// issuer) **before** the grant is loaded onto a principal. Setting it
    /// on an in-memory principal alone does not survive the next request.
    pub consumed: bool,
}

impl ScopedGrant {
    /// Create a multi-use (until expiry / revoke) grant without time expiry.
    pub fn new(
        id: impl Into<String>,
        grantee_did: impl Into<Did>,
        issuer_did: impl Into<Did>,
        domains: Vec<AccessDomain>,
        operations: Vec<AccessOperation>,
    ) -> Self {
        Self {
            id: id.into(),
            grantee_did: grantee_did.into(),
            issuer_did: issuer_did.into(),
            domains,
            operations,
            expires_at_unix: None,
            consumed: false,
        }
    }

    pub fn with_expiry(mut self, expires_at_unix: u64) -> Self {
        self.expires_at_unix = Some(expires_at_unix);
        self
    }

    /// Mark revoked (for store-backed loads or issuer revoke paths).
    pub fn mark_consumed(mut self) -> Self {
        self.consumed = true;
        self
    }

    /// Whether the grant is currently usable at `now_unix`.
    pub fn is_active(&self, now_unix: u64) -> bool {
        if self.consumed {
            return false;
        }
        if let Some(exp) = self.expires_at_unix {
            if now_unix > exp {
                return false;
            }
        }
        true
    }

    /// Whether this grant covers the requested domain/op pair.
    pub fn covers(&self, domain: AccessDomain, op: AccessOperation) -> bool {
        self.domains.contains(&domain) && self.operations.contains(&op)
    }
}

/// Evaluate whether any active grant on the list covers the access.
///
/// Callers should pass at most [`MAX_GRANTS_PER_PRINCIPAL`] grants
/// (`SecurityPrincipal::with_grants` truncates).
pub fn grants_allow(
    grants: &[ScopedGrant],
    grantee_did: &str,
    domain: AccessDomain,
    op: AccessOperation,
    now_unix: u64,
) -> bool {
    grants.iter().any(|g| {
        g.grantee_did == grantee_did && g.is_active(now_unix) && g.covers(domain, op)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use AccessDomain::*;
    use AccessOperation::*;

    #[test]
    fn active_grant_covers_wallet_read() {
        let g = ScopedGrant::new(
            "g1",
            "did:zhtp:alice",
            "did:zhtp:council",
            vec![WalletGraph],
            vec![Read, Enumerate],
        );
        assert!(g.is_active(1_000));
        assert!(g.covers(WalletGraph, Read));
        assert!(!g.covers(Governance, Read));
        assert!(grants_allow(
            &[g],
            "did:zhtp:alice",
            WalletGraph,
            Read,
            1_000
        ));
    }

    #[test]
    fn expired_grant_denied() {
        let g = ScopedGrant::new(
            "g1",
            "did:zhtp:alice",
            "did:zhtp:council",
            vec![WalletGraph],
            vec![Read],
        )
        .with_expiry(100);
        assert!(!g.is_active(101));
        assert!(!grants_allow(&[g], "did:zhtp:alice", WalletGraph, Read, 101));
    }

    #[test]
    fn consumed_grant_denied_when_loaded_revoked() {
        // `consumed` only works as a sticky flag set *before* attach (store).
        let g = ScopedGrant::new(
            "g1",
            "did:zhtp:alice",
            "did:zhtp:council",
            vec![NodeGraph],
            vec![Traverse],
        )
        .mark_consumed();
        assert!(!g.is_active(1));
        assert!(!grants_allow(&[g], "did:zhtp:alice", NodeGraph, Traverse, 1));
    }

    #[test]
    fn max_grants_per_principal_is_bounded() {
        assert!(MAX_GRANTS_PER_PRINCIPAL > 0);
        assert!(MAX_GRANTS_PER_PRINCIPAL <= 128);
    }
}
