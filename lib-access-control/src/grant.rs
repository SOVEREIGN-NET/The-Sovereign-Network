//! Scoped grants — time-bounded, domain-scoped elevation (#2935 Phase 3).
//!
//! Replaces ad-hoc `Role::System` god-mode and overuse of Council for ops.
//! Issuance is council-only at the API layer; this module is pure evaluation.

use crate::types::{AccessDomain, AccessOperation, Did};
use serde::{Deserialize, Serialize};

/// A council-issued (or future-governance-issued) scoped grant held by a principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedGrant {
    /// Stable grant id (hex or uuid string).
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
    /// When true, grant is single-use and already spent.
    pub consumed: bool,
    /// Optional max successful uses. `None` = unlimited until expiry/consume.
    pub max_uses: Option<u32>,
    /// Successful use count.
    pub uses: u32,
}

impl ScopedGrant {
    /// Create a multi-use grant without expiry.
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
            max_uses: None,
            uses: 0,
        }
    }

    pub fn with_expiry(mut self, expires_at_unix: u64) -> Self {
        self.expires_at_unix = Some(expires_at_unix);
        self
    }

    pub fn with_max_uses(mut self, max_uses: u32) -> Self {
        self.max_uses = Some(max_uses);
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
        if let Some(max) = self.max_uses {
            if self.uses >= max {
                return false;
            }
        }
        true
    }

    /// Whether this grant covers the requested domain/op pair.
    pub fn covers(&self, domain: AccessDomain, op: AccessOperation) -> bool {
        self.domains.contains(&domain) && self.operations.contains(&op)
    }

    /// Record a successful use. Marks `consumed` when max_uses is 1 or exhausted.
    pub fn record_use(&mut self) {
        self.uses = self.uses.saturating_add(1);
        if let Some(max) = self.max_uses {
            if self.uses >= max {
                self.consumed = true;
            }
        }
    }
}

/// Evaluate whether any active grant on the list covers the access.
pub fn grants_allow(
    grants: &[ScopedGrant],
    grantee_did: &str,
    domain: AccessDomain,
    op: AccessOperation,
    now_unix: u64,
) -> bool {
    grants.iter().any(|g| {
        g.grantee_did == grantee_did
            && g.is_active(now_unix)
            && g.covers(domain, op)
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
    fn single_use_grant_consumes() {
        let mut g = ScopedGrant::new(
            "g1",
            "did:zhtp:alice",
            "did:zhtp:council",
            vec![NodeGraph],
            vec![Traverse],
        )
        .with_max_uses(1);
        assert!(g.is_active(1));
        g.record_use();
        assert!(g.consumed);
        assert!(!g.is_active(2));
    }
}
