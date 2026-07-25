//! In-process grant registry (offer / claim / revoke).
//!
//! Phase B2 skeleton: thread-safe memory store. Persistence (sled/chain) can
//! wrap the same API later without changing callers.

use crate::grant_auth::{
    protocol_may_offer, GrantAuthDescriptor, GrantAuthError, GrantClass, GrantRecord, GrantStatus,
    IssuerKind,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Process-local grant registry.
#[derive(Clone, Default)]
pub struct GrantRegistry {
    inner: Arc<Mutex<HashMap<String, GrantRecord>>>,
}

impl GrantRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an Offered grant. Rejects forbidden protocol classes.
    pub fn register_offer(&self, record: GrantRecord) -> Result<(), GrantAuthError> {
        if record.status != GrantStatus::Offered {
            return Err(GrantAuthError::InvalidStatus);
        }
        if record.issuer_kind == IssuerKind::Protocol && !protocol_may_offer(record.class) {
            return Err(GrantAuthError::ProtocolClassForbidden);
        }
        if matches!(
            record.class,
            GrantClass::Ops | GrantClass::AuditRead | GrantClass::VoteGovernance
        ) && record.issuer_kind == IssuerKind::Protocol
        {
            return Err(GrantAuthError::ProtocolClassForbidden);
        }
        let mut map = self.inner.lock().expect("grant registry lock");
        if map.contains_key(&record.id) {
            return Err(GrantAuthError::InvalidStatus);
        }
        map.insert(record.id.clone(), record);
        Ok(())
    }

    pub fn get(&self, grant_id: &str) -> Option<GrantRecord> {
        self.inner
            .lock()
            .expect("grant registry lock")
            .get(grant_id)
            .cloned()
    }

    pub fn list_for_grantee(&self, grantee_did: &str) -> Vec<GrantRecord> {
        self.inner
            .lock()
            .expect("grant registry lock")
            .values()
            .filter(|r| r.grantee_did == grantee_did)
            .cloned()
            .collect()
    }

    /// Claim an offer: bind auth descriptor, status → Active.
    pub fn claim(
        &self,
        grant_id: &str,
        grantee_did: &str,
        auth: GrantAuthDescriptor,
        now_unix: u64,
    ) -> Result<GrantRecord, GrantAuthError> {
        let mut map = self.inner.lock().expect("grant registry lock");
        let rec = map.get_mut(grant_id).ok_or(GrantAuthError::NotExercisable)?;
        if rec.grantee_did != grantee_did {
            return Err(GrantAuthError::GranteeMismatch);
        }
        let claimed = rec.clone().claim_with_auth(auth, now_unix)?;
        *rec = claimed.clone();
        Ok(claimed)
    }

    pub fn revoke(&self, grant_id: &str) -> Result<(), GrantAuthError> {
        let mut map = self.inner.lock().expect("grant registry lock");
        let rec = map.get_mut(grant_id).ok_or(GrantAuthError::NotExercisable)?;
        rec.revoked = true;
        rec.status = GrantStatus::Revoked;
        Ok(())
    }

    /// Mark Offered rows past unclaimed_ttl as Lapsed.
    pub fn lapse_unclaimed(&self, now_unix: u64) -> usize {
        let mut map = self.inner.lock().expect("grant registry lock");
        let mut n = 0;
        for rec in map.values_mut() {
            if rec.status == GrantStatus::Offered {
                if let Some(ttl) = rec.unclaimed_ttl_unix {
                    if now_unix > ttl {
                        rec.status = GrantStatus::Lapsed;
                        n += 1;
                    }
                }
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant_auth::{GrantAuthScheme, GrantClass};
    use crate::types::{AccessDomain, AccessOperation};

    #[test]
    fn offer_claim_list_revoke() {
        let reg = GrantRegistry::new();
        let offer = GrantRecord::offer_council(
            "g1",
            "did:zhtp:alice",
            "did:zhtp:council",
            GrantClass::AuditRead,
            vec![AccessDomain::WalletGraph],
            vec![AccessOperation::Read],
        );
        reg.register_offer(offer).unwrap();
        assert_eq!(reg.list_for_grantee("did:zhtp:alice").len(), 1);
        let active = reg
            .claim(
                "g1",
                "did:zhtp:alice",
                GrantAuthDescriptor {
                    scheme: GrantAuthScheme::DevAccept,
                    public_key: vec![],
                },
                100,
            )
            .unwrap();
        assert_eq!(active.status, GrantStatus::Active);
        reg.revoke("g1").unwrap();
        assert!(reg.get("g1").unwrap().revoked);
    }

    #[test]
    fn protocol_ops_offer_rejected() {
        let reg = GrantRegistry::new();
        let bad = GrantRecord::offer_protocol(
            "bad",
            "did:zhtp:op",
            "did:zhtp:protocol",
            GrantClass::Ops,
            vec![AccessDomain::NodeGraph],
            vec![AccessOperation::Traverse],
            "n1",
        );
        assert_eq!(
            reg.register_offer(bad),
            Err(GrantAuthError::ProtocolClassForbidden)
        );
    }
}
