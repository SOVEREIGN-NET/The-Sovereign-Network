//! Grant authentication half — dual-auth elevation (DID ∧ grant proof).
//!
//! Authorization (domain/op/expiry) lives in [`crate::grant`]. This module is
//! structural verify + types for offer/claim/exercise. Production Dilithium
//! (or other) signature checks plug in via [`GrantSignatureVerifier`]; the
//! library stays free of crypto crates.

use crate::grant::ScopedGrant;
use crate::types::{AccessDomain, AccessOperation, Did};
use serde::{Deserialize, Serialize};

/// Who created the grant offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerKind {
    /// Council / governance vote registered the offer.
    Council,
    /// Protocol rule (e.g. node admission) registered the offer.
    Protocol,
}

/// High-level grant purpose (class catalog; domains still authoritative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantClass {
    /// Protocol: may operate a node (scope carries node_id). Not halt/export/audit.
    NodeOperate,
    /// Catastrophic / maintenance ops (halt, export, import, provision).
    Ops,
    /// Cross-identity wallet / graph audit.
    AuditRead,
    /// Governance vote / council admin exercise.
    VoteGovernance,
    /// Explicit act-as / spend delegation (optional).
    DelegateSpend,
    /// Unclassified / custom domain set only.
    Custom,
}

/// Lifecycle of a registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    /// Protocol rail pre-offer (request submitted, not yet accepted).
    Requested,
    /// Registered vs grantee DID; not exercisable until claimed.
    Offered,
    /// Claimed; grant pubkey bound; dual-auth exercise allowed.
    Active,
    Revoked,
    Expired,
    /// Unclaimed offer past unclaimed_ttl.
    Lapsed,
}

/// How the grant secret is proven at exercise time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantAuthScheme {
    /// Signature over exercise message verified with `grant_pubkey` via a
    /// [`GrantSignatureVerifier`] (production: Dilithium, etc.).
    Signature,
    /// Test/dev only: signature bytes must equal `b"DEV-OK"`.
    DevAccept,
}

/// Public half of grant auth material (never private keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAuthDescriptor {
    pub scheme: GrantAuthScheme,
    /// Public key or scheme-specific material (empty for DevAccept).
    #[serde(default)]
    pub public_key: Vec<u8>,
}

/// Registry row before/after claim (metadata + auth descriptor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    pub id: String,
    pub grantee_did: Did,
    pub issuer_did: Did,
    pub issuer_kind: IssuerKind,
    pub class: GrantClass,
    pub domains: Vec<AccessDomain>,
    pub operations: Vec<AccessOperation>,
    pub status: GrantStatus,
    /// Optional absolute expiry (unix seconds).
    pub expires_at_unix: Option<u64>,
    /// When status is Offered, drop to Lapsed after this time if unclaimed.
    pub unclaimed_ttl_unix: Option<u64>,
    /// Scope parameter (e.g. node_id for NodeOperate).
    #[serde(default)]
    pub scope: Option<String>,
    /// Bound at claim; required for Active Signature scheme.
    #[serde(default)]
    pub auth: Option<GrantAuthDescriptor>,
    pub claimed_at_unix: Option<u64>,
    pub revoked: bool,
}

impl GrantRecord {
    /// Build an Offered council grant (not yet claimable for exercise).
    pub fn offer_council(
        id: impl Into<String>,
        grantee_did: impl Into<Did>,
        issuer_did: impl Into<Did>,
        class: GrantClass,
        domains: Vec<AccessDomain>,
        operations: Vec<AccessOperation>,
    ) -> Self {
        Self {
            id: id.into(),
            grantee_did: grantee_did.into(),
            issuer_did: issuer_did.into(),
            issuer_kind: IssuerKind::Council,
            class,
            domains,
            operations,
            status: GrantStatus::Offered,
            expires_at_unix: None,
            unclaimed_ttl_unix: None,
            scope: None,
            auth: None,
            claimed_at_unix: None,
            revoked: false,
        }
    }

    /// Build an Offered protocol grant (e.g. NodeOperate).
    pub fn offer_protocol(
        id: impl Into<String>,
        grantee_did: impl Into<Did>,
        issuer_did: impl Into<Did>,
        class: GrantClass,
        domains: Vec<AccessDomain>,
        operations: Vec<AccessOperation>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            grantee_did: grantee_did.into(),
            issuer_did: issuer_did.into(),
            issuer_kind: IssuerKind::Protocol,
            class,
            domains,
            operations,
            status: GrantStatus::Offered,
            expires_at_unix: None,
            unclaimed_ttl_unix: None,
            scope: Some(scope.into()),
            auth: None,
            claimed_at_unix: None,
            revoked: false,
        }
    }

    pub fn with_expiry(mut self, expires_at_unix: u64) -> Self {
        self.expires_at_unix = Some(expires_at_unix);
        self
    }

    pub fn with_unclaimed_ttl(mut self, unclaimed_ttl_unix: u64) -> Self {
        self.unclaimed_ttl_unix = Some(unclaimed_ttl_unix);
        self
    }

    /// Claim with grantee-provided grant pubkey (preferred cold path).
    pub fn claim_with_auth(
        mut self,
        auth: GrantAuthDescriptor,
        now_unix: u64,
    ) -> Result<Self, GrantAuthError> {
        if self.revoked {
            return Err(GrantAuthError::Revoked);
        }
        if self.status != GrantStatus::Offered {
            return Err(GrantAuthError::InvalidStatus);
        }
        if let Some(ttl) = self.unclaimed_ttl_unix {
            if now_unix > ttl {
                return Err(GrantAuthError::Lapsed);
            }
        }
        if matches!(auth.scheme, GrantAuthScheme::Signature) && auth.public_key.is_empty() {
            return Err(GrantAuthError::MissingPublicKey);
        }
        // Protocol must not mint catastrophic classes — enforced at offer time too.
        if self.issuer_kind == IssuerKind::Protocol
            && matches!(
                self.class,
                GrantClass::Ops | GrantClass::AuditRead | GrantClass::VoteGovernance
            )
        {
            return Err(GrantAuthError::ProtocolClassForbidden);
        }
        self.auth = Some(auth);
        self.status = GrantStatus::Active;
        self.claimed_at_unix = Some(now_unix);
        Ok(self)
    }

    /// Whether this record may be exercised at `now_unix` (status + expiry).
    pub fn is_exercisable(&self, now_unix: u64) -> bool {
        if self.revoked || self.status != GrantStatus::Active {
            return false;
        }
        if let Some(exp) = self.expires_at_unix {
            if now_unix > exp {
                return false;
            }
        }
        true
    }

    /// Convert to attachable [`ScopedGrant`] for policy evaluation (no secrets).
    pub fn to_scoped_grant(&self) -> ScopedGrant {
        let mut g = ScopedGrant::new(
            self.id.clone(),
            self.grantee_did.clone(),
            self.issuer_did.clone(),
            self.domains.clone(),
            self.operations.clone(),
        );
        if let Some(exp) = self.expires_at_unix {
            g = g.with_expiry(exp);
        }
        if self.revoked {
            g = g.mark_consumed();
        }
        g
    }
}

/// Proof presented with a DID session to exercise a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantExerciseProof {
    pub grant_id: String,
    pub grantee_did: Did,
    /// Must match the server session binding string.
    pub session_binding: String,
    /// Unix seconds when the client signed.
    pub signed_at_unix: u64,
    /// Scheme-specific signature (or `DEV-OK` for DevAccept).
    pub signature: Vec<u8>,
}

/// Canonical message bytes for grant exercise signatures.
pub fn grant_exercise_message(
    grant_id: &str,
    grantee_did: &str,
    session_binding: &str,
    signed_at_unix: u64,
) -> Vec<u8> {
    format!(
        "zhtp-grant-exercise|v1|{grant_id}|{grantee_did}|{session_binding}|{signed_at_unix}"
    )
    .into_bytes()
}

/// Pluggable signature verify (production crypto lives outside this crate).
pub trait GrantSignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Verifier that always fails (forces explicit plug-in).
pub struct RejectAllVerifier;

impl GrantSignatureVerifier for RejectAllVerifier {
    fn verify(&self, _public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
        false
    }
}

/// Dev verifier: accepts any non-empty pubkey if signature is `DEV-OK`.
pub struct DevOkVerifier;

impl GrantSignatureVerifier for DevOkVerifier {
    fn verify(&self, public_key: &[u8], _message: &[u8], signature: &[u8]) -> bool {
        !public_key.is_empty() && signature == b"DEV-OK"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantAuthError {
    NotExercisable,
    GrantIdMismatch,
    GranteeMismatch,
    SessionMismatch,
    ClockSkew,
    MissingAuth,
    MissingPublicKey,
    BadSignature,
    InvalidStatus,
    Revoked,
    Lapsed,
    ProtocolClassForbidden,
}

impl std::fmt::Display for GrantAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotExercisable => write!(f, "grant not exercisable"),
            Self::GrantIdMismatch => write!(f, "grant id mismatch"),
            Self::GranteeMismatch => write!(f, "grantee mismatch"),
            Self::SessionMismatch => write!(f, "session binding mismatch"),
            Self::ClockSkew => write!(f, "signed_at outside allowed skew"),
            Self::MissingAuth => write!(f, "grant has no auth descriptor"),
            Self::MissingPublicKey => write!(f, "signature scheme requires public key"),
            Self::BadSignature => write!(f, "grant signature verification failed"),
            Self::InvalidStatus => write!(f, "invalid grant status for operation"),
            Self::Revoked => write!(f, "grant revoked"),
            Self::Lapsed => write!(f, "offer lapsed before claim"),
            Self::ProtocolClassForbidden => {
                write!(f, "protocol issuer cannot mint this grant class")
            }
        }
    }
}

impl std::error::Error for GrantAuthError {}

/// Max |now - signed_at| for exercise proofs (seconds).
pub const GRANT_PROOF_MAX_SKEW_SECS: u64 = 300;

/// Verify structural dual-auth proof against an Active grant record.
pub fn verify_grant_proof<V: GrantSignatureVerifier>(
    record: &GrantRecord,
    proof: &GrantExerciseProof,
    now_unix: u64,
    session_binding: &str,
    verifier: &V,
) -> Result<(), GrantAuthError> {
    if !record.is_exercisable(now_unix) {
        return Err(GrantAuthError::NotExercisable);
    }
    if proof.grant_id != record.id {
        return Err(GrantAuthError::GrantIdMismatch);
    }
    if proof.grantee_did != record.grantee_did {
        return Err(GrantAuthError::GranteeMismatch);
    }
    if proof.session_binding != session_binding {
        return Err(GrantAuthError::SessionMismatch);
    }
    let skew = now_unix.abs_diff(proof.signed_at_unix);
    if skew > GRANT_PROOF_MAX_SKEW_SECS {
        return Err(GrantAuthError::ClockSkew);
    }
    let auth = record.auth.as_ref().ok_or(GrantAuthError::MissingAuth)?;
    match auth.scheme {
        GrantAuthScheme::DevAccept => {
            if proof.signature != b"DEV-OK" {
                return Err(GrantAuthError::BadSignature);
            }
        }
        GrantAuthScheme::Signature => {
            if auth.public_key.is_empty() {
                return Err(GrantAuthError::MissingPublicKey);
            }
            let msg = grant_exercise_message(
                &proof.grant_id,
                &proof.grantee_did,
                &proof.session_binding,
                proof.signed_at_unix,
            );
            if !verifier.verify(&auth.public_key, &msg, &proof.signature) {
                return Err(GrantAuthError::BadSignature);
            }
        }
    }
    Ok(())
}

/// Protocol offer class guard at mint time.
pub fn protocol_may_offer(class: GrantClass) -> bool {
    matches!(class, GrantClass::NodeOperate | GrantClass::Custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use AccessDomain::*;
    use AccessOperation::*;

    fn active_dev_grant() -> GrantRecord {
        GrantRecord::offer_council(
            "g-audit-1",
            "did:zhtp:alice",
            "did:zhtp:council",
            GrantClass::AuditRead,
            vec![WalletGraph],
            vec![Read, Enumerate],
        )
        .claim_with_auth(
            GrantAuthDescriptor {
                scheme: GrantAuthScheme::DevAccept,
                public_key: vec![],
            },
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn dual_auth_dev_proof_ok() {
        let rec = active_dev_grant();
        let proof = GrantExerciseProof {
            grant_id: "g-audit-1".into(),
            grantee_did: "did:zhtp:alice".into(),
            session_binding: "sess-1".into(),
            signed_at_unix: 1_050,
            signature: b"DEV-OK".to_vec(),
        };
        assert!(verify_grant_proof(&rec, &proof, 1_060, "sess-1", &RejectAllVerifier).is_ok());
    }

    #[test]
    fn dual_auth_rejects_session_mismatch() {
        let rec = active_dev_grant();
        let proof = GrantExerciseProof {
            grant_id: "g-audit-1".into(),
            grantee_did: "did:zhtp:alice".into(),
            session_binding: "sess-1".into(),
            signed_at_unix: 1_050,
            signature: b"DEV-OK".to_vec(),
        };
        assert_eq!(
            verify_grant_proof(&rec, &proof, 1_060, "sess-OTHER", &RejectAllVerifier),
            Err(GrantAuthError::SessionMismatch)
        );
    }

    #[test]
    fn unclaimed_offer_not_exercisable() {
        let offer = GrantRecord::offer_council(
            "g1",
            "did:zhtp:alice",
            "did:zhtp:council",
            GrantClass::Ops,
            vec![NodeGraph],
            vec![Traverse],
        );
        assert!(!offer.is_exercisable(1_000));
    }

    #[test]
    fn protocol_cannot_claim_ops_class() {
        let offer = GrantRecord::offer_protocol(
            "g-bad",
            "did:zhtp:op",
            "did:zhtp:protocol",
            GrantClass::Ops,
            vec![NodeGraph],
            vec![Traverse],
            "node-1",
        );
        let err = offer
            .claim_with_auth(
                GrantAuthDescriptor {
                    scheme: GrantAuthScheme::DevAccept,
                    public_key: vec![],
                },
                1,
            )
            .unwrap_err();
        assert_eq!(err, GrantAuthError::ProtocolClassForbidden);
    }

    #[test]
    fn protocol_node_operate_claim_ok() {
        let rec = GrantRecord::offer_protocol(
            "g-node",
            "did:zhtp:op",
            "did:zhtp:protocol",
            GrantClass::NodeOperate,
            vec![NodeGraph],
            vec![Traverse],
            "node-g1",
        )
        .claim_with_auth(
            GrantAuthDescriptor {
                scheme: GrantAuthScheme::DevAccept,
                public_key: vec![],
            },
            10,
        )
        .unwrap();
        assert_eq!(rec.status, GrantStatus::Active);
        assert_eq!(rec.scope.as_deref(), Some("node-g1"));
        assert!(protocol_may_offer(GrantClass::NodeOperate));
        assert!(!protocol_may_offer(GrantClass::Ops));
    }

    #[test]
    fn signature_scheme_uses_verifier() {
        let rec = GrantRecord::offer_council(
            "g-sig",
            "did:zhtp:alice",
            "did:zhtp:council",
            GrantClass::Ops,
            vec![NodeGraph],
            vec![Traverse],
        )
        .claim_with_auth(
            GrantAuthDescriptor {
                scheme: GrantAuthScheme::Signature,
                public_key: b"pk".to_vec(),
            },
            1_000,
        )
        .unwrap();
        let proof = GrantExerciseProof {
            grant_id: "g-sig".into(),
            grantee_did: "did:zhtp:alice".into(),
            session_binding: "s".into(),
            signed_at_unix: 1_000,
            signature: b"DEV-OK".to_vec(),
        };
        assert!(verify_grant_proof(&rec, &proof, 1_000, "s", &DevOkVerifier).is_ok());
        assert_eq!(
            verify_grant_proof(&rec, &proof, 1_000, "s", &RejectAllVerifier),
            Err(GrantAuthError::BadSignature)
        );
    }

    #[test]
    fn to_scoped_grant_covers_domain() {
        let rec = active_dev_grant();
        let g = rec.to_scoped_grant();
        assert!(g.covers(WalletGraph, Read));
        assert!(g.is_active(2_000));
    }
}
