//! Dual-auth grant offer / claim / elevate API (Phase B2 skeleton).
//!
//! Endpoints:
//!   GET  /api/v1/grants/me              — list offers + active for caller DID
//!   POST /api/v1/grants/claim           — bind grant pubkey → Active
//!   POST /api/v1/grants/elevate         — GrantExerciseProof[] → elevated session
//!   POST /api/v1/grants/offers/register — bootstrap council/ops offer (role-gated)
//!
//! Fat roles still exercise until Phase D cut-over. Grant private keys never
//! appear here — claim accepts **public** auth material only.

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use lib_access_control::{
    AccessDomain, AccessOperation, GrantAuthDescriptor, GrantAuthScheme, GrantClass, GrantExerciseProof,
    GrantRecord, GrantStatus, IssuerKind, RejectAllVerifier, Role,
};
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use crate::api::principal::{extract_principal_from_request, is_ops_elevated};
use crate::elevated_session::{
    get_global_elevated_sessions, session_binding_from_request, DEFAULT_ELEVATED_TTL_SECS,
};
use crate::runtime::grant_registry_provider::get_global_grant_registry;

fn create_json_response(data: serde_json::Value) -> Result<ZhtpResponse> {
    let json_response = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

fn error_resp(status: ZhtpStatus, msg: &str) -> ZhtpResponse {
    ZhtpResponse::error(status, msg.to_string())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn record_json(r: &GrantRecord) -> serde_json::Value {
    json!({
        "id": r.id,
        "grantee_did": r.grantee_did,
        "issuer_did": r.issuer_did,
        "issuer_kind": r.issuer_kind,
        "class": r.class,
        "domains": r.domains,
        "operations": r.operations,
        "status": r.status,
        "expires_at_unix": r.expires_at_unix,
        "unclaimed_ttl_unix": r.unclaimed_ttl_unix,
        "scope": r.scope,
        "claimed_at_unix": r.claimed_at_unix,
        "revoked": r.revoked,
        "has_auth": r.auth.is_some(),
    })
}

#[derive(Deserialize)]
struct ClaimBody {
    grant_id: String,
    /// `signature` (production) or `dev_accept` (only with feature `dev-grants`)
    #[serde(default = "default_scheme")]
    scheme: String,
    /// Hex-encoded public key for signature scheme.
    #[serde(default)]
    public_key_hex: String,
}

fn default_scheme() -> String {
    "signature".into()
}

#[derive(Deserialize)]
struct ElevateBody {
    proofs: Vec<ElevateProofBody>,
    /// Optional override; default DEFAULT_ELEVATED_TTL_SECS (capped).
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Deserialize)]
struct ElevateProofBody {
    grant_id: String,
    /// Unix seconds when the client signed.
    signed_at_unix: u64,
    /// Hex signature (or literal `DEV-OK` when `dev-grants` is enabled).
    signature_hex: String,
}

#[derive(Deserialize)]
struct RegisterOfferBody {
    grant_id: String,
    grantee_did: String,
    /// `council` | `protocol`
    #[serde(default = "default_issuer_kind")]
    issuer_kind: String,
    /// `ops` | `audit_read` | `vote_governance` | `node_operate` | `delegate_spend` | `custom`
    class: String,
    domains: Vec<String>,
    operations: Vec<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    expires_at_unix: Option<u64>,
    #[serde(default)]
    unclaimed_ttl_unix: Option<u64>,
}

fn default_issuer_kind() -> String {
    "council".into()
}

fn parse_class(s: &str) -> Option<GrantClass> {
    match s.trim().to_ascii_lowercase().as_str() {
        "node_operate" | "nodeoperate" => Some(GrantClass::NodeOperate),
        "ops" => Some(GrantClass::Ops),
        "audit_read" | "auditread" => Some(GrantClass::AuditRead),
        "vote_governance" | "votegovernance" => Some(GrantClass::VoteGovernance),
        "delegate_spend" | "delegatespend" => Some(GrantClass::DelegateSpend),
        "custom" => Some(GrantClass::Custom),
        _ => None,
    }
}

fn parse_domain(s: &str) -> Option<AccessDomain> {
    match s.trim() {
        "CoreIdentity" | "core_identity" => Some(AccessDomain::CoreIdentity),
        "ServiceEndpoints" | "service_endpoints" => Some(AccessDomain::ServiceEndpoints),
        "WalletGraph" | "wallet_graph" => Some(AccessDomain::WalletGraph),
        "NodeGraph" | "node_graph" => Some(AccessDomain::NodeGraph),
        "Governance" | "governance" => Some(AccessDomain::Governance),
        "UbiData" | "ubi_data" => Some(AccessDomain::UbiData),
        "ZkProofMeta" | "zk_proof_meta" => Some(AccessDomain::ZkProofMeta),
        "ZkProofPrivate" | "zk_proof_private" => Some(AccessDomain::ZkProofPrivate),
        "PrivateDataRef" | "private_data_ref" => Some(AccessDomain::PrivateDataRef),
        _ => None,
    }
}

fn parse_op(s: &str) -> Option<AccessOperation> {
    match s.trim() {
        "Resolve" | "resolve" => Some(AccessOperation::Resolve),
        "Read" | "read" => Some(AccessOperation::Read),
        "Traverse" | "traverse" => Some(AccessOperation::Traverse),
        "Enumerate" | "enumerate" => Some(AccessOperation::Enumerate),
        "Subscribe" | "subscribe" => Some(AccessOperation::Subscribe),
        _ => None,
    }
}

fn parse_auth_scheme(s: &str) -> Option<GrantAuthScheme> {
    match s.trim().to_ascii_lowercase().as_str() {
        "signature" => Some(GrantAuthScheme::Signature),
        #[cfg(any(test, feature = "dev-grants"))]
        "dev_accept" | "devaccept" => Some(GrantAuthScheme::DevAccept),
        _ => None,
    }
}

fn decode_sig(signature_hex: &str) -> Result<Vec<u8>, String> {
    let t = signature_hex.trim();
    if t.eq_ignore_ascii_case("DEV-OK") {
        return Ok(b"DEV-OK".to_vec());
    }
    hex::decode(t).map_err(|e| format!("invalid signature_hex: {e}"))
}

pub struct GrantsHandler;

impl GrantsHandler {
    pub fn new() -> Self {
        Self
    }

    async fn handle_list_me(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let principal = extract_principal_from_request(request);
        if matches!(principal.role, Role::Public) {
            return Ok(error_resp(ZhtpStatus::Unauthorized, "authentication required"));
        }
        let reg = get_global_grant_registry();
        let rows: Vec<_> = reg
            .list_for_grantee(&principal.did)
            .iter()
            .map(record_json)
            .collect();
        create_json_response(json!({
            "grantee_did": principal.did,
            "grants": rows,
        }))
    }

    async fn handle_claim(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let principal = extract_principal_from_request(request);
        if matches!(principal.role, Role::Public) {
            return Ok(error_resp(ZhtpStatus::Unauthorized, "authentication required"));
        }
        let body: ClaimBody = match serde_json::from_slice(&request.body) {
            Ok(b) => b,
            Err(e) => {
                return Ok(error_resp(
                    ZhtpStatus::BadRequest,
                    &format!("invalid claim body: {e}"),
                ));
            }
        };
        let scheme = match parse_auth_scheme(&body.scheme) {
            Some(s) => s,
            None => {
                return Ok(error_resp(
                    ZhtpStatus::BadRequest,
                    "scheme must be signature (or dev_accept with dev-grants)",
                ));
            }
        };
        let public_key = if body.public_key_hex.is_empty() {
            vec![]
        } else {
            match hex::decode(body.public_key_hex.trim()) {
                Ok(k) => k,
                Err(e) => {
                    return Ok(error_resp(
                        ZhtpStatus::BadRequest,
                        &format!("invalid public_key_hex: {e}"),
                    ));
                }
            }
        };
        let auth = GrantAuthDescriptor { scheme, public_key };
        let reg = get_global_grant_registry();
        match reg.claim(&body.grant_id, &principal.did, auth, now_unix()) {
            Ok(rec) => {
                info!(
                    target: "access_control",
                    grant_id = %rec.id,
                    grantee = %principal.did,
                    "grant claimed"
                );
                create_json_response(json!({ "status": "active", "grant": record_json(&rec) }))
            }
            Err(e) => Ok(error_resp(ZhtpStatus::Forbidden, &e.to_string())),
        }
    }

    async fn handle_elevate(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let principal = extract_principal_from_request(request);
        if matches!(principal.role, Role::Public) {
            return Ok(error_resp(ZhtpStatus::Unauthorized, "authentication required"));
        }
        let body: ElevateBody = match serde_json::from_slice(&request.body) {
            Ok(b) => b,
            Err(e) => {
                return Ok(error_resp(
                    ZhtpStatus::BadRequest,
                    &format!("invalid elevate body: {e}"),
                ));
            }
        };
        if body.proofs.is_empty() {
            return Ok(error_resp(ZhtpStatus::BadRequest, "proofs required"));
        }
        let binding = session_binding_from_request(request);
        let now = now_unix();
        let mut proofs = Vec::with_capacity(body.proofs.len());
        for p in &body.proofs {
            let signature = match decode_sig(&p.signature_hex) {
                Ok(s) => s,
                Err(e) => return Ok(error_resp(ZhtpStatus::BadRequest, &e)),
            };
            proofs.push(GrantExerciseProof {
                grant_id: p.grant_id.clone(),
                grantee_did: principal.did.clone(),
                session_binding: binding.clone(),
                signed_at_unix: p.signed_at_unix,
                signature,
            });
        }
        let reg = get_global_grant_registry();
        // HARD GATE (Phase B3 before D): Signature needs a real Dilithium verifier.
        // RejectAll keeps Signature fail-closed. DevAccept is not compiled into
        // production (requires feature dev-grants). Do not cut fat roles until B3.
        let records = match reg.verify_and_collect_for_elevate(
            &principal.did,
            &proofs,
            now,
            &binding,
            &RejectAllVerifier,
        ) {
            Ok(r) => r,
            Err(e) => return Ok(error_resp(ZhtpStatus::Forbidden, &e.to_string())),
        };
        let grants: Vec<_> = records.iter().map(|r| r.to_scoped_grant()).collect();
        let ttl = body
            .ttl_secs
            .unwrap_or(DEFAULT_ELEVATED_TTL_SECS)
            .min(DEFAULT_ELEVATED_TTL_SECS);
        let entry = get_global_elevated_sessions().put(&principal.did, &binding, grants, ttl);
        info!(
            target: "access_control",
            grantee = %principal.did,
            grant_count = entry.grants.len(),
            expires_at = entry.expires_at_unix,
            "elevated session created"
        );
        create_json_response(json!({
            "status": "elevated",
            "session_binding": binding,
            "expires_at_unix": entry.expires_at_unix,
            "grant_ids": entry.grants.iter().map(|g| &g.id).collect::<Vec<_>>(),
        }))
    }

    async fn handle_register_offer(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let principal = extract_principal_from_request(request);
        // Bootstrap issuance: Council or ops-elevated (InfraAdmin / ops grant).
        // Real council vote rail replaces this in B2a.
        if !matches!(principal.role, Role::Council) && !is_ops_elevated(&principal) {
            return Ok(error_resp(
                ZhtpStatus::Forbidden,
                "register offer requires Council or ops elevation",
            ));
        }
        let body: RegisterOfferBody = match serde_json::from_slice(&request.body) {
            Ok(b) => b,
            Err(e) => {
                return Ok(error_resp(
                    ZhtpStatus::BadRequest,
                    &format!("invalid offer body: {e}"),
                ));
            }
        };
        let class = match parse_class(&body.class) {
            Some(c) => c,
            None => return Ok(error_resp(ZhtpStatus::BadRequest, "unknown grant class")),
        };
        let domains: Result<Vec<_>, _> = body
            .domains
            .iter()
            .map(|d| parse_domain(d).ok_or_else(|| format!("unknown domain: {d}")))
            .collect();
        let domains = match domains {
            Ok(d) if !d.is_empty() => d,
            Ok(_) => return Ok(error_resp(ZhtpStatus::BadRequest, "domains required")),
            Err(e) => return Ok(error_resp(ZhtpStatus::BadRequest, &e)),
        };
        let operations: Result<Vec<_>, _> = body
            .operations
            .iter()
            .map(|o| parse_op(o).ok_or_else(|| format!("unknown operation: {o}")))
            .collect();
        let operations = match operations {
            Ok(o) if !o.is_empty() => o,
            Ok(_) => return Ok(error_resp(ZhtpStatus::BadRequest, "operations required")),
            Err(e) => return Ok(error_resp(ZhtpStatus::BadRequest, &e)),
        };
        let issuer_kind = match body.issuer_kind.trim().to_ascii_lowercase().as_str() {
            "council" => IssuerKind::Council,
            "protocol" => IssuerKind::Protocol,
            _ => {
                return Ok(error_resp(
                    ZhtpStatus::BadRequest,
                    "issuer_kind must be council or protocol",
                ));
            }
        };
        let mut rec = match issuer_kind {
            IssuerKind::Council => GrantRecord::offer_council(
                body.grant_id.clone(),
                body.grantee_did.clone(),
                principal.did.clone(),
                class,
                domains,
                operations,
            ),
            IssuerKind::Protocol => {
                let scope = body.scope.clone().unwrap_or_default();
                if scope.is_empty() {
                    return Ok(error_resp(
                        ZhtpStatus::BadRequest,
                        "protocol offers require scope (e.g. node_id)",
                    ));
                }
                GrantRecord::offer_protocol(
                    body.grant_id.clone(),
                    body.grantee_did.clone(),
                    principal.did.clone(),
                    class,
                    domains,
                    operations,
                    scope,
                )
            }
        };
        if let Some(exp) = body.expires_at_unix {
            rec = rec.with_expiry(exp);
        }
        if let Some(ttl) = body.unclaimed_ttl_unix {
            rec = rec.with_unclaimed_ttl(ttl);
        }
        debug_assert_eq!(rec.status, GrantStatus::Offered);
        let reg = get_global_grant_registry();
        match reg.register_offer(rec.clone()) {
            Ok(()) => {
                info!(
                    target: "access_control",
                    grant_id = %rec.id,
                    grantee = %rec.grantee_did,
                    issuer = %principal.did,
                    ?issuer_kind,
                    "grant offer registered"
                );
                create_json_response(json!({ "status": "offered", "grant": record_json(&rec) }))
            }
            Err(e) => Ok(error_resp(ZhtpStatus::Conflict, &e.to_string())),
        }
    }
}

impl Default for GrantsHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for GrantsHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path = request
            .uri
            .split('?')
            .next()
            .unwrap_or("")
            .trim_end_matches('/');

        match (&request.method, path) {
            (ZhtpMethod::Get, "/api/v1/grants/me") => Ok(self.handle_list_me(&request).await?),
            (ZhtpMethod::Post, "/api/v1/grants/claim") => Ok(self.handle_claim(&request).await?),
            (ZhtpMethod::Post, "/api/v1/grants/elevate") => {
                Ok(self.handle_elevate(&request).await?)
            }
            (ZhtpMethod::Post, "/api/v1/grants/offers/register") => {
                Ok(self.handle_register_offer(&request).await?)
            }
            _ => Ok(error_resp(ZhtpStatus::NotFound, "Not found")),
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        let path = request.uri.split('?').next().unwrap_or("");
        path.starts_with("/api/v1/grants")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_access_control::{GrantAuthDescriptor, GrantAuthScheme, GrantClass};
    use lib_crypto::Hash;
    use lib_protocols::types::ZhtpHeaders;

    fn did_hash(hex32: &str) -> Hash {
        let v = hex::decode(hex32).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        Hash(a)
    }

    fn req(method: ZhtpMethod, uri: &str, body: serde_json::Value, did_hex: Option<&str>) -> ZhtpRequest {
        let mut headers = ZhtpHeaders::new();
        // set() lowercases custom keys so headers.get() finds them.
        headers.set("x-grant-session-binding", "test-bind".into());
        ZhtpRequest {
            method,
            uri: uri.into(),
            version: "1.0".into(),
            headers,
            body: serde_json::to_vec(&body).unwrap(),
            timestamp: 0,
            requester: did_hex.map(did_hash),
            auth_proof: None,
        }
    }

    #[tokio::test]
    async fn offer_claim_elevate_flow() {
        // Unique ids so parallel/global registry tests do not collide.
        let gid = format!("b2-flow-{}", uuid_like());
        let alice_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let alice_did = format!("did:zhtp:{alice_hex}");

        let reg = get_global_grant_registry();
        let offer = GrantRecord::offer_council(
            &gid,
            &alice_did,
            "did:zhtp:council",
            GrantClass::AuditRead,
            vec![AccessDomain::WalletGraph],
            vec![AccessOperation::Read, AccessOperation::Enumerate],
        );
        reg.register_offer(offer).unwrap();
        reg.claim(
            &gid,
            &alice_did,
            GrantAuthDescriptor {
                scheme: GrantAuthScheme::DevAccept,
                public_key: vec![],
            },
            now_unix(),
        )
        .unwrap();

        let h = GrantsHandler::new();
        let elevate = req(
            ZhtpMethod::Post,
            "/api/v1/grants/elevate",
            json!({
                "proofs": [{
                    "grant_id": gid,
                    "signed_at_unix": now_unix(),
                    "signature_hex": "DEV-OK"
                }]
            }),
            Some(alice_hex),
        );
        let resp = h.handle_request(elevate).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Ok, "{:?}", resp.status_message);

        // Principal extraction should attach grant.
        let follow = req(ZhtpMethod::Get, "/api/v1/grants/me", json!({}), Some(alice_hex));
        let p = extract_principal_from_request(&follow);
        assert!(
            p.grant_allows(AccessDomain::WalletGraph, AccessOperation::Read, now_unix()),
            "expected elevated grant on principal, grants={:?}",
            p.grants
        );
    }

    fn uuid_like() -> u64 {
        now_unix()
            .wrapping_mul(31)
            .wrapping_add(std::process::id() as u64)
    }
}
