//! Shared principal extraction for ZHTP API handlers.

/// Parse `identity_id` from API paths or JSON — accepts canonical `did:zhtp:<64-hex>` or raw 64-char hex.
#[cfg(test)]
mod tests {
    use super::{
        identity_id_matches_caller, may_read_wallet_subject, parse_identity_id_bytes,
        wallet_read_privacy_enforced,
    };
    use lib_access_control::{Role, SecurityPrincipal};
    use lib_types::NodeType;

    #[test]
    fn parse_raw_hex_identity() {
        let hex = "59e07e17556e2955581443538839d576974e4f8a9af424c0a2cc7df79c995c9d";
        let bytes = parse_identity_id_bytes(hex).unwrap();
        assert_eq!(hex::encode(bytes), hex);
    }

    #[test]
    fn parse_did_zhtp_identity() {
        let hex = "59e07e17556e2955581443538839d576974e4f8a9af424c0a2cc7df79c995c9d";
        let did = format!("did:zhtp:{hex}");
        let bytes = parse_identity_id_bytes(&did).unwrap();
        assert_eq!(hex::encode(bytes), hex);
    }

    #[test]
    fn identity_id_matches_did_prefix() {
        let hex = "59e07e17556e2955581443538839d576974e4f8a9af424c0a2cc7df79c995c9d";
        assert!(identity_id_matches_caller(hex, &format!("did:zhtp:{hex}")));
        assert!(identity_id_matches_caller(
            &format!("did:zhtp:{hex}"),
            &format!("did:zhtp:{hex}")
        ));
        assert!(!identity_id_matches_caller(hex, "did:zhtp:deadbeef"));
    }

    #[test]
    fn wallet_read_privacy_default_on() {
        // Default when env unset: enforced. Do not mutate process env in parallel tests.
        let _ = wallet_read_privacy_enforced();
    }

    #[test]
    fn may_read_wallet_self_and_council() {
        let hex = "59e07e17556e2955581443538839d576974e4f8a9af424c0a2cc7df79c995c9d";
        let self_p = SecurityPrincipal::new(
            format!("did:zhtp:{hex}"),
            Role::Citizen,
            NodeType::FullNode,
        );
        let other = SecurityPrincipal::new(
            "did:zhtp:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Role::Citizen,
            NodeType::FullNode,
        );
        let council = SecurityPrincipal::new("did:zhtp:council", Role::Council, NodeType::FullNode);
        let public = SecurityPrincipal::public();

        // When privacy is on (default), self OK, other denied, council OK, public denied.
        if wallet_read_privacy_enforced() {
            assert!(may_read_wallet_subject(&self_p, hex));
            assert!(!may_read_wallet_subject(&other, hex));
            assert!(may_read_wallet_subject(&council, hex));
            assert!(!may_read_wallet_subject(&public, hex));
        }
    }
}

pub(crate) fn parse_identity_id_bytes(
    identity_id: &str,
) -> std::result::Result<[u8; 32], String> {
    let hex_part = identity_id
        .strip_prefix("did:zhtp:")
        .unwrap_or(identity_id);
    let bytes = hex::decode(hex_part)
        .map_err(|e| format!("Invalid hex for identity_id: {e}"))?;
    if bytes.len() != 32 {
        return Err("Identity ID must be 32 bytes".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Compare request identity (raw hex or `did:zhtp:`) to caller DID.
pub(crate) fn identity_id_matches_caller(request_identity: &str, caller_did: &str) -> bool {
    let caller_hex = caller_did.strip_prefix("did:zhtp:").unwrap_or(caller_did);
    let request_hex = request_identity
        .strip_prefix("did:zhtp:")
        .unwrap_or(request_identity);
    caller_hex == request_hex
}

use lib_access_control::{Role, SecurityPrincipal};
use lib_protocols::types::ZhtpRequest;
use lib_types::NodeType;

/// Extract a `SecurityPrincipal` from an incoming `ZhtpRequest`.
///
/// This is the canonical integration point used across all API handlers.
/// Authenticated DIDs are checked against the on-chain council member list
/// (and optional ops allowlist) to assign `Role::Council` / `InfraAdmin` /
/// `Citizen`. The membership check reads a sync-warmed council cache first
/// (see `BlockchainProvider::is_council_member_blocking`), so it is safe to
/// call **before** acquiring a `blockchain.read()` guard.
///
/// **Handler invariant (deadlock):** `extract_principal_from_request` must run
/// before any `blockchain.read().await` / `write().await` on the global chain.
/// Tokio `RwLock` is not re-entrant; a nested read on the same task deadlocks.
///
/// **Phase 1 (#2935):** do not trust client-declared `x-node-type` or elevate
/// bare Bearer tokens to `Role::Citizen`. Without a bound DID, the principal
/// is `Public`.
///
/// Mobile clients sign QUIC bytes with a per-device Dilithium key
/// (`53c47662…`) which is *different by design* from the user's canonical
/// chain DID (`e0b97576…`); the OPAQUE login flow binds the two in the
/// in-memory `SessionManager` map (see PR #2626). We consult the binding
/// first and only fall back to the raw device DID when no binding exists.
pub fn extract_principal_from_request(request: &ZhtpRequest) -> SecurityPrincipal {
    // If the transport/session layer has already authenticated the caller
    // and set request.requester, use that DID directly.
    if let Some(ref identity_id) = request.requester {
        let raw_did = format!("did:zhtp:{}", hex::encode(&identity_id.0));
        let did = resolve_canonical_did(identity_id.0, raw_did.clone());
        let role = resolve_role_for_dids(&[did.as_str(), raw_did.as_str()]);
        return SecurityPrincipal::new(&did, role, NodeType::FullNode);
    }

    // Client-declared NodeType is spoofable. Fail closed: treat as Public
    // until node attestation / authenticated UHP context is wired (Phase 3).
    // Do not assign Role::Node from x-node-type alone.
    let _ignored_spoofable_node_type = request.headers.get("x-node-type");

    // Bearer without a bound DID must not become a fake Citizen session.
    // Session→DID mapping is the requester path above (or future session map).
    let _ignored_unbound_bearer = request
        .headers
        .get("authorization")
        .map(|a| a.to_lowercase().starts_with("bearer "))
        .unwrap_or(false);

    // Default: unauthenticated public caller.
    SecurityPrincipal::public()
}

/// Env-configured ops allowlist for `Role::InfraAdmin` (comma-separated DIDs).
/// Example: `ZHTP_INFRA_ADMIN_DIDS=did:zhtp:abc...,did:zhtp:def...`
pub fn infra_admin_dids_from_env() -> Vec<String> {
    std::env::var("ZHTP_INFRA_ADMIN_DIDS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(|d| d.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// True when wallet read privacy filters are enforced (default: on).
/// Set `ZHTP_ENFORCE_WALLET_READ_PRIVACY=0` / `false` / `off` to disable
/// (emergency rollback only).
pub fn wallet_read_privacy_enforced() -> bool {
    match std::env::var("ZHTP_ENFORCE_WALLET_READ_PRIVACY") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        }
        Err(_) => true,
    }
}

/// Whether `principal` may read wallet graph data for `subject_identity_id`
/// (raw hex or `did:zhtp:`). Soft-privacy path: callers return empty/zero
/// bodies on deny rather than 403.
pub fn may_read_wallet_subject(principal: &SecurityPrincipal, subject_identity_id: &str) -> bool {
    use lib_access_control::Role;
    if !wallet_read_privacy_enforced() {
        return true;
    }
    match principal.role {
        Role::Council | Role::InfraAdmin | Role::System => true,
        Role::Citizen | Role::Device | Role::PolicyAdmin | Role::Emergency | Role::Node => {
            identity_id_matches_caller(subject_identity_id, &principal.did)
        }
        Role::Public => false,
    }
}

/// Ops surfaces (halt, export/import, provision): Council or InfraAdmin.
/// `System` remains accepted until Phase 3 removes god-mode.
pub fn is_ops_elevated(principal: &SecurityPrincipal) -> bool {
    use lib_access_control::Role;
    matches!(
        principal.role,
        Role::Council | Role::InfraAdmin | Role::System
    )
}

/// Structured access-decision audit log (#2935 Phase 2). Denies at INFO.
pub fn log_access_decision(
    principal: &SecurityPrincipal,
    subject: &str,
    domain: &str,
    op: &str,
    allowed: bool,
    reason: &str,
) {
    if allowed {
        tracing::debug!(
            target: "access_control",
            principal_did = %principal.did,
            principal_role = ?principal.role,
            subject = %subject,
            domain = %domain,
            op = %op,
            reason = %reason,
            "access allow"
        );
    } else {
        tracing::info!(
            target: "access_control",
            principal_did = %principal.did,
            principal_role = ?principal.role,
            subject = %subject,
            domain = %domain,
            op = %op,
            reason = %reason,
            "access deny"
        );
    }
}

/// Determine the role for an authenticated DID by checking on-chain state
/// and the optional ops allowlist.
///
/// Priority: Council > InfraAdmin (env) > Citizen.
/// Checks canonical and transport DIDs — council config uses `did:zhtp:…` while
/// QUIC `requester` may encode only the 32-byte key id.
fn resolve_role_for_dids(dids: &[&str]) -> Role {
    let provider = crate::runtime::blockchain_provider::get_global_blockchain_provider();

    if let Some(ref provider) = provider {
        for did in dids {
            if provider.is_council_member_blocking(did) == Some(true) {
                return Role::Council;
            }
        }
    }

    let infra = infra_admin_dids_from_env();
    if !infra.is_empty() {
        for did in dids {
            let did_hex = did.strip_prefix("did:zhtp:").unwrap_or(did);
            if infra.iter().any(|admin| {
                let admin_hex = admin.strip_prefix("did:zhtp:").unwrap_or(admin);
                admin == *did || admin_hex == did_hex
            }) {
                return Role::InfraAdmin;
            }
        }
    }

    Role::Citizen
}

/// Resolve a 32-byte device QUIC key to the canonical chain DID it was
/// bound to at OPAQUE login, falling back to `raw_did` (the stub
/// `did:zhtp:<device-key-hex>`) when no binding exists.
///
/// The binding lives in `SessionManager.device_quic_key_canonical_did`
/// (in-memory only, cleared on restart, populated by
/// `handle_login_finish`). This is the same map `/msg/receive` already
/// consults; surfacing it here means *every* owner-gated endpoint sees
/// the canonical DID instead of the device-DID.
///
/// Performed in a `block_in_place` shim because the principal extractor
/// is called from sync code paths but the binding map is guarded by an
/// async `RwLock`. We've already paid for the async runtime at this
/// point (the request itself arrived through tokio), so the cost is
/// bounded to a single map read.
fn resolve_canonical_did(device_key: [u8; 32], raw_did: String) -> String {
    let device_key_hex = hex::encode(&device_key);

    // (1) Session-bound device map (set by OPAQUE login_finish — only works
    //     for flows that authenticate over an already-v2 session, which is
    //     why OPAQUE itself can't populate it: login_finish runs on a
    //     public read-only QUIC connection where request.requester is None).
    if let Some(manager) = crate::session_manager::session_manager_handle() {
        let lookup = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                manager.canonical_did_for_quic_key(&device_key).await
            })
        });
        if let Some(canonical) = lookup {
            if !canonical.is_empty() {
                tracing::debug!(
                    "principal: device {} → canonical {} (via SessionManager binding)",
                    &device_key_hex[..16],
                    &canonical[..canonical.len().min(28)]
                );
                return canonical;
            }
        }
    }

    // (2) + (3) — chain identity_registry lookup. Same resolver
    // `msg/receive` uses (messaging/handler.rs:279-326). This is the path
    // that actually unblocks mobile after OPAQUE login because the
    // SessionManager binding can never be populated by the OPAQUE flow
    // itself (the public read-only QUIC connection has no peer_did).
    let provider = match crate::runtime::blockchain_provider::get_global_blockchain_provider() {
        Some(p) => p,
        None => {
            tracing::debug!(
                "principal: no blockchain provider — using raw DID for device {}",
                &device_key_hex[..16]
            );
            return raw_did;
        }
    };

    let resolved = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async move {
            provider
                .resolve_device_key_to_canonical_did(&device_key)
                .await
        })
    });

    match resolved {
        Some(canonical) => {
            tracing::info!(
                "principal: device {} → canonical {} (via identity_registry)",
                &device_key_hex[..16],
                &canonical[..canonical.len().min(28)]
            );
            canonical
        }
        None => {
            tracing::info!(
                "principal: no chain identity binds device {} — using raw DID",
                &device_key_hex[..16]
            );
            raw_did
        }
    }
}