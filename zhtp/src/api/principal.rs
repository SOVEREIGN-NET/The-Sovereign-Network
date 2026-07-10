//! Shared principal extraction for ZHTP API handlers.

/// Parse `identity_id` from API paths or JSON — accepts canonical `did:zhtp:<64-hex>` or raw 64-char hex.
#[cfg(test)]
mod tests {
    use super::parse_identity_id_bytes;

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
}

pub fn parse_identity_id_bytes(identity_id: &str) -> Result<[u8; 32], String> {
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

use lib_access_control::{Role, SecurityPrincipal};
use lib_protocols::types::ZhtpRequest;
use lib_types::NodeType;

/// Extract a `SecurityPrincipal` from an incoming `ZhtpRequest`.
///
/// This is the canonical integration point used across all API handlers.
/// Authenticated DIDs are checked against the on-chain council member list
/// to assign `Role::Council` vs `Role::Citizen`. The membership check reads a
/// sync-warmed council cache first (see `BlockchainProvider::is_council_member_blocking`),
/// so it is safe to call **before** acquiring a `blockchain.read()` guard.
///
/// **Handler invariant (deadlock):** `extract_principal_from_request` must run
/// before any `blockchain.read().await` / `write().await` on the global chain.
/// Tokio `RwLock` is not re-entrant; a nested read on the same task deadlocks.
/// Council-gated handlers audited in this PR (all extract principal first):
/// - `network/mod.rs` — halt-consensus
/// - `notifications/mod.rs` — subscriber list
/// - `blockchain/mod.rs` — export/import chain, list wallets (Council bypass paths)
/// - `dao/mod.rs` — council register, entity-registry init
/// - `wallet/mod.rs` — cross-wallet transfer, stake/unstake, simple send (Council bypass)
///
/// Mobile clients sign QUIC bytes with a per-device Dilithium key
/// (`53c47662…`) which is *different by design* from the user's canonical
/// chain DID (`e0b97576…`); the OPAQUE login flow binds the two in the
/// in-memory `SessionManager` map (see PR #2626). The previous version of
/// this function turned `request.requester.0` directly into
/// `did:zhtp:<device-key-hex>` — the device-DID — which made every
/// owner-gated endpoint 403 even immediately after a successful OPAQUE
/// login. We now consult the binding first and only fall back to the raw
/// device DID when no binding exists (i.e. pre-OPAQUE-login traffic).
pub fn extract_principal_from_request(request: &ZhtpRequest) -> SecurityPrincipal {
    // If the transport/session layer has already authenticated the caller
    // and set request.requester, use that DID directly.
    if let Some(ref identity_id) = request.requester {
        let raw_did = format!("did:zhtp:{}", hex::encode(&identity_id.0));
        let did = resolve_canonical_did(identity_id.0, raw_did.clone());
        let role = resolve_role_for_dids(&[did.as_str(), raw_did.as_str()]);
        return SecurityPrincipal::new(&did, role, NodeType::FullNode);
    }

    // Node-to-node calls may declare their node type.
    // TODO: in production this should come from authenticated UHP context,
    // not from caller-controlled headers.
    if let Some(node_type_str) = request.headers.get("x-node-type") {
        let node_type = NodeType::from_config(Some(&node_type_str));
        return SecurityPrincipal::new("did:zhtp:node", Role::Node, node_type);
    }

    // Authenticated sessions (placeholder: any bearer token is treated as
    // a citizen session until full session-to-principal mapping is wired).
    if let Some(auth) = request.headers.get("authorization") {
        if auth.to_lowercase().starts_with("bearer ") {
            return SecurityPrincipal::new(
                "did:zhtp:session",
                Role::Citizen,
                NodeType::FullNode,
            );
        }
    }

    // Default: unauthenticated public caller.
    SecurityPrincipal::public()
}

/// Determine the role for an authenticated DID by checking on-chain state.
///
/// Council members get `Role::Council`, everyone else gets `Role::Citizen`.
/// Checks canonical and transport DIDs — council config uses `did:zhtp:…` while
/// QUIC `requester` may encode only the 32-byte key id.
fn resolve_role_for_dids(dids: &[&str]) -> Role {
    let provider = match crate::runtime::blockchain_provider::get_global_blockchain_provider() {
        Some(p) => p,
        None => return Role::Citizen,
    };

    for did in dids {
        if provider.is_council_member_blocking(did) == Some(true) {
            return Role::Council;
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