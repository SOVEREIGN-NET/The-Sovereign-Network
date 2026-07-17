//! Shared recipient DID resolution for messaging endpoints.
//!
//! MSG-R3: `/msg/receive` and `/msg/inbound` must use the same resolver so a
//! client does not see an empty inbox on one path and mail on the other.
//!
//! Resolution order (first hit wins):
//! 1. Session-bound device map (OPAQUE login: quic_key → canonical DID)
//! 2. Blockchain durable identity lookup by device key id
//! 3. Fallback stub DID `did:zhtp:{key_id}` (empty inbox, not an error)

use lib_blockchain::Blockchain;
use lib_protocols::types::ZhtpRequest;

/// Resolve the authenticated requester to the canonical recipient DID.
///
/// `requester_key_id` is hex-encoded `IdentityId` (32 bytes).
/// Optional `request` supplies the raw key bytes for session-manager lookup.
/// Optional `blockchain` is preferred for path (2); falls back to global chain.
pub async fn resolve_recipient_did(
    requester_key_id: &str,
    request: Option<&ZhtpRequest>,
    blockchain: Option<&Blockchain>,
) -> String {
    let key_id_did = format!("did:zhtp:{}", requester_key_id);

    // (1) Session-bound device map (OPAQUE / mobile ephemeral QUIC keys).
    if let Some(req) = request {
        if let (Some(mgr), Some(req_id)) = (
            crate::session_manager::session_manager_handle(),
            req.requester.as_ref(),
        ) {
            if let Some(did) = mgr.canonical_did_for_quic_key(&req_id.0).await {
                return did;
            }
        }
    } else if let Ok(key_bytes) = hex::decode(requester_key_id) {
        // Inbound stream path: only key_id hex is available; try session map
        // if we have a 32-byte key.
        if key_bytes.len() == 32 {
            if let Some(mgr) = crate::session_manager::session_manager_handle() {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_bytes);
                if let Some(did) = mgr.canonical_did_for_quic_key(&arr).await {
                    return did;
                }
            }
        }
    }

    // (2) Durable blockchain identity lookup (sled-first).
    if let Some(bc) = blockchain {
        if let Some(did) = bc.did_by_device_key_id(requester_key_id) {
            return did;
        }
    } else if let Ok(blockchain_arc) =
        crate::runtime::blockchain_provider::get_global_blockchain().await
    {
        let bc = blockchain_arc.read().await;
        if let Some(did) = bc.did_by_device_key_id(requester_key_id) {
            return did;
        }
    }

    // (3) Stub — deposit store returns empty for unknown DIDs.
    key_id_did
}

/// Convenience for HTTP handlers that have a full request + local blockchain.
pub async fn resolve_recipient_did_from_request(
    request: &ZhtpRequest,
    blockchain: &Blockchain,
) -> Result<String, String> {
    let requester_key_id = request
        .requester
        .as_ref()
        .map(|id| hex::encode(&id.0))
        .unwrap_or_default();

    if requester_key_id.is_empty() {
        return Err("Authenticated DID required".to_string());
    }

    Ok(resolve_recipient_did(&requester_key_id, Some(request), Some(blockchain)).await)
}
