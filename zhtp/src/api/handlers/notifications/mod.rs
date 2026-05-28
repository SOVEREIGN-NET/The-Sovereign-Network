//! Notification subscription endpoints.
//!
//! Opt-in mailing list keyed by DID. Mobile clients call subscribe to be
//! notified later — for example when a new app launches on the network.
//!
//! Intentionally **not** a chain transaction and **not** signed:
//! - No value transfer / global consensus needed (subscribers are local
//!   to the validator they hit; mobile re-subscribes on next launch if
//!   the validator state is lost).
//! - Worst-case abuse is someone subscribing another DID and that DID
//!   receiving spam notifications. The notification-delivery layer can
//!   filter; the subscribe-by-DID surface stays trivially cheap.
//!
//! Endpoints:
//!
//! | Method | Path                                 | Auth           |
//! |--------|--------------------------------------|----------------|
//! | POST   | /api/v1/notifications/subscribe      | Open           |
//! | POST   | /api/v1/notifications/unsubscribe    | Open           |
//! | GET    | /api/v1/notifications/subscribers    | Council only   |
//!
//! Storage: a single `sled::Tree` under `node_data_dir()/notifications.sled`.
//! Key = DID bytes, value = creation-time unix seconds (u64 LE). Per-validator,
//! not cross-replicated. `INSERT` is idempotent, so duplicate subscribes are
//! harmless.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

use lib_access_control::Role;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;

use crate::api::principal::extract_principal_from_request;

const TREE_NAME: &str = "notifications_subscribers";
const MAX_DID_LEN: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubscribeRequest {
    did: String,
}

pub struct NotificationsHandler {
    tree: sled::Tree,
}

impl NotificationsHandler {
    pub fn new() -> Result<Self> {
        let path = crate::node_data_dir().join("notifications.sled");
        let db = sled::open(&path)
            .map_err(|e| anyhow::anyhow!("Failed to open notifications sled at {:?}: {}", path, e))?;
        let tree = db
            .open_tree(TREE_NAME)
            .map_err(|e| anyhow::anyhow!("Failed to open notifications tree: {}", e))?;
        info!(
            "Notifications subscriber store: {:?} ({} existing subscribers)",
            path,
            tree.len()
        );
        Ok(Self { tree })
    }

    fn err(status: ZhtpStatus, msg: impl Into<String>) -> ZhtpResponse {
        ZhtpResponse::error(status, msg.into())
    }

    fn json_ok(data: serde_json::Value) -> ZhtpResponse {
        match serde_json::to_vec(&data) {
            Ok(bytes) => ZhtpResponse::success_with_content_type(
                bytes,
                "application/json".to_string(),
                None,
            ),
            Err(e) => Self::err(
                ZhtpStatus::InternalServerError,
                format!("response serialize failed: {}", e),
            ),
        }
    }

    /// Canonical ZHTP DIDs are `did:zhtp:<64-hex>` — a 32-byte identity hash
    /// in lowercase hex. Anything else is malformed and would later fail to
    /// decode in any consumer of this list; reject it here rather than
    /// persisting garbage to sled.
    fn validate_did(did: &str) -> Result<(), String> {
        if did.is_empty() {
            return Err("did is required".to_string());
        }
        if did.len() > MAX_DID_LEN {
            return Err(format!("did exceeds max length {}", MAX_DID_LEN));
        }
        let hex = did
            .strip_prefix("did:zhtp:")
            .ok_or_else(|| "did must start with 'did:zhtp:'".to_string())?;
        if hex.len() != 64 {
            return Err("did identity hash must be 64 hex characters".to_string());
        }
        if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(
                "did identity hash must be lowercase hex (0-9, a-f)".to_string()
            );
        }
        Ok(())
    }

    async fn handle_subscribe(&self, request: ZhtpRequest) -> ZhtpResponse {
        let req: SubscribeRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => {
                return Self::err(
                    ZhtpStatus::BadRequest,
                    format!("invalid request body: {}", e),
                )
            }
        };
        if let Err(msg) = Self::validate_did(&req.did) {
            return Self::err(ZhtpStatus::BadRequest, msg);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // sled insert is idempotent: re-subscribe is a no-op other than
        // refreshing the timestamp value.
        let value: [u8; 8] = now.to_le_bytes();
        if let Err(e) = self.tree.insert(req.did.as_bytes(), &value) {
            warn!("notifications: sled insert failed for did={}: {}", req.did, e);
            return Self::err(
                ZhtpStatus::InternalServerError,
                format!("storage write failed: {}", e),
            );
        }
        // Best-effort flush; durability isn't critical for an opt-in
        // mailing list (mobile will re-subscribe on next launch).
        let _ = self.tree.flush_async().await;

        info!("notifications: subscribed did={}", req.did);
        Self::json_ok(json!({ "subscribed": true, "did": req.did }))
    }

    async fn handle_unsubscribe(&self, request: ZhtpRequest) -> ZhtpResponse {
        let req: SubscribeRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => {
                return Self::err(
                    ZhtpStatus::BadRequest,
                    format!("invalid request body: {}", e),
                )
            }
        };
        if let Err(msg) = Self::validate_did(&req.did) {
            return Self::err(ZhtpStatus::BadRequest, msg);
        }

        let removed = match self.tree.remove(req.did.as_bytes()) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!(
                    "notifications: sled remove failed for did={}: {}",
                    req.did, e
                );
                return Self::err(
                    ZhtpStatus::InternalServerError,
                    format!("storage write failed: {}", e),
                );
            }
        };
        let _ = self.tree.flush_async().await;

        info!(
            "notifications: unsubscribe did={} (removed={})",
            req.did, removed
        );
        Self::json_ok(json!({ "removed": removed, "did": req.did }))
    }

    async fn handle_list(&self, request: ZhtpRequest) -> ZhtpResponse {
        // Council-only.
        let principal = extract_principal_from_request(&request);
        if principal.role != Role::Council {
            return Self::err(
                ZhtpStatus::Forbidden,
                "Notifications subscriber list requires Council role".to_string(),
            );
        }

        let mut subscribers: Vec<serde_json::Value> = Vec::new();
        for kv in self.tree.iter() {
            match kv {
                Ok((k, v)) => {
                    let did = match std::str::from_utf8(&k) {
                        Ok(s) => s.to_string(),
                        Err(_) => continue,
                    };
                    let subscribed_at = if v.len() >= 8 {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&v[..8]);
                        u64::from_le_bytes(bytes)
                    } else {
                        0
                    };
                    subscribers.push(json!({
                        "did": did,
                        "subscribed_at": subscribed_at,
                    }));
                }
                Err(e) => {
                    warn!("notifications: sled iter error: {}", e);
                }
            }
        }
        Self::json_ok(json!({
            "count": subscribers.len(),
            "subscribers": subscribers,
        }))
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for NotificationsHandler {
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        let uri = request.uri.trim_end_matches('/');
        let resp = match (&request.method, uri) {
            (ZhtpMethod::Post, "/api/v1/notifications/subscribe") => {
                self.handle_subscribe(request).await
            }
            (ZhtpMethod::Post, "/api/v1/notifications/unsubscribe") => {
                self.handle_unsubscribe(request).await
            }
            (ZhtpMethod::Get, "/api/v1/notifications/subscribers") => {
                self.handle_list(request).await
            }
            _ => Self::err(
                ZhtpStatus::NotFound,
                "Unknown notifications endpoint".to_string(),
            ),
        };
        Ok(resp)
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/notifications")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_handler() -> NotificationsHandler {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = sled::open(dir.path().join("notifications.sled")).expect("sled");
        let tree = db.open_tree(TREE_NAME).expect("tree");
        // Leak the tempdir so the sled stays open for the lifetime of the test.
        let _ = Box::leak(Box::new(dir));
        NotificationsHandler { tree }
    }

    fn mk_request(method: ZhtpMethod, uri: &str, body: Vec<u8>) -> ZhtpRequest {
        ZhtpRequest {
            method,
            uri: uri.to_string(),
            version: "1.0".to_string(),
            headers: Default::default(),
            body,
            timestamp: 0,
            requester: None,
            auth_proof: None,
        }
    }

    fn body_for_did(did: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "did": did })).unwrap()
    }

    #[tokio::test]
    async fn subscribe_and_list_roundtrip() {
        let h = tmp_handler();
        let did = "did:zhtp:aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11111111";

        // Subscribe.
        let req = mk_request(
            ZhtpMethod::Post,
            "/api/v1/notifications/subscribe",
            body_for_did(did),
        );
        let resp = h.handle_subscribe(req).await;
        assert_eq!(resp.status, ZhtpStatus::Ok);

        // Duplicate subscribe is idempotent — same DID, no double-count.
        let req = mk_request(
            ZhtpMethod::Post,
            "/api/v1/notifications/subscribe",
            body_for_did(did),
        );
        let resp = h.handle_subscribe(req).await;
        assert_eq!(resp.status, ZhtpStatus::Ok);
        assert_eq!(h.tree.len(), 1, "duplicate subscribe must not double-count");

        // Unsubscribe removes the entry.
        let req = mk_request(
            ZhtpMethod::Post,
            "/api/v1/notifications/unsubscribe",
            body_for_did(did),
        );
        let resp = h.handle_unsubscribe(req).await;
        assert_eq!(resp.status, ZhtpStatus::Ok);
        assert_eq!(h.tree.len(), 0);
    }

    #[tokio::test]
    async fn rejects_bad_did_shape() {
        let h = tmp_handler();
        for bad in &["", "not-a-did", "did:other:abc"] {
            let req = mk_request(
                ZhtpMethod::Post,
                "/api/v1/notifications/subscribe",
                body_for_did(bad),
            );
            let resp = h.handle_subscribe(req).await;
            assert_eq!(
                resp.status,
                ZhtpStatus::BadRequest,
                "expected BadRequest for did={:?}",
                bad
            );
        }
        assert_eq!(h.tree.len(), 0);
    }

    #[tokio::test]
    async fn list_is_council_only() {
        let h = tmp_handler();
        let req = mk_request(
            ZhtpMethod::Get,
            "/api/v1/notifications/subscribers",
            Vec::new(),
        );
        let resp = h.handle_list(req).await;
        assert_eq!(resp.status, ZhtpStatus::Forbidden);
    }
}
