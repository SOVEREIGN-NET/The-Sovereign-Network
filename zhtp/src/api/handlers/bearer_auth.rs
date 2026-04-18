//! Bearer token authentication middleware (#2157)
//!
//! Wraps any ZhtpRequestHandler and enforces bearer token validation before
//! delegating to the inner handler. Applied to all routes classified as
//! PROTECTED in the endpoint protection matrix (see unified_server.rs #2156).
//!
//! Routes that manage their own auth internally (mobile_auth, tx endpoints)
//! do not use this wrapper — they call validate_access_token() themselves.

use std::sync::Arc;

use lib_identity::auth::mobile_delegation::MobileAuthStore;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use serde_json::json;

/// Wraps an inner handler with bearer token enforcement.
/// Returns 401 if the Authorization header is missing or the token is invalid.
pub struct BearerAuthMiddleware {
    inner: Arc<dyn ZhtpRequestHandler>,
    store: Arc<MobileAuthStore>,
}

impl BearerAuthMiddleware {
    pub fn new(inner: Arc<dyn ZhtpRequestHandler>, store: Arc<MobileAuthStore>) -> Self {
        Self { inner, store }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for BearerAuthMiddleware {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let token = match extract_bearer(&request) {
            Some(t) => t,
            None => return Ok(unauthorized("Missing Bearer token")),
        };

        let ip = extract_ip(&request);
        let ua = extract_ua(&request);

        if let Err(e) = self.store.validate_access_token(&token, &ip, &ua).await {
            return Ok(unauthorized(&e.to_string()));
        }

        self.inner.handle_request(request).await
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        self.inner.can_handle(request)
    }

    fn priority(&self) -> u32 {
        self.inner.priority()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_bearer(request: &ZhtpRequest) -> Option<String> {
    request
        .headers
        .authorization
        .as_deref()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

fn extract_ip(request: &ZhtpRequest) -> String {
    request
        .headers
        .custom
        .get("X-Forwarded-For")
        .or_else(|| request.headers.custom.get("x-forwarded-for"))
        .or_else(|| request.headers.custom.get("X-Real-IP"))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_ua(request: &ZhtpRequest) -> String {
    request
        .headers
        .user_agent
        .clone()
        .unwrap_or_else(|| "unknown".to_string())
}

fn unauthorized(message: &str) -> ZhtpResponse {
    ZhtpResponse::error_json(ZhtpStatus::Unauthorized, &json!({ "error": message }))
        .unwrap_or_else(|_| ZhtpResponse::error(ZhtpStatus::Unauthorized, message.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::auth::mobile_delegation::{MobileDelegatedSession, MobileAuthStore};
    use lib_identity::auth::mobile_delegation::Capability;
    use lib_protocols::types::{ZhtpHeaders, ZhtpMethod};
    use lib_crypto::Hash;
    use std::sync::Arc;

    struct EchoHandler;

    #[async_trait::async_trait]
    impl ZhtpRequestHandler for EchoHandler {
        async fn handle_request(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
            Ok(ZhtpResponse::success(b"ok".to_vec()))
        }
        fn can_handle(&self, _: &ZhtpRequest) -> bool { true }
    }

    fn make_request(bearer: Option<&str>) -> ZhtpRequest {
        let mut headers = ZhtpHeaders::new();
        if let Some(token) = bearer {
            headers.authorization = Some(format!("Bearer {}", token));
        }
        ZhtpRequest {
            method: ZhtpMethod::Get,
            uri: "/api/v1/wallet".to_string(),
            version: "1.0".to_string(),
            headers,
            body: vec![],
            timestamp: 0,
            requester: None,
            auth_proof: None,
        }
    }

    #[tokio::test]
    async fn missing_bearer_returns_401() {
        let store = Arc::new(MobileAuthStore::new());
        let mw = BearerAuthMiddleware::new(Arc::new(EchoHandler), store);
        let resp = mw.handle_request(make_request(None)).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Unauthorized);
    }

    #[tokio::test]
    async fn invalid_bearer_returns_401() {
        let store = Arc::new(MobileAuthStore::new());
        let mw = BearerAuthMiddleware::new(Arc::new(EchoHandler), store);
        let resp = mw.handle_request(make_request(Some("bogus_token"))).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Unauthorized);
    }

    #[tokio::test]
    async fn valid_bearer_delegates_to_inner() {
        let store = Arc::new(MobileAuthStore::new());
        store.insert_session_for_test(MobileDelegatedSession {
            access_token: "valid_tok".to_string(),
            refresh_token: "ref".to_string(),
            identity_id: Hash::from_bytes(&[7u8; 32]),
            public_key_hex: "aa".repeat(1312),
            granted_capabilities: vec![Capability::ReadBalance],
            created_at: 0,
            access_expires_at: u64::MAX,
            refresh_expires_at: u64::MAX,
            bound_ip: "unknown".to_string(),
            bound_user_agent: "unknown".to_string(),
            challenge_session_id: "cs7".to_string(),
            device_id: None,
            revoked: false,
        }).await;

        let mw = BearerAuthMiddleware::new(Arc::new(EchoHandler), store);
        let resp = mw.handle_request(make_request(Some("valid_tok"))).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Ok);
    }

    #[tokio::test]
    async fn revoked_session_returns_401() {
        let store = Arc::new(MobileAuthStore::new());
        store.insert_session_for_test(MobileDelegatedSession {
            access_token: "revoked_tok".to_string(),
            refresh_token: "ref2".to_string(),
            identity_id: Hash::from_bytes(&[8u8; 32]),
            public_key_hex: "bb".repeat(1312),
            granted_capabilities: vec![Capability::ReadBalance],
            created_at: 0,
            access_expires_at: u64::MAX,
            refresh_expires_at: u64::MAX,
            bound_ip: "unknown".to_string(),
            bound_user_agent: "unknown".to_string(),
            challenge_session_id: "cs8".to_string(),
            device_id: None,
            revoked: false,
        }).await;
        store.revoke_session("revoked_tok", "test").await.unwrap();

        let mw = BearerAuthMiddleware::new(Arc::new(EchoHandler), store);
        let resp = mw.handle_request(make_request(Some("revoked_tok"))).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Unauthorized);
    }
}
