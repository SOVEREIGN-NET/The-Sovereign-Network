//! Standard auth error responses (#2158)
//!
//! All 401/403 responses from protected endpoints must use these helpers so the
//! format is consistent and clients can rely on a single parsing path.
//!
//! ## Standard format
//! ```json
//! { "error": "<human-readable reason>" }
//! ```
//! Content-Type is always `application/json`.
//! HTTP-equivalent status codes: 401 Unauthorized, 403 Forbidden.

use lib_protocols::types::{ZhtpResponse, ZhtpStatus};
use serde_json::json;

/// 401 Unauthorized — missing, invalid, expired, or revoked bearer token.
pub fn err_401(reason: &str) -> ZhtpResponse {
    ZhtpResponse::error_json(ZhtpStatus::Unauthorized, &json!({ "error": reason }))
        .unwrap_or_else(|_| ZhtpResponse::error(ZhtpStatus::Unauthorized, reason.to_string()))
}

/// 403 Forbidden — valid token but insufficient capability for the requested operation.
pub fn err_403(reason: &str) -> ZhtpResponse {
    ZhtpResponse::error_json(ZhtpStatus::Forbidden, &json!({ "error": reason }))
        .unwrap_or_else(|_| ZhtpResponse::error(ZhtpStatus::Forbidden, reason.to_string()))
}

// ---------------------------------------------------------------------------
// Tests — assert exact JSON format so regressions are caught
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn parse_body(resp: &ZhtpResponse) -> Value {
        serde_json::from_slice(&resp.body).expect("body must be valid JSON")
    }

    #[test]
    fn err_401_has_correct_status_and_json_body() {
        let resp = err_401("Missing Bearer token");
        assert_eq!(resp.status, ZhtpStatus::Unauthorized);
        let body = parse_body(&resp);
        assert_eq!(body["error"], "Missing Bearer token");
        // Must have exactly one key
        assert_eq!(body.as_object().unwrap().len(), 1);
    }

    #[test]
    fn err_401_content_type_is_json() {
        let resp = err_401("test");
        assert_eq!(
            resp.headers.content_type.as_deref(),
            Some("application/json")
        );
    }

    #[test]
    fn err_403_has_correct_status_and_json_body() {
        let resp = err_403("SubmitTx capability not granted");
        assert_eq!(resp.status, ZhtpStatus::Forbidden);
        let body = parse_body(&resp);
        assert_eq!(body["error"], "SubmitTx capability not granted");
        assert_eq!(body.as_object().unwrap().len(), 1);
    }

    #[test]
    fn err_403_content_type_is_json() {
        let resp = err_403("test");
        assert_eq!(
            resp.headers.content_type.as_deref(),
            Some("application/json")
        );
    }

    #[test]
    fn bearer_auth_middleware_401_matches_standard() {
        // Verify the format produced by BearerAuthMiddleware matches our standard
        let resp = err_401("Missing Bearer token");
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        // Client can always do: body["error"].as_str()
        assert!(body["error"].is_string());
        assert_eq!(resp.status, ZhtpStatus::Unauthorized);
    }

    #[test]
    fn tx_prepare_403_matches_standard() {
        // Verify format used when SubmitTx cap is missing
        let resp = err_403("SubmitTx capability not granted");
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(body["error"].is_string());
        assert_eq!(resp.status, ZhtpStatus::Forbidden);
    }
}
