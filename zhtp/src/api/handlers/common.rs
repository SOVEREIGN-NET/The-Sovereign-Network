//! Common Handler Utilities
//!
//! Shared helper functions for ZHTP API handlers to eliminate duplication.

use anyhow::Result;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};

/// Helper function to create JSON responses correctly
pub fn create_json_response(data: serde_json::Value) -> Result<ZhtpResponse> {
    let json_response = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

/// Create an error response with the given status and message
pub fn create_error_response(status: ZhtpStatus, message: String) -> ZhtpResponse {
    ZhtpResponse::error(status, message)
}

/// Extract client IP from request headers
///
/// Checks X-Real-IP first, then X-Forwarded-For, falls back to "unknown"
pub fn extract_client_ip(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("X-Real-IP")
        .or_else(|| {
            request
                .headers
                .get("X-Forwarded-For")
                .and_then(|f| f.split(',').next().map(|s| s.trim().to_string()))
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Extract user agent from request headers
pub fn extract_user_agent(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string())
}

/// Validate DID format
///
/// Ensures DID starts with "did:" and is within length bounds
pub fn validate_did_format(did: &str) -> Result<()> {
    if !did.starts_with("did:zhtp:") && !did.starts_with("did:") {
        return Err(anyhow::anyhow!("Invalid DID format"));
    }
    if did.len() < 10 || did.len() > 200 {
        return Err(anyhow::anyhow!("DID length must be between 10 and 200 characters"));
    }
    Ok(())
}
