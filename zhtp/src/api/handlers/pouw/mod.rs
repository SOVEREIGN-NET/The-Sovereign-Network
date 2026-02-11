//! Proof of Useful Work (PoUW) API Handlers
//!
//! Implements ZHTP handlers for the PoUW protocol:
//! - GET /pouw/challenge: Generate and issue challenge tokens  
//! - GET /pouw/health: Service health check

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use chrono::Utc;
use uuid::Uuid;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

use crate::pouw::challenge::ChallengeGenerator;

// ============================================================================
// Response Types
// ============================================================================

/// Standardized PoUW error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PouwErrorResponse {
    pub error: String,
    pub code: u16,
    pub timestamp: u64,
}

/// GET /pouw/challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeApiResponse {
    pub status: String,
    pub token: String,
    pub expires_at: u64,
    pub expires_in_secs: u64,
    pub timestamp: u64,
}

/// GET /pouw/health response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PouwHealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    pub uptime_secs: u64,
}

// ============================================================================
// Handler Implementation
// ============================================================================

/// Proof of Useful Work API handler
pub struct PouwHandler {
    challenge_generator: Arc<ChallengeGenerator>,
    start_time: std::time::Instant,
}

impl PouwHandler {
    /// Create a new PoUW handler with the given challenge generator
    pub fn new(challenge_generator: Arc<ChallengeGenerator>) -> Self {
        Self {
            challenge_generator,
            start_time: std::time::Instant::now(),
        }
    }

    /// Parse query string from request URI
    fn parse_query_params(uri: &str) -> (Option<String>, Option<u64>, Option<u32>) {
        let mut capabilities = None;
        let mut max_bytes = None;
        let mut max_receipts = None;

        if let Some(query_start) = uri.find('?') {
            let query_string = &uri[query_start + 1..];
            for param in query_string.split('&') {
                if let Some(eq_pos) = param.find('=') {
                    let (key, value) = param.split_at(eq_pos);
                    let value = &value[1..]; // Skip '='
                    match key {
                        "capabilities" => capabilities = Some(value.to_string()),
                        "max_bytes" => {
                            max_bytes = value.parse().ok();
                        }
                        "max_receipts" => {
                            max_receipts = value.parse().ok();
                        }
                        _ => {}
                    }
                }
            }
        }

        (capabilities, max_bytes, max_receipts)
    }

    /// Handle GET /pouw/challenge request
    async fn handle_get_challenge(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let (capabilities, max_bytes, max_receipts) = Self::parse_query_params(&request.uri);

        info!(
            capabilities = ?capabilities,
            max_bytes = ?max_bytes,
            max_receipts = ?max_receipts,
            "Challenge request received"
        );

        // Generate challenge
        match self
            .challenge_generator
            .generate_challenge(
                capabilities.as_deref(),
                max_bytes,
                max_receipts,
                None,
            )
            .await
        {
            Ok(challenge) => {
                let now = Utc::now().timestamp() as u64;
                let response = ChallengeApiResponse {
                    status: "ok".to_string(),
                    token: challenge.token,
                    expires_at: challenge.expires_at,
                    expires_in_secs: challenge.expires_at.saturating_sub(now),
                    timestamp: now,
                };

                info!("Challenge issued successfully");
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap_or_default(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(err) => {
                error!(error = %err, "Failed to generate challenge");
                let error_response = PouwErrorResponse {
                    error: format!("Failed to generate challenge: {}", err),
                    code: 500,
                    timestamp: Utc::now().timestamp() as u64,
                };
                ZhtpResponse::error_json(
                    ZhtpStatus::InternalServerError,
                    &error_response,
                )
            }
        }
    }

    /// Handle GET /pouw/health request
    async fn handle_get_health(&self) -> ZhtpResult<ZhtpResponse> {
        let uptime = self.start_time.elapsed().as_secs();
        let response = PouwHealthResponse {
            status: "healthy".to_string(),
            service: "pouw".to_string(),
            version: "1.0".to_string(),
            uptime_secs: uptime,
        };

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response).unwrap_or_default(),
            "application/json".to_string(),
            None,
        ))
    }
}

// ============================================================================
// ZhtpRequestHandler Implementation
// ============================================================================

#[async_trait::async_trait]
impl ZhtpRequestHandler for PouwHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!(
            method = ?request.method,
            uri = %request.uri,
            "PoUW API request received"
        );

        let response = match (request.method, request.uri.as_str()) {
            // Challenge endpoints
            (ZhtpMethod::Get, uri) if uri.starts_with("/pouw/challenge") => {
                self.handle_get_challenge(&request).await
            }
            // Health check
            (ZhtpMethod::Get, "/pouw/health") => self.handle_get_health().await,
            // Not found
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("PoUW endpoint not found: {} {}", request.method, request.uri),
                ))
            }
        };

        response
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/pouw")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_params_empty() {
        let (cap, bytes, receipts) = PouwHandler::parse_query_params("/pouw/challenge");
        assert!(cap.is_none());
        assert!(bytes.is_none());
        assert!(receipts.is_none());
    }

    #[test]
    fn test_parse_query_params_with_values() {
        let (cap, bytes, receipts) = PouwHandler::parse_query_params(
            "/pouw/challenge?capabilities=hash,merkle&max_bytes=1024&max_receipts=10",
        );
        assert_eq!(cap, Some("hash,merkle".to_string()));
        assert_eq!(bytes, Some(1024));
        assert_eq!(receipts, Some(10));
    }
}
