//! PoUW (Proof-of-Useful-Work) QUIC Handler
//!
//! Implements the server-side PoUW endpoints over QUIC:
//! - GET /pouw/challenge - Issue challenge tokens to clients
//! - POST /pouw/submit - Receive and validate proof receipts
//!
//! This handler wires the core PoUW logic from zhtp/src/pouw/ to QUIC.

use std::sync::Arc;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use tracing::{info, warn, debug};
use async_trait::async_trait;

use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

use crate::pouw::{
    ChallengeGenerator, ReceiptValidator, RewardCalculator,
    PouwMetrics, PouwRateLimiter, RateLimitResult, types::ReceiptBatch,
};

/// PoUW Handler for QUIC endpoints
pub struct PouwHandler {
    /// Challenge generator (Phase 1)
    challenge_generator: Arc<RwLock<ChallengeGenerator>>,
    /// Receipt validator (Phase 2)
    receipt_validator: Arc<RwLock<ReceiptValidator>>,
    /// Reward calculator (Phase 3)
    reward_calculator: Arc<RwLock<RewardCalculator>>,
    /// Metrics collection
    metrics: Arc<PouwMetrics>,
    /// Rate limiter
    rate_limiter: Arc<PouwRateLimiter>,
}

impl PouwHandler {
    /// Create a new PoUW handler
    pub fn new(
        challenge_generator: ChallengeGenerator,
        receipt_validator: ReceiptValidator,
        reward_calculator: RewardCalculator,
    ) -> Self {
        Self {
            challenge_generator: Arc::new(RwLock::new(challenge_generator)),
            receipt_validator: Arc::new(RwLock::new(receipt_validator)),
            reward_calculator: Arc::new(RwLock::new(reward_calculator)),
            metrics: Arc::new(PouwMetrics::new()),
            rate_limiter: Arc::new(PouwRateLimiter::default()),
        }
    }

    /// Parse query parameters from URI
    fn parse_query_params(uri: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(query) = uri.split('?').nth(1) {
            for pair in query.split('&') {
                let mut parts = pair.split('=');
                if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                    params.insert(key.to_string(), value.to_string());
                }
            }
        }
        params
    }

    /// Handle GET /pouw/challenge request
    async fn handle_get_challenge(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        debug!("Handling PoUW challenge request");

        // Parse query parameters
        let params = Self::parse_query_params(&request.uri);
        let cap = params.get("cap").cloned();
        let max_bytes = params.get("max_bytes").and_then(|v| v.parse().ok());
        let max_receipts = params.get("max_receipts").and_then(|v| v.parse().ok());

        // Rate limit check
        let client_ip = Self::extract_client_ip(request);
        if let Some(ip) = &client_ip {
            let limit_result = self.rate_limiter.check_ip(ip.clone()).await;
            if let RateLimitResult::Denied { reason, retry_after: _ } = limit_result {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::TooManyRequests,
                    format!("Rate limited: {:?}", reason),
                ));
            }
        }

        // Generate challenge
        let generator = self.challenge_generator.read().await;
        let challenge = generator.generate_challenge(
            cap.as_deref(),
            max_bytes,
            max_receipts,
            client_ip,
        ).await
            .map_err(|e| anyhow::anyhow!("Challenge generation failed: {}", e))?;

        // Record metrics
        self.metrics.record_challenge_issued().await;

        // Serialize response
        let response = ChallengeResponse {
            token: general_purpose::STANDARD.encode(&challenge.token),
            expires_at: challenge.expires_at,
        };

        Ok(ZhtpResponse::json(&response, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Handle POST /pouw/submit request
    async fn handle_submit_receipt(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        debug!("Handling PoUW receipt submission");

        // Rate limit check
        let client_ip = Self::extract_client_ip(request);
        if let Some(ip) = &client_ip {
            let limit_result = self.rate_limiter.check_ip(ip.clone()).await;
            if let RateLimitResult::Denied { reason, retry_after: _ } = limit_result {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::TooManyRequests,
                    format!("Rate limited: {:?}", reason),
                ));
            }
        }

        // Parse receipt batch
        let batch: ReceiptBatch = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // Validate receipts
        let validator = self.receipt_validator.read().await;
        let validation_result = validator.validate_batch(&batch).await
            .map_err(|e| anyhow::anyhow!("Validation failed: {}", e))?;

        // Record metrics
        for reason in &validation_result.rejected {
            self.metrics.record_rejection(Some(
                crate::pouw::RejectionReason::BadProof
            )).await;
        }

        // Calculate rewards if valid
        if !validation_result.accepted.is_empty() {
            let calculator = self.reward_calculator.read().await;
            let rewards = calculator.calculate_epoch_rewards(validation_result.accepted.len() as u64).await
                .map_err(|e| anyhow::anyhow!("Reward calculation failed: {}", e))?;

            let response = SubmitResponse {
                accepted: validation_result.accepted.len(),
                rejected: validation_result.rejected.len(),
                rewards,
            };
            Ok(ZhtpResponse::json(&response, None).map_err(|e| anyhow::anyhow!(e))?)
        } else {
            let response = SubmitResponse {
                accepted: 0,
                rejected: batch.receipts.len(),
                rewards: vec![],
            };
            Ok(ZhtpResponse::json(&response, None).map_err(|e| anyhow::anyhow!(e))?)
        }
    }

    /// Handle GET /pouw/health request
    async fn handle_health_check(&self) -> ZhtpResult<ZhtpResponse> {
        let metrics = self.metrics.snapshot().await;
        Ok(ZhtpResponse::json(&metrics, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    /// Extract client IP from request headers
    fn extract_client_ip(request: &ZhtpRequest) -> Option<IpAddr> {
        request
            .headers
            .get("x-forwarded-for")
            .or_else(|| request.headers.get("x-real-ip"))
            .and_then(|v| v.parse().ok())
    }
}

#[async_trait]
impl ZhtpRequestHandler for PouwHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        match (request.method.as_str(), request.uri.as_str()) {
            ("GET", "/pouw/challenge") => {
                self.handle_get_challenge(&request).await
            }
            ("POST", "/pouw/submit") => {
                self.handle_submit_receipt(&request).await
            }
            ("GET", "/pouw/health") => {
                self.handle_health_check().await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("PoUW endpoint not found: {} {}", request.method, request.uri),
                ))
            }
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/pouw")
    }

    fn priority(&self) -> u32 {
        100
    }
}

/// Request to submit receipts
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitReceiptRequest {
    pub receipts: Vec<Vec<u8>>,
}

/// Response for receipt submission
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub accepted: usize,
    pub rejected: usize,
    pub rewards: Vec<Reward>,
}

/// Challenge response
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub token: String,
    pub expires_at: u64,
}

/// Reward info
#[derive(Debug, Serialize, Deserialize)]
pub struct Reward {
    pub recipient: String,
    pub amount: u64,
    pub epoch: u64,
}
