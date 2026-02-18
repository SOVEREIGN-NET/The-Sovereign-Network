//! PoUW (Proof-of-Useful-Work) QUIC Handler
//!
//! Implements the server-side PoUW endpoints over QUIC:
//! - GET /pouw/challenge - Issue challenge tokens to clients
//! - POST /pouw/submit - Receive and validate proof receipts

use std::sync::Arc;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use tracing::{debug};
use async_trait::async_trait;

use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod};

use crate::pouw::{
    ChallengeGenerator, ReceiptValidator, RewardCalculator,
    PouwMetrics, PouwRateLimiter, RateLimitResult, types::ReceiptBatch,
};

pub struct PouwHandler {
    challenge_generator: Arc<RwLock<ChallengeGenerator>>,
    receipt_validator: Arc<RwLock<ReceiptValidator>>,
    reward_calculator: Arc<RwLock<RewardCalculator>>,
    metrics: Arc<PouwMetrics>,
    rate_limiter: Arc<PouwRateLimiter>,
}

impl PouwHandler {
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
            rate_limiter: Arc::new(PouwRateLimiter::with_defaults()),
        }
    }

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

    async fn handle_get_challenge(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        debug!("Handling PoUW challenge request");
        
        let params = Self::parse_query_params(&request.uri);
        let cap = params.get("cap").cloned();
        let max_bytes = params.get("max_bytes").and_then(|v| v.parse().ok());
        let max_receipts = params.get("max_receipts").and_then(|v| v.parse().ok());

        let client_ip = Self::extract_client_ip(request);
        if let Some(ip) = &client_ip {
            let limit_result = self.rate_limiter.check_ip(ip.clone()).await;
            if !limit_result.is_allowed() {
                return Ok(ZhtpResponse::error(
                    lib_protocols::types::ZhtpStatus::TooManyRequests,
                    "Rate limited".to_string(),
                ));
            }
        }

        let generator = self.challenge_generator.read().await;
        let challenge = generator.generate_challenge(
            cap.as_deref(),
            max_bytes,
            max_receipts,
            client_ip,
        ).await.map_err(|e| anyhow::anyhow!(e))?;

        self.metrics.record_challenge_issued();

        let response = ChallengeResponse {
            token: general_purpose::STANDARD.encode(&challenge.token),
            expires_at: challenge.expires_at,
        };

        Ok(ZhtpResponse::json(&response, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    async fn handle_submit_receipt(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        debug!("Handling PoUW receipt submission");

        let client_ip = Self::extract_client_ip(request);
        if let Some(ip) = &client_ip {
            let limit_result = self.rate_limiter.check_ip(ip.clone()).await;
            if !limit_result.is_allowed() {
                return Ok(ZhtpResponse::error(
                    lib_protocols::types::ZhtpStatus::TooManyRequests,
                    "Rate limited".to_string(),
                ));
            }
        }

        let batch: ReceiptBatch = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let validator = self.receipt_validator.read().await;
        let result = validator.validate_batch(&batch).await
            .map_err(|e| anyhow::anyhow!("Validation failed: {}", e))?;

        let response = SubmitResponse {
            accepted: result.accepted.len(),
            rejected: result.rejected.len(),
            rewards: vec![],
        };

        Ok(ZhtpResponse::json(&response, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    async fn handle_health_check(&self) -> ZhtpResult<ZhtpResponse> {
        Ok(ZhtpResponse::json(&serde_json::json!({"status": "ok"}), None).map_err(|e| anyhow::anyhow!(e))?)
    }

    fn extract_client_ip(request: &ZhtpRequest) -> Option<String> {
        request.headers.get("x-forwarded-for")
            .or_else(|| request.headers.get("x-real-ip"))
            .cloned()
    }
}

#[async_trait]
impl ZhtpRequestHandler for PouwHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        match (request.method.as_str(), request.uri.as_str()) {
            ("GET", "/pouw/challenge") => self.handle_get_challenge(&request).await,
            ("POST", "/pouw/submit") => self.handle_submit_receipt(&request).await,
            ("GET", "/pouw/health") => self.handle_health_check().await,
            _ => Ok(ZhtpResponse::error(
                lib_protocols::types::ZhtpStatus::NotFound,
                format!("Not found: {} {}", request.method, request.uri),
            ))
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/pouw")
    }

    fn priority(&self) -> u32 { 100 }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub accepted: usize,
    pub rejected: usize,
    pub rewards: Vec<Reward>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub token: String,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reward {
    pub recipient: String,
    pub amount: u64,
    pub epoch: u64,
}
