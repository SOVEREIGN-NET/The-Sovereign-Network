//! PoUW (Proof-of-Useful-Work) QUIC Handler

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::debug;
use async_trait::async_trait;

use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use crate::pouw::{
    ChallengeGenerator, ReceiptValidator, RewardCalculator,
    PouwMetrics, PouwRateLimiter, types::ReceiptBatch,
};

pub struct PouwHandler {
    challenge_generator: Arc<ChallengeGenerator>,
    receipt_validator: Arc<RwLock<ReceiptValidator>>,
    /// TODO: Wire up reward_calculator to calculate and distribute rewards for validated receipts.
    /// This will be used in Phase 3 to aggregate receipts by epoch, apply proof type multipliers,
    /// and trigger on-chain payouts. See zhtp/src/pouw/rewards.rs for implementation details.
    reward_calculator: Arc<RwLock<RewardCalculator>>,
    metrics: Arc<PouwMetrics>,
    rate_limiter: Arc<PouwRateLimiter>,
}

impl PouwHandler {
    pub fn new(
        challenge_generator: Arc<ChallengeGenerator>,
        receipt_validator: ReceiptValidator,
        reward_calculator: RewardCalculator,
    ) -> Self {
        Self {
            challenge_generator,
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

        // Parse query parameters from the request URI to configure the challenge.
        let params = Self::parse_query_params(&request.uri);

        // Capability: default to "hash" if not provided.
        let capability = params
            .get("cap")
            .map(|s| s.as_str())
            .or(Some("hash"));

        // Optional numeric limits from query parameters; invalid values are ignored.
        let max_bytes = params
            .get("max_bytes")
            .and_then(|v| v.parse::<u64>().ok());

        let max_receipts = params
            .get("max_receipts")
            .and_then(|v| v.parse::<u32>().ok());

        let challenge = self
            .challenge_generator
            .generate_challenge(capability, max_bytes, max_receipts, None)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        self.metrics.record_challenge_issued();

        let body = serde_json::json!({
            "token": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &challenge.token),
            "expires_at": challenge.expires_at,
        });

        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    async fn handle_submit_receipt(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        debug!("Handling PoUW receipt submission");

        let batch: ReceiptBatch = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let validator = self.receipt_validator.read().await;
        let result = validator.validate_batch(&batch)
            .await
            .map_err(|e| anyhow::anyhow!("Validation failed: {}", e))?;

        let body = serde_json::json!({
            "accepted": result.accepted.len(),
            "rejected": result.rejected.len(),
        });

        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
    }

    async fn handle_health_check(&self) -> ZhtpResult<ZhtpResponse> {
        let body = serde_json::json!({"status": "ok"});
        Ok(ZhtpResponse::json(&body, None).map_err(|e| anyhow::anyhow!(e))?)
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
                ZhtpStatus::NotFound,
                format!("Not found: {} {}", request.method, request.uri),
            ))
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/pouw")
    }

    fn priority(&self) -> u32 { 100 }
}
