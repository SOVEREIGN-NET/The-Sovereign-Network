//! PoUW (Proof-of-Useful-Work) QUIC Handler

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use async_trait::async_trait;
use hex;

use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use crate::pouw::{
    ChallengeGenerator, ReceiptValidator, RewardCalculator,
    PouwMetrics, PouwRateLimiter, types::ReceiptBatch,
};

pub struct PouwHandler {
    challenge_generator: Arc<ChallengeGenerator>,
    receipt_validator: Arc<RwLock<ReceiptValidator>>,
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

    async fn handle_get_challenge(&self, _request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        debug!("Handling PoUW challenge request");
        
        let challenge = self.challenge_generator.generate_challenge(Some("hash"), None, None, None)
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

        // Calculate rewards for newly accepted receipts only.
        let mut rewards = vec![];
        let mut reward_calc = serde_json::json!({ "status": "skipped", "reason": "no_accepted_receipts" });
        if !result.accepted.is_empty() {
            let validated = validator
                .get_validated_receipts_for_nonces(&result.accepted)
                .await;
            if !validated.is_empty() {
                let calculator = self.reward_calculator.read().await;
                let current_epoch = calculator.current_epoch();
                match calculator.calculate_epoch_rewards(&validated, current_epoch).await {
                    Ok(epoch_rewards) => {
                        for r in epoch_rewards {
                            rewards.push(serde_json::json!({
                                "reward_id": hex::encode(&r.reward_id),
                                "client_did": r.client_did,
                                "amount": r.final_amount,
                                "epoch": r.epoch,
                            }));
                        }
                        reward_calc = serde_json::json!({
                            "status": "ok",
                            "epoch": current_epoch,
                            "calculated_rewards": rewards.len(),
                        });
                    }
                    Err(e) => {
                        warn!("Failed to calculate rewards: {}", e);
                        reward_calc = serde_json::json!({
                            "status": "failed",
                            "error": e.to_string(),
                        });
                    }
                }
            } else {
                reward_calc = serde_json::json!({
                    "status": "skipped",
                    "reason": "no_validated_receipts_for_batch",
                });
            }
        }

        let body = serde_json::json!({
            "accepted": result.accepted.len(),
            "rejected": result.rejected.len(),
            "rewards": rewards,
            "reward_calculation": reward_calc,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_handler() -> PouwHandler {
        let (node_pubkey, node_privkey) = lib_crypto::classical::ed25519::ed25519_keypair();
        let mut priv_arr = [0u8; 32];
        let mut node_id = [0u8; 32];
        priv_arr.copy_from_slice(&node_privkey[..32]);
        node_id.copy_from_slice(&node_pubkey[..32]);
        let generator = Arc::new(ChallengeGenerator::new(priv_arr, node_id));
        let validator = ReceiptValidator::new(generator.clone());
        let reward_calculator = RewardCalculator::new(1_700_000_000);
        PouwHandler::new(generator, validator, reward_calculator)
    }

    #[test]
    fn can_handle_pouw_routes() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/pouw/health".to_string(), None).unwrap();
        assert!(handler.can_handle(&req));
    }

    #[test]
    fn rejects_non_pouw_routes() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/status".to_string(), None).unwrap();
        assert!(!handler.can_handle(&req));
    }

    #[tokio::test]
    async fn health_route_returns_ok() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/pouw/health".to_string(), None).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::Ok);
    }

    #[tokio::test]
    async fn unknown_route_returns_not_found() {
        let handler = build_test_handler();
        let req = ZhtpRequest::get("/pouw/unknown".to_string(), None).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status, ZhtpStatus::NotFound);
    }
}